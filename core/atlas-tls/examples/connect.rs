//! Живое соединение с настоящим сервером — проверка клиента на практике.
//!
//! Эталонные векторы RFC 8448 доказывают правильность вычислений, но не
//! доказывают, что автомат договорится с чужой реализацией. Здесь
//! рукопожатие идёт до конца с настоящим сервером, и результат виден
//! целиком: выбранный шифронабор, группа обмена, ALPN, цепочка
//! сертификатов и ответ на запрос.
//!
//! ```text
//! cargo run --example connect -- www.google.com
//! cargo run --example connect -- rutube.ru --dump-cert
//! ```
//!
//! Если в окружении задан `HTTPS_PROXY`, соединение идёт через `CONNECT`.
//! Тогда обязательно надо смотреть на издателя сертификата: прокси может
//! перевыпускать TLS, и тогда измерение описывает прокси, а не интернет.

// Инструмент исследования: вход — аргументы командной строки и ответ
// сервера, которым мы и так собираемся доверять ровно настолько,
// насколько нужно для печати диагностики.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use atlas_tls::client::{AcceptAnyServer, ClientConfig};
use atlas_tls::fingerprint::{ja4, Transport};
use atlas_tls::keyexchange::Group;
use atlas_tls::stream::TlsStream;

fn main() {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "www.google.com".to_owned());
    let flags: Vec<String> = args.collect();
    let dump_cert = flags.iter().any(|f| f == "--dump-cert");
    let classic_only = flags.iter().any(|f| f == "--x25519-only");
    let no_ech = flags.iter().any(|f| f == "--no-ech");
    let no_request = flags.iter().any(|f| f == "--no-request");

    let started = Instant::now();
    let socket = match open_socket(&host) {
        Ok(socket) => socket,
        Err(err) => {
            eprintln!("сокет: {err}");
            std::process::exit(1);
        }
    };
    let connected = started.elapsed();

    let mut config = ClientConfig::new(host.clone()).with_verifier(Box::new(AcceptAnyServer));
    if classic_only {
        config.groups = vec![Group::X25519];
    }
    if no_ech {
        config.profile = config.profile.without_ech();
    }

    let mut stream = match TlsStream::connect(socket, config) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("рукопожатие с {host}: {err}");
            std::process::exit(2);
        }
    };
    let handshaked = started.elapsed();

    let connection = stream.connection();
    println!("узел              {host}");
    println!("tcp               {} мс", connected.as_millis());
    println!("рукопожатие       {} мс (всего)", handshaked.as_millis());
    println!(
        "шифронабор        {}",
        connection
            .cipher_suite()
            .map_or_else(|| "—".to_owned(), |s| format!("0x{s:04x}"))
    );
    println!(
        "группа            {}",
        connection
            .group()
            .map_or_else(|| "—".to_owned(), |g| format!("{g:?} (0x{:04x})", g.code()))
    );
    println!("повторное hello   {}", connection.was_retried());
    println!("alpn              {}", connection.alpn().unwrap_or("—"));
    println!(
        "наш ja4           {}",
        ja4(connection.client_hello(), Transport::Tcp).to_string_full()
    );

    if let Some(certificate) = connection.peer_certificate() {
        println!("сертификатов      {}", certificate.entries.len());
        for (index, entry) in certificate.entries.iter().enumerate() {
            println!("  [{index}] {} байт DER", entry.data.len());
        }
        if dump_cert {
            if let Some(der) = certificate.end_entity() {
                let path = std::env::temp_dir().join("atlas-peer-cert.der");
                std::fs::write(&path, der).expect("запись сертификата");
                println!("сертификат        {}", path.display());
            }
        }
    }

    // Настоящая проверка: пойдут ли прикладные данные в обе стороны.
    // Говорить надо на том протоколе, о котором договорились: HTTP/1.1
    // в соединении с согласованным `h2` сервер обрывает предупреждением
    // `unexpected_message`, и это правильно с его стороны.
    let http2 = connection.alpn() == Some("h2");
    let request = if http2 {
        http2_opening()
    } else {
        format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: atlas/0.1\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        )
        .into_bytes()
    };

    if !no_request {
        if let Err(err) = stream.write_all(&request) {
            eprintln!("запрос: {err}");
            std::process::exit(3);
        }
    }

    let mut response = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                // В HTTP/2 сервер не закрывает соединение сам; довольно
                // первой пачки кадров, чтобы убедиться, что канал живой.
                if http2 && response.len() >= 9 {
                    break;
                }
                if response.len() > 64 * 1024 {
                    break;
                }
            }
            Err(err) => {
                eprintln!("чтение: {err}");
                break;
            }
        }
    }

    if http2 {
        println!("ответ             {}", describe_http2(&response));
    } else {
        let head = String::from_utf8_lossy(&response);
        println!(
            "ответ             {}",
            head.lines().next().unwrap_or("(пусто)")
        );
    }
    println!("получено          {} байт", response.len());
    println!("всего             {} мс", started.elapsed().as_millis());

    let _ = stream.close();
}

/// Преамбула HTTP/2 и пустой кадр `SETTINGS` — минимум, на который
/// сервер обязан ответить своим `SETTINGS`.
fn http2_opening() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    // длина 0, тип SETTINGS(4), флаги 0, поток 0
    out.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    out
}

/// Пересказать заголовки кадров HTTP/2 человеческим языком.
fn describe_http2(data: &[u8]) -> String {
    const NAMES: [&str; 10] = [
        "DATA",
        "HEADERS",
        "PRIORITY",
        "RST_STREAM",
        "SETTINGS",
        "PUSH_PROMISE",
        "PING",
        "GOAWAY",
        "WINDOW_UPDATE",
        "CONTINUATION",
    ];

    let mut frames = Vec::new();
    let mut offset = 0;
    while offset + 9 <= data.len() {
        let length = usize::from(data[offset]) << 16
            | usize::from(data[offset + 1]) << 8
            | usize::from(data[offset + 2]);
        let kind = data[offset + 3];
        let name = NAMES
            .get(usize::from(kind))
            .copied()
            .unwrap_or("(неизвестный)");
        frames.push(format!("{name}({length})"));
        offset += 9 + length;
    }
    if frames.is_empty() {
        "(кадров нет)".to_owned()
    } else {
        frames.join(" ")
    }
}

/// Открыть TCP-соединение, при необходимости через `CONNECT`.
fn open_socket(host: &str) -> std::io::Result<TcpStream> {
    let target = format!("{host}:443");

    let proxy = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .ok();

    let Some(proxy) = proxy else {
        let socket = TcpStream::connect(&target)?;
        socket.set_read_timeout(Some(Duration::from_secs(20)))?;
        return Ok(socket);
    };

    let authority = proxy
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let mut socket = TcpStream::connect(authority)?;
    socket.set_read_timeout(Some(Duration::from_secs(20)))?;

    write!(
        socket,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\n\r\n"
    )?;
    socket.flush()?;

    // Прочитать ответ прокси ровно до конца заголовков и ни байтом больше:
    // следом сразу идёт TLS, и лишний прочитанный байт его сломает.
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        let read = socket.read(&mut byte)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "прокси оборвал ответ",
            ));
        }
        header.push(byte[0]);
        if header.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "заголовок прокси слишком длинный",
            ));
        }
    }

    let status = String::from_utf8_lossy(&header);
    let line = status.lines().next().unwrap_or_default();
    if !line.contains(" 200") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("прокси ответил: {line}"),
        ));
    }
    Ok(socket)
}
