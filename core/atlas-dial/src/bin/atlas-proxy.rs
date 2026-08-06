//! Локальный прокси, уводящий трафик в туннель.
//!
//! ```text
//! atlas-proxy --key 'vless://…' --listen 127.0.0.1:1080
//! curl -x http://127.0.0.1:1080 https://example.org/
//! ```
//!
//! Слушает HTTP-прокси с методом `CONNECT`. Выбор не случайный: именно
//! этот способ понимает iOS через `.mobileconfig` с PAC — то есть
//! единственный, каким сборка `lite` под LiveContainer сможет забрать
//! системный трафик, не имея права на `NEPacketTunnelProvider`
//! (см. `docs/05-clients.md`). Заодно его понимают `curl`, браузеры и
//! почти всё остальное.
//!
//! Каждое соединение поднимает **свой** туннель. Так дороже по
//! рукопожатиям, но зато у наблюдателя нет одного долгоживущего потока,
//! в который сходится вся активность пользователя.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::io::{self, BufRead as _, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use atlas_dial::{dial_with, DialOptions, Target};
use atlas_types::ProxyKey;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|at| args.get(at + 1))
            .cloned()
    };

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("atlas-proxy --key 'vless://…' [--listen 127.0.0.1:1080] [--no-ech]");
        return;
    }

    let Some(uri) = value("--key") else {
        eprintln!("нужен ключ доступа: --key 'vless://…'");
        std::process::exit(1);
    };
    let key = match ProxyKey::parse(&uri) {
        Ok(key) => Arc::new(key),
        Err(error) => {
            eprintln!("ключ не разбирается: {error}");
            std::process::exit(1);
        }
    };

    let listen = value("--listen").unwrap_or_else(|| "127.0.0.1:1080".to_owned());
    let options = Arc::new(DialOptions {
        ech: !args.iter().any(|a| a == "--no-ech"),
        ..DialOptions::default()
    });

    let listener = TcpListener::bind(&listen).unwrap_or_else(|error| {
        eprintln!("не удалось занять {listen}: {error}");
        std::process::exit(1);
    });
    let bound = listener.local_addr().map_or(listen, |a| a.to_string());

    println!("прокси           {bound}");
    println!("точка выхода     {}:{}", key.host, key.port);
    println!(
        "сайт прикрытия   {}",
        key.security.sni.as_deref().unwrap_or("—")
    );
    println!();
    println!("Проверить:  curl -x http://{bound} https://example.org/");

    for incoming in listener.incoming() {
        let Ok(socket) = incoming else { continue };
        let key = Arc::clone(&key);
        let options = Arc::clone(&options);
        let _ = std::thread::Builder::new()
            .name("atlas-proxy".to_owned())
            .spawn(move || {
                if let Err(error) = serve(socket, &key, &options) {
                    eprintln!("соединение: {error}");
                }
            });
    }
}

/// Обслужить одно соединение прокси.
fn serve(mut socket: TcpStream, key: &ProxyKey, options: &DialOptions) -> io::Result<()> {
    socket.set_nodelay(true)?;
    let (host, port) = read_connect(&mut socket)?;

    let tunnel = match dial_with(key, &Target::domain(host.clone(), port), options) {
        Ok(tunnel) => tunnel,
        Err(error) => {
            // Причину видит только локальный клиент; наружу она не идёт.
            let _ = socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return Err(io::Error::other(error.to_string()));
        }
    };

    socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    socket.flush()?;
    splice(socket, tunnel)
}

/// Прочитать запрос `CONNECT host:port` и заголовки до пустой строки.
fn read_connect(socket: &mut TcpStream) -> io::Result<(String, u16)> {
    let mut reader = BufReader::new(socket.try_clone()?);
    let mut request = String::new();
    reader.read_line(&mut request)?;

    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default().to_owned();

    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = socket.write_all(
            "HTTP/1.1 405 Method Not Allowed\r\n\r\nПоддерживается только CONNECT.\n".as_bytes(),
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("метод {method} не поддерживается"),
        ));
    }

    // Остаток заголовков дочитывается и отбрасывается: в туннель они не
    // идут, там уже начинается TLS клиента.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
    }

    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "нет порта в цели CONNECT"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "порт не число"))?;
    Ok((host.to_owned(), port))
}

/// Гонять байты между локальным клиентом и туннелем.
///
/// Туннель нельзя раздвоить, как сокет, поэтому направления разведены
/// так: чтение из туннеля живёт в отдельном потоке вместе с самим
/// туннелем, а запись в него идёт через канал.
fn splice<T: Read + Write + Send + 'static>(socket: TcpStream, tunnel: T) -> io::Result<()> {
    let mut local_read = socket.try_clone()?;
    let mut local_write = socket;

    let (sender, receiver) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut tunnel_read = tunnel;

    let pump = std::thread::spawn(move || -> io::Result<()> {
        // Всё, что просят отправить, уходит в туннель; всё, что пришло
        // оттуда, — локальному клиенту.
        let mut buf = vec![0_u8; 16 * 1024];
        loop {
            // Сначала отдать накопившееся к отправке, не блокируясь.
            while let Ok(chunk) = receiver.try_recv() {
                if chunk.is_empty() {
                    let _ = tunnel_read.flush();
                    return Ok(());
                }
                tunnel_read.write_all(&chunk)?;
                tunnel_read.flush()?;
            }
            match tunnel_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if local_write
                        .write_all(buf.get(..read).unwrap_or_default())
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = local_write.shutdown(std::net::Shutdown::Write);
        Ok(())
    });

    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        match local_read.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if sender
                    .send(buf.get(..read).unwrap_or_default().to_vec())
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    let _ = sender.send(Vec::new());
    let _ = pump.join();
    Ok(())
}
