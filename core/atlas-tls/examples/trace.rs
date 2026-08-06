//! Пошаговый след рукопожатия: что ушло, что пришло, чем это было.
//!
//! Нужен, когда живое соединение обрывается, а эталонные тесты зелёные:
//! тогда расхождение не в вычислениях, а в порядке или составе записей,
//! и увидеть его можно только на проводе.
//!
//! ```text
//! cargo run --example trace -- www.google.com
//! ```
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
use std::time::Duration;

use atlas_tls::client::{AcceptAnyServer, ClientConfig, Connection};

fn main() {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "www.google.com".to_owned());
    let mut socket = open_socket(&host).expect("сокет");

    let config = ClientConfig::new(host.clone())
        .with_verifier(Box::new(AcceptAnyServer))
        .with_profile(atlas_tls::Chrome::v141().without_ech());
    let mut connection = Connection::new(config).expect("клиент");

    let mut buf = [0_u8; 16384];
    for round in 0..4 {
        let out = connection.take_output();
        if !out.is_empty() {
            println!("→ {} байт", out.len());
            for record in split_records(&out) {
                println!("   {}", describe(&record));
            }
            socket.write_all(&out).expect("запись");
            socket.flush().expect("сброс");
        }

        if !connection.is_handshaking() && round > 0 {
            println!("рукопожатие завершено, слушаем дальше");
        }

        let read = match socket.read(&mut buf) {
            Ok(0) => {
                println!("← обрыв");
                break;
            }
            Ok(n) => n,
            Err(err) => {
                println!("← ошибка: {err}");
                break;
            }
        };
        println!("← {read} байт");
        for record in split_records(&buf[..read]) {
            println!("   {}", describe(&record));
        }

        connection.read_tls(&buf[..read]).expect("приём");
        match connection.process() {
            Ok(()) => println!("   состояние: рукопожатие={}", connection.is_handshaking()),
            Err(err) => {
                println!("   ошибка разбора: {err}");
                break;
            }
        }
    }

    println!("шифронабор {:?}", connection.cipher_suite());
    println!("группа     {:?}", connection.group());
    println!("alpn       {:?}", connection.alpn());
}

/// Разрезать поток на записи по заголовкам, не расшифровывая.
fn split_records(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + 5 <= data.len() {
        let length = usize::from(u16::from_be_bytes([data[offset + 3], data[offset + 4]]));
        let end = (offset + 5 + length).min(data.len());
        out.push(data[offset..end].to_vec());
        offset = end;
    }
    out
}

fn describe(record: &[u8]) -> String {
    let kind = match record.first() {
        Some(20) => "change_cipher_spec",
        Some(21) => "alert",
        Some(22) => "handshake",
        Some(23) => "application_data",
        _ => "(неизвестно)",
    };
    let mut text = format!(
        "{kind} ver={:02x}{:02x} len={}",
        record.get(1).copied().unwrap_or(0),
        record.get(2).copied().unwrap_or(0),
        record.len().saturating_sub(5)
    );
    if record.first() == Some(&22) {
        if let Some(msg) = record.get(5) {
            text.push_str(&format!(" msg_type={msg}"));
        }
    }
    if record.first() == Some(&21) {
        text.push_str(&format!(
            " level={:?} desc={:?}",
            record.get(5),
            record.get(6)
        ));
    }
    text
}

fn open_socket(host: &str) -> std::io::Result<TcpStream> {
    let target = format!("{host}:443");
    let Ok(proxy) = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")) else {
        let socket = TcpStream::connect(&target)?;
        socket.set_read_timeout(Some(Duration::from_secs(15)))?;
        return Ok(socket);
    };

    let authority = proxy
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned();
    let mut socket = TcpStream::connect(authority)?;
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    write!(
        socket,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
    )?;
    socket.flush()?;

    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        if socket.read(&mut byte)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "прокси оборвал ответ",
            ));
        }
        header.push(byte[0]);
    }
    Ok(socket)
}
