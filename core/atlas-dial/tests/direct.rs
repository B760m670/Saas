//! Ярус T0 от начала до конца: прокси без ключа доводит трафик до цели.
//!
//! Здесь проверяется то, ради чего всё затевалось: приложение,
//! которому не дали **ничего** — ни ключа, ни адреса точки выхода, — всё
//! равно работает. Тесты самого приёма живут в `desync.rs` и проверяют
//! нарезку по байтам; здесь проверяется, что нарезанное доезжает.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};

use atlas_dial::proxy::Proxy;
use atlas_dial::DialOptions;

/// Поднять сервер, который отвечает на всё, что ему прислали.
fn echo_server() -> (String, std::thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut got = vec![0_u8; 4096];
        let read = socket.read(&mut got).unwrap();
        got.truncate(read);
        socket.write_all("ответ сервера".as_bytes()).unwrap();
        socket.flush().unwrap();
        got
    });
    (address.to_string(), handle)
}

/// Прокси без ключа обязан довести трафик до настоящего сайта.
///
/// Тот же прокси с ключом ответил бы `502`: точки выхода за ключом нет.
/// Здесь ключа нет вовсе — и именно поэтому всё работает.
#[test]
fn a_proxy_without_a_key_still_reaches_the_target() {
    let (target, server) = echo_server();
    let proxy = Proxy::start_direct("127.0.0.1:0", DialOptions::default()).unwrap();
    let address = proxy.address().to_string();

    let mut client = TcpStream::connect(&address).unwrap();
    client
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .unwrap();
    client.flush().unwrap();

    let mut reader = BufReader::new(client.try_clone().unwrap());
    let mut status = String::new();
    reader.read_line(&mut status).unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "прокси без ключа обязан принять соединение, а ответил: {status}"
    );
    // Дочитать пустую строку после заголовков.
    let mut blank = String::new();
    reader.read_line(&mut blank).unwrap();

    // Приветствие TLS, узнаваемое разбором: с ним включается нарезка.
    let hello = sample_hello("rutracker.org");
    client.write_all(&hello).unwrap();
    client.flush().unwrap();

    let delivered = server.join().unwrap();
    assert_eq!(
        delivered, hello,
        "нарезанное приветствие обязано доехать до цели без потерь"
    );

    let mut back = [0_u8; 64];
    let read = client.read(&mut back).unwrap();
    assert_eq!(&back[..read], "ответ сервера".as_bytes());

    proxy.stop();
}

/// Приветствие TLS с заданным именем — того же вида, что строит браузер.
fn sample_hello(name: &str) -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend_from_slice(&0_u16.to_be_bytes());
    let name_len = u16::try_from(name.len()).unwrap();
    let list_len = name_len + 3;
    ext.extend_from_slice(&(list_len + 2).to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&name_len.to_be_bytes());
    ext.extend_from_slice(name.as_bytes());

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0xab; 32]);
    body.push(0);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&ext);

    let mut message = vec![0x01];
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    message.extend_from_slice(&len[1..]);
    message.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&u16::try_from(message.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&message);
    record
}
