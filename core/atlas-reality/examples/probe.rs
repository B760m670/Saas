//! Зонд совместимости с настоящим сервером REALITY.
//!
//! Собирает `ClientHello` профилем Chrome, запечатывает в него метку и
//! отправляет указанному серверу. Ответ сервера показывает, принят ли
//! клиент: при верной метке сервер продолжает рукопожатие сам, при
//! неверной — прозрачно передаёт соединение сайту прикрытия.
//!
//! ```text
//! cargo run --example probe -- <адрес> <pbk> <shortId hex> <sni>
//! ```

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::Duration;

use atlas_reality::Client;
use atlas_tls::profile::{X25519, X25519_MLKEM768};
use atlas_tls::{Chrome, HelloParams};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, addr, pbk, short_id, sni] = args.as_slice() else {
        eprintln!("нужно: <адрес> <pbk> <shortId hex> <sni>");
        std::process::exit(2);
    };

    let pbk_bytes: [u8; 32] = base64_url(pbk)
        .try_into()
        .expect("pbk должен быть 32 байта");
    let short_id_bytes = from_hex(short_id);

    let client = Client::new(pbk_bytes, &short_id_bytes, [26, 3, 27]).expect("клиент");
    let session = client.begin();

    let params = HelloParams::new(sni.clone())
        .with_key_shares(vec![
            (X25519_MLKEM768, vec![0x33; 1216]),
            (X25519, session.public_key().to_vec()),
        ])
        .with_session_id(vec![0_u8; 32]);

    let hello = Chrome::v141().client_hello(&params).expect("ClientHello");
    let mut handshake = hello.to_handshake().expect("сериализация");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    session
        .seal(&mut handshake, now)
        .expect("запечатывание метки");

    // Оборачиваем в запись TLS.
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    println!("отправляем {} байт, SNI {sni}", record.len());

    let mut stream = TcpStream::connect(addr.as_str()).expect("подключение");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.write_all(&record).expect("отправка");

    let mut response = vec![0_u8; 8192];
    match stream.read(&mut response) {
        Ok(0) => println!("сервер закрыл соединение, не ответив"),
        Ok(n) => {
            println!("получено {n} байт");
            describe(response.get(..n).unwrap_or_default());
        }
        Err(err) => println!("чтение не удалось: {err}"),
    }
}

/// Коротко описать, что прислал сервер.
fn describe(response: &[u8]) {
    match response {
        [0x16, 0x03, _, ..] => {
            println!("это запись handshake");
            // Тип handshake-сообщения идёт сразу за пятибайтовым заголовком.
            match response.get(5) {
                Some(0x02) => println!("  ServerHello — сервер продолжает рукопожатие"),
                Some(other) => println!("  тип сообщения {other:#04x}"),
                None => println!("  запись пуста"),
            }
        }
        [0x15, 0x03, _, ..] => println!("это alert — сервер отверг соединение на уровне TLS"),
        _ => println!(
            "не запись TLS: {:02x?}",
            response.get(..8).unwrap_or_default()
        ),
    }
}

fn base64_url(input: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = 0_u32;
    let mut count = 0_u32;
    let mut out = Vec::new();
    for byte in input.bytes().filter(|b| *b != b'=') {
        let Some(index) = ALPHABET.iter().position(|c| *c == byte) else {
            continue;
        };
        bits = (bits << 6) | index as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out
}

fn from_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .filter_map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect()
}
