//! Разбор захваченного `ClientHello` и вычисление его отпечатков.
//!
//! Принимает файл с шестнадцатеричной записью handshake-сообщения —
//! по одному захвату на строку.
//!
//! ```text
//! cargo run --example inspect -- hello.hex
//! ```

use atlas_tls::fingerprint::{ja3, ja4};
use atlas_tls::{ClientHello, Transport};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("укажите файл с шестнадцатеричной записью");
        std::process::exit(2);
    };
    let text = std::fs::read_to_string(&path).unwrap_or_default();

    for (index, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let bytes: Vec<u8> = line
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .filter_map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|s| u8::from_str_radix(s, 16).ok())
            })
            .collect();

        println!("=== захват {index}: {} байт ===", bytes.len());
        match ClientHello::parse(&bytes) {
            Ok(hello) => {
                let fp = ja4(&hello, Transport::Tcp);
                println!("JA4        {fp}");
                println!("JA3        {}", ja3(&hello).hash);
                println!("SNI        {:?}", hello.server_name());
                println!("ALPN       {:?}", hello.alpn());
                println!("session_id {} байт", hello.session_id.len());
                println!("шифры      {}", hello.cipher_suites.len());
                println!(
                    "шифры hex  {}",
                    hello
                        .cipher_suites
                        .iter()
                        .map(|c| format!("{c:04x}"))
                        .collect::<Vec<_>>()
                        .join(",")
                );
                println!(
                    "расширения {}",
                    hello
                        .extensions
                        .iter()
                        .map(|e| format!("{:04x}", e.ext_type))
                        .collect::<Vec<_>>()
                        .join(",")
                );
                println!(
                    "группы     {}",
                    hello
                        .supported_groups()
                        .iter()
                        .map(|g| format!("{g:04x}"))
                        .collect::<Vec<_>>()
                        .join(",")
                );
                println!(
                    "sigalgs    {}",
                    hello
                        .signature_algorithms()
                        .iter()
                        .map(|s| format!("{s:04x}"))
                        .collect::<Vec<_>>()
                        .join(",")
                );
                println!("JA3 строка {}", ja3(&hello).raw);
            }
            Err(err) => println!("не разобрано: {err}"),
        }
    }
}
