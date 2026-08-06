//! Туннель по ключу доступа: от `vless://` до ответа сайта.
//!
//! ```text
//! cargo run --example tunnel -- 'vless://…' example.org
//! cargo run --example tunnel -- 'vless://…' example.org --no-ech
//! ```
//!
//! Без ключа под рукой пример всё равно полезен: если подставить ссылку
//! на **чужой настоящий сайт**, соединение обязано дойти до проверки
//! сертификата и там оборваться. Это и есть проверка того, что REALITY
//! отличает свою точку выхода от постороннего сервера.

// Инструмент исследования: вход — аргументы командной строки.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::io::{Read, Write};
use std::time::Instant;

use atlas_dial::{dial_with, DialOptions, Error, Target};
use atlas_types::ProxyKey;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(uri) = args.next() else {
        eprintln!("нужен ключ доступа: cargo run --example tunnel -- 'vless://…' example.org");
        std::process::exit(1);
    };
    let host = args.next().unwrap_or_else(|| "example.org".to_owned());
    let flags: Vec<String> = args.collect();

    let key = match ProxyKey::parse(&uri) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("ключ не разбирается: {error}");
            std::process::exit(1);
        }
    };

    println!("точка выхода     {}:{}", key.host, key.port);
    println!("протокол         {:?}", key.protocol);
    println!("маскировка       {:?}", key.security.kind);
    println!("режим потока     {:?}", key.flow);
    println!(
        "сайт прикрытия   {}",
        key.security.sni.as_deref().unwrap_or("—")
    );
    for warning in key.warnings() {
        println!("предупреждение   {warning:?}");
    }
    println!("назначение       {host}:443");
    println!();

    let options = DialOptions {
        ech: !flags.iter().any(|f| f == "--no-ech"),
        ..DialOptions::default()
    };

    let started = Instant::now();
    let mut tunnel = match dial_with(&key, &Target::domain(host.clone(), 443), &options) {
        Ok(tunnel) => tunnel,
        Err(error) => {
            // Разные причины требуют разных действий, и различать их
            // стоит уже здесь.
            match &error {
                Error::Unsupported(what) => eprintln!("схема пока не собирается: {what}"),
                Error::Key(what) => eprintln!("ключ непригоден: {what}"),
                Error::Io(io) if io.to_string().contains("REALITY") => {
                    eprintln!("сервер не является нашей точкой выхода: {io}");
                    eprintln!("(так и должно быть, если ссылка указывает на посторонний сайт)");
                }
                Error::Io(io) => eprintln!("соединение не установлено: {io}"),
            }
            std::process::exit(2);
        }
    };
    println!("туннель поднят   {} мс", started.elapsed().as_millis());
    println!(
        "обрамление       {}",
        if tunnel.is_direct() {
            "прямое"
        } else {
            "Vision"
        }
    );

    // Простой HTTP-запрос: через туннель он идёт как обычный TCP.
    let request =
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: atlas/0.1\r\nConnection: close\r\nAccept: */*\r\n\r\n");
    if let Err(error) = tunnel.write_all(request.as_bytes()) {
        eprintln!("запрос не ушёл: {error}");
        std::process::exit(3);
    }

    let mut answer = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        match tunnel.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => {
                answer.extend_from_slice(buf.get(..read).unwrap_or_default());
                if answer.len() > 256 * 1024 {
                    break;
                }
            }
            Err(error) => {
                eprintln!("чтение оборвалось: {error}");
                break;
            }
        }
    }

    let head = String::from_utf8_lossy(&answer);
    println!(
        "ответ            {}",
        head.lines().next().unwrap_or("(пусто)")
    );
    println!("получено         {} байт", answer.len());
    println!(
        "обрамление       {}",
        if tunnel.is_direct() {
            "прямое"
        } else {
            "Vision"
        }
    );
    println!("всего            {} мс", started.elapsed().as_millis());
}
