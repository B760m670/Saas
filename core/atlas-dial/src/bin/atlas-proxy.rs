//! Локальный прокси, уводящий трафик в туннель.
//!
//! ```text
//! atlas-proxy --key 'vless://…' --listen 127.0.0.1:1080
//! curl -x http://127.0.0.1:1080 https://example.org/
//! ```
//!
//! Вся работа живёт в [`atlas_dial::proxy`]: тот же прокси нужен
//! клиентам через `atlas-ffi`, и двух копий одной перекачки в проекте
//! быть не должно. Здесь — только разбор доводов и вывод на экран.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::time::Duration;

use atlas_dial::{DialOptions, Proxy};
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
        println!("atlas-proxy --key 'vless://…' [--listen 127.0.0.1:1080] [--no-ech] [--stats]");
        return;
    }

    let Some(uri) = value("--key") else {
        eprintln!("нужен ключ доступа: --key 'vless://…'");
        std::process::exit(1);
    };
    let key = match ProxyKey::parse(&uri) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("ключ не разбирается: {error}");
            std::process::exit(1);
        }
    };

    let listen = value("--listen").unwrap_or_else(|| "127.0.0.1:1080".to_owned());
    let options = DialOptions {
        ech: !args.iter().any(|a| a == "--no-ech"),
        ..DialOptions::default()
    };

    let host = key.host.clone();
    let port = key.port;
    let sni = key.security.sni.clone();

    let proxy = match Proxy::start(key, &listen, options) {
        Ok(proxy) => proxy,
        Err(error) => {
            eprintln!("не удалось занять {listen}: {error}");
            std::process::exit(1);
        }
    };

    println!("прокси           {}", proxy.address());
    println!("точка выхода     {host}:{port}");
    println!("сайт прикрытия   {}", sni.as_deref().unwrap_or("—"));
    println!();
    println!(
        "Проверить:  curl -x http://{} https://example.org/",
        proxy.address()
    );

    if args.iter().any(|a| a == "--stats") {
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let stats = proxy.stats();
            println!(
                "соединений {} (сейчас {}), отказов {}, вверх {} Б, вниз {} Б",
                stats.accepted, stats.active, stats.failed, stats.to_target, stats.from_target
            );
        }
    }

    // Прокси живёт в своих потоках; главному остаётся только не выходить.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
