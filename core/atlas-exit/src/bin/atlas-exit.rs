//! Запуск точки выхода.
//!
//! ```text
//! atlas-exit --listen 0.0.0.0:443 --host 203.0.113.7 --cover www.microsoft.com:443
//! ```
//!
//! При первом запуске ключи генерируются и печатается готовая ссылка
//! `vless://` — её и надо вставить в клиент. Приватный ключ никуда не
//! записывается: точка выхода одноразовая по замыслу, а долговечность
//! ключа означала бы, что его утечка компрометирует всё прошлое.
//! Постоянный ключ задаётся явно через `--secret`.
//!
//! `--host` — это адрес, **по которому до машины достучится клиент**, а
//! не адрес прослушивания. Они совпадают редко: слушают обычно на всех
//! картах (`0.0.0.0`), а снаружи машина видна по одному конкретному
//! адресу, и часто ещё через проброс порта. Правило выбора и причины —
//! в [`atlas_exit::link`].

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::net::TcpListener;
use std::sync::Arc;

use atlas_exit::{link, ExitConfig, ExitPoint, Policy};
use atlas_reality::Server;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|at| args.get(at + 1))
            .cloned()
    };
    let flag = |name: &str| args.iter().any(|a| a == name);

    if flag("--help") || flag("-h") {
        println!("atlas-exit --listen АДРЕС --cover ДОМЕН:ПОРТ [--host АДРЕС[:ПОРТ]]");
        println!("           [--secret BASE64] [--sid HEX] [--uuid UUID] [--allow-private]");
        println!();
        println!("  --listen  где занять сокет; по умолчанию 127.0.0.1:8443");
        println!("  --host    как до этой машины достучится клиент — внешний адрес");
        println!("            или имя. Обязателен, если --listen на всех картах");
        println!("  --cover   чужой сайт, которым прикидываемся для посторонних");
        return;
    }

    let listen = value("--listen").unwrap_or_else(|| "127.0.0.1:8443".to_owned());
    let cover = value("--cover").unwrap_or_else(|| "www.microsoft.com:443".to_owned());
    let short_id = value("--sid").unwrap_or_else(|| "dead".to_owned());
    let uuid = value("--uuid").unwrap_or_else(atlas_crypto::credentials::generate_uuid);

    let secret = value("--secret").map(|text| {
        decode_key(&text).unwrap_or_else(|| {
            eprintln!("--secret: не разбирается как 32 байта в base64url");
            std::process::exit(1);
        })
    });

    let short_id_bytes = decode_hex(&short_id).unwrap_or_else(|| {
        eprintln!("--sid: не разбирается как hex");
        std::process::exit(1);
    });

    let reality = match secret {
        Some(bytes) => Server::from_secret(bytes),
        None => Server::generate(),
    }
    .with_short_id(&short_id_bytes)
    .unwrap_or_else(|error| {
        eprintln!("shortId: {error}");
        std::process::exit(1);
    });

    let public_key = base64_url(&reality.public_key());
    let sni = cover
        .rsplit_once(':')
        .map_or_else(|| cover.clone(), |(host, _)| host.to_owned());

    let listener = TcpListener::bind(&listen).unwrap_or_else(|error| {
        eprintln!("не удалось занять {listen}: {error}");
        std::process::exit(1);
    });
    let bound = listener.local_addr().unwrap_or_else(|error| {
        eprintln!("не удалось узнать занятый адрес: {error}");
        std::process::exit(1);
    });

    // Отказ здесь — до первого принятого соединения. Ключ, который
    // никуда не ведёт, хуже, чем отсутствие ключа: он выглядит
    // рабочим, и искать причину пойдут в туннеле.
    let (endpoint, reach) =
        link::endpoint(bound, value("--host").as_deref()).unwrap_or_else(|error| {
            eprintln!("{error}");
            std::process::exit(1);
        });

    println!("слушает          {bound}");
    println!("адрес для ключа  {endpoint} — {}", reach.note());
    println!("сайт прикрытия   {cover}");
    println!("публичный ключ   {public_key}");
    println!();
    println!("Ключ доступа (вставить в клиент):");
    println!(
        "{}",
        link::AccessKey {
            endpoint: &endpoint,
            uuid: &uuid,
            sni: &sni,
            public_key: &public_key,
            short_id: &short_id,
        }
        .to_link()
    );
    println!();

    let policy = Policy {
        allow_private: flag("--allow-private"),
        ..Policy::default()
    };
    if policy.allow_private {
        println!("ВНИМАНИЕ: разрешены соединения во внутреннюю сеть.");
        println!("Такую точку нельзя отдавать никому, кроме себя.");
        println!();
    }

    let verbose = flag("--verbose");
    let point = Arc::new(
        ExitPoint::new(ExitConfig::new(reality, cover).with_policy(policy)).with_log(Arc::new(
            move |message: &str| {
                if verbose {
                    eprintln!("[exit] {message}");
                }
            },
        )),
    );
    if let Err(error) = point.serve(&listener) {
        eprintln!("точка выхода остановлена: {error}");
        std::process::exit(1);
    }
}

fn base64_url(raw: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

fn decode_key(text: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()?
        .try_into()
        .ok()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            core::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
        })
        .collect()
}
