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
        println!("  --check-cover  проверить сайт прикрытия и выйти");
        println!("  --skip-check   не проверять сайт прикрытия при запуске");
        println!("  --cover-limit  предел отдачи постороннему, КБ/с — защита");
        println!("                 от выкачки вашей квоты через сайт прикрытия");
        println!("  --pq-seed BASE64  семя ML-DSA-65: включает постквантовую");
        println!("                 проверку сертификата. Обязано пережить");
        println!("                 перезапуск, иначе выданные ключи отвалятся");
        return;
    }

    let listen = value("--listen").unwrap_or_else(|| "127.0.0.1:8443".to_owned());
    let cover = value("--cover").unwrap_or_else(|| "www.microsoft.com:443".to_owned());
    let short_id = value("--sid").unwrap_or_else(|| "dead".to_owned());
    let uuid = value("--uuid").unwrap_or_else(atlas_crypto::credentials::generate_uuid);

    // Проверка идёт до всего остального: собирать ключи и занимать порт
    // ради сайта прикрытия, на котором REALITY не заработает, незачем.
    if !flag("--skip-check") {
        check_cover(&cover, flag("--check-cover"), flag("--pq-seed"));
    }
    if flag("--check-cover") {
        return;
    }

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

    // Постквантовая проверка. Семя, а не готовый ключ: при перезапуске
    // из того же семени рождается та же пара, и розданные ключи
    // продолжают подходить. Без флага всё работает как раньше — проверка
    // необязательна с обеих сторон.
    let post_quantum = value("--pq-seed").map(|text| {
        let seed = decode_key(&text).unwrap_or_else(|| {
            eprintln!("--pq-seed: не разбирается как 32 байта в base64url");
            std::process::exit(1);
        });
        std::sync::Arc::new(atlas_crypto::sign::SigningKey::from_seed(&seed))
    });
    let pq_verify = post_quantum
        .as_ref()
        .map(|key| base64_url(&key.post_quantum_public_key()));

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
            post_quantum: pq_verify.as_deref(),
        }
        .to_link()
    );
    println!();

    // Посторонний получает сайт прикрытия целиком — и вправе качать его
    // через нас сколько угодно, за наш трафик. Предел задаёт хозяин: он
    // один знает свой тариф, а угаданное значение само стало бы
    // отличием (см. atlas_exit::throttle).
    let cover_limit = value("--cover-limit").map(|text| {
        let kb: u64 = text.parse().unwrap_or_else(|_| {
            eprintln!("--cover-limit: ожидается число килобайт в секунду");
            std::process::exit(1);
        });
        atlas_exit::throttle::Limit::per_second(kb.saturating_mul(1024))
    });

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
        ExitPoint::new({
            let config = ExitConfig::new(reality, cover).with_policy(policy);
            let config = match cover_limit {
                Some(limit) => config.with_cover_limit(limit),
                None => config,
            };
            match post_quantum {
                Some(key) => config.with_post_quantum(key),
                None => config,
            }
        })
        .with_log(Arc::new(move |message: &str| {
            if verbose {
                eprintln!("[exit] {message}");
            }
        })),
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

/// Проверить сайт прикрытия и рассказать, что вышло.
///
/// # Почему непригодность — отказ, а не предупреждение
///
/// Без TLS 1.3 у сайта прикрытия REALITY не работает: общий секрет
/// выводится из доли `key_share`, а до TLS 1.3 её не существует. Точка
/// выхода при этом поднимется и напечатает ключ, ключ вставится в
/// клиент, и человек будет искать причину в туннеле — там, где её нет.
/// Дешевле отказать здесь.
///
/// Недоступность сайта отказом не считается: сеть могла моргнуть, а
/// точка выхода, не встающая из-за чужой недоступности, хуже точки
/// выхода с сомнительным прикрытием.
fn check_cover(cover: &str, verbose: bool, post_quantum: bool) {
    match atlas_exit::cover::inspect(cover) {
        Ok(report) => {
            if verbose {
                println!("сайт прикрытия   {}", report.name);
                println!("адрес            {}", report.probed);
                println!("всего адресов    {}", report.addresses.len());
                println!("TLS 1.3          {}", report.tls13);
                println!("ALPN             {}", report.alpn.as_deref().unwrap_or("—"));
                println!("рукопожатие      {} мс", report.handshake.as_millis());
                println!(
                    "сертификат       {}",
                    match report.selects_certificate_by_name {
                        Some(true) => "разный для разных имён — возможно, CDN",
                        Some(false) => "один и тот же для любого имени",
                        None => "чужие имена не обслуживаются",
                    }
                );
            }
            for warning in report.warnings() {
                eprintln!("внимание: {warning}");
            }
            if post_quantum {
                if verbose {
                    println!("цепочка          {} байт", report.chain_bytes);
                }
                if let Some(note) = report.post_quantum_note() {
                    eprintln!("внимание: {note}");
                }
            }
            if !report.usable() {
                eprintln!();
                eprintln!("Сайт прикрытия не годится. Возьмите другой через --cover");
                eprintln!("или, если уверены, обойдите проверку через --skip-check.");
                std::process::exit(1);
            }
        }
        Err(error) => {
            // Не отказ: сеть могла моргнуть, а сайт прикрытия нужен не
            // при запуске, а при первом постороннем.
            eprintln!("внимание: сайт прикрытия {cover} не проверить: {error}");
        }
    }
}
