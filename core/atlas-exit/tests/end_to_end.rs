//! Полный круг по настоящим сокетам.
//!
//! Здесь впервые сходится всё: клиент разбирает `vless://`, открывает
//! TCP, проводит рукопожатие TLS 1.3 с меткой REALITY, точка выхода
//! узнаёт своего, принимает VLESS и соединяется с адресом назначения.
//!
//! И — что важнее — здесь же проверяется поведение с посторонними.
//! Отказ, обрыв или любой наш собственный байт в ответ выдали бы точку
//! выхода зонду. Посторонний обязан увидеть сайт прикрытия.

// Вход теста — байты, которые он же и породил.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use atlas_dial::{dial_with, DialOptions, Target};
use atlas_exit::{ExitConfig, ExitPoint};
use atlas_reality::Server;
use atlas_types::ProxyKey;

const SHORT_ID: &str = "dead";
const UUID: &str = "11111111-2222-3333-4444-555555555555";
const SNI: &str = "www.microsoft.com";

/// Простой сервер, отвечающий на всё одной и той же строкой.
///
/// Играет две роли: адрес назначения для своего клиента и сайт
/// прикрытия для постороннего. Строки разные, чтобы было видно, кто
/// куда попал.
fn spawn_responder(banner: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();

    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut socket) = incoming else { break };
            std::thread::spawn(move || {
                let mut buf = [0_u8; 4096];
                // Дожидаемся хоть чего-нибудь и отвечаем.
                let _ = socket.read(&mut buf);
                let _ = socket.write_all(banner.as_bytes());
                let _ = socket.flush();
            });
        }
    });
    address
}

/// Поднять точку выхода, вернув её адрес и публичный ключ REALITY.
fn spawn_exit(cover: &str) -> (String, String) {
    let reality = Server::generate().with_short_id(&[0xde, 0xad]).unwrap();
    let public_key = base64_url(&reality.public_key());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();

    // Назначение в тестах — петля, поэтому ограничения ослаблены явно.
    // На настоящей точке выхода это делать нельзя, и по умолчанию закрыто.
    let point = Arc::new(ExitPoint::new(
        ExitConfig::new(reality, cover.to_owned())
            .with_common_name(SNI)
            .with_policy(atlas_exit::Policy {
                allow_private: true,
                ..atlas_exit::Policy::default()
            }),
    ));
    std::thread::spawn(move || {
        let _ = point.serve(&listener);
    });
    (address, public_key)
}

fn base64_url(raw: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// Ключ доступа к поднятой точке выхода.
fn key_for(exit: &str, public_key: &str, flow: &str) -> ProxyKey {
    let uri = format!(
        "vless://{UUID}@{exit}?type=tcp&security=reality&sni={SNI}\
         &pbk={public_key}&sid={SHORT_ID}&fp=chrome{flow}#test"
    );
    ProxyKey::parse(&uri).unwrap()
}

fn options() -> DialOptions {
    DialOptions {
        // Промежуточный узел среды разработки рвёт приветствия с ECH;
        // на петле его нет, но настройка та же, что в поле.
        ech: false,
        connect_timeout: Duration::from_secs(5),
        read_timeout: Some(Duration::from_secs(10)),
        ..DialOptions::default()
    }
}

/// Разобрать `host:port` на части для ключа доступа.
fn split_address(address: &str) -> (String, u16) {
    let (host, port) = address.rsplit_once(':').unwrap();
    (host.to_owned(), port.parse().unwrap())
}

#[test]
fn a_known_client_reaches_the_destination() {
    let destination = spawn_responder("НАЗНАЧЕНИЕ");
    let cover = spawn_responder("ПРИКРЫТИЕ");
    let (exit, public_key) = spawn_exit(&cover);

    let key = key_for(&exit, &public_key, "&flow=xtls-rprx-vision");
    let (host, port) = split_address(&destination);

    let mut tunnel =
        dial_with(&key, &Target::domain(host, port), &options()).expect("туннель обязан подняться");

    tunnel.write_all(b"privet").unwrap();
    tunnel.flush().unwrap();

    let mut answer = Vec::new();
    let _ = tunnel.read_to_end(&mut answer);
    assert_eq!(
        String::from_utf8_lossy(&answer),
        "НАЗНАЧЕНИЕ",
        "данные обязаны дойти до адреса назначения и вернуться"
    );
}

#[test]
fn the_same_works_without_vision() {
    let destination = spawn_responder("БЕЗ ОБРАМЛЕНИЯ");
    let cover = spawn_responder("ПРИКРЫТИЕ");
    let (exit, public_key) = spawn_exit(&cover);

    let key = key_for(&exit, &public_key, "");
    let (host, port) = split_address(&destination);

    let mut tunnel =
        dial_with(&key, &Target::domain(host, port), &options()).expect("туннель обязан подняться");
    tunnel.write_all(b"privet").unwrap();
    tunnel.flush().unwrap();

    let mut answer = Vec::new();
    let _ = tunnel.read_to_end(&mut answer);
    assert_eq!(String::from_utf8_lossy(&answer), "БЕЗ ОБРАМЛЕНИЯ");
}

#[test]
fn a_stranger_sees_the_cover_site() {
    // Главная проверка всего проекта. Соединение без метки обязано
    // попасть на сайт прикрытия — не получить отказ, не оборваться, а
    // именно попасть, целиком и прозрачно.
    let cover = spawn_responder("ПРИКРЫТИЕ");
    let (exit, _) = spawn_exit(&cover);

    let mut socket = TcpStream::connect(&exit).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Приветствие настоящего браузера, без всякой метки.
    let mut browser = atlas_tls::client::Connection::new(
        atlas_tls::client::ClientConfig::new(SNI)
            .with_profile(atlas_tls::Chrome::v141().without_ech()),
    )
    .unwrap();
    socket.write_all(&browser.take_output()).unwrap();
    socket.flush().unwrap();

    let mut answer = Vec::new();
    let _ = socket.read_to_end(&mut answer);
    assert_eq!(
        String::from_utf8_lossy(&answer),
        "ПРИКРЫТИЕ",
        "посторонний обязан увидеть сайт прикрытия, а не отказ"
    );
}

#[test]
fn the_cover_site_receives_the_bytes_unchanged() {
    // Сайт прикрытия обязан увидеть ровно то, что прислал клиент:
    // соединение проксируется байт в байт, включая уже прочитанное нами
    // приветствие. Иначе он ответил бы иначе, и разница была бы видна.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let cover = listener.local_addr().unwrap().to_string();

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut socket, _)) = listener.accept() {
            let mut buf = vec![0_u8; 8192];
            let read = socket.read(&mut buf).unwrap_or(0);
            let _ = sender.send(buf[..read].to_vec());
            let _ = socket.write_all(b"ok");
        }
    });

    let (exit, _) = spawn_exit(&cover);
    let mut socket = TcpStream::connect(&exit).unwrap();

    let mut browser = atlas_tls::client::Connection::new(
        atlas_tls::client::ClientConfig::new(SNI)
            .with_profile(atlas_tls::Chrome::v141().without_ech()),
    )
    .unwrap();
    let hello = browser.take_output();
    socket.write_all(&hello).unwrap();
    socket.flush().unwrap();

    let seen = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("сайт прикрытия обязан получить соединение");
    assert_eq!(seen, hello, "байты обязаны дойти без единого изменения");
}

#[test]
fn a_client_with_a_foreign_key_also_sees_the_cover_site() {
    // Клиент настроен на другую точку выхода: метка есть, но чужая.
    // Отличаться от случайного браузера этот случай не должен.
    let cover = spawn_responder("ПРИКРЫТИЕ");
    let (exit, _) = spawn_exit(&cover);

    let stranger = Server::generate().with_short_id(&[0xde, 0xad]).unwrap();
    let key = key_for(&exit, &base64_url(&stranger.public_key()), "");

    let outcome = dial_with(&key, &Target::domain("example.org", 443), &options());
    // Соединение живёт — просто за ним чужой сайт, и проверка
    // сертификата его отвергает. Обрыва на уровне TCP быть не должно.
    assert!(outcome.is_err());
}

#[test]
fn a_replayed_hello_goes_to_the_cover_site() {
    // Зонд, повторяющий записанное приветствие, обязан увидеть ровно то
    // же, что и любой посторонний. Иначе повтор сам становится способом
    // опознать точку выхода: первый раз ответили, второй оборвали —
    // значит, здесь не сайт.
    let cover = spawn_responder("ПРИКРЫТИЕ");
    let reality = Server::generate().with_short_id(&[0xde, 0xad]).unwrap();
    let public = reality.public_key();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exit = listener.local_addr().unwrap().to_string();
    let point = Arc::new(ExitPoint::new(
        ExitConfig::new(reality, cover)
            .with_common_name(SNI)
            .with_policy(atlas_exit::Policy {
                allow_private: true,
                ..atlas_exit::Policy::default()
            }),
    ));
    std::thread::spawn(move || {
        let _ = point.serve(&listener);
    });

    // Приветствие с действующей меткой, собранное один раз.
    let sealer = atlas_reality::Sealer::new(
        public,
        &[0xde, 0xad],
        [26, 3, 27],
        atlas_reality::now_seconds(),
    )
    .unwrap();
    let mut client = atlas_tls::client::Connection::new(
        atlas_tls::client::ClientConfig::new(SNI)
            .with_profile(atlas_tls::Chrome::v141().without_ech())
            .with_sealer(Box::new(sealer.clone()))
            .with_verifier(Box::new(atlas_reality::Verifier::new(sealer.auth_key()))),
    )
    .unwrap();
    let hello = client.take_output();

    // Первый раз — нас узнают, и в ответ приходит `ServerHello`, а не
    // страница прикрытия.
    let mut first = TcpStream::connect(&exit).unwrap();
    first
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    first.write_all(&hello).unwrap();
    let mut answer = [0_u8; 16];
    let read = first.read(&mut answer).unwrap_or(0);
    assert!(read > 0, "своего обязаны обслужить");
    assert_eq!(answer[0], 22, "в ответ идёт запись рукопожатия");

    // Второй раз с теми же байтами — уже нет.
    let mut second = TcpStream::connect(&exit).unwrap();
    second
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    second.write_all(&hello).unwrap();
    let mut repeated = Vec::new();
    let _ = second.read_to_end(&mut repeated);
    assert_eq!(
        String::from_utf8_lossy(&repeated),
        "ПРИКРЫТИЕ",
        "повтор обязан быть уведён на сайт прикрытия"
    );
}

#[test]
fn a_large_payload_goes_through_the_tunnel_intact() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let destination = listener.local_addr().unwrap().to_string();

    // Эхо: возвращает всё, что получило.
    std::thread::spawn(move || {
        if let Ok((mut socket, _)) = listener.accept() {
            let mut buf = vec![0_u8; 32 * 1024];
            let mut seen = 0_usize;
            while seen < 200_000 {
                let Ok(read) = socket.read(&mut buf) else {
                    break;
                };
                if read == 0 {
                    break;
                }
                seen += read;
                if socket.write_all(&buf[..read]).is_err() {
                    break;
                }
            }
        }
    });

    let cover = spawn_responder("ПРИКРЫТИЕ");
    let (exit, public_key) = spawn_exit(&cover);
    let key = key_for(&exit, &public_key, "&flow=xtls-rprx-vision");
    let (host, port) = split_address(&destination);

    let mut tunnel =
        dial_with(&key, &Target::domain(host, port), &options()).expect("туннель обязан подняться");

    let payload: Vec<u8> = (0..200_000_u32).map(|i| (i % 251) as u8).collect();
    tunnel.write_all(&payload).unwrap();
    tunnel.flush().unwrap();

    let mut answer = vec![0_u8; payload.len()];
    let mut filled = 0;
    while filled < answer.len() {
        match tunnel.read(&mut answer[filled..]) {
            Ok(0) | Err(_) => break,
            Ok(read) => filled += read,
        }
    }
    assert_eq!(filled, payload.len(), "объём обязан дойти целиком");
    assert_eq!(answer, payload, "и без искажений");
}

#[test]
fn by_default_the_exit_point_refuses_to_reach_inside() {
    // Клиент вправе назвать любой адрес. Точка, которой человек
    // поделился, обязана отказать: `127.0.0.1` ведёт к службам самого
    // узла, а частные диапазоны — во внутреннюю сеть хостера.
    let destination = spawn_responder("ВНУТРЕННЯЯ СЛУЖБА");
    let cover = spawn_responder("ПРИКРЫТИЕ");

    let reality = Server::generate().with_short_id(&[0xde, 0xad]).unwrap();
    let public_key = base64_url(&reality.public_key());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exit = listener.local_addr().unwrap().to_string();

    // Настройки по умолчанию — то есть внутрь нельзя.
    let point = Arc::new(ExitPoint::new(
        ExitConfig::new(reality, cover).with_common_name(SNI),
    ));
    std::thread::spawn(move || {
        let _ = point.serve(&listener);
    });

    let key = key_for(&exit, &public_key, "");
    let (host, port) = split_address(&destination);
    let mut tunnel =
        dial_with(&key, &Target::domain(host, port), &options()).expect("туннель поднимается");

    // Туннель поднялся — клиент-то свой. А вот до внутренней службы
    // данные дойти не должны.
    tunnel.write_all(b"privet").unwrap();
    tunnel.flush().unwrap();
    let mut answer = Vec::new();
    let _ = tunnel.read_to_end(&mut answer);
    assert!(
        answer.is_empty(),
        "внутренняя служба не должна была ответить: {}",
        String::from_utf8_lossy(&answer)
    );
}

#[test]
fn the_policy_recognises_what_is_inside() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    for inside in [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.1",
        "172.16.5.5",
        // Метаданные виртуальной машины у большинства облаков.
        "169.254.169.254",
        // Общий диапазон операторов.
        "100.64.0.1",
        "0.0.0.0",
    ] {
        let ip: Ipv4Addr = inside.parse().unwrap();
        assert!(
            !atlas_exit::is_public(IpAddr::V4(ip)),
            "{inside} обязан считаться внутренним"
        );
    }

    for outside in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1"] {
        let ip: Ipv4Addr = outside.parse().unwrap();
        assert!(
            atlas_exit::is_public(IpAddr::V4(ip)),
            "{outside} обязан считаться внешним"
        );
    }

    for inside in ["::1", "fc00::1", "fd12::1", "fe80::1", "::"] {
        let ip: Ipv6Addr = inside.parse().unwrap();
        assert!(
            !atlas_exit::is_public(IpAddr::V6(ip)),
            "{inside} обязан считаться внутренним"
        );
    }
    assert!(atlas_exit::is_public(IpAddr::V6(
        "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
    )));
}

/// Сайт прикрытия, отдающий много байт сразу.
///
/// Нужен именно объём: ограничение полосы на коротком ответе не видно,
/// а проверять надо именно длинную выкачку — ту, ради которой предел и
/// заводится.
fn spawn_bulk_responder(bytes: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();

    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut socket) = incoming else { break };
            std::thread::spawn(move || {
                let mut buf = [0_u8; 4096];
                let _ = socket.read(&mut buf);
                let _ = socket.write_all(&vec![0x5a_u8; bytes]);
                let _ = socket.flush();
            });
        }
    });
    address
}

/// Поднять точку выхода с ограничением полосы до сайта прикрытия.
fn spawn_limited_exit(cover: &str, limit: atlas_exit::throttle::Limit) -> String {
    let reality = Server::generate().with_short_id(&[0xde, 0xad]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();

    let point = Arc::new(ExitPoint::new(
        ExitConfig::new(reality, cover.to_owned())
            .with_common_name(SNI)
            .with_cover_limit(limit)
            .with_policy(atlas_exit::Policy {
                allow_private: true,
                ..atlas_exit::Policy::default()
            }),
    ));
    std::thread::spawn(move || {
        let _ = point.serve(&listener);
    });
    address
}

/// Сходить на точку выхода посторонним и выкачать всё, что дадут.
fn drain_as_stranger(exit: &str) -> (usize, Duration) {
    let mut socket = TcpStream::connect(exit).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();

    let mut browser = atlas_tls::client::Connection::new(
        atlas_tls::client::ClientConfig::new(SNI)
            .with_profile(atlas_tls::Chrome::v141().without_ech()),
    )
    .unwrap();
    socket.write_all(&browser.take_output()).unwrap();
    socket.flush().unwrap();

    let started = std::time::Instant::now();
    let mut answer = Vec::new();
    let _ = socket.read_to_end(&mut answer);
    (answer.len(), started.elapsed())
}

#[test]
fn the_cover_limit_actually_slows_a_stranger_down() {
    // Ведро проверено само по себе в модуле throttle. Здесь проверяется
    // другое: что точка выхода его в самом деле применяет. Правильный
    // ограничитель, никуда не подключённый, выглядит в тестах точно так
    // же, как подключённый.
    const PAYLOAD: usize = 256 * 1024;

    let cover = spawn_bulk_responder(PAYLOAD);
    // 64 КБ/с без всплеска: 256 КБ обязаны занять около четырёх секунд.
    let exit = spawn_limited_exit(
        &cover,
        atlas_exit::throttle::Limit::per_second(64 * 1024).with_burst(0),
    );

    let (got, took) = drain_as_stranger(&exit);

    assert_eq!(got, PAYLOAD, "ограничение задерживает, но не теряет байты");
    assert!(
        took >= Duration::from_secs(3),
        "выкачка заняла {took:?} — ограничение не применилось"
    );
    // Верхняя граница не менее важна нижней. Без неё незамеченным
    // остаётся другой отказ: соединение доходит до конца, но пишущая
    // сторона не закрывается, и посторонний висит до своего таймаута.
    // Ровно это и было при первом подключении ограничения — четыре
    // секунды передачи и тридцать секунд ожидания сверху.
    assert!(
        took < Duration::from_secs(10),
        "выкачка заняла {took:?} при ожидаемых четырёх — \
         похоже, пишущая сторона не закрывается"
    );
}

#[test]
fn without_a_limit_the_same_payload_flies_through() {
    // Отрицательный контроль к предыдущему тесту. Без него медленная
    // выкачка ничего не доказывала бы: она могла бы объясняться самим
    // стендом, а не ограничением.
    const PAYLOAD: usize = 256 * 1024;

    let cover = spawn_bulk_responder(PAYLOAD);
    let (exit, _) = spawn_exit(&cover);

    let (got, took) = drain_as_stranger(&exit);

    assert_eq!(got, PAYLOAD);
    assert!(
        took < Duration::from_secs(1),
        "без ограничения выкачка заняла {took:?} — стенд сам по себе медленный, \
         и проверка ограничения ничего не значит"
    );
}
