//! Сквозная проверка: метка внутри настоящего `ClientHello`.
//!
//! Отдельные тесты крейта работают на упрощённом сообщении. Здесь берётся
//! `ClientHello`, собранный профилем Chrome со всеми расширениями,
//! перемешиванием и дополнением, — то самое, что уйдёт в сеть.
//!
//! Главное утверждение теста: **метка не меняет отпечаток**. Если бы
//! меняла, весь смысл REALITY терялся бы — трафик стал бы отличим от
//! браузерного на первом пакете, несмотря на безупречную маскировку
//! сертификата.

#![allow(clippy::unwrap_used)]

use atlas_reality::{Client, Server};
use atlas_tls::fingerprint::ja4;
use atlas_tls::profile::X25519;
use atlas_tls::{Chrome, ClientHello, HelloParams, Transport};

/// Опубликованный отпечаток Chrome, тот же, что в `atlas-tls`.
const CHROME_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";

const SHORT_ID: [u8; 2] = [0xde, 0xad];
const VERSION: [u8; 3] = [25, 3, 27];
const NOW: u32 = 1_800_000_000;

/// Собрать `ClientHello`, положив эфемерный ключ клиента в `key_share`.
fn build_hello(client_public: [u8; 32]) -> Vec<u8> {
    let params = HelloParams::new("www.microsoft.com")
        .with_key_shares(vec![(X25519, client_public.to_vec())])
        .with_session_id(vec![0_u8; 32]);
    Chrome::classic()
        .client_hello(&params)
        .unwrap()
        .to_handshake()
        .unwrap()
}

#[test]
fn marker_survives_a_real_client_hello() {
    let mut server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();
    let session = client.begin();

    let mut handshake = build_hello(session.public_key());
    session.seal(&mut handshake, NOW).unwrap();

    let marker = server
        .authenticate(&handshake, &session.public_key(), NOW)
        .unwrap();

    assert_eq!(marker.version, VERSION);
    assert_eq!(marker.timestamp, NOW);
    assert_eq!(&marker.short_id[..2], &SHORT_ID);
}

#[test]
fn sealing_does_not_disturb_the_fingerprint() {
    let server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();
    let session = client.begin();

    let mut handshake = build_hello(session.public_key());

    let before = ja4(&ClientHello::parse(&handshake).unwrap(), Transport::Tcp).to_string_full();
    session.seal(&mut handshake, NOW).unwrap();
    let after = ja4(&ClientHello::parse(&handshake).unwrap(), Transport::Tcp).to_string_full();

    assert_eq!(before, CHROME_JA4);
    assert_eq!(after, CHROME_JA4, "метка изменила отпечаток");
}

#[test]
fn message_length_is_unchanged() {
    // Длина ClientHello — тоже наблюдаемая величина. Метка занимает ровно
    // то место, где браузер держит идентификатор сессии, поэтому размер
    // сообщения меняться не должен.
    let server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();
    let session = client.begin();

    let mut handshake = build_hello(session.public_key());
    let before = handshake.len();
    session.seal(&mut handshake, NOW).unwrap();

    assert_eq!(handshake.len(), before);
    assert_eq!(handshake.len(), 512, "профиль Chrome дополняет до 512 байт");
}

#[test]
fn foreign_client_is_rejected() {
    // Проба цензора: подключение с чужим ключом. Сервер обязан отказать —
    // и в бою передать такое соединение настоящему сайту прикрытия.
    let mut server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let stranger = Server::generate();
    let client = Client::new(stranger.public_key(), &SHORT_ID, VERSION).unwrap();
    let session = client.begin();

    let mut handshake = build_hello(session.public_key());
    session.seal(&mut handshake, NOW).unwrap();

    assert!(server
        .authenticate(&handshake, &session.public_key(), NOW)
        .is_err());
}

#[test]
fn plain_browser_hello_is_rejected() {
    // Обычный браузер без метки: в session_id случайные байты.
    let mut server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let handshake = build_hello([0x42; 32]);

    assert!(server.authenticate(&handshake, &[0x42; 32], NOW).is_err());
}

#[test]
fn unknown_short_id_is_rejected() {
    let mut server = Server::generate().with_short_id(&[0x01, 0x02]).unwrap();
    let client = Client::new(server.public_key(), &[0x03, 0x04], VERSION).unwrap();
    let session = client.begin();

    let mut handshake = build_hello(session.public_key());
    session.seal(&mut handshake, NOW).unwrap();

    assert!(server
        .authenticate(&handshake, &session.public_key(), NOW)
        .is_err());
}

#[test]
fn stale_hello_is_rejected() {
    // Записанный и воспроизведённый позже ClientHello не должен приниматься.
    let mut server = Server::generate()
        .with_short_id(&SHORT_ID)
        .unwrap()
        .with_max_skew(120);
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();
    let session = client.begin();

    let mut handshake = build_hello(session.public_key());
    session.seal(&mut handshake, NOW).unwrap();

    // В пределах допуска — принимается.
    assert!(server
        .authenticate(&handshake, &session.public_key(), NOW + 119)
        .is_ok());
    // За пределами — нет.
    assert!(server
        .authenticate(&handshake, &session.public_key(), NOW + 121)
        .is_err());
    // Повтор через час тем более.
    assert!(server
        .authenticate(&handshake, &session.public_key(), NOW + 3600)
        .is_err());
}

#[test]
fn tampering_with_any_extension_is_detected() {
    // Аутентифицируются все байты сообщения, а не только session_id.
    // Значит подменить SNI или список шифров, сохранив метку, нельзя.
    let mut server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();
    let session = client.begin();

    let mut sealed = build_hello(session.public_key());
    session.seal(&mut sealed, NOW).unwrap();

    // Пробуем испортить байты вне области session_id.
    for index in [5_usize, 100, 200, 400, 500] {
        let mut tampered = sealed.clone();
        if let Some(byte) = tampered.get_mut(index) {
            *byte ^= 0x01;
        }
        assert!(
            server
                .authenticate(&tampered, &session.public_key(), NOW)
                .is_err(),
            "изменение байта {index} должно отвергаться"
        );
    }
}

#[test]
fn each_connection_uses_a_fresh_ephemeral_key() {
    let mut server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();

    let first = client.begin();
    let second = client.begin();
    assert_ne!(first.public_key(), second.public_key());

    // И метка первого не открывается ключом второго.
    let mut handshake = build_hello(first.public_key());
    first.seal(&mut handshake, NOW).unwrap();
    assert!(server
        .authenticate(&handshake, &second.public_key(), NOW)
        .is_err());
}

#[test]
fn sealed_region_is_indistinguishable_from_random() {
    // Слабая, но осмысленная проверка: у ста меток не должно быть ни
    // повторов, ни заметного перекоса в распределении байт.
    let server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();

    let mut seen = std::collections::HashSet::new();
    let mut ones = 0_u32;

    for _ in 0..100 {
        let session = client.begin();
        let mut handshake = build_hello(session.public_key());
        session.seal(&mut handshake, NOW).unwrap();

        let sealed = handshake.get(39..71).unwrap().to_vec();
        ones += sealed.iter().copied().map(u8::count_ones).sum::<u32>();
        assert!(seen.insert(sealed), "две метки совпали");
    }

    // 100 меток по 32 байта = 25600 бит. Для случайных данных доля единиц
    // укладывается в 50 % с запасом на пять процентных пунктов.
    let ratio = f64::from(ones) / f64::from(100 * 32 * 8);
    assert!((0.45..0.55).contains(&ratio), "доля единичных бит: {ratio}");
}

#[test]
fn a_replayed_hello_is_refused() {
    // Записанное чужое приветствие, отправленное повторно. Достроить
    // рукопожатие противник не сможет — секретной части эфемерной доли
    // у него нет. Но ему это и не нужно: если сервер поведёт себя как
    // REALITY, а не уведёт соединение на сайт прикрытия, точка выхода
    // тем самым выдана. Ровно то активное зондирование, против которого
    // REALITY и придуман.
    let mut server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();
    let session = client.begin();

    let mut handshake = build_hello(session.public_key());
    session.seal(&mut handshake, NOW).unwrap();

    assert!(
        server
            .authenticate(&handshake, &session.public_key(), NOW)
            .is_ok(),
        "первое подключение проходит"
    );
    assert_eq!(server.tracked_connections(), 1);

    for later in [NOW, NOW + 1, NOW + 60, NOW + 119] {
        assert!(
            server
                .authenticate(&handshake, &session.public_key(), later)
                .is_err(),
            "повтор в момент {later} обязан быть отвергнут"
        );
    }
}

#[test]
fn an_honest_reconnect_is_not_mistaken_for_a_replay() {
    // Каждое честное подключение берёт свежую эфемерную долю, поэтому и
    // метка получается другая. Защита от повтора не должна мешать
    // клиенту, переподключающемуся хоть десять раз в секунду.
    let mut server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();

    for attempt in 0..16 {
        let session = client.begin();
        let mut handshake = build_hello(session.public_key());
        session.seal(&mut handshake, NOW).unwrap();
        assert!(
            server
                .authenticate(&handshake, &session.public_key(), NOW)
                .is_ok(),
            "переподключение {attempt} обязано пройти"
        );
    }
    assert_eq!(server.tracked_connections(), 16);
}

#[test]
fn the_replay_window_is_bounded_by_the_clock_check() {
    // Помнить метку дольше, чем её вообще может принять проверка часов,
    // незачем: за пределами окна приветствие отвергается и без кэша.
    let mut server = Server::generate()
        .with_short_id(&SHORT_ID)
        .unwrap()
        .with_max_skew(10);
    let client = Client::new(server.public_key(), &SHORT_ID, VERSION).unwrap();
    let session = client.begin();

    let mut handshake = build_hello(session.public_key());
    session.seal(&mut handshake, NOW).unwrap();
    assert!(server
        .authenticate(&handshake, &session.public_key(), NOW)
        .is_ok());

    // Далеко за горизонтом приветствие отвергается ещё до окна —
    // проверкой часов. Именно поэтому помнить метку дольше не нужно:
    // за пределами интервала защиту обеспечивает время.
    assert!(server
        .authenticate(&handshake, &session.public_key(), NOW + 1000)
        .is_err());
    assert_eq!(
        server.tracked_connections(),
        1,
        "отвергнутая попытка в окно не попадает"
    );

    // Очистка ленивая: старое вычищается при следующем успешном приёме,
    // а не по таймеру. Проверяем, что окно действительно не копится.
    let session = client.begin();
    let mut later = build_hello(session.public_key());
    session.seal(&mut later, NOW + 1000).unwrap();
    assert!(server
        .authenticate(&later, &session.public_key(), NOW + 1000)
        .is_ok());
    assert_eq!(
        server.tracked_connections(),
        1,
        "метка из прошлого окна вытеснена, осталась только свежая"
    );
}
