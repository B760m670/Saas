//! Полный круг: наш клиент против нашей точки выхода.
//!
//! До сих пор каждая половина проверялась порознь — клиент против чужих
//! серверов, сервер против выдуманных приветствий. Здесь они встречаются:
//! настоящее рукопожатие TLS 1.3 с меткой REALITY внутри, от
//! `ClientHello` до прикладных данных в обе стороны.
//!
//! Обе стороны наши, и общая ошибка в понимании протокола так не
//! ловится, — за это отвечают векторы RFC 8448 и живые серверы. Здесь
//! проверяется другое: что клиент и точка выхода **договариваются**, и
//! что посторонний клиент не проходит.

// Вход теста — байты, которые он же и породил.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::Arc;

use atlas_reality::{Certificates, Sealer, Server, Verifier};
use atlas_tls::client::{ClientConfig, Connection};
use atlas_tls::server::{ServerConfig, ServerConnection};
use atlas_tls::Chrome;

const SHORT_ID: [u8; 2] = [0xde, 0xad];
const VERSION: [u8; 3] = [26, 3, 27];
const SNI: &str = "www.microsoft.com";

/// Прогнать рукопожатие до конца, передавая байты между сторонами.
fn handshake(client: &mut Connection, server: &mut ServerConnection) {
    for _ in 0..8 {
        let to_server = client.take_output();
        if !to_server.is_empty() {
            server.read_tls(&to_server).expect("сервер принял байты");
            server.process().expect("сервер разобрал");
        }
        let to_client = server.take_output();
        if !to_client.is_empty() {
            client.read_tls(&to_client).expect("клиент принял байты");
            client.process().expect("клиент разобрал");
        }
        if to_server.is_empty() && to_client.is_empty() {
            break;
        }
    }
}

/// Пара «клиент — точка выхода», настроенная на один ключ.
fn pair(exit: Server, common_name: &str) -> (Connection, ServerConnection) {
    let sealer = Sealer::new(
        exit.public_key(),
        &SHORT_ID,
        VERSION,
        atlas_reality::now_seconds(),
    )
    .unwrap();
    let verifier = Verifier::new(sealer.auth_key());

    let client = Connection::new(
        ClientConfig::new(SNI)
            .with_profile(Chrome::v141())
            .with_sealer(Box::new(sealer))
            .with_verifier(Box::new(verifier)),
    )
    .unwrap();

    let server = ServerConnection::new(
        ServerConfig::new(Box::new(Certificates::new(exit, common_name)))
            .with_alpn(vec!["h2".to_owned(), "http/1.1".to_owned()]),
    );
    (client, server)
}

#[test]
fn the_circle_closes() {
    let exit = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let (mut client, mut server) = pair(exit, SNI);

    handshake(&mut client, &mut server);

    assert!(!client.is_handshaking(), "клиент не завершил рукопожатие");
    assert!(!server.is_handshaking(), "сервер не завершил рукопожатие");
    assert_eq!(client.cipher_suite(), server.cipher_suite());
    assert_eq!(client.group(), server.group());
    assert_eq!(client.alpn(), Some("h2"));
    assert_eq!(server.alpn(), Some("h2"));

    // Постквантовая группа обязана быть выбрана: клиент её предлагает,
    // сервер предпочитает.
    assert_eq!(client.group(), Some(atlas_tls::Group::X25519MlKem768));
}

#[test]
fn application_data_flows_both_ways() {
    let exit = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let (mut client, mut server) = pair(exit, SNI);
    handshake(&mut client, &mut server);

    client.send(b"zapros ot klienta".as_slice()).unwrap();
    let out = client.take_output();
    server.read_tls(&out).unwrap();
    server.process().unwrap();
    assert_eq!(server.take_plaintext(), b"zapros ot klienta");

    server.send(b"otvet tochki vyhoda".as_slice()).unwrap();
    let out = server.take_output();
    client.read_tls(&out).unwrap();
    client.process().unwrap();
    assert_eq!(client.take_plaintext(), b"otvet tochki vyhoda");
}

#[test]
fn a_large_payload_survives_record_fragmentation() {
    let exit = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let (mut client, mut server) = pair(exit, SNI);
    handshake(&mut client, &mut server);

    let payload: Vec<u8> = (0..70_000_u32).map(|i| (i % 251) as u8).collect();
    client.send(&payload).unwrap();
    let stream = client.take_output();
    assert!(
        stream.len() > 1 << 14,
        "должно получиться несколько записей"
    );

    // Кормим сервер кусками, не совпадающими с границами записей.
    for chunk in stream.chunks(997) {
        server.read_tls(chunk).unwrap();
        server.process().unwrap();
    }
    assert_eq!(server.take_plaintext(), payload);
}

#[test]
fn a_client_with_the_wrong_key_is_not_served() {
    // Клиент настроен на одну точку, соединяется с другой. Сервер не
    // должен ответить ничем: посторонний обязан быть уведён на сайт
    // прикрытия, а не получить наш `ServerHello`.
    let stranger = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let sealer = Sealer::new(
        stranger.public_key(),
        &SHORT_ID,
        VERSION,
        atlas_reality::now_seconds(),
    )
    .unwrap();
    let mut client = Connection::new(
        ClientConfig::new(SNI)
            .with_sealer(Box::new(sealer.clone()))
            .with_verifier(Box::new(Verifier::new(sealer.auth_key()))),
    )
    .unwrap();

    let ours = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let mut server =
        ServerConnection::new(ServerConfig::new(Box::new(Certificates::new(ours, SNI))));

    let hello = client.take_output();
    server.read_tls(&hello).unwrap();
    let outcome = server.process();

    assert!(outcome.is_err(), "чужая метка обязана быть отвергнута");
    assert!(
        server.take_output().is_empty(),
        "постороннему нельзя отвечать ни байтом"
    );
}

#[test]
fn a_browser_without_a_marker_is_not_served() {
    // Обычный браузер, случайно попавший на этот адрес: метки нет,
    // `session_id` случаен. Ответа быть не должно.
    let ours = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let mut server =
        ServerConnection::new(ServerConfig::new(Box::new(Certificates::new(ours, SNI))));

    let mut browser = Connection::new(ClientConfig::new(SNI)).unwrap();
    let hello = browser.take_output();
    server.read_tls(&hello).unwrap();

    assert!(server.process().is_err());
    assert!(server.take_output().is_empty());
}

#[test]
fn a_replayed_hello_is_not_served_either() {
    // Записанное приветствие настоящего клиента, отправленное повторно.
    // Именно так зонд проверяет, REALITY ли перед ним.
    let exit = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let public = exit.public_key();
    let certificates = Arc::new(Certificates::new(exit, SNI));

    let sealer = Sealer::new(public, &SHORT_ID, VERSION, atlas_reality::now_seconds()).unwrap();
    let mut client = Connection::new(
        ClientConfig::new(SNI)
            .with_sealer(Box::new(sealer.clone()))
            .with_verifier(Box::new(Verifier::new(sealer.auth_key()))),
    )
    .unwrap();
    let hello = client.take_output();

    // Первый раз — обслуживаем.
    let mut first = ServerConnection::new(ServerConfig::new(Box::new(SharedCertificates(
        Arc::clone(&certificates),
    ))));
    first.read_tls(&hello).unwrap();
    first.process().expect("первое соединение обязано пройти");
    assert!(!first.take_output().is_empty());

    // Второй раз с теми же байтами — нет.
    let mut second = ServerConnection::new(ServerConfig::new(Box::new(SharedCertificates(
        certificates,
    ))));
    second.read_tls(&hello).unwrap();
    assert!(second.process().is_err(), "повтор обязан быть отвергнут");
    assert!(second.take_output().is_empty());
}

/// Один источник сертификатов на несколько соединений.
///
/// Так и работает настоящая точка выхода: окно повторов и разрешённые
/// `shortId` у неё общие, а соединений много.
#[derive(Debug)]
struct SharedCertificates(Arc<Certificates>);

impl atlas_tls::server::CertificateSource for SharedCertificates {
    fn accept(
        &self,
        hello: &atlas_tls::ClientHello,
        raw: &[u8],
    ) -> atlas_tls::Result<Box<dyn atlas_tls::server::Pending>> {
        self.0.accept(hello, raw)
    }
}

#[test]
fn the_certificate_the_server_issues_is_the_one_the_client_accepts() {
    // Проверка стыка: сертификат выпускается сервером и принимается
    // клиентом, и оба конца сходятся на одном общем ключе, придя к нему
    // разными путями.
    let exit = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let (mut client, mut server) = pair(exit, SNI);
    handshake(&mut client, &mut server);

    let certificate = client.peer_certificate().expect("сертификат получен");
    let der = certificate.end_entity().expect("конечный сертификат");
    let parsed = atlas_reality::cert::TemporaryCertificate::parse(der).unwrap();

    assert_eq!(parsed.signature.len(), 64, "на месте подписи — HMAC-SHA512");
    assert_eq!(parsed.public_key.len(), 32);
    // Проверка подлинности уже прошла внутри рукопожатия: если бы
    // сертификат не сошёлся, `handshake` упал бы на разборе.
    assert!(!client.is_handshaking());
}

#[test]
fn each_connection_gets_a_fresh_certificate() {
    // Постоянный ключ в сертификате связал бы соединения между собой
    // для того, кто способен заглянуть внутрь туннеля.
    let exit = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let public = exit.public_key();
    let certificates = Arc::new(Certificates::new(exit, SNI));

    let mut keys = std::collections::HashSet::new();
    for _ in 0..4 {
        let sealer = Sealer::new(public, &SHORT_ID, VERSION, atlas_reality::now_seconds()).unwrap();
        let mut client = Connection::new(
            ClientConfig::new(SNI)
                .with_sealer(Box::new(sealer.clone()))
                .with_verifier(Box::new(Verifier::new(sealer.auth_key()))),
        )
        .unwrap();
        let mut server = ServerConnection::new(ServerConfig::new(Box::new(SharedCertificates(
            Arc::clone(&certificates),
        ))));

        handshake(&mut client, &mut server);
        assert!(!client.is_handshaking());

        let der = client
            .peer_certificate()
            .and_then(atlas_tls::handshake::Certificate::end_entity)
            .unwrap();
        let parsed = atlas_reality::cert::TemporaryCertificate::parse(der).unwrap();
        keys.insert(parsed.public_key);
    }
    assert_eq!(keys.len(), 4, "ключ обязан быть новым на каждое соединение");
}

#[test]
fn the_post_quantum_branch_closes_too() {
    // Единственное место, где эта ветвь проверяется целиком: сервер
    // подписывает, клиент проверяет. Совпадение с чужой реализацией
    // по-прежнему открытый вопрос — но между нашими половинами
    // расхождения нет.
    let exit = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let signing = Arc::new(atlas_crypto::sign::SigningKey::generate());
    let public_key = signing.post_quantum_public_key();

    let sealer = Sealer::new(
        exit.public_key(),
        &SHORT_ID,
        VERSION,
        atlas_reality::now_seconds(),
    )
    .unwrap();
    let mut client = Connection::new(
        ClientConfig::new(SNI)
            .with_sealer(Box::new(sealer.clone()))
            .with_verifier(Box::new(
                Verifier::new(sealer.auth_key()).with_post_quantum(public_key),
            )),
    )
    .unwrap();

    let mut server = ServerConnection::new(ServerConfig::new(Box::new(
        Certificates::new(exit, SNI).with_post_quantum(signing),
    )));

    handshake(&mut client, &mut server);
    assert!(
        !client.is_handshaking(),
        "постквантовая проверка не сошлась"
    );
    assert!(!server.is_handshaking());
}

#[test]
fn a_wrong_post_quantum_key_is_refused() {
    let exit = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let signing = Arc::new(atlas_crypto::sign::SigningKey::generate());
    // Клиент ждёт подпись другого ключа.
    let other = atlas_crypto::sign::SigningKey::generate().post_quantum_public_key();

    let sealer = Sealer::new(
        exit.public_key(),
        &SHORT_ID,
        VERSION,
        atlas_reality::now_seconds(),
    )
    .unwrap();
    let mut client = Connection::new(
        ClientConfig::new(SNI)
            .with_sealer(Box::new(sealer.clone()))
            .with_verifier(Box::new(
                Verifier::new(sealer.auth_key()).with_post_quantum(other),
            )),
    )
    .unwrap();
    let mut server = ServerConnection::new(ServerConfig::new(Box::new(
        Certificates::new(exit, SNI).with_post_quantum(signing),
    )));

    // Рукопожатие обязано оборваться на проверке сертификата.
    let hello = client.take_output();
    server.read_tls(&hello).unwrap();
    server.process().unwrap();
    let flight = server.take_output();
    client.read_tls(&flight).unwrap();

    assert!(matches!(
        client.process(),
        Err(atlas_tls::Error::Untrusted(_))
    ));
}
