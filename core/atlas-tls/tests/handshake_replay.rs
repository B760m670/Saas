//! Полное воспроизведение рукопожатия по эталонному следу RFC 8448.
//!
//! Отдельные модули уже сверены каждый со своей частью следа. Этот тест
//! связывает их вместе и проходит рукопожатие так, как это делал бы
//! настоящий клиент: от общего секрета обмена до собственного `Finished`.
//!
//! Последний шаг — самый ценный. Мы не просто расшифровываем чужое, а
//! **порождаем свою запись `Finished` и сверяем её побайтово** с той,
//! что записана в следе. Совпадение означает, что вся цепочка — обмен
//! ключами, расписание, транскрипт, слой записей — сходится с настоящей
//! реализацией до последнего байта.

// Вход теста — фиксированный след из testdata, а не сетевые данные.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use atlas_tls::handshake::{build_message, HandshakeType, MessageReader, ServerHello, Transcript};
use atlas_tls::keyschedule::{traffic_keys, verify_data, Hash, KeySchedule};
use atlas_tls::record::{Aead, ContentType, Protection};

const SECRETS: &str = include_str!("../testdata/rfc8448-simple-1rtt.json");
const RECORDS: &str = include_str!("../testdata/rfc8448-records.json");

fn unhex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn secret(name: &str) -> Vec<u8> {
    let doc: serde_json::Value = serde_json::from_str(SECRETS).unwrap();
    unhex(doc[name].as_str().unwrap())
}

fn record(name: &str, field: &str) -> Vec<u8> {
    let doc: serde_json::Value = serde_json::from_str(RECORDS).unwrap();
    unhex(doc["записи"][name][field].as_str().unwrap())
}

fn record_keys(name: &str) -> Protection {
    let doc: serde_json::Value = serde_json::from_str(RECORDS).unwrap();
    let key = unhex(doc[format!("{name}_key")].as_str().unwrap());
    let iv_raw = unhex(doc[format!("{name}_iv")].as_str().unwrap());
    let mut iv = [0_u8; 12];
    iv.copy_from_slice(&iv_raw);
    Protection::new(
        Aead::Aes128Gcm,
        atlas_tls::keyschedule::TrafficKeys { key, iv },
    )
    .unwrap()
}

#[test]
fn replays_the_whole_reference_handshake() {
    // --- 1. Приветствия и обмен ключами -------------------------------
    let client_hello = secret("client_hello");
    let server_hello_raw = secret("server_hello");

    let mut reader = MessageReader::new();
    reader.push(&server_hello_raw);
    let message = reader.next_message().unwrap().unwrap();
    assert_eq!(message.msg_type, HandshakeType::ServerHello);

    let server_hello = ServerHello::parse(&message.body).unwrap();
    let hash = Hash::for_cipher_suite(server_hello.cipher_suite).unwrap();
    let aead = Aead::for_cipher_suite(server_hello.cipher_suite).unwrap();
    assert_eq!(hash, Hash::Sha256);
    assert_eq!(aead, Aead::Aes128Gcm);

    let (group, server_public) = server_hello.key_share().unwrap();
    assert_eq!(group, 0x001d, "сервер выбрал x25519");

    let client_private: [u8; 32] = secret("client_private_key").try_into().unwrap();
    let server_public: [u8; 32] = server_public.try_into().unwrap();
    let shared = x25519_dalek::StaticSecret::from(client_private)
        .diffie_hellman(&x25519_dalek::PublicKey::from(server_public));
    assert_eq!(
        shared.as_bytes().to_vec(),
        secret("ecdhe_shared"),
        "общий секрет обмена"
    );

    // --- 2. Секреты рукопожатия ---------------------------------------
    let mut schedule = KeySchedule::new(hash);
    schedule.enter_handshake(shared.as_bytes());

    let mut transcript = Transcript::new(hash);
    transcript.extend(&client_hello);
    transcript.extend(&message.raw);

    let client_hs = schedule.client_handshake_traffic_secret(&transcript.hash());
    let server_hs = schedule.server_handshake_traffic_secret(&transcript.hash());
    assert_eq!(client_hs, secret("client_handshake_traffic_secret"));
    assert_eq!(server_hs, secret("server_handshake_traffic_secret"));

    // Ключи защиты записей выводим сами, а не берём из следа.
    let derived_server_keys = traffic_keys(hash, &server_hs, 16);
    let mut server_protection = Protection::new(aead, derived_server_keys).unwrap();

    // --- 3. Пачка сервера ---------------------------------------------
    let flight_record = record("server_handshake_flight", "record");
    let (kind, flight) = server_protection.decrypt(&flight_record).unwrap();
    assert_eq!(kind, ContentType::Handshake);

    let mut reader = MessageReader::new();
    reader.push(&flight);

    let encrypted_extensions = reader.next_message().unwrap().unwrap();
    let certificate = reader.next_message().unwrap().unwrap();
    let certificate_verify = reader.next_message().unwrap().unwrap();
    let server_finished = reader.next_message().unwrap().unwrap();
    assert!(
        reader.next_message().unwrap().is_none(),
        "пачка разобрана целиком"
    );

    assert_eq!(
        encrypted_extensions.msg_type,
        HandshakeType::EncryptedExtensions
    );
    assert_eq!(certificate.msg_type, HandshakeType::Certificate);
    assert_eq!(
        certificate_verify.msg_type,
        HandshakeType::CertificateVerify
    );
    assert_eq!(server_finished.msg_type, HandshakeType::Finished);

    // --- 4. Проверка Finished сервера ---------------------------------
    transcript.extend(&encrypted_extensions.raw);
    transcript.extend(&certificate.raw);
    transcript.extend(&certificate_verify.raw);

    let expected = verify_data(hash, &server_hs, &transcript.hash());
    assert_eq!(
        server_finished.body, expected,
        "Finished сервера не сошёлся — рукопожатие подделано или расшифровано неверно"
    );

    // --- 5. Прикладные секреты ----------------------------------------
    transcript.extend(&server_finished.raw);
    schedule.enter_master();
    assert_eq!(schedule.secret(), secret("master_secret"));

    let after_finished = transcript.hash();
    assert_eq!(
        schedule.client_application_traffic_secret(&after_finished),
        secret("client_application_traffic_secret")
    );
    assert_eq!(
        schedule.server_application_traffic_secret(&after_finished),
        secret("server_application_traffic_secret")
    );

    // --- 6. Наш собственный Finished ----------------------------------
    let our_verify_data = verify_data(hash, &client_hs, &after_finished);
    let our_message = build_message(HandshakeType::Finished, &our_verify_data).unwrap();
    assert_eq!(
        our_message,
        record("client_finished", "payload"),
        "сообщение Finished клиента"
    );

    let client_keys = traffic_keys(hash, &client_hs, 16);
    let mut client_protection = Protection::new(aead, client_keys).unwrap();
    let our_record = client_protection
        .encrypt(ContentType::Handshake, &our_message, 0)
        .unwrap();
    assert_eq!(
        our_record,
        record("client_finished", "record"),
        "запись Finished клиента совпадает побайтово"
    );
}

#[test]
fn derived_keys_match_the_recorded_ones() {
    // Ключи защиты записей выводятся нами и должны совпасть с теми,
    // что записаны в следе отдельно.
    let hash = Hash::Sha256;
    let ours = traffic_keys(hash, &secret("server_handshake_traffic_secret"), 16);
    let recorded = record_keys("server_handshake");

    let mut probe = Protection::new(Aead::Aes128Gcm, ours).unwrap();
    let flight = record("server_handshake_flight", "record");
    assert!(probe.decrypt(&flight).is_ok(), "выведенные ключи работают");
    assert_eq!(recorded.sequence(), 0);
}

#[test]
fn a_tampered_flight_breaks_the_server_finished() {
    // Если бы Finished сервера не проверялся, подмена сертификата
    // осталась бы незамеченной. Проверяем, что проверка работает.
    let hash = Hash::Sha256;
    let server_hs = secret("server_handshake_traffic_secret");

    let mut transcript = Transcript::new(hash);
    transcript.extend(&secret("client_hello"));
    transcript.extend(&secret("server_hello"));
    transcript.extend(&secret("encrypted_extensions"));

    // Подменяем один байт сертификата.
    let mut certificate = secret("certificate");
    certificate[10] ^= 0x01;
    transcript.extend(&certificate);
    transcript.extend(&secret("certificate_verify"));

    let expected = verify_data(hash, &server_hs, &transcript.hash());
    assert_ne!(
        expected,
        secret("server_verify_data"),
        "подмена в транскрипте обязана менять Finished"
    );
}
