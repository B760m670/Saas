//! Сверка с живым захватом настоящего браузера.
//!
//! Этот тест закрывает пункт, который до сих пор оставался открытым:
//! предыдущая сверка шла с **опубликованным** отпечатком, то есть
//! доверяла чужой публикации. Здесь эталон снят с работающего Chromium
//! локальной ловушкой, и байты `ClientHello` лежат в репозитории.
//!
//! Проверяются два независимых утверждения, которые важно не смешивать:
//!
//! 1. **Наша реализация JA4 верна** — отпечаток, посчитанный по
//!    захваченным байтам, совпадает с записанным. Сборщик здесь ни при чём.
//! 2. **Наш сборщик верен** — профиль порождает `ClientHello` с тем же
//!    отпечатком, что и настоящий браузер.
//!
//! Как обновить эталон — `docs/08-fingerprint-calibration.md`.

// Вход теста — фиксированный файл из testdata, а не сетевые данные.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use atlas_tls::fingerprint::{ja3, ja4};
use atlas_tls::profile::{X25519, X25519_MLKEM768};
use atlas_tls::{Chrome, ClientHello, HelloParams, Transport};

const CAPTURE: &str = include_str!("../testdata/chromium-141-linux.json");

struct Reference {
    hello: ClientHello,
    ja4: String,
    ja3: String,
    sni: String,
}

fn reference() -> Reference {
    let doc: serde_json::Value = serde_json::from_str(CAPTURE).unwrap();
    let hex = doc["client_hello_hex"].as_str().unwrap();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();

    Reference {
        hello: ClientHello::parse(&bytes).unwrap(),
        ja4: doc["ja4"].as_str().unwrap().to_owned(),
        ja3: doc["ja3"].as_str().unwrap().to_owned(),
        sni: doc["sni"].as_str().unwrap().to_owned(),
    }
}

#[test]
fn our_fingerprint_implementation_matches_the_capture() {
    let reference = reference();
    assert_eq!(
        ja4(&reference.hello, Transport::Tcp).to_string_full(),
        reference.ja4
    );
    assert_eq!(ja3(&reference.hello).hash, reference.ja3);
}

#[test]
fn our_parser_reads_the_capture_correctly() {
    let reference = reference();
    assert_eq!(
        reference.hello.server_name().as_deref(),
        Some(reference.sni.as_str())
    );
    assert_eq!(reference.hello.alpn(), vec!["h2", "http/1.1"]);
    // Тридцать два байта — ровно то поле, куда REALITY прячет метку.
    assert_eq!(reference.hello.session_id.len(), 32);
}

#[test]
fn our_builder_reproduces_the_captured_fingerprint() {
    let reference = reference();

    // Ключевые доли те же, что у браузера: постквантовая группа впереди,
    // за ней классическая.
    let params = HelloParams::new(&reference.sni)
        .with_key_shares(vec![
            (X25519_MLKEM768, vec![0x33; 1216]),
            (X25519, vec![0x11; 32]),
        ])
        .with_session_id(vec![0x22; 32]);

    let ours = Chrome::v141().client_hello(&params).unwrap();
    assert_eq!(
        ja4(&ours, Transport::Tcp).to_string_full(),
        reference.ja4,
        "профиль разошёлся с живым захватом Chromium"
    );
}

#[test]
fn we_send_the_same_extension_set_as_the_browser() {
    let reference = reference();
    let ours = Chrome::v141()
        .client_hello(&HelloParams::new(&reference.sni).with_key_shares(vec![
            (X25519_MLKEM768, vec![0x33; 1216]),
            (X25519, vec![0x11; 32]),
        ]))
        .unwrap();

    let types = |hello: &ClientHello| -> std::collections::BTreeSet<u16> {
        hello
            .extensions
            .iter()
            .map(|e| e.ext_type)
            .filter(|t| !atlas_tls::grease::is_grease(*t))
            .collect()
    };

    assert_eq!(
        types(&ours),
        types(&reference.hello),
        "набор расширений отличается от браузерного"
    );
}

#[test]
fn we_send_the_same_cipher_list_as_the_browser() {
    let reference = reference();
    let ours = Chrome::v141()
        .client_hello(&HelloParams::new(&reference.sni))
        .unwrap();

    let ciphers = |hello: &ClientHello| -> Vec<u16> {
        hello
            .cipher_suites
            .iter()
            .copied()
            .filter(|c| !atlas_tls::grease::is_grease(*c))
            .collect()
    };

    // Порядок тоже значим: JA4 его сортирует, а JA3 — нет.
    assert_eq!(ciphers(&ours), ciphers(&reference.hello));
}

#[test]
fn we_send_the_same_groups_and_signature_algorithms() {
    let reference = reference();
    let ours = Chrome::v141()
        .client_hello(&HelloParams::new(&reference.sni))
        .unwrap();

    let strip = |values: Vec<u16>| -> Vec<u16> {
        values
            .into_iter()
            .filter(|v| !atlas_tls::grease::is_grease(*v))
            .collect()
    };

    assert_eq!(
        strip(ours.supported_groups()),
        strip(reference.hello.supported_groups()),
        "список групп отличается"
    );
    assert_eq!(
        ours.signature_algorithms(),
        reference.hello.signature_algorithms(),
        "алгоритмы подписи отличаются"
    );
}

#[test]
fn the_browser_frames_its_extensions_with_grease() {
    // Подтверждение решения перемешивать: у браузера GREASE стоит первым
    // и последним, а середина идёт в произвольном порядке.
    let reference = reference();
    let types: Vec<u16> = reference
        .hello
        .extensions
        .iter()
        .map(|e| e.ext_type)
        .collect();

    assert!(atlas_tls::grease::is_grease(*types.first().unwrap()));
    assert!(atlas_tls::grease::is_grease(*types.last().unwrap()));
    assert_eq!(
        types
            .iter()
            .filter(|t| atlas_tls::grease::is_grease(**t))
            .count(),
        2
    );
}
