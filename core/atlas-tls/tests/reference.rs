//! Сверка с опубликованными эталонными отпечатками.
//!
//! Это главный тест крейта и, возможно, всего проекта. Он отвечает на
//! вопрос «отличим ли наш клиент от браузера по первому пакету».
//!
//! Эталон — не наш собственный вывод, зафиксированный «как есть», а
//! публично известный отпечаток Chrome. Направление зависимости именно
//! такое: если сборщик перестаёт его воспроизводить, ошибка в сборщике,
//! а не в эталоне.
//!
//! # Границы этого теста
//!
//! Тест проверяет, что мы воспроизводим **опубликованный** отпечаток
//! конкретной конфигурации Chrome. Он не может подтвердить, что этот
//! отпечаток соответствует той версии Chrome, которая сегодня
//! преобладает в сетях: для этого нужен свежий захват реального трафика.
//! Перед выпуском профиль обязан пройти калибровку по живому захвату —
//! см. `docs/08-fingerprint-calibration.md`.

#![allow(clippy::unwrap_used)]

use atlas_tls::fingerprint::{ja3, ja4};
use atlas_tls::profile::{X25519, X25519_MLKEM768};
use atlas_tls::{Chrome, ClientHello, HelloParams, Transport};

/// Опубликованный отпечаток Chrome для конфигурации без постквантовой
/// группы: TLS 1.3, SNI, 15 шифров, 16 расширений, ALPN `h2`.
const CHROME_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";

fn classic_params() -> HelloParams {
    HelloParams::new("www.microsoft.com")
        .with_key_shares(vec![(X25519, vec![0x11; 32])])
        .with_session_id(vec![0x22; 32])
}

#[test]
fn chrome_profile_reproduces_published_fingerprint() {
    let hello = Chrome::classic().client_hello(&classic_params()).unwrap();
    let fp = ja4(&hello, Transport::Tcp);

    assert_eq!(
        fp.to_string_full(),
        CHROME_JA4,
        "отпечаток разошёлся с эталоном Chrome — клиент стал отличим"
    );
}

#[test]
fn fingerprint_is_stable_across_connections() {
    // Случайны random, session_id, значения GREASE и порядок расширений.
    // Ни одно из этого не должно влиять на отпечаток.
    let profile = Chrome::classic();
    let fingerprints: std::collections::HashSet<String> = (0..64)
        .map(|_| {
            let hello = profile.client_hello(&classic_params()).unwrap();
            ja4(&hello, Transport::Tcp).to_string_full()
        })
        .collect();

    assert_eq!(fingerprints, [CHROME_JA4.to_owned()].into_iter().collect());
}

#[test]
fn fingerprint_survives_serialisation() {
    // Отпечаток считается и по построенной структуре, и по разобранным
    // байтам одинаково — иначе тест ничего не проверял бы про провод.
    let hello = Chrome::classic().client_hello(&classic_params()).unwrap();
    let wire = hello.to_record().unwrap();
    let parsed = ClientHello::parse(&wire).unwrap();

    assert_eq!(
        ja4(&parsed, Transport::Tcp).to_string_full(),
        CHROME_JA4,
        "отпечаток по проводным байтам обязан совпадать"
    );
}

#[test]
fn fingerprint_does_not_depend_on_sni() {
    // Домен прикрытия у REALITY меняется от точки к точке. Если бы от него
    // менялся отпечаток, ротация `dest` сама выдавала бы клиента.
    for host in [
        "www.microsoft.com",
        "a.io",
        "www.some-very-long-domain.example",
    ] {
        let params = HelloParams::new(host)
            .with_key_shares(vec![(X25519, vec![0x11; 32])])
            .with_session_id(vec![0x22; 32]);
        let hello = Chrome::classic().client_hello(&params).unwrap();
        assert_eq!(
            ja4(&hello, Transport::Tcp).to_string_full(),
            CHROME_JA4,
            "домен {host} изменил отпечаток"
        );
    }
}

#[test]
fn fingerprint_does_not_depend_on_session_id_contents() {
    // REALITY прячет в session_id зашифрованную метку. Она обязана быть
    // неотличима от обычных случайных байт — в том числе по отпечатку.
    let random = HelloParams::new("www.microsoft.com")
        .with_key_shares(vec![(X25519, vec![0x11; 32])])
        .with_session_id(vec![0x5a; 32]);
    let hello = Chrome::classic().client_hello(&random).unwrap();
    assert_eq!(ja4(&hello, Transport::Tcp).to_string_full(), CHROME_JA4);
}

#[test]
fn post_quantum_variant_keeps_hashed_parts() {
    // Постквантовая группа меняет содержимое supported_groups и размер
    // key_share, но набор типов расширений остаётся прежним. Значит
    // хэшируемые части JA4 совпадают, а различаться может лишь счётчик
    // расширений — из-за padding, который зависит от длины сообщения.
    let pq = Chrome::default()
        .client_hello(
            &HelloParams::new("www.microsoft.com")
                .with_key_shares(vec![
                    (X25519_MLKEM768, vec![0x33; 1216]),
                    (X25519, vec![0x11; 32]),
                ])
                .with_session_id(vec![0x22; 32]),
        )
        .unwrap();
    let fp = ja4(&pq, Transport::Tcp);

    assert_eq!(fp.b, "8daaf6152771", "список шифров не менялся");
    assert!(
        fp.a.starts_with("t13d15"),
        "версия, SNI и шифры те же: {}",
        fp.a
    );
    assert!(fp.a.ends_with("h2"));
}

#[test]
fn ja3_string_has_five_fields() {
    // JA3 считаем для совместимости со старыми системами анализа.
    // Как ориентир он непригоден — Chrome перемешивает расширения, —
    // но формат обязан быть корректным.
    let hello = Chrome::classic().client_hello(&classic_params()).unwrap();
    let fp = ja3(&hello);

    let fields: Vec<&str> = fp.raw.split(',').collect();
    assert_eq!(fields.len(), 5, "{}", fp.raw);
    assert_eq!(
        fields.first().copied(),
        Some("771"),
        "версия TLS 1.2 в поле legacy"
    );
    assert_eq!(fp.hash.len(), 32);
}
