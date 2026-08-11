//! Проверка того, что ключ для точки выхода строится целиком на устройстве.
//!
//! Это исполняемое доказательство центрального утверждения проекта: чтобы
//! получить рабочую конфигурацию VLESS + REALITY, ничего покупать и ни у
//! кого спрашивать не нужно. Весь секретный материал рождается здесь.

#![allow(clippy::unwrap_used)]

use atlas_crypto::credentials::RelayCredentials;
use atlas_types::{
    Credentials, Fingerprint, Flow, Protocol, ProxyKey, RealityConfig, SecurityConfig,
    SecurityKind, TransportConfig, TransportKind,
};

/// Собрать конфигурацию клиента из свежесгенерированных учётных данных.
fn build_key(host: &str, port: u16, dest: &str) -> ProxyKey {
    let creds = RelayCredentials::generate(3).unwrap();

    ProxyKey {
        protocol: Protocol::Vless,
        host: host.to_owned(),
        port,
        credentials: Credentials::Uuid {
            uuid: creds.uuid.clone(),
        },
        transport: TransportConfig {
            kind: TransportKind::Tcp,
            ..TransportConfig::default()
        },
        security: SecurityConfig {
            kind: SecurityKind::Reality,
            sni: Some(dest.to_owned()),
            alpn: Vec::new(),
            fingerprint: Fingerprint::Chrome,
            allow_insecure: false,
            reality: Some(RealityConfig {
                public_key: creds.reality.public_base64(),
                short_id: creds.short_ids.first().cloned().unwrap_or_default(),
                spider_x: Some("/".to_owned()),
                post_quantum_verify: None,
            }),
        },
        flow: Flow::XtlsRprxVision,
        obfs: None,
        tag: "Моя точка".to_owned(),
        extra: std::collections::BTreeMap::new(),
    }
}

#[test]
fn generated_key_is_valid_and_clean() {
    let key = build_key("203.0.113.7", 443, "www.microsoft.com");

    // Ключ пригоден к использованию…
    key.validate().unwrap();
    // …и не вызывает ни одного замечания по скрытности.
    assert!(key.warnings().is_empty(), "{:?}", key.warnings());
}

#[test]
fn generated_key_survives_export_and_import() {
    let key = build_key("203.0.113.7", 443, "www.microsoft.com");

    // Экспорт своей точки — например, чтобы поделиться с близкими.
    let uri = key.to_uri();
    assert!(uri.starts_with("vless://"));
    assert!(uri.contains("security=reality"));
    assert!(uri.contains("flow=xtls-rprx-vision"));

    let imported = ProxyKey::parse(&uri).unwrap();
    assert_eq!(key, imported);
    imported.validate().unwrap();
}

#[test]
fn every_point_gets_its_own_material() {
    let first = build_key("203.0.113.7", 443, "www.microsoft.com");
    let second = build_key("203.0.113.7", 443, "www.microsoft.com");

    assert_ne!(
        first.credentials, second.credentials,
        "UUID должен быть свой"
    );
    assert_ne!(
        first.security.reality.as_ref().map(|r| &r.public_key),
        second.security.reality.as_ref().map(|r| &r.public_key),
        "пара REALITY должна быть своя"
    );
}

#[test]
fn short_id_passes_reality_constraints() {
    // validate() проверяет форму shortId; несколько прогонов ловят
    // случайные значения, которые могли бы её нарушить.
    for _ in 0..64 {
        build_key("198.51.100.4", 8443, "www.apple.com")
            .validate()
            .unwrap();
    }
}
