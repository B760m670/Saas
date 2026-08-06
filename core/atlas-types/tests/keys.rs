//! Интеграционные тесты разбора ключей.
//!
//! Образцы соответствуют тому, что реально выдают панели и клиенты, включая
//! разнобой в написании параметров.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use atlas_types::{
    Credentials, Fingerprint, Flow, Protocol, ProxyKey, SecurityKind, Subscription, TransportKind,
    Warning,
};

const UUID: &str = "11111111-2222-3333-4444-555555555555";

// ---------------------------------------------------------------------------
// VLESS + REALITY — основной боевой вариант
// ---------------------------------------------------------------------------

#[test]
fn vless_reality_vision_full() {
    let uri = format!(
        "vless://{UUID}@192.0.2.10:443?type=tcp&security=reality\
         &pbk=Zx1cAbCdEf&sid=6ba1&spx=%2F&sni=www.microsoft.com\
         &fp=chrome&flow=xtls-rprx-vision#Точка%20РФ"
    );
    let key = ProxyKey::parse(&uri).unwrap();

    assert_eq!(key.protocol, Protocol::Vless);
    assert_eq!(key.host, "192.0.2.10");
    assert_eq!(key.port, 443);
    assert_eq!(key.credentials, Credentials::Uuid { uuid: UUID.into() });
    assert_eq!(key.transport.kind, TransportKind::Tcp);
    assert_eq!(key.security.kind, SecurityKind::Reality);
    assert_eq!(key.security.sni.as_deref(), Some("www.microsoft.com"));
    assert_eq!(key.security.fingerprint, Fingerprint::Chrome);
    assert_eq!(key.flow, Flow::XtlsRprxVision);
    assert_eq!(key.tag, "Точка РФ");

    let reality = key.security.reality.as_ref().unwrap();
    assert_eq!(reality.public_key, "Zx1cAbCdEf");
    assert_eq!(reality.short_id, "6ba1");
    assert_eq!(reality.spider_x.as_deref(), Some("/"));

    key.validate().unwrap();
    assert!(key.warnings().is_empty());
}

#[test]
fn vless_reality_round_trips() {
    let uri = format!(
        "vless://{UUID}@example.com:443?type=tcp&security=reality\
         &pbk=PBK&sid=aabb&sni=www.example.org&fp=chrome&flow=xtls-rprx-vision#tag"
    );
    let first = ProxyKey::parse(&uri).unwrap();
    let second = ProxyKey::parse(&first.to_uri()).unwrap();
    assert_eq!(first, second, "повторный разбор должен давать тот же ключ");
}

#[test]
fn vless_accepts_alternative_param_spellings() {
    // Некоторые панели пишут publicKey/shortId/spiderX вместо pbk/sid/spx.
    let uri = format!(
        "vless://{UUID}@example.com:443?type=tcp&security=reality\
         &publicKey=PBK&shortId=aabb&spiderX=%2Findex&peer=www.example.org"
    );
    let key = ProxyKey::parse(&uri).unwrap();
    let reality = key.security.reality.as_ref().unwrap();
    assert_eq!(reality.public_key, "PBK");
    assert_eq!(reality.short_id, "aabb");
    assert_eq!(reality.spider_x.as_deref(), Some("/index"));
    assert_eq!(key.security.sni.as_deref(), Some("www.example.org"));
}

#[test]
fn vless_ws_over_cdn() {
    let uri = format!(
        "vless://{UUID}@cdn.example.com:443?type=ws&security=tls\
         &path=%2Fapi%2Fv1&host=worker.example.workers.dev&sni=cdn.example.com&fp=chrome#CDN"
    );
    let key = ProxyKey::parse(&uri).unwrap();
    assert_eq!(key.transport.kind, TransportKind::WebSocket);
    assert_eq!(key.transport.path.as_deref(), Some("/api/v1"));
    assert_eq!(
        key.transport.host.as_deref(),
        Some("worker.example.workers.dev")
    );
    assert!(key.transport.kind.cdn_compatible());
    key.validate().unwrap();
}

#[test]
fn splithttp_is_recognised_as_xhttp() {
    let uri = format!("vless://{UUID}@example.com:443?type=splithttp&security=tls&path=%2Fx");
    let key = ProxyKey::parse(&uri).unwrap();
    assert_eq!(key.transport.kind, TransportKind::XHttp);
}

// ---------------------------------------------------------------------------
// Прочие схемы
// ---------------------------------------------------------------------------

#[test]
fn trojan_defaults_to_tls() {
    let key = ProxyKey::parse("trojan://p%40ssword@example.com:443?sni=example.com#T").unwrap();
    assert_eq!(key.protocol, Protocol::Trojan);
    assert_eq!(
        key.credentials,
        Credentials::Password {
            password: "p@ssword".into()
        }
    );
    assert_eq!(key.security.kind, SecurityKind::Tls);
    key.validate().unwrap();
}

#[test]
fn shadowsocks_sip002_base64_userinfo() {
    // base64url("2022-blake3-aes-128-gcm:c2VjcmV0")
    let userinfo = atlas_types::b64::encode_url_nopad("2022-blake3-aes-128-gcm:c2VjcmV0");
    let key = ProxyKey::parse(&format!("ss://{userinfo}@example.com:8388#SS")).unwrap();
    assert_eq!(
        key.credentials,
        Credentials::Shadowsocks {
            method: "2022-blake3-aes-128-gcm".into(),
            password: "c2VjcmV0".into()
        }
    );
    assert!(
        key.warnings().is_empty(),
        "ветка 2022 замечаний не вызывает"
    );
}

#[test]
fn legacy_shadowsocks_is_flagged() {
    let userinfo = atlas_types::b64::encode_url_nopad("aes-256-gcm:hunter2");
    let key = ProxyKey::parse(&format!("ss://{userinfo}@example.com:8388")).unwrap();
    assert!(key.warnings().contains(&Warning::LegacyShadowsocks));
}

#[test]
fn hysteria2_accepts_both_schemes_and_obfs() {
    for scheme in ["hysteria2", "hy2"] {
        let uri = format!(
            "{scheme}://secret@example.com:443?sni=example.com\
             &obfs=salamander&obfs-password=xyz#HY"
        );
        let key = ProxyKey::parse(&uri).unwrap();
        assert_eq!(key.protocol, Protocol::Hysteria2);
        assert_eq!(key.transport.kind, TransportKind::Quic);
        assert_eq!(key.security.kind, SecurityKind::Tls);
        let obfs = key.obfs.as_ref().unwrap();
        assert_eq!(obfs.kind, "salamander");
        assert_eq!(obfs.password, "xyz");
        key.validate().unwrap();
    }
}

#[test]
fn tuic_splits_uuid_and_password() {
    let uri = format!(
        "tuic://{UUID}:secret@example.com:443?congestion_control=bbr\
         &udp_relay_mode=native&alpn=h3&sni=example.com#TUIC"
    );
    let key = ProxyKey::parse(&uri).unwrap();
    assert_eq!(
        key.credentials,
        Credentials::UuidPassword {
            uuid: UUID.into(),
            password: "secret".into()
        }
    );
    assert_eq!(key.security.alpn, vec!["h3".to_owned()]);
    // Нераспознанные параметры не теряются.
    assert_eq!(
        key.extra.get("congestion_control").map(String::as_str),
        Some("bbr")
    );
    assert!(key.to_uri().contains("congestion_control=bbr"));
}

#[test]
fn vmess_json_payload() {
    let payload = serde_json::json!({
        "v": "2", "ps": "Узел", "add": "example.com", "port": 443,
        "id": UUID, "aid": 0, "net": "ws", "type": "none",
        "host": "example.com", "path": "/ws", "tls": "tls", "fp": "chrome"
    });
    let uri = format!("vmess://{}", atlas_types::b64::encode(payload.to_string()));
    let key = ProxyKey::parse(&uri).unwrap();

    assert_eq!(key.protocol, Protocol::Vmess);
    assert_eq!(
        key.port, 443,
        "порт числом должен читаться так же, как строкой"
    );
    assert_eq!(key.transport.kind, TransportKind::WebSocket);
    assert_eq!(key.transport.path.as_deref(), Some("/ws"));
    assert_eq!(key.tag, "Узел");
    assert!(key.warnings().contains(&Warning::ObsoleteProtocol));

    let again = ProxyKey::parse(&key.to_uri()).unwrap();
    assert_eq!(again.host, key.host);
    assert_eq!(again.transport.kind, key.transport.kind);
}

#[test]
fn ipv6_host_survives_round_trip() {
    let uri = format!("vless://{UUID}@[2001:db8::1]:443?type=tcp&security=tls&sni=a.example");
    let key = ProxyKey::parse(&uri).unwrap();
    assert_eq!(key.host, "2001:db8::1");
    assert!(key.to_uri().contains("[2001:db8::1]:443"));
}

// ---------------------------------------------------------------------------
// Проверка смысловых ошибок
// ---------------------------------------------------------------------------

#[test]
fn rejects_vless_without_masking() {
    let key = ProxyKey::parse(&format!("vless://{UUID}@example.com:80?type=tcp")).unwrap();
    // Разбирается — но использовать нельзя: UUID пойдёт открытым текстом.
    assert!(key.validate().is_err());
}

#[test]
fn rejects_vision_on_cdn_transport() {
    let uri = format!(
        "vless://{UUID}@example.com:443?type=ws&security=tls&sni=a.example&flow=xtls-rprx-vision"
    );
    assert!(ProxyKey::parse(&uri).unwrap().validate().is_err());
}

#[test]
fn rejects_reality_without_sni() {
    let uri = format!("vless://{UUID}@example.com:443?type=tcp&security=reality&pbk=PBK");
    assert!(ProxyKey::parse(&uri).unwrap().validate().is_err());
}

#[test]
fn rejects_malformed_short_id() {
    let uri = format!(
        "vless://{UUID}@example.com:443?type=tcp&security=reality&pbk=PBK&sni=a.example&sid=zzz"
    );
    assert!(ProxyKey::parse(&uri).unwrap().validate().is_err());
}

#[test]
fn rejects_bad_uuid_and_unknown_scheme() {
    assert!(ProxyKey::parse("vless://not-a-uuid@example.com:443?security=tls").is_err());
    assert!(ProxyKey::parse("wireguard://x@example.com:443").is_err());
    assert!(ProxyKey::parse("vless://").is_err());
}

#[test]
fn flags_insecure_and_random_fingerprint() {
    let uri = format!(
        "vless://{UUID}@example.com:443?type=tcp&security=tls&sni=a.example\
         &allowInsecure=1&fp=random"
    );
    let warnings = ProxyKey::parse(&uri).unwrap().warnings();
    assert!(warnings.contains(&Warning::InsecureTls));
    assert!(warnings.contains(&Warning::RandomFingerprint));
}

#[test]
fn flags_reality_without_vision() {
    let uri =
        format!("vless://{UUID}@example.com:443?type=tcp&security=reality&pbk=PBK&sni=a.example");
    let warnings = ProxyKey::parse(&uri).unwrap().warnings();
    assert!(warnings.contains(&Warning::RealityWithoutVision));
}

// ---------------------------------------------------------------------------
// Подписки
// ---------------------------------------------------------------------------

#[test]
fn subscription_mixes_schemes() {
    let body = format!(
        "vless://{UUID}@a.example:443?type=tcp&security=reality&pbk=P&sni=s.example\n\
         trojan://pw@b.example:443?sni=b.example\n\
         hy2://pw@c.example:443?sni=c.example\n"
    );
    let sub = Subscription::parse(&body);
    assert_eq!(sub.len(), 3);
    assert!(sub.rejected.is_empty());
    assert_eq!(sub.keys[2].protocol, Protocol::Hysteria2);
}
