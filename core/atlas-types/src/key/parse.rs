//! Разбор URI в [`ProxyKey`].
//!
//! Принцип — максимальная терпимость. Пользователь приходит с ключом, который
//! ему выдали, и этот ключ обязан импортироваться, даже если сгенерировавший
//! его клиент вольно обошёлся со спецификацией.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::b64;
use crate::error::{Error, Result};
use crate::protocol::{Fingerprint, Flow, Protocol, SecurityKind, TransportKind};
use crate::uri::{decode_component, RawUri};

use super::{Credentials, ObfsConfig, ProxyKey, RealityConfig, SecurityConfig, TransportConfig};

/// Параметры, которые мы разбираем сами; всё остальное уходит в `extra`.
const KNOWN_PARAMS: &[&str] = &[
    "type",
    "network",
    "net",
    "security",
    "encryption",
    "sni",
    "peer",
    "servername",
    "host",
    "path",
    "servicename",
    "mode",
    "headertype",
    "seed",
    "alpn",
    "fp",
    "pbk",
    "publickey",
    "sid",
    "shortid",
    "spx",
    "spiderx",
    "flow",
    "allowinsecure",
    "insecure",
    "skip-cert-verify",
    "obfs",
    "obfs-password",
    "obfspassword",
];

pub(super) fn parse(input: &str) -> Result<ProxyKey> {
    let trimmed = input.trim();
    let (scheme, _) = trimmed.split_once("://").ok_or(Error::MissingScheme)?;
    let protocol = Protocol::from_scheme(scheme)
        .ok_or_else(|| Error::UnknownScheme(scheme.to_ascii_lowercase()))?;

    // VMess не является URI: после схемы идёт base64 от JSON.
    if protocol == Protocol::Vmess {
        return parse_vmess(trimmed);
    }

    let uri = RawUri::parse(trimmed)?;
    let port = uri.port.ok_or(Error::Missing("порт"))?;
    if uri.host.is_empty() {
        return Err(Error::Missing("адрес точки"));
    }

    let credentials = match protocol {
        Protocol::Vless => Credentials::Uuid {
            uuid: normalize_uuid(userinfo(&uri)?)?,
        },
        Protocol::Trojan | Protocol::Hysteria2 | Protocol::AnyTls | Protocol::AmneziaWg => {
            Credentials::Password {
                password: decode_component(userinfo(&uri)?),
            }
        }
        Protocol::Tuic => {
            let raw = userinfo(&uri)?;
            let (uuid, password) = raw
                .split_once(':')
                .ok_or_else(|| Error::invalid("userinfo", "ожидается `uuid:пароль`"))?;
            Credentials::UuidPassword {
                uuid: normalize_uuid(uuid)?,
                password: decode_component(password),
            }
        }
        Protocol::Shadowsocks => parse_ss_credentials(&uri)?,
        Protocol::Vmess => unreachable!("обработан выше"),
    };

    let transport = parse_transport(&uri, protocol);
    let security = parse_security(&uri, protocol);
    let flow = uri
        .param("flow")
        .and_then(Flow::parse)
        .unwrap_or(Flow::None);
    let obfs = uri.param("obfs").map(|kind| ObfsConfig {
        kind: kind.to_owned(),
        password: uri
            .param_any(&["obfs-password", "obfsPassword"])
            .unwrap_or_default()
            .to_owned(),
    });

    Ok(ProxyKey {
        protocol,
        host: uri.host.clone(),
        port,
        credentials,
        transport,
        security,
        flow,
        obfs,
        tag: uri.fragment.clone().unwrap_or_default(),
        extra: collect_extra(&uri),
    })
}

fn userinfo(uri: &RawUri) -> Result<&str> {
    uri.userinfo
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(Error::Missing("учётные данные"))
}

/// Привести UUID к каноническому виду и проверить форму 8-4-4-4-12.
fn normalize_uuid(raw: &str) -> Result<String> {
    const GROUP_LENGTHS: [usize; 5] = [8, 4, 4, 4, 12];

    let lower = raw.trim().to_ascii_lowercase();
    let groups: Vec<usize> = lower.split('-').map(str::len).collect();
    let shape_ok = groups == GROUP_LENGTHS;

    if !shape_ok || !lower.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(Error::invalid(
            "uuid",
            format!("`{raw}` не имеет формы 8-4-4-4-12"),
        ));
    }
    Ok(lower)
}

/// Shadowsocks существует в трёх форматах записи одновременно.
fn parse_ss_credentials(uri: &RawUri) -> Result<Credentials> {
    let raw = userinfo(uri)?;

    // SIP002: userinfo — base64 от `method:password`.
    if let Ok(decoded) = b64::decode_str(raw, "ss-userinfo") {
        if let Some((method, password)) = decoded.split_once(':') {
            return Ok(Credentials::Shadowsocks {
                method: method.to_owned(),
                password: password.to_owned(),
            });
        }
    }

    // Ветка 2022 и часть клиентов пишут `method:password` открытым текстом.
    let decoded = decode_component(raw);
    let (method, password) = decoded
        .split_once(':')
        .ok_or_else(|| Error::invalid("userinfo", "ожидается `шифр:пароль`"))?;
    Ok(Credentials::Shadowsocks {
        method: method.to_owned(),
        password: password.to_owned(),
    })
}

fn parse_transport(uri: &RawUri, protocol: Protocol) -> TransportConfig {
    // У QUIC-протоколов транспорт предопределён, параметр `type` там не пишут.
    let kind = if protocol.is_udp_based() {
        TransportKind::Quic
    } else {
        uri.param_any(&["type", "network", "net"])
            .and_then(TransportKind::parse)
            .unwrap_or_default()
    };

    TransportConfig {
        kind,
        path: uri.param("path").map(str::to_owned),
        host: uri.param("host").map(str::to_owned),
        service_name: uri
            .param_any(&["serviceName", "servicename"])
            .map(str::to_owned),
        mode: uri.param("mode").map(str::to_owned),
        header_type: uri
            .param_any(&["headerType", "headertype"])
            .map(str::to_owned),
        seed: uri.param("seed").map(str::to_owned),
    }
}

fn parse_security(uri: &RawUri, protocol: Protocol) -> SecurityConfig {
    // QUIC-протоколы всегда несут TLS внутри себя, `security` для них не пишут.
    let default_kind = if protocol.is_udp_based() || protocol == Protocol::Trojan {
        SecurityKind::Tls
    } else {
        SecurityKind::None
    };
    let kind = uri
        .param("security")
        .and_then(SecurityKind::parse)
        .unwrap_or(default_kind);

    let reality = if kind == SecurityKind::Reality {
        Some(RealityConfig {
            public_key: uri
                .param_any(&["pbk", "publicKey", "publickey"])
                .unwrap_or_default()
                .to_owned(),
            short_id: uri
                .param_any(&["sid", "shortId", "shortid"])
                .unwrap_or_default()
                .to_owned(),
            spider_x: uri
                .param_any(&["spx", "spiderX", "spiderx"])
                .map(str::to_owned),
        })
    } else {
        None
    };

    SecurityConfig {
        kind,
        sni: uri
            .param_any(&["sni", "peer", "servername", "serverName"])
            .map(str::to_owned),
        alpn: uri
            .param("alpn")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        fingerprint: uri
            .param("fp")
            .and_then(Fingerprint::parse)
            .unwrap_or_default(),
        allow_insecure: uri.param_bool("allowInsecure")
            || uri.param_bool("insecure")
            || uri.param_bool("skip-cert-verify"),
        reality,
    }
}

fn collect_extra(uri: &RawUri) -> BTreeMap<String, String> {
    uri.query
        .iter()
        .filter(|(k, _)| !KNOWN_PARAMS.contains(&k.to_ascii_lowercase().as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

// ---------------------------------------------------------------------------
// VMess
// ---------------------------------------------------------------------------

/// Разобрать `vmess://` — base64 от JSON.
///
/// Формат неформальный: разные клиенты кладут числа то строками, то числами,
/// поэтому все значения читаются терпимо.
fn parse_vmess(input: &str) -> Result<ProxyKey> {
    let payload = input
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    let json = b64::decode_str(payload, "vmess-payload")?;
    let value: Value = serde_json::from_str(&json).map_err(|e| Error::Json(e.to_string()))?;

    let host = json_str(&value, "add").ok_or(Error::Missing("адрес точки"))?;
    let port: u16 = json_str(&value, "port")
        .ok_or(Error::Missing("порт"))?
        .parse()
        .map_err(|_| Error::invalid("port", "не является номером порта"))?;
    let uuid = normalize_uuid(&json_str(&value, "id").ok_or(Error::Missing("учётные данные"))?)?;

    let kind = json_str(&value, "net")
        .and_then(|v| TransportKind::parse(&v))
        .unwrap_or_default();
    let security_kind = match json_str(&value, "tls").as_deref() {
        Some("tls" | "xtls") => SecurityKind::Tls,
        Some("reality") => SecurityKind::Reality,
        _ => SecurityKind::None,
    };

    let transport = TransportConfig {
        kind,
        path: json_str(&value, "path"),
        host: json_str(&value, "host"),
        service_name: json_str(&value, "serviceName").or_else(|| json_str(&value, "path")),
        mode: None,
        // В VMess-JSON поле `type` — это именно обфускация заголовка,
        // а транспорт лежит в `net`. Частый источник путаницы.
        header_type: json_str(&value, "type"),
        seed: None,
    };

    let security = SecurityConfig {
        kind: security_kind,
        sni: json_str(&value, "sni").or_else(|| json_str(&value, "host")),
        alpn: json_str(&value, "alpn")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        fingerprint: json_str(&value, "fp")
            .and_then(|v| Fingerprint::parse(&v))
            .unwrap_or_default(),
        allow_insecure: matches!(json_str(&value, "verify_cert").as_deref(), Some("false")),
        reality: None,
    };

    Ok(ProxyKey {
        protocol: Protocol::Vmess,
        host,
        port,
        credentials: Credentials::Uuid { uuid },
        transport,
        security,
        flow: Flow::None,
        obfs: None,
        tag: json_str(&value, "ps").unwrap_or_default(),
        extra: BTreeMap::new(),
    })
}

/// Прочитать поле JSON как строку, приняв и строку, и число.
fn json_str(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}
