//! Построение канонического URI из [`ProxyKey`].
//!
//! В отличие от разбора, построение строгое: пишем один вариант написания
//! каждого параметра — тот, который понимают все распространённые клиенты.

use serde_json::json;

use crate::b64;
use crate::protocol::{Flow, Protocol, SecurityKind, TransportKind};
use crate::uri::{encode_param, join_host_port};

use super::{Credentials, ProxyKey};

pub(super) fn to_uri(key: &ProxyKey) -> String {
    if key.protocol == Protocol::Vmess {
        return build_vmess(key);
    }
    if key.protocol == Protocol::Shadowsocks {
        return build_shadowsocks(key);
    }

    let userinfo = match &key.credentials {
        Credentials::Uuid { uuid } => uuid.clone(),
        Credentials::Password { password } => encode_param(password),
        Credentials::UuidPassword { uuid, password } => {
            format!("{uuid}:{}", encode_param(password))
        }
        // Обработан выше отдельной веткой.
        Credentials::Shadowsocks { .. } => String::new(),
    };

    let query = build_query(key);
    let mut out = format!(
        "{}://{userinfo}@{}",
        key.protocol.scheme(),
        join_host_port(&key.host, key.port)
    );
    if !query.is_empty() {
        out.push('?');
        out.push_str(&query);
    }
    append_tag(&mut out, &key.tag);
    out
}

fn build_query(key: &ProxyKey) -> String {
    let mut params: Vec<(&str, String)> = Vec::new();

    // Для QUIC-протоколов транспорт предопределён — параметр не пишем.
    if !key.protocol.is_udp_based() {
        params.push(("type", key.transport.kind.as_str().to_owned()));
        params.push(("security", key.security.kind.as_str().to_owned()));
    }

    if let Some(sni) = &key.security.sni {
        params.push(("sni", sni.clone()));
    }
    if !key.security.alpn.is_empty() {
        params.push(("alpn", key.security.alpn.join(",")));
    }
    if key.security.kind != SecurityKind::None {
        params.push(("fp", key.security.fingerprint.as_str().to_owned()));
    }
    if key.security.allow_insecure {
        params.push(("allowInsecure", "1".to_owned()));
    }

    if let Some(reality) = &key.security.reality {
        params.push(("pbk", reality.public_key.clone()));
        if !reality.short_id.is_empty() {
            params.push(("sid", reality.short_id.clone()));
        }
        if let Some(spx) = &reality.spider_x {
            params.push(("spx", spx.clone()));
        }
    }

    match key.transport.kind {
        TransportKind::WebSocket | TransportKind::HttpUpgrade | TransportKind::XHttp => {
            if let Some(path) = &key.transport.path {
                params.push(("path", path.clone()));
            }
            if let Some(host) = &key.transport.host {
                params.push(("host", host.clone()));
            }
            if let Some(mode) = &key.transport.mode {
                params.push(("mode", mode.clone()));
            }
        }
        TransportKind::Grpc => {
            if let Some(name) = &key.transport.service_name {
                params.push(("serviceName", name.clone()));
            }
            if let Some(mode) = &key.transport.mode {
                params.push(("mode", mode.clone()));
            }
        }
        TransportKind::Kcp => {
            if let Some(seed) = &key.transport.seed {
                params.push(("seed", seed.clone()));
            }
            if let Some(ht) = &key.transport.header_type {
                params.push(("headerType", ht.clone()));
            }
        }
        TransportKind::Tcp => {
            if let Some(ht) = &key.transport.header_type {
                params.push(("headerType", ht.clone()));
            }
        }
        TransportKind::Quic => {}
    }

    if key.flow != Flow::None {
        params.push(("flow", key.flow.as_str().to_owned()));
    }
    if let Some(obfs) = &key.obfs {
        params.push(("obfs", obfs.kind.clone()));
        if !obfs.password.is_empty() {
            params.push(("obfs-password", obfs.password.clone()));
        }
    }

    for (name, value) in &key.extra {
        params.push((name.as_str(), value.clone()));
    }

    params
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", encode_param(&v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// SIP002: `ss://base64url(method:password)@host:port#tag`.
fn build_shadowsocks(key: &ProxyKey) -> String {
    let Credentials::Shadowsocks { method, password } = &key.credentials else {
        return String::new();
    };
    let userinfo = b64::encode_url_nopad(format!("{method}:{password}"));
    let mut out = format!("ss://{userinfo}@{}", join_host_port(&key.host, key.port));
    append_tag(&mut out, &key.tag);
    out
}

/// `vmess://base64(json)`.
fn build_vmess(key: &ProxyKey) -> String {
    let uuid = match &key.credentials {
        Credentials::Uuid { uuid } => uuid.as_str(),
        _ => "",
    };
    let tls = match key.security.kind {
        SecurityKind::None => "",
        SecurityKind::Tls => "tls",
        SecurityKind::Reality => "reality",
    };

    let payload = json!({
        "v": "2",
        "ps": key.tag,
        "add": key.host,
        "port": key.port.to_string(),
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "net": key.transport.kind.as_str(),
        "type": key.transport.header_type.clone().unwrap_or_else(|| "none".to_owned()),
        "host": key.transport.host.clone().unwrap_or_default(),
        "path": key.transport.path.clone().unwrap_or_default(),
        "tls": tls,
        "sni": key.security.sni.clone().unwrap_or_default(),
        "alpn": key.security.alpn.join(","),
        "fp": key.security.fingerprint.as_str(),
    });

    format!("vmess://{}", b64::encode(payload.to_string()))
}

fn append_tag(out: &mut String, tag: &str) {
    if !tag.is_empty() {
        out.push('#');
        out.push_str(&encode_param(tag));
    }
}
