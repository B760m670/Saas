//! Идентификаторы расширений TLS и кодирование их тел.
//!
//! Конструкторы инфаллибельны: значения, не помещающиеся в поле своей
//! длины (например, имя протокола длиннее 255 байт), молча пропускаются.
//! Такие входы не встречаются в реальных профилях, а возврат ошибки из
//! каждого конструктора сделал бы описание профиля нечитаемым.

use atlas_crypto::rng::OsRng;

use crate::bytes::{Reader, Writer};
use crate::hello::Extension;

/// `server_name` — SNI.
pub const SERVER_NAME: u16 = 0x0000;
/// `status_request` — OCSP stapling.
pub const STATUS_REQUEST: u16 = 0x0005;
/// `supported_groups` — эллиптические кривые и постквантовые группы.
pub const SUPPORTED_GROUPS: u16 = 0x000a;
/// `ec_point_formats`.
pub const EC_POINT_FORMATS: u16 = 0x000b;
/// `signature_algorithms`.
pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// `application_layer_protocol_negotiation`.
pub const ALPN: u16 = 0x0010;
/// `signed_certificate_timestamp`.
pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
/// `padding`.
pub const PADDING: u16 = 0x0015;
/// `extended_master_secret`.
pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
/// `compress_certificate`.
pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
/// `session_ticket`.
pub const SESSION_TICKET: u16 = 0x0023;
/// `supported_versions`.
pub const SUPPORTED_VERSIONS: u16 = 0x002b;
/// `psk_key_exchange_modes`.
pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
/// `key_share`.
pub const KEY_SHARE: u16 = 0x0033;
/// `application_settings` (ALPS), первая кодовая точка Chrome.
///
/// В Chrome 141 заменена на [`APPLICATION_SETTINGS_V2`]; оставлена для
/// профилей старых версий.
pub const APPLICATION_SETTINGS: u16 = 0x4469;
/// `application_settings` (ALPS), кодовая точка Chrome 141.
pub const APPLICATION_SETTINGS_V2: u16 = 0x44cd;
/// `trust_anchors` — Trust Anchor Identifiers, прототип Chrome.
///
/// В `ClientHello` отправляется с пустым списком: клиент лишь объявляет,
/// что понимает механизм.
pub const TRUST_ANCHORS: u16 = 0xca34;
/// `encrypted_client_hello`.
///
/// Захват Chromium 141 показал, что браузер отправляет это расширение
/// **всегда**, даже когда у сервера нет ECH-конфигурации: в этом случае
/// содержимое случайное (режим GREASE). Поэтому отсутствие расширения
/// само стало отличием от браузера — см. `docs/08-fingerprint-calibration.md`.
pub const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// `renegotiation_info`.
pub const RENEGOTIATION_INFO: u16 = 0xff01;

/// SNI с одним именем хоста.
#[must_use]
pub fn server_name(host: &str) -> Extension {
    let mut w = Writer::new();
    let _ = w.nested_u16(|list| {
        // Тип записи 0 — `host_name`, других типов на практике нет.
        list.u8(0);
        let _ = list.nested_u16(|name| name.bytes(host.as_bytes()));
    });
    Extension::raw(SERVER_NAME, w.finish())
}

/// `supported_groups`.
#[must_use]
pub fn supported_groups(groups: &[u16]) -> Extension {
    let mut w = Writer::new();
    let _ = w.nested_u16(|list| list.list_u16(groups));
    Extension::raw(SUPPORTED_GROUPS, w.finish())
}

/// `ec_point_formats`.
#[must_use]
pub fn ec_point_formats(formats: &[u8]) -> Extension {
    let mut w = Writer::new();
    let _ = w.nested_u8(|list| list.bytes(formats));
    Extension::raw(EC_POINT_FORMATS, w.finish())
}

/// `signature_algorithms`.
#[must_use]
pub fn signature_algorithms(algorithms: &[u16]) -> Extension {
    let mut w = Writer::new();
    let _ = w.nested_u16(|list| list.list_u16(algorithms));
    Extension::raw(SIGNATURE_ALGORITHMS, w.finish())
}

/// ALPN со списком имён протоколов.
#[must_use]
pub fn alpn(protocols: &[&str]) -> Extension {
    Extension::raw(ALPN, name_list(protocols))
}

/// ALPS — тот же формат тела, что у ALPN.
#[must_use]
pub fn application_settings(protocols: &[&str]) -> Extension {
    Extension::raw(APPLICATION_SETTINGS, name_list(protocols))
}

/// ALPS с кодовой точкой Chrome 141.
#[must_use]
pub fn application_settings_v2(protocols: &[&str]) -> Extension {
    Extension::raw(APPLICATION_SETTINGS_V2, name_list(protocols))
}

/// `trust_anchors` с пустым списком — так его шлёт Chrome.
#[must_use]
pub fn trust_anchors() -> Extension {
    Extension::raw(TRUST_ANCHORS, vec![0x00, 0x00])
}

/// ECH в режиме GREASE: расширение присутствует, содержимое случайно.
///
/// Раскладка снята с живого захвата Chromium 141:
///
/// ```text
/// тип(1)=0 | kdf(2) | aead(2) | config_id(1) | enc<2> | payload<2>
/// ```
///
/// Длины `enc` и `payload` берутся те же, что у браузера, — 32 и 144
/// байта: они наблюдаемы, и отличие в них было бы заметно.
#[must_use]
pub fn ech_grease() -> Extension {
    const ENC_LEN: usize = 32;
    const PAYLOAD_LEN: usize = 144;

    let mut w = Writer::new();
    w.u8(0x00); // ECHClientHelloType::outer
    w.u16(0x0001); // HKDF-SHA256
    w.u16(0x0001); // AES-128-GCM
    w.u8(OsRng::bytes::<1>()[0]); // config_id
    let _ = w.nested_u16(|body| body.bytes(&OsRng::bytes::<ENC_LEN>()));
    let _ = w.nested_u16(|body| {
        // Полезная нагрузка при GREASE — просто случайные байты.
        let mut chunk = [0_u8; PAYLOAD_LEN];
        OsRng::fill(&mut chunk);
        body.bytes(&chunk);
    });
    Extension::raw(ENCRYPTED_CLIENT_HELLO, w.finish())
}

/// `supported_versions` для `ClientHello` (однобайтовый префикс списка).
#[must_use]
pub fn supported_versions(versions: &[u16]) -> Extension {
    let mut w = Writer::new();
    let _ = w.nested_u8(|list| list.list_u16(versions));
    Extension::raw(SUPPORTED_VERSIONS, w.finish())
}

/// `psk_key_exchange_modes`.
#[must_use]
pub fn psk_key_exchange_modes(modes: &[u8]) -> Extension {
    let mut w = Writer::new();
    let _ = w.nested_u8(|list| list.bytes(modes));
    Extension::raw(PSK_KEY_EXCHANGE_MODES, w.finish())
}

/// `compress_certificate`.
#[must_use]
pub fn compress_certificate(algorithms: &[u16]) -> Extension {
    let mut w = Writer::new();
    let _ = w.nested_u8(|list| list.list_u16(algorithms));
    Extension::raw(COMPRESS_CERTIFICATE, w.finish())
}

/// `key_share` со списком пар «группа — открытый ключ».
#[must_use]
pub fn key_share(entries: &[(u16, Vec<u8>)]) -> Extension {
    let mut w = Writer::new();
    let _ = w.nested_u16(|list| {
        for (group, key) in entries {
            list.u16(*group);
            let _ = list.nested_u16(|body| body.bytes(key));
        }
    });
    Extension::raw(KEY_SHARE, w.finish())
}

/// `status_request` в том виде, в каком его шлют браузеры.
#[must_use]
pub fn status_request() -> Extension {
    // status_type=ocsp(1), пустые responder_id_list и request_extensions.
    Extension::raw(STATUS_REQUEST, vec![0x01, 0x00, 0x00, 0x00, 0x00])
}

/// `renegotiation_info` с пустым значением.
#[must_use]
pub fn renegotiation_info() -> Extension {
    Extension::raw(RENEGOTIATION_INFO, vec![0x00])
}

/// `padding` заданной длины, заполненный нулями.
#[must_use]
pub fn padding(len: usize) -> Extension {
    Extension::raw(PADDING, vec![0_u8; len])
}

/// Общий формат «список имён с однобайтовой длиной каждое».
fn name_list(names: &[&str]) -> Vec<u8> {
    let mut w = Writer::new();
    let _ = w.nested_u16(|list| {
        for name in names {
            // Имена длиннее 255 байт не помещаются в префикс — пропускаем.
            let _ = list.nested_u8(|body| body.bytes(name.as_bytes()));
        }
    });
    w.finish()
}

/// Разобрать тело SNI и вернуть первое имя хоста.
#[must_use]
pub fn parse_server_name(body: &[u8]) -> Option<String> {
    let mut r = Reader::new(body);
    let list = r.vec_u16().ok()?;
    let mut r = Reader::new(list);
    while !r.is_empty() {
        let name_type = r.u8().ok()?;
        let name = r.vec_u16().ok()?;
        if name_type == 0 {
            return String::from_utf8(name.to_vec()).ok();
        }
    }
    None
}

/// Разобрать тело ALPN или ALPS.
#[must_use]
pub fn parse_alpn(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut r = Reader::new(body);
    let Ok(list) = r.vec_u16() else {
        return out;
    };
    let mut r = Reader::new(list);
    while !r.is_empty() {
        let Ok(name) = r.vec_u8() else { break };
        if let Ok(text) = String::from_utf8(name.to_vec()) {
            out.push(text);
        }
    }
    out
}

/// Разобрать список 16-битных значений с однобайтовым префиксом длины.
#[must_use]
pub fn parse_u8_prefixed_u16_list(body: &[u8]) -> Vec<u16> {
    let mut r = Reader::new(body);
    r.vec_u8()
        .map(|list| {
            list.chunks_exact(2)
                .map(|pair| match pair {
                    [hi, lo] => u16::from_be_bytes([*hi, *lo]),
                    _ => 0,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Разобрать список 16-битных значений с двухбайтовым префиксом длины.
#[must_use]
pub fn parse_u16_prefixed_u16_list(body: &[u8]) -> Vec<u16> {
    let mut r = Reader::new(body);
    r.list_u16().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_round_trips() {
        let ext = server_name("www.microsoft.com");
        assert_eq!(
            parse_server_name(&ext.body).as_deref(),
            Some("www.microsoft.com")
        );
    }

    #[test]
    fn alpn_round_trips() {
        let ext = alpn(&["h2", "http/1.1"]);
        assert_eq!(parse_alpn(&ext.body), vec!["h2", "http/1.1"]);
    }

    #[test]
    fn supported_versions_round_trips() {
        let ext = supported_versions(&[0x0304, 0x0303]);
        assert_eq!(parse_u8_prefixed_u16_list(&ext.body), vec![0x0304, 0x0303]);
    }

    #[test]
    fn signature_algorithms_round_trip() {
        let ext = signature_algorithms(&[0x0403, 0x0804]);
        assert_eq!(parse_u16_prefixed_u16_list(&ext.body), vec![0x0403, 0x0804]);
    }

    #[test]
    fn status_request_matches_browser_encoding() {
        assert_eq!(status_request().body, vec![0x01, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn parsers_tolerate_garbage() {
        for body in [vec![], vec![0xff], vec![0x00, 0xff, 0x01], vec![0x00; 5]] {
            let _ = parse_server_name(&body);
            let _ = parse_alpn(&body);
            let _ = parse_u8_prefixed_u16_list(&body);
            let _ = parse_u16_prefixed_u16_list(&body);
        }
    }
}
