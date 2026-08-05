//! Совместимость с настоящим сервером REALITY.
//!
//! До этого теста в документации крейта стояла честная оговорка:
//! реализация внутренне согласована, но совместимость с Xray не доказана.
//! Здесь она доказывается.
//!
//! В `testdata` лежит `ClientHello`, порождённый **настоящим клиентом
//! Xray 26.3.27**, и одноразовый приватный ключ сервера, которому этот
//! клиент писал. Тест открывает чужую метку нашим кодом. Если открывается
//! и разбирается в осмысленные поля — значит вывод ключа, выбор соли,
//! состав аутентифицируемых данных и раскладка метки у нас совпадают
//! с эталоном.
//!
//! Чего тест по-прежнему не доказывает: полное рукопожатие TLS у нас
//! пока не реализовано, поэтому сквозное соединение с сервером Xray
//! не проверено.

// Вход теста — фиксированный файл из testdata, а не сетевые данные.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use atlas_reality::auth;
use atlas_reality::marker::SHORT_ID_LEN;

const CAPTURE: &str = include_str!("../testdata/xray-26.3.27-client.json");

fn field(name: &str) -> String {
    let doc: serde_json::Value = serde_json::from_str(CAPTURE).unwrap();
    doc[name].as_str().unwrap().to_owned()
}

fn hello() -> Vec<u8> {
    field("client_hello_hex")
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn base64_url(input: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let (mut bits, mut count, mut out) = (0_u32, 0_u32, Vec::new());
    for byte in input.bytes().filter(|b| *b != b'=') {
        let Some(idx) = A.iter().position(|c| *c == byte) else {
            continue;
        };
        bits = (bits << 6) | idx as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from(bits >> count & 0xff).unwrap());
        }
    }
    out
}

/// Достать открытый ключ клиента из `key_share`, группа X25519.
fn client_public_key(hello: &[u8]) -> [u8; 32] {
    let mut i = 4 + 2 + 32;
    i += 1 + usize::from(*hello.get(i).unwrap());
    i += 2 + usize::from(u16::from_be_bytes([
        *hello.get(i).unwrap(),
        *hello.get(i + 1).unwrap(),
    ]));
    i += 1 + usize::from(*hello.get(i).unwrap());
    let total = usize::from(u16::from_be_bytes([
        *hello.get(i).unwrap(),
        *hello.get(i + 1).unwrap(),
    ]));
    i += 2;
    let end = i + total;

    while i < end {
        let ext = u16::from_be_bytes([*hello.get(i).unwrap(), *hello.get(i + 1).unwrap()]);
        let len = usize::from(u16::from_be_bytes([
            *hello.get(i + 2).unwrap(),
            *hello.get(i + 3).unwrap(),
        ]));
        i += 4;
        if ext == 0x0033 {
            let body = hello.get(i..i + len).unwrap();
            let mut j = 2;
            while j + 4 <= body.len() {
                let group = u16::from_be_bytes([*body.get(j).unwrap(), *body.get(j + 1).unwrap()]);
                let kl = usize::from(u16::from_be_bytes([
                    *body.get(j + 2).unwrap(),
                    *body.get(j + 3).unwrap(),
                ]));
                j += 4;
                if group == 0x001d && kl == 32 {
                    return body.get(j..j + 32).unwrap().try_into().unwrap();
                }
                j += kl;
            }
        }
        i += len;
    }
    panic!("в key_share нет доли X25519");
}

#[test]
fn we_can_open_a_marker_made_by_real_xray() {
    let hello = hello();
    let secret: [u8; 32] = base64_url(&field("server_private_key")).try_into().unwrap();
    let client_public = client_public_key(&hello);

    // Тот же вывод ключа, что и в нашем клиенте.
    let shared = x25519_dalek::StaticSecret::from(secret)
        .diffie_hellman(&x25519_dalek::PublicKey::from(client_public));
    let random = auth::random_of_public(&hello).unwrap();
    let key = auth::derive_auth_key(shared.as_bytes(), &random);

    let marker = auth::open(&hello, &key).expect("метка настоящего Xray должна открываться");

    // Поля разбираются в осмысленные значения, а не в шум.
    let doc: serde_json::Value = serde_json::from_str(CAPTURE).unwrap();
    let expected_version: Vec<u8> = doc["ожидаемая_версия"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
        .collect();
    assert_eq!(marker.version.to_vec(), expected_version);

    // shortId `dead` дополнен нулями до восьми байт — как у нас.
    let mut expected_short_id = [0_u8; SHORT_ID_LEN];
    expected_short_id[0] = 0xde;
    expected_short_id[1] = 0xad;
    assert_eq!(marker.short_id, expected_short_id);

    // Время правдоподобное: захват сделан в 2026 году.
    assert!(
        (1_700_000_000..2_000_000_000).contains(&marker.timestamp),
        "время метки: {}",
        marker.timestamp
    );
}

#[test]
fn a_wrong_server_key_does_not_open_it() {
    let hello = hello();
    let client_public = client_public_key(&hello);

    let other = x25519_dalek::StaticSecret::from([0x11_u8; 32]);
    let shared = other.diffie_hellman(&x25519_dalek::PublicKey::from(client_public));
    let random = auth::random_of_public(&hello).unwrap();
    let key = auth::derive_auth_key(shared.as_bytes(), &random);

    assert!(auth::open(&hello, &key).is_err());
}
