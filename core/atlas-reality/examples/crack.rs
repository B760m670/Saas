//! Поиск точной схемы аутентификации по захвату эталонного клиента.
//!
//! Инструмент исследования, а не часть продукта: перебирает разумные
//! варианты источника открытого ключа, состава AAD и соли HKDF и
//! показывает, какой из них открывает метку настоящего клиента.
//!
//! Прямая индексация здесь допустима: вход — заведомо корректный захват
//! из файла, а не сетевые данные. В боевом коде так делать нельзя, и
//! рабочие крейты этого не делают.

#![allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;

const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LEN: usize = 32;
const RANDOM_OFFSET: usize = 6;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, priv_b64, hex_path] = args.as_slice() else {
        eprintln!("нужно: <приватный ключ base64url> <файл с hex>");
        std::process::exit(2);
    };

    let secret: [u8; 32] = base64_url(priv_b64).try_into().expect("32 байта");
    let text = std::fs::read_to_string(hex_path).expect("файл");
    let hello: Vec<u8> = from_hex(text.trim());

    let random: [u8; 32] = hello
        .get(RANDOM_OFFSET..RANDOM_OFFSET + 32)
        .and_then(|s| s.try_into().ok())
        .expect("random");

    // Все кандидаты в открытые ключи клиента из key_share.
    let candidates = key_share_candidates(&hello);
    println!("кандидатов в ключи: {}", candidates.len());

    let secret = x25519_dalek::StaticSecret::from(secret);

    for (name, client_pub) in &candidates {
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*client_pub));

        for (salt_name, salt) in [
            ("random[0..20]", &random[..20]),
            ("random[0..32]", &random[..]),
        ] {
            let hkdf = Hkdf::<Sha256>::new(Some(salt), shared.as_bytes());
            let mut key = [0_u8; 32];
            if hkdf.expand(b"REALITY", &mut key).is_err() {
                continue;
            }

            for (aad_name, aad) in [
                ("session_id обнулён", zeroed(&hello)),
                ("сообщение как есть", hello.clone()),
            ] {
                let nonce: [u8; 12] = random[20..].try_into().unwrap_or([0; 12]);
                let ciphertext = hello
                    .get(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
                    .unwrap_or_default();

                if let Ok(plain) = Aes256Gcm::new((&key).into()).decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                ) {
                    println!("\n>>> ПОДОШЛО");
                    println!("    ключ клиента: {name}");
                    println!("    соль:         {salt_name}");
                    println!("    AAD:          {aad_name}");
                    println!("    открытый текст: {}", hex(&plain));
                    let ts = u32::from_be_bytes(plain[4..8].try_into().unwrap_or([0; 4]));
                    println!(
                        "    версия {:?}, время {ts}, shortId {}",
                        &plain[..3],
                        hex(&plain[8..16])
                    );
                    return;
                }
            }
        }
    }
    println!("\nни один вариант не подошёл");
}

/// Все 32-байтовые куски из `key_share`, которые могут быть ключом X25519.
fn key_share_candidates(hello: &[u8]) -> Vec<(String, [u8; 32])> {
    let mut out = Vec::new();
    let mut i = 4 + 2 + 32;
    i += 1 + usize::from(hello[i]);
    i += 2 + usize::from(u16::from_be_bytes([hello[i], hello[i + 1]]));
    i += 1 + usize::from(hello[i]);
    let total = usize::from(u16::from_be_bytes([hello[i], hello[i + 1]]));
    i += 2;
    let end = i + total;

    while i < end {
        let ext = u16::from_be_bytes([hello[i], hello[i + 1]]);
        let len = usize::from(u16::from_be_bytes([hello[i + 2], hello[i + 3]]));
        i += 4;
        if ext == 0x0033 {
            let body = &hello[i..i + len];
            let mut j = 2;
            while j + 4 <= body.len() {
                let group = u16::from_be_bytes([body[j], body[j + 1]]);
                let kl = usize::from(u16::from_be_bytes([body[j + 2], body[j + 3]]));
                j += 4;
                let key = &body[j..(j + kl).min(body.len())];
                if kl == 32 {
                    if let Ok(k) = <[u8; 32]>::try_from(key) {
                        out.push((format!("группа {group:#06x} целиком"), k));
                    }
                } else if kl > 32 {
                    if let Ok(k) = <[u8; 32]>::try_from(&key[key.len() - 32..]) {
                        out.push((format!("группа {group:#06x}, последние 32"), k));
                    }
                    if let Ok(k) = <[u8; 32]>::try_from(&key[..32]) {
                        out.push((format!("группа {group:#06x}, первые 32"), k));
                    }
                }
                j += kl;
            }
        }
        i += len;
    }
    out
}

fn zeroed(hello: &[u8]) -> Vec<u8> {
    let mut out = hello.to_vec();
    out[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
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
            out.push((bits >> count) as u8);
        }
    }
    out
}
