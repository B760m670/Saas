//! Вычисление отпечатков JA3 и JA4 по `ClientHello`.
//!
//! Это измерительный инструмент, а не транспорт: он нужен, чтобы в CI
//! сравнивать отпечаток нашего `ClientHello` с эталоном настоящего
//! браузера. Расхождение хотя бы в одном символе означает, что
//! пользователь помечен уже на первом пакете, — и это должно ронять сборку.
//!
//! # Чем JA4 лучше JA3
//!
//! JA3 хэширует списки **в порядке отправки**. Chrome с версии 110
//! перемешивает расширения при каждом соединении, поэтому JA3 у него
//! нестабилен — как ориентир он бесполезен. JA4 списки сортирует, поэтому
//! от перестановки не зависит. Отсюда следствие для нас: **наш
//! `ClientHello` тоже обязан перемешивать расширения**, иначе постоянный
//! JA3 при браузерном JA4 сам становится отличительным признаком.

use md5::Digest as _;

use crate::ext;
use crate::grease;
use crate::hello::ClientHello;

/// Транспорт, поверх которого идёт TLS. Влияет на первый символ JA4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TLS поверх TCP.
    Tcp,
    /// QUIC.
    Quic,
    /// DTLS.
    Dtls,
}

impl Transport {
    const fn as_char(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
            Self::Dtls => 'd',
        }
    }
}

/// Значение, которым JA4 заменяет пустой список.
const EMPTY_HASH: &str = "000000000000";
/// Длина усечения хэшей в JA4.
const HASH_LEN: usize = 12;

/// Полный отпечаток JA3: строка исходных полей и её MD5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3 {
    /// Исходная строка до хэширования.
    pub raw: String,
    /// MD5 в шестнадцатеричном виде.
    pub hash: String,
}

/// Вычислить JA3.
///
/// Формат: `версия,шифры,расширения,группы,форматы_точек`, значения
/// десятичные через дефис, GREASE отброшен.
#[must_use]
pub fn ja3(hello: &ClientHello) -> Ja3 {
    let ciphers = join_decimal(
        hello
            .cipher_suites
            .iter()
            .copied()
            .filter(|v| not_grease(*v)),
    );
    let extensions = join_decimal(
        hello
            .extensions
            .iter()
            .map(|e| e.ext_type)
            .filter(|v| not_grease(*v)),
    );
    let groups = join_decimal(
        hello
            .supported_groups()
            .into_iter()
            .filter(|v| not_grease(*v)),
    );
    let formats = hello
        .ec_point_formats()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join("-");

    let raw = format!(
        "{},{ciphers},{extensions},{groups},{formats}",
        hello.legacy_version
    );
    let hash = hex(&md5::Md5::digest(raw.as_bytes()));
    Ja3 { raw, hash }
}

/// Отпечаток JA4, разложенный на три части.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4 {
    /// Читаемая часть: транспорт, версия, наличие SNI, счётчики, ALPN.
    pub a: String,
    /// Усечённый SHA-256 отсортированных шифронаборов.
    pub b: String,
    /// Усечённый SHA-256 отсортированных расширений и алгоритмов подписи.
    pub c: String,
}

impl Ja4 {
    /// Отпечаток целиком, в каноническом виде `a_b_c`.
    #[must_use]
    pub fn to_string_full(&self) -> String {
        format!("{}_{}_{}", self.a, self.b, self.c)
    }
}

impl core::fmt::Display for Ja4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}_{}_{}", self.a, self.b, self.c)
    }
}

/// Вычислить JA4 по спецификации `FoxIO`.
#[must_use]
pub fn ja4(hello: &ClientHello, transport: Transport) -> Ja4 {
    let ciphers: Vec<u16> = hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| not_grease(*v))
        .collect();
    let ext_types: Vec<u16> = hello
        .extensions
        .iter()
        .map(|e| e.ext_type)
        .filter(|v| not_grease(*v))
        .collect();

    let a = format!(
        "{}{}{}{}{}{}",
        transport.as_char(),
        version_code(hello),
        if hello.extension(ext::SERVER_NAME).is_some() {
            'd'
        } else {
            'i'
        },
        two_digits(ciphers.len()),
        two_digits(ext_types.len()),
        alpn_code(hello),
    );

    let b = if ciphers.is_empty() {
        EMPTY_HASH.to_owned()
    } else {
        let mut sorted = ciphers;
        sorted.sort_unstable();
        truncated_sha256(&join_hex(sorted.into_iter()))
    };

    // Из хэша расширений исключаются SNI и ALPN: их наличие уже отражено
    // в читаемой части, а значения слишком изменчивы.
    let mut hashed: Vec<u16> = ext_types
        .into_iter()
        .filter(|t| *t != ext::SERVER_NAME && *t != ext::ALPN)
        .collect();

    let c = if hashed.is_empty() {
        EMPTY_HASH.to_owned()
    } else {
        hashed.sort_unstable();
        let sig_algs = hello.signature_algorithms();
        let mut payload = join_hex(hashed.into_iter());
        // Алгоритмы подписи добавляются в исходном порядке, без сортировки.
        if !sig_algs.is_empty() {
            payload.push('_');
            payload.push_str(&join_hex(sig_algs.into_iter()));
        }
        truncated_sha256(&payload)
    };

    Ja4 { a, b, c }
}

/// Двухсимвольный код версии TLS.
///
/// Берётся максимум из `supported_versions`, а при отсутствии расширения —
/// поле `legacy_version`.
fn version_code(hello: &ClientHello) -> &'static str {
    let version = hello
        .supported_versions()
        .into_iter()
        .filter(|v| !grease::is_grease(*v))
        .max()
        .unwrap_or(hello.legacy_version);

    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// Два символа ALPN: первый и последний буквенно-цифровые символы первого
/// имени протокола.
fn alpn_code(hello: &ClientHello) -> String {
    let Some(first) = hello.alpn().into_iter().next() else {
        return "00".to_owned();
    };
    let bytes = first.as_bytes();
    let (Some(head), Some(tail)) = (bytes.first(), bytes.last()) else {
        return "00".to_owned();
    };

    // Небуквенно-цифровые значения представляются шестнадцатерично.
    if head.is_ascii_alphanumeric() && tail.is_ascii_alphanumeric() {
        format!("{}{}", *head as char, *tail as char)
    } else {
        format!("{:x}{:x}", head >> 4, tail & 0x0f)
    }
}

fn not_grease(value: u16) -> bool {
    !grease::is_grease(value)
}

fn two_digits(count: usize) -> String {
    format!("{:02}", count.min(99))
}

fn join_decimal(values: impl Iterator<Item = u16>) -> String {
    values.map(|v| v.to_string()).collect::<Vec<_>>().join("-")
}

fn join_hex(values: impl Iterator<Item = u16>) -> String {
    values
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn truncated_sha256(input: &str) -> String {
    let digest = sha2::Sha256::digest(input.as_bytes());
    let full = hex(&digest);
    full.get(..HASH_LEN).unwrap_or(&full).to_owned()
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hello::{Extension, LEGACY_VERSION};

    fn minimal(extensions: Vec<Extension>, ciphers: Vec<u16>) -> ClientHello {
        ClientHello {
            legacy_version: LEGACY_VERSION,
            random: [0_u8; 32],
            session_id: vec![0_u8; 32],
            cipher_suites: ciphers,
            compression_methods: vec![0],
            extensions,
        }
    }

    #[test]
    fn empty_lists_use_placeholder_hash() {
        let hello = minimal(Vec::new(), Vec::new());
        let fp = ja4(&hello, Transport::Tcp);
        assert_eq!(fp.b, EMPTY_HASH);
        assert_eq!(fp.c, EMPTY_HASH);
        // Нет SNI и нет ALPN.
        assert_eq!(fp.a, "t12i0000 00".replace(' ', ""));
    }

    #[test]
    fn grease_is_excluded_from_counts_and_hashes() {
        let plain = minimal(
            vec![ext::supported_versions(&[0x0304])],
            vec![0x1301, 0x1302],
        );
        let greased = minimal(
            vec![
                Extension::empty(grease::VALUES[0]),
                ext::supported_versions(&[0x0304]),
                Extension::empty(grease::VALUES[5]),
            ],
            vec![grease::VALUES[2], 0x1301, 0x1302],
        );
        assert_eq!(ja4(&plain, Transport::Tcp), ja4(&greased, Transport::Tcp));
    }

    #[test]
    fn extension_order_does_not_change_ja4() {
        let forward = minimal(
            vec![
                ext::server_name("example.org"),
                ext::supported_versions(&[0x0304]),
                ext::signature_algorithms(&[0x0403, 0x0804]),
                ext::alpn(&["h2"]),
            ],
            vec![0x1301],
        );
        let reversed = minimal(
            forward.extensions.iter().rev().cloned().collect(),
            vec![0x1301],
        );
        assert_eq!(
            ja4(&forward, Transport::Tcp),
            ja4(&reversed, Transport::Tcp),
            "JA4 обязан быть устойчив к перестановке расширений"
        );
    }

    #[test]
    fn extension_order_does_change_ja3() {
        let forward = minimal(
            vec![
                ext::server_name("example.org"),
                ext::supported_versions(&[0x0304]),
            ],
            vec![0x1301],
        );
        let reversed = minimal(
            forward.extensions.iter().rev().cloned().collect(),
            vec![0x1301],
        );
        assert_ne!(
            ja3(&forward).hash,
            ja3(&reversed).hash,
            "именно поэтому JA3 бесполезен как ориентир для Chrome"
        );
    }

    #[test]
    fn sni_presence_flips_the_marker() {
        let with = minimal(vec![ext::server_name("a.example")], vec![0x1301]);
        let without = minimal(Vec::new(), vec![0x1301]);
        assert!(ja4(&with, Transport::Tcp).a.starts_with("t12d"));
        assert!(ja4(&without, Transport::Tcp).a.starts_with("t12i"));
    }

    #[test]
    fn version_comes_from_supported_versions() {
        let hello = minimal(
            vec![ext::supported_versions(&[
                grease::VALUES[0],
                0x0304,
                0x0303,
            ])],
            vec![0x1301],
        );
        assert!(ja4(&hello, Transport::Tcp).a.starts_with("t13"));
    }

    #[test]
    fn transport_selects_the_leading_character() {
        let hello = minimal(Vec::new(), vec![0x1301]);
        assert!(ja4(&hello, Transport::Quic).a.starts_with('q'));
        assert!(ja4(&hello, Transport::Dtls).a.starts_with('d'));
    }

    #[test]
    fn alpn_uses_first_and_last_characters() {
        let h2 = minimal(vec![ext::alpn(&["h2", "http/1.1"])], vec![0x1301]);
        assert!(ja4(&h2, Transport::Tcp).a.ends_with("h2"));

        let http11 = minimal(vec![ext::alpn(&["http/1.1"])], vec![0x1301]);
        assert!(ja4(&http11, Transport::Tcp).a.ends_with("h1"));
    }

    #[test]
    fn counts_are_capped_at_ninety_nine() {
        let ciphers: Vec<u16> = (0..150).map(|i| 0x1000 + i).collect();
        let hello = minimal(Vec::new(), ciphers);
        assert!(ja4(&hello, Transport::Tcp).a.contains("99"));
    }
}
