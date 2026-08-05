//! Хэширование и выведение ключей на BLAKE3.
//!
//! BLAKE3 выбран как единственная хэш-функция проекта: он даёт хэш, KDF и MAC
//! в одном примитиве, что убирает целый класс ошибок, возникающих при
//! самостоятельной сборке HKDF из хэша и HMAC.

/// Длина всех выходов в байтах.
pub const LEN: usize = 32;

/// Хэш произвольных данных.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; LEN] {
    *blake3::hash(data).as_bytes()
}

/// Хэш последовательности фрагментов без их предварительной склейки.
///
/// Фрагменты разделяются их длинами, поэтому `["ab", "c"]` и `["a", "bc"]`
/// дают разные результаты. Без такого разделения появляется возможность
/// подобрать другой набор фрагментов с тем же хэшем.
#[must_use]
pub fn hash_parts(parts: &[&[u8]]) -> [u8; LEN] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Вывести ключ из входного материала в заданном контексте.
///
/// `context` обязан быть уникальной для места применения константой,
/// зашитой в код — например `"atlas hybrid kem v1"`. Разные контексты дают
/// независимые ключи из одного и того же материала, что не даёт
/// переиспользовать ключ одного назначения в другом.
#[must_use]
pub fn derive_key(context: &'static str, material: &[&[u8]]) -> [u8; LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in material {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let mut out = [0_u8; LEN];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Шестнадцатеричное представление в нижнем регистре.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Запись в String инфаллибельна, ошибку возвращать неоткуда.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_sensitive() {
        assert_eq!(hash(b"atlas"), hash(b"atlas"));
        assert_ne!(hash(b"atlas"), hash(b"atlaS"));
    }

    #[test]
    fn parts_are_length_separated() {
        // Без разделения по длинам эти два вызова совпали бы.
        assert_ne!(hash_parts(&[b"ab", b"c"]), hash_parts(&[b"a", b"bc"]));
    }

    #[test]
    fn contexts_are_independent() {
        assert_ne!(
            derive_key("atlas test a", &[b"same"]),
            derive_key("atlas test b", &[b"same"])
        );
    }

    #[test]
    fn hex_pads_single_digits() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
