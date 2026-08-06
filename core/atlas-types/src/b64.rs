//! Терпимое декодирование base64.
//!
//! Ключи в дикой природе закодированы чем угодно: стандартным алфавитом и
//! URL-safe, с паддингом и без, иногда с переносами строк внутри. Отказ
//! декодировать по формальному признаку означает, что пользователь не сможет
//! импортировать рабочий ключ — поэтому пробуем все варианты.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;

use crate::error::{Error, Result};

/// Декодировать base64, перебирая известные алфавиты и режимы паддинга.
///
/// # Errors
///
/// [`Error::Base64`], если ни один вариант не подошёл.
pub fn decode(input: &str, field: &'static str) -> Result<Vec<u8>> {
    // Переносы строк встречаются в подписках, отдающих один длинный blob.
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Err(Error::Base64(field));
    }

    STANDARD
        .decode(&cleaned)
        .or_else(|_| URL_SAFE.decode(&cleaned))
        .or_else(|_| STANDARD_NO_PAD.decode(&cleaned))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&cleaned))
        .map_err(|_| Error::Base64(field))
}

/// Декодировать base64 в строку.
///
/// # Errors
///
/// [`Error::Base64`] при неверной кодировке, [`Error::Utf8`] если результат
/// не является корректным UTF-8.
pub fn decode_str(input: &str, field: &'static str) -> Result<String> {
    let bytes = decode(input, field)?;
    String::from_utf8(bytes).map_err(|_| Error::Utf8(field))
}

/// Закодировать в стандартный base64 с паддингом.
#[must_use]
pub fn encode(input: impl AsRef<[u8]>) -> String {
    STANDARD.encode(input)
}

/// Закодировать в URL-safe base64 без паддинга.
///
/// Используется там, где значение попадает в query-параметр.
#[must_use]
pub fn encode_url_nopad(input: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_common_variant() {
        // "aes-128-gcm:пароль?" — содержит и не-ASCII, и символ, который
        // по-разному кодируется стандартным и URL-safe алфавитом.
        let original = "aes-128-gcm:пароль?";
        for encoded in [
            STANDARD.encode(original),
            URL_SAFE.encode(original),
            STANDARD_NO_PAD.encode(original),
            URL_SAFE_NO_PAD.encode(original),
        ] {
            assert_eq!(decode_str(&encoded, "test").unwrap(), original);
        }
    }

    #[test]
    fn ignores_embedded_whitespace() {
        let encoded = STANDARD.encode("hello world");
        let split = format!("{}\n{}", &encoded[..4], &encoded[4..]);
        assert_eq!(decode_str(&split, "test").unwrap(), "hello world");
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert!(decode("", "test").is_err());
        assert!(decode("!!!!", "test").is_err());
    }
}
