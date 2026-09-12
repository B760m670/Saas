//! Проверка подписи входящего уведомления.
//!
//! Это самое опасное место во всём приёме оплаты. Уведомление приходит
//! обычным HTTP-запросом на открытый адрес — прислать его может кто угодно.
//! Единственное, что отличает сообщение сервиса от подделки, — подпись,
//! посчитанная на общем секрете. Ошибка здесь не заметна ни в логах, ни в
//! тестах на «счастливом пути»: подписки просто начнут выдаваться бесплатно
//! всем, кто угадал формат.
//!
//! Отсюда два правила, которым подчинён весь модуль.
//!
//! Сравнение идёт за постоянное время. Побайтовое сравнение с ранним
//! выходом выдаёт длину совпавшего префикса задержкой ответа, а этого
//! достаточно, чтобы подобрать подпись по одному знаку за раз.
//!
//! Любая невозможность посчитать подпись означает отказ. Функции не
//! возвращают ошибку, которую вызывающий может забыть проверить, —
//! непосчитанная подпись просто не совпадает ни с чем.

use core::fmt::{self, Write as _};

use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Способ, которым сервис подписывает уведомление.
///
/// Схемы делятся на две породы. `HmacSha256` считается по телу запроса на
/// отдельном ключе — ключ хранится здесь. `Sha256` и `Md5` — это дайджест
/// строки, которую сервис собирает из полей уведомления в заранее оговорённом
/// порядке, и секрет входит в саму строку; собирает её адаптер конкретного
/// сервиса, потому что порядок полей у всех разный.
pub enum Scheme {
    /// HMAC-SHA256 по телу запроса.
    HmacSha256(Vec<u8>),
    /// SHA-256 от строки, собранной адаптером.
    Sha256,
    /// MD5 от строки, собранной адаптером.
    ///
    /// Криптографически MD5 давно сломан, но выбор здесь не наш: несколько
    /// сервисов до сих пор подписывают только так. Для подделки уведомления
    /// нужен прообраз, а не коллизия, и на это MD5 пока держится — но если
    /// у сервиса есть выбор схемы, брать надо не эту.
    Md5,
}

impl fmt::Debug for Scheme {
    /// Секрет не печатается: `Debug` рано или поздно попадает в лог.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HmacSha256(_) => f.write_str("Scheme::HmacSha256(<секрет>)"),
            Self::Sha256 => f.write_str("Scheme::Sha256"),
            Self::Md5 => f.write_str("Scheme::Md5"),
        }
    }
}

impl Scheme {
    /// Посчитать подпись сообщения. Шестнадцатеричная запись, нижний регистр.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> String {
        match self {
            Self::HmacSha256(secret) => {
                let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
                    // Недостижимо: HMAC принимает ключ любой длины. Если
                    // это когда-нибудь изменится, пустая подпись не совпадёт
                    // ни с чем — отказ, а не пропуск.
                    return String::new();
                };
                mac.update(message);
                hex(&mac.finalize().into_bytes())
            }
            Self::Sha256 => hex(&Sha256::digest(message)),
            Self::Md5 => hex(&Md5::digest(message)),
        }
    }

    /// Совпадает ли присланная подпись с посчитанной.
    ///
    /// Регистр присланной подписи не важен — сервисы шлют и верхний, и нижний.
    #[must_use]
    pub fn verify(&self, message: &[u8], presented: &str) -> bool {
        let expected = self.sign(message);
        if expected.is_empty() {
            return false;
        }
        let presented = presented.trim().to_ascii_lowercase();
        // Длина не секрет: она определяется схемой, а не ключом.
        if presented.len() != expected.len() {
            return false;
        }
        bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Запись в `String` не может отказать.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::Scheme;

    /// RFC 4231, тестовый случай 1. Проверяется не наша арифметика, а то,
    /// что мы вызываем HMAC так, как его понимает остальной мир.
    #[test]
    fn hmac_matches_the_published_vector() {
        let scheme = Scheme::HmacSha256(vec![0x0b; 20]);
        assert_eq!(
            scheme.sign(b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn digests_match_the_published_vectors() {
        assert_eq!(
            Scheme::Sha256.sign(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(Scheme::Md5.sign(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn upper_case_signatures_are_accepted() {
        let scheme = Scheme::Sha256;
        let signature = scheme.sign(b"abc").to_ascii_uppercase();
        assert!(scheme.verify(b"abc", &signature));
    }

    #[test]
    fn a_changed_message_no_longer_verifies() {
        let scheme = Scheme::HmacSha256(b"secret".to_vec());
        let signature = scheme.sign(br#"{"order":"1","amount":"299.00"}"#);
        assert!(!scheme.verify(br#"{"order":"1","amount":"1.00"}"#, &signature));
    }

    #[test]
    fn a_different_secret_no_longer_verifies() {
        let message = b"order=1&amount=299.00";
        let signature = Scheme::HmacSha256(b"secret".to_vec()).sign(message);
        assert!(!Scheme::HmacSha256(b"another".to_vec()).verify(message, &signature));
    }

    /// Отдельно от «не совпало»: подпись, которую вообще не прислали, не
    /// должна проходить через пустое сравнение.
    #[test]
    fn an_empty_signature_is_rejected() {
        let scheme = Scheme::Sha256;
        assert!(!scheme.verify(b"abc", ""));
        assert!(!scheme.verify(b"abc", "   "));
    }

    #[test]
    fn a_truncated_signature_is_rejected() {
        let scheme = Scheme::Sha256;
        let full = scheme.sign(b"abc");
        let short = full.get(..32).unwrap_or_default();
        assert!(!short.is_empty());
        assert!(!scheme.verify(b"abc", short));
    }
}
