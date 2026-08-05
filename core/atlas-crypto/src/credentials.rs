//! Генерация учётных данных для собственных точек выхода.
//!
//! Это модуль, из-за которого проекту не нужны покупные ключи. Когда ATLAS
//! разворачивает точку на бесплатном аккаунте пользователя, весь секретный
//! материал создаётся здесь, на устройстве: пара X25519 для REALITY,
//! идентификатор пользователя, `shortId`, пароли для протоколов с общим
//! секретом.
//!
//! Секреты не покидают устройство. Наружу уходит только конфигурация точки,
//! в которой из секретного — ничего, кроме того, что и так должно быть на
//! сервере.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::hash;
use crate::rng::OsRng;

/// Максимальная длина `shortId` в байтах — ограничение REALITY.
pub const SHORT_ID_MAX_BYTES: usize = 8;

/// Пара ключей X25519 для REALITY.
///
/// Приватная часть остаётся на сервере точки, публичная попадает в
/// конфигурацию клиента (параметр `pbk`).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RealityKeypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl core::fmt::Debug for RealityKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Публичную часть печатать безопасно, приватную — нет.
        write!(f, "RealityKeypair {{ public: {} }}", self.public_base64())
    }
}

impl RealityKeypair {
    /// Сгенерировать новую пару.
    #[must_use]
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    /// Приватный ключ в том виде, в каком его ждёт конфигурация сервера.
    #[must_use]
    pub fn secret_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.secret)
    }

    /// Публичный ключ — значение параметра `pbk` в конфигурации клиента.
    #[must_use]
    pub fn public_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public)
    }

    /// Публичный ключ в виде байт.
    #[must_use]
    pub const fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
}

/// Сгенерировать идентификатор пользователя в формате UUID версии 4.
///
/// Полностью случайный: 122 бита энтропии. Именно он подставляется как
/// логин VLESS и как пользователь TUIC.
#[must_use]
pub fn generate_uuid() -> String {
    let mut bytes = OsRng::bytes::<16>();

    // Версия 4 в старших битах седьмого байта, вариант RFC 4122 — в восьмом.
    if let Some(byte) = bytes.get_mut(6) {
        *byte = (*byte & 0x0f) | 0x40;
    }
    if let Some(byte) = bytes.get_mut(8) {
        *byte = (*byte & 0x3f) | 0x80;
    }

    let hex = hash::to_hex(&bytes);
    let mut out = String::with_capacity(36);
    let mut rest = hex.as_str();
    for (index, width) in [8_usize, 4, 4, 4, 12].into_iter().enumerate() {
        if index > 0 {
            out.push('-');
        }
        let (group, tail) = rest.split_at(width.min(rest.len()));
        out.push_str(group);
        rest = tail;
    }
    out
}

/// Сгенерировать `shortId` для REALITY — hex заданной длины в байтах.
///
/// # Errors
///
/// [`Error::OutOfRange`], если длина нулевая или больше
/// [`SHORT_ID_MAX_BYTES`].
pub fn generate_short_id(len_bytes: usize) -> Result<String> {
    if len_bytes == 0 || len_bytes > SHORT_ID_MAX_BYTES {
        return Err(Error::OutOfRange("длина shortId"));
    }
    let mut bytes = [0_u8; SHORT_ID_MAX_BYTES];
    OsRng::fill(&mut bytes);
    Ok(hash::to_hex(bytes.get(..len_bytes).unwrap_or(&bytes)))
}

/// Сгенерировать пароль для протоколов с общим секретом.
///
/// Возвращается base64url без паддинга, чтобы значение можно было положить
/// в URI без экранирования.
///
/// # Errors
///
/// [`Error::OutOfRange`], если запрошено меньше 16 байт: ниже этого порога
/// пароль перестаёт быть стойким к перебору.
pub fn generate_password(len_bytes: usize) -> Result<String> {
    const MIN_BYTES: usize = 16;
    if len_bytes < MIN_BYTES {
        return Err(Error::OutOfRange("длина пароля"));
    }
    let mut bytes = vec![0_u8; len_bytes];
    OsRng::fill(&mut bytes);
    let encoded = URL_SAFE_NO_PAD.encode(&bytes);
    bytes.zeroize();
    Ok(encoded)
}

/// Полный комплект учётных данных одной точки выхода.
#[derive(Debug)]
pub struct RelayCredentials {
    /// Идентификатор пользователя для VLESS и TUIC.
    pub uuid: String,
    /// Пара ключей REALITY.
    pub reality: RealityKeypair,
    /// Набор допустимых `shortId`.
    ///
    /// Их несколько, чтобы одну и ту же точку можно было выдать нескольким
    /// людям с разными идентификаторами и отозвать доступ одного, не трогая
    /// остальных.
    pub short_ids: Vec<String>,
    /// Пароль для протоколов с общим секретом (Trojan, Hysteria2, `AnyTLS`).
    pub password: String,
}

impl RelayCredentials {
    /// Сгенерировать комплект с `short_id_count` идентификаторами.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`], если запрошено нулевое количество `shortId`.
    pub fn generate(short_id_count: usize) -> Result<Self> {
        if short_id_count == 0 {
            return Err(Error::OutOfRange("количество shortId"));
        }

        let short_ids = (0..short_id_count)
            // Длина 4 байта: 2^32 вариантов, перебрать через сеть невозможно,
            // при этом значение остаётся коротким.
            .map(|_| generate_short_id(4))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            uuid: generate_uuid(),
            reality: RealityKeypair::generate(),
            short_ids,
            password: generate_password(32)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn uuid_has_canonical_shape() {
        let uuid = generate_uuid();
        let groups: Vec<usize> = uuid.split('-').map(str::len).collect();
        assert_eq!(groups, vec![8, 4, 4, 4, 12]);
        assert!(uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    #[test]
    fn uuid_declares_version_four_and_rfc_variant() {
        let uuid = generate_uuid();
        let mut parts = uuid.split('-');
        let third = parts.nth(2).unwrap();
        let fourth = parts.next().unwrap();
        assert!(third.starts_with('4'), "версия: {uuid}");
        assert!(
            matches!(fourth.chars().next(), Some('8' | '9' | 'a' | 'b')),
            "вариант: {uuid}"
        );
    }

    #[test]
    fn uuids_do_not_repeat() {
        let generated: std::collections::HashSet<String> =
            (0..256).map(|_| generate_uuid()).collect();
        assert_eq!(generated.len(), 256);
    }

    #[test]
    fn reality_public_key_matches_secret() {
        let pair = RealityKeypair::generate();
        let secret = x25519_dalek::StaticSecret::from(pair.secret);
        let derived = x25519_dalek::PublicKey::from(&secret);
        assert_eq!(&derived.to_bytes(), pair.public_bytes());
    }

    #[test]
    fn reality_encoding_is_url_safe_and_unpadded() {
        let pair = RealityKeypair::generate();
        for encoded in [pair.public_base64(), pair.secret_base64()] {
            assert!(!encoded.contains('='), "паддинг: {encoded}");
            assert!(
                !encoded.contains('+') && !encoded.contains('/'),
                "{encoded}"
            );
            assert_eq!(URL_SAFE_NO_PAD.decode(&encoded).unwrap().len(), 32);
        }
    }

    #[test]
    fn reality_debug_hides_secret() {
        let pair = RealityKeypair::generate();
        let rendered = format!("{pair:?}");
        assert!(rendered.contains(&pair.public_base64()));
        assert!(!rendered.contains(&pair.secret_base64()));
    }

    #[test]
    fn short_id_respects_bounds() {
        assert_eq!(generate_short_id(4).unwrap().len(), 8);
        assert_eq!(generate_short_id(8).unwrap().len(), 16);
        assert!(generate_short_id(0).is_err());
        assert!(generate_short_id(9).is_err());
    }

    #[test]
    fn short_id_is_valid_hex_of_even_length() {
        let id = generate_short_id(4).unwrap();
        assert_eq!(id.len() % 2, 0);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn password_rejects_weak_lengths() {
        assert!(generate_password(15).is_err());
        assert!(generate_password(16).is_ok());
    }

    #[test]
    fn full_set_is_internally_consistent() {
        let creds = RelayCredentials::generate(3).unwrap();
        assert_eq!(creds.short_ids.len(), 3);
        // Совпадение двух shortId означало бы неисправный генератор.
        let unique: std::collections::HashSet<_> = creds.short_ids.iter().collect();
        assert_eq!(unique.len(), 3);
        assert_eq!(creds.uuid.len(), 36);
        assert!(RelayCredentials::generate(0).is_err());
    }
}
