//! Гибридный обмен ключами: X25519 + ML-KEM-768.
//!
//! Комбинатор устроен так, что общий секрет остаётся стойким, если стойка
//! **хотя бы одна** из двух схем. В общий секрет заводится не только пара
//! промежуточных секретов, но и весь транскрипт обмена (обе части
//! шифртекста и оба открытых ключа) — это связывает секрет с конкретным
//! обменом и не даёт переиспользовать чужой шифртекст.
//!
//! Мотив постквантовой части — «harvest now, decrypt later»: записанный
//! сегодня трафик расшифруют позже, когда появится подходящая машина.

use ml_kem::{Decapsulate as _, Encapsulate as _, Generate as _, KeyExport as _, TryKeyInit as _};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::hash;
use crate::rng::OsRng;

/// Контекст выведения общего секрета. Менять нельзя — это ломает совместимость.
const KDF_CONTEXT: &str = "atlas hybrid kem x25519+mlkem768 v1";

/// Длина открытого ключа X25519.
pub const X25519_LEN: usize = 32;
/// Длина открытого ключа ML-KEM-768.
pub const MLKEM_PUBLIC_LEN: usize = 1184;
/// Длина шифртекста ML-KEM-768.
pub const MLKEM_CIPHERTEXT_LEN: usize = 1088;

/// Общий секрет обмена.
///
/// Затирается при уничтожении, чтобы не оставлять материал в памяти
/// дольше необходимого.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret([u8; hash::LEN]);

impl SharedSecret {
    /// Байты секрета.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; hash::LEN] {
        &self.0
    }
}

// Ручная реализация: производный `Debug` печатал бы секрет в логи.
impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<скрыто>)")
    }
}

/// Секретная часть гибридной пары. Хранится только у получателя.
pub struct SecretKey {
    x: x25519_dalek::StaticSecret,
    pq: ml_kem::DecapsulationKey768,
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(<скрыто>)")
    }
}

impl SecretKey {
    /// Сгенерировать новую пару ключей.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            x: x25519_dalek::StaticSecret::random_from_rng(&mut rng),
            pq: ml_kem::DecapsulationKey768::generate_from_rng(&mut rng),
        }
    }

    /// Открытая часть пары.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            x: x25519_dalek::PublicKey::from(&self.x),
            pq: self.pq.encapsulation_key().clone(),
        }
    }

    /// Восстановить общий секрет из шифртекста отправителя.
    ///
    /// # Errors
    ///
    /// [`Error::BadEncoding`], если шифртекст имеет неверную длину.
    pub fn decapsulate(&self, ct: &Ciphertext) -> Result<SharedSecret> {
        let their_x = x25519_dalek::PublicKey::from(ct.x);
        let x_shared = self.x.diffie_hellman(&their_x);
        let pq_shared = self.pq.decapsulate(&ct.pq);

        Ok(combine(
            x_shared.as_bytes(),
            pq_shared.as_slice(),
            &self.public_key(),
            ct,
        ))
    }
}

/// Открытая часть гибридной пары. Публикуется в дескрипторе точки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    x: x25519_dalek::PublicKey,
    pq: ml_kem::EncapsulationKey768,
}

impl PublicKey {
    /// Создать общий секрет и шифртекст для его передачи владельцу ключа.
    #[must_use]
    pub fn encapsulate(&self) -> (Ciphertext, SharedSecret) {
        let mut rng = OsRng;

        let eph = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
        let eph_public = x25519_dalek::PublicKey::from(&eph);
        let x_shared = eph.diffie_hellman(&self.x);

        let (pq_ct, pq_shared) = self.pq.encapsulate_with_rng(&mut rng);

        let ct = Ciphertext {
            x: eph_public.to_bytes(),
            pq: pq_ct,
        };
        let secret = combine(x_shared.as_bytes(), pq_shared.as_slice(), self, &ct);
        (ct, secret)
    }

    /// Сериализовать: X25519, затем ML-KEM-768.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_LEN + MLKEM_PUBLIC_LEN);
        out.extend_from_slice(self.x.as_bytes());
        out.extend_from_slice(&self.pq.to_bytes());
        out
    }

    /// Восстановить открытый ключ из байтов.
    ///
    /// # Errors
    ///
    /// [`Error::BadEncoding`] при неверной длине или недопустимом ключе.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (x_raw, pq_raw) = bytes
            .split_at_checked(X25519_LEN)
            .ok_or(Error::BadEncoding("открытый ключ обмена"))?;

        let x_array: [u8; X25519_LEN] = x_raw
            .try_into()
            .map_err(|_| Error::BadEncoding("открытый ключ X25519"))?;
        let pq = ml_kem::EncapsulationKey768::new_from_slice(pq_raw)
            .map_err(|_| Error::BadEncoding("открытый ключ ML-KEM-768"))?;

        Ok(Self {
            x: x25519_dalek::PublicKey::from(x_array),
            pq,
        })
    }
}

/// Шифртекст обмена: эфемерный открытый ключ X25519 и капсула ML-KEM-768.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    x: [u8; X25519_LEN],
    pq: ml_kem::ml_kem_768::Ciphertext,
}

impl Ciphertext {
    /// Сериализовать: X25519, затем ML-KEM-768.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_LEN + MLKEM_CIPHERTEXT_LEN);
        out.extend_from_slice(&self.x);
        out.extend_from_slice(self.pq.as_slice());
        out
    }

    /// Восстановить шифртекст из байтов.
    ///
    /// # Errors
    ///
    /// [`Error::BadEncoding`] при неверной длине.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (x_raw, pq_raw) = bytes
            .split_at_checked(X25519_LEN)
            .ok_or(Error::BadEncoding("шифртекст обмена"))?;

        let x: [u8; X25519_LEN] = x_raw
            .try_into()
            .map_err(|_| Error::BadEncoding("шифртекст X25519"))?;
        let pq = ml_kem::ml_kem_768::Ciphertext::try_from(pq_raw)
            .map_err(|_| Error::BadEncoding("шифртекст ML-KEM-768"))?;

        Ok(Self { x, pq })
    }
}

/// Свести две половины и транскрипт обмена в один общий секрет.
///
/// Включение транскрипта обязательно: без него шифртекст одной половины
/// можно было бы подменить, не изменив итоговый секрет.
fn combine(
    x_shared: &[u8],
    pq_shared: &[u8],
    recipient: &PublicKey,
    ct: &Ciphertext,
) -> SharedSecret {
    SharedSecret(hash::derive_key(
        KDF_CONTEXT,
        &[
            x_shared,
            pq_shared,
            recipient.x.as_bytes(),
            &recipient.pq.to_bytes(),
            &ct.x,
            ct.pq.as_slice(),
        ],
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_agree() {
        let secret = SecretKey::generate();
        let (ct, sender_secret) = secret.public_key().encapsulate();
        let receiver_secret = secret.decapsulate(&ct).unwrap();
        assert_eq!(sender_secret.as_bytes(), receiver_secret.as_bytes());
    }

    #[test]
    fn each_exchange_is_fresh() {
        let secret = SecretKey::generate();
        let (_, first) = secret.public_key().encapsulate();
        let (_, second) = secret.public_key().encapsulate();
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn other_key_yields_other_secret() {
        let alice = SecretKey::generate();
        let mallory = SecretKey::generate();
        let (ct, sender_secret) = alice.public_key().encapsulate();
        let wrong = mallory.decapsulate(&ct).unwrap();
        assert_ne!(sender_secret.as_bytes(), wrong.as_bytes());
    }

    #[test]
    fn tampered_x25519_half_changes_secret() {
        let secret = SecretKey::generate();
        let (ct, sender_secret) = secret.public_key().encapsulate();

        let mut raw = ct.to_bytes();
        // Портим первый байт эфемерного ключа X25519.
        if let Some(first) = raw.first_mut() {
            *first ^= 0x01;
        }
        let tampered = Ciphertext::from_bytes(&raw).unwrap();

        let result = secret.decapsulate(&tampered).unwrap();
        assert_ne!(sender_secret.as_bytes(), result.as_bytes());
    }

    #[test]
    fn public_key_survives_serialisation() {
        let secret = SecretKey::generate();
        let public = secret.public_key();
        let restored = PublicKey::from_bytes(&public.to_bytes()).unwrap();
        assert_eq!(public, restored);

        let (ct, sender_secret) = restored.encapsulate();
        assert_eq!(
            sender_secret.as_bytes(),
            secret.decapsulate(&ct).unwrap().as_bytes()
        );
    }

    #[test]
    fn ciphertext_survives_serialisation() {
        let secret = SecretKey::generate();
        let (ct, _) = secret.public_key().encapsulate();
        assert_eq!(ct, Ciphertext::from_bytes(&ct.to_bytes()).unwrap());
    }

    #[test]
    fn rejects_wrong_lengths() {
        assert!(PublicKey::from_bytes(&[0_u8; 10]).is_err());
        assert!(Ciphertext::from_bytes(&[0_u8; 10]).is_err());
    }

    #[test]
    fn debug_hides_secret_material() {
        let secret = SecretKey::generate();
        let (_, shared) = secret.public_key().encapsulate();
        assert!(!format!("{shared:?}").contains(&hash::to_hex(&shared.as_bytes()[..4])));
        assert_eq!(format!("{secret:?}"), "SecretKey(<скрыто>)");
    }
}
