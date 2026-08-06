//! Гибридные подписи: Ed25519 + ML-DSA-65.
//!
//! Подпись считается верной, только если верны **обе** составляющие.
//!
//! Смысл гибрида: Ed25519 сломается перед достаточно большим квантовым
//! компьютером, ML-DSA — молодой алгоритм, у которого может обнаружиться
//! классическая слабость. Требование обеих подписей означает, что для
//! подделки нужно сломать оба независимых допущения.
//!
//! Применение — подпись дескрипторов точек выхода и голов каталога
//! (см. `docs/04-control-plane.md`).

use ml_dsa::{
    signature::{Keypair as _, Signer as _, Verifier as _},
    EncodedSignature, EncodedVerifyingKey, MlDsa65,
};

use crate::error::{Error, Result};
use crate::hash;
use crate::rng::OsRng;

/// Длина открытого ключа Ed25519.
pub const ED_PUBLIC_LEN: usize = 32;
/// Длина подписи Ed25519.
pub const ED_SIGNATURE_LEN: usize = 64;

/// Ключ подписи. Содержит секретный материал.
#[derive(Debug)]
pub struct SigningKey {
    ed: ed25519_dalek::SigningKey,
    pq: ml_dsa::SigningKey<MlDsa65>,
}

impl SigningKey {
    /// Сгенерировать новую пару ключей.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            ed: ed25519_dalek::SigningKey::generate(&mut rng),
            pq: <ml_dsa::SigningKey<MlDsa65> as ml_dsa::Generate>::generate_from_rng(&mut rng),
        }
    }

    /// Открытая часть ключа.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            ed: self.ed.verifying_key(),
            pq: self.pq.verifying_key(),
        }
    }

    /// Подписать сообщение в заданном контексте.
    ///
    /// `context` разделяет назначения подписи: подпись дескриптора нельзя
    /// предъявить как подпись головы каталога, даже если байты сообщения
    /// совпали.
    #[must_use]
    pub fn sign(&self, context: &'static str, message: &[u8]) -> Signature {
        let digest = domain_digest(context, message);
        Signature {
            ed: self.ed.sign(&digest),
            pq: self.pq.sign(&digest),
        }
    }
}

impl SigningKey {
    /// Подписать сообщение **одной лишь** ML-DSA-65, как есть.
    ///
    /// Пара к [`PostQuantumKey::verify`]. Нужна там, где схему задаём не
    /// мы: точка выхода REALITY кладёт такую подпись в расширение
    /// временного сертификата, и добавить туда свой префикс разделения
    /// назначений значило бы разойтись с чужой реализацией.
    ///
    /// Для всего своего пользоваться надо [`SigningKey::sign`]: гибрид
    /// требует сломать оба независимых допущения, а не одно.
    #[must_use]
    pub fn sign_post_quantum(&self, message: &[u8]) -> Vec<u8> {
        self.pq.sign(message).encode().as_slice().to_vec()
    }

    /// Голая постквантовая половина открытого ключа.
    ///
    /// Именно её точка выхода публикует для проверки своей подписи в
    /// сертификате REALITY.
    #[must_use]
    pub fn post_quantum_public_key(&self) -> Vec<u8> {
        self.verifying_key().post_quantum_bytes()
    }
}

/// Открытый ключ для проверки подписи.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyingKey {
    ed: ed25519_dalek::VerifyingKey,
    pq: ml_dsa::VerifyingKey<MlDsa65>,
}

impl VerifyingKey {
    /// Проверить подпись.
    ///
    /// # Errors
    ///
    /// [`Error::BadSignature`], если хотя бы одна из двух подписей неверна.
    pub fn verify(&self, context: &'static str, message: &[u8], sig: &Signature) -> Result<()> {
        let digest = domain_digest(context, message);

        // Обе проверки выполняются всегда, без короткого замыкания: так у
        // наблюдателя нет возможности по времени ответа определить, какая
        // именно из подписей не сошлась.
        let ed_ok = self.ed.verify(&digest, &sig.ed).is_ok();
        let pq_ok = self.pq.verify(&digest, &sig.pq).is_ok();

        if ed_ok & pq_ok {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    /// Устойчивый идентификатор ключа: `BLAKE3` от обеих его частей.
    ///
    /// Используется как `relay_id` в дескрипторах.
    #[must_use]
    pub fn id(&self) -> [u8; hash::LEN] {
        hash::derive_key(
            "atlas verifying key id v1",
            &[self.ed.as_bytes(), self.pq.encode().as_slice()],
        )
    }

    /// Голая постквантовая половина ключа.
    #[must_use]
    pub fn post_quantum_bytes(&self) -> Vec<u8> {
        self.pq.encode().as_slice().to_vec()
    }

    /// Сериализовать в байты: сначала Ed25519, затем ML-DSA-65.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(ED_PUBLIC_LEN + EncodedVerifyingKey::<MlDsa65>::default().len());
        out.extend_from_slice(self.ed.as_bytes());
        out.extend_from_slice(self.pq.encode().as_slice());
        out
    }

    /// Восстановить ключ из байтов.
    ///
    /// # Errors
    ///
    /// [`Error::BadEncoding`] при неверной длине или некорректной точке кривой.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (ed_raw, pq_raw) = bytes
            .split_at_checked(ED_PUBLIC_LEN)
            .ok_or(Error::BadEncoding("открытый ключ подписи"))?;

        let ed_array: [u8; ED_PUBLIC_LEN] = ed_raw
            .try_into()
            .map_err(|_| Error::BadEncoding("открытый ключ Ed25519"))?;
        let ed = ed25519_dalek::VerifyingKey::from_bytes(&ed_array)
            .map_err(|_| Error::BadEncoding("открытый ключ Ed25519"))?;

        let pq_encoded = EncodedVerifyingKey::<MlDsa65>::try_from(pq_raw)
            .map_err(|_| Error::BadEncoding("открытый ключ ML-DSA-65"))?;
        let pq = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pq_encoded);

        Ok(Self { ed, pq })
    }
}

/// Открытый ключ голой ML-DSA-65 — без классической половины.
///
/// Гибрид [`VerifyingKey`] — то, чем подписывает **наш** control plane, и
/// для него это правильный выбор. Но проверять чужие подписи, сделанные
/// одной лишь ML-DSA-65, гибридом нельзя: там нет второй половины.
///
/// Такой случай ровно один — постквантовое подтверждение точки выхода в
/// REALITY. Сообщение там подписывается как есть, без разделения
/// назначений: схему задаём не мы, и добавить свой префикс значило бы
/// разойтись с чужой реализацией.
#[derive(Debug, Clone, PartialEq)]
pub struct PostQuantumKey(ml_dsa::VerifyingKey<MlDsa65>);

impl PostQuantumKey {
    /// Восстановить ключ из байтов.
    ///
    /// # Errors
    ///
    /// [`Error::BadEncoding`] при неверной длине.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes)
            .map_err(|_| Error::BadEncoding("открытый ключ ML-DSA-65"))?;
        Ok(Self(ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded)))
    }

    /// Проверить подпись над сообщением.
    ///
    /// Возвращает признак, а не `Result`: у вызывающего нет права
    /// сообщать наружу, чем именно проверка не устроила.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(encoded) = EncodedSignature::<MlDsa65>::try_from(signature) else {
            return false;
        };
        let Some(parsed) = ml_dsa::Signature::<MlDsa65>::decode(&encoded) else {
            return false;
        };
        self.0.verify(message, &parsed).is_ok()
    }
}

/// Гибридная подпись.
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    ed: ed25519_dalek::Signature,
    pq: ml_dsa::Signature<MlDsa65>,
}

impl Signature {
    /// Сериализовать: сначала Ed25519 (64 байта), затем ML-DSA-65.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.ed.to_bytes());
        out.extend_from_slice(self.pq.encode().as_slice());
        out
    }

    /// Восстановить подпись из байтов.
    ///
    /// # Errors
    ///
    /// [`Error::BadEncoding`] при неверной длине или неразбираемой подписи.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (ed_raw, pq_raw) = bytes
            .split_at_checked(ED_SIGNATURE_LEN)
            .ok_or(Error::BadEncoding("подпись"))?;

        let ed_array: [u8; ED_SIGNATURE_LEN] = ed_raw
            .try_into()
            .map_err(|_| Error::BadEncoding("подпись Ed25519"))?;
        let ed = ed25519_dalek::Signature::from_bytes(&ed_array);

        let pq_encoded = EncodedSignature::<MlDsa65>::try_from(pq_raw)
            .map_err(|_| Error::BadEncoding("подпись ML-DSA-65"))?;
        let pq = ml_dsa::Signature::<MlDsa65>::decode(&pq_encoded)
            .ok_or(Error::BadEncoding("подпись ML-DSA-65"))?;

        Ok(Self { ed, pq })
    }
}

/// Свернуть контекст и сообщение в фиксированный дайджест.
///
/// Подписывается не само сообщение, а дайджест с привязкой к контексту.
/// Это даёт разделение назначений и убирает зависимость стоимости подписи
/// от размера сообщения.
fn domain_digest(context: &'static str, message: &[u8]) -> [u8; hash::LEN] {
    hash::derive_key(context, &[message])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const CTX: &str = "atlas test signature v1";

    #[test]
    fn round_trip_verifies() {
        let key = SigningKey::generate();
        let vk = key.verifying_key();
        let sig = key.sign(CTX, "дескриптор точки".as_bytes());
        vk.verify(CTX, "дескриптор точки".as_bytes(), &sig).unwrap();
    }

    #[test]
    fn rejects_modified_message() {
        let key = SigningKey::generate();
        let sig = key.sign(CTX, "оригинал".as_bytes());
        assert!(key
            .verifying_key()
            .verify(CTX, "подмена".as_bytes(), &sig)
            .is_err());
    }

    #[test]
    fn rejects_other_context() {
        let key = SigningKey::generate();
        let sig = key.sign(CTX, "сообщение".as_bytes());
        assert!(key
            .verifying_key()
            .verify("atlas другой контекст v1", "сообщение".as_bytes(), &sig)
            .is_err());
    }

    #[test]
    fn rejects_other_key() {
        let sig = SigningKey::generate().sign(CTX, "сообщение".as_bytes());
        let other = SigningKey::generate().verifying_key();
        assert!(other.verify(CTX, "сообщение".as_bytes(), &sig).is_err());
    }

    #[test]
    fn verifying_key_survives_serialisation() {
        let key = SigningKey::generate();
        let vk = key.verifying_key();
        let restored = VerifyingKey::from_bytes(&vk.to_bytes()).unwrap();
        assert_eq!(vk, restored);

        let sig = key.sign(CTX, "данные".as_bytes());
        restored.verify(CTX, "данные".as_bytes(), &sig).unwrap();
    }

    #[test]
    fn signature_survives_serialisation() {
        let key = SigningKey::generate();
        let sig = key.sign(CTX, "данные".as_bytes());
        let restored = Signature::from_bytes(&sig.to_bytes()).unwrap();
        key.verifying_key()
            .verify(CTX, "данные".as_bytes(), &restored)
            .unwrap();
    }

    #[test]
    fn rejects_truncated_encodings() {
        let key = SigningKey::generate();
        let vk_bytes = key.verifying_key().to_bytes();
        let sig_bytes = key.sign(CTX, b"x").to_bytes();

        assert!(VerifyingKey::from_bytes(&[]).is_err());
        let short_vk = vk_bytes.get(..vk_bytes.len() - 1).unwrap_or_default();
        assert!(VerifyingKey::from_bytes(short_vk).is_err());
        // Только классическая половина, без постквантовой — тоже отказ.
        let ed_only = sig_bytes.get(..ED_SIGNATURE_LEN).unwrap_or_default();
        assert!(Signature::from_bytes(ed_only).is_err());
    }

    #[test]
    fn ids_are_stable_and_unique() {
        let key = SigningKey::generate();
        assert_eq!(key.verifying_key().id(), key.verifying_key().id());
        assert_ne!(
            key.verifying_key().id(),
            SigningKey::generate().verifying_key().id()
        );
    }
}
