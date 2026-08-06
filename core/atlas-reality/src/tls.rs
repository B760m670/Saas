//! Связка REALITY с клиентом TLS.
//!
//! Два конца одной верёвки. На исходящей стороне метка запечатывается в
//! готовое приветствие; на входящей — сервер обязан доказать, что знает
//! тот же общий секрет. Между ними лежит ключ, который вычисляется один
//! раз при печати и передаётся проверке через [`AuthKey`].
//!
//! # Что проверяется вместо цепочки сертификатов
//!
//! Настоящая цепочка сервера прикрытия всегда валидна и не доказывает
//! ничего: любой может поставить перед собой чужой сайт. Точка выхода
//! доказывает себя иначе — присылает временный сертификат с ключом
//! Ed25519, в поле подписи которого лежит не подпись, а
//! `HMAC-SHA512(authKey, открытый_ключ)`. Вычислить это значение может
//! только тот, кто знает приватный ключ точки: `authKey` выведен из
//! обмена нашей эфемерной доли с ним.
//!
//! Совпадение длин не случайно: `HMAC-SHA512` и подпись Ed25519 — по
//! шестьдесят четыре байта, поэтому подделка проходит любую проверку
//! формы и отличима только знанием секрета.
//!
//! # Постквантовая проверка
//!
//! При заданном ключе ML-DSA-65 сервер обязан дополнительно подписать
//! `HMAC-SHA512(authKey, открытый_ключ ‖ ClientHello ‖ ServerHello)` и
//! положить подпись в первое расширение сертификата. Это привязывает
//! доказательство к конкретному рукопожатию и переживает появление
//! квантовой машины: `HMAC` остаётся стойким, а подпись перестаёт
//! зависеть от стойкости X25519.
//!
//! # Чего эта проверка не даёт
//!
//! Она **не** отличает «за адресом настоящий сайт» от «нас
//! перенаправили»: в обоих случаях сертификат просто не проходит
//! проверку. Различать их клиент не должен — снаружи эти случаи и не
//! различаются, в этом и смысл REALITY.

use std::sync::{Arc, OnceLock};

use hmac::{KeyInit as _, Mac as _, SimpleHmac};
use sha2::Sha512;

use atlas_tls::client::{HelloSealer, PeerIdentity, ServerVerifier};
use atlas_tls::keyexchange::KeyShares;
use atlas_tls::profile::{X25519, X25519_MLKEM768};

use crate::auth;
use crate::cert::TemporaryCertificate;
use crate::marker::{Marker, SHORT_ID_LEN};
use crate::{Error, Result};

/// Ключ, вычисленный при печати метки и нужный при проверке сервера.
///
/// Печать и проверка происходят в разное время и в разных местах
/// клиента, поэтому ключ передаётся через общую ячейку, а не через
/// возвращаемое значение. Записывается ровно один раз.
#[derive(Debug, Clone, Default)]
pub struct AuthKey(Arc<OnceLock<[u8; 32]>>);

impl AuthKey {
    /// Создать пустую ячейку.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Значение, если печать уже состоялась.
    #[must_use]
    pub fn get(&self) -> Option<[u8; 32]> {
        self.0.get().copied()
    }

    /// Заполнить ячейку заранее известным значением.
    ///
    /// Клиенту это не нужно — он получает ключ из печати метки. Нужно
    /// **точке выхода**: она вычисляет тот же ключ из своей приватной
    /// части и доли клиента, и по нему строит временный сертификат.
    #[must_use]
    pub fn from_shared(value: [u8; 32]) -> Self {
        let cell = Self::default();
        cell.set(value);
        cell
    }

    fn set(&self, value: [u8; 32]) {
        let _ = self.0.set(value);
    }
}

/// Печать метки в готовое приветствие.
#[derive(Debug, Clone)]
pub struct Sealer {
    server_public: [u8; 32],
    short_id: [u8; SHORT_ID_LEN],
    version: [u8; 3],
    timestamp: u32,
    key: AuthKey,
}

impl Sealer {
    /// Создать печать.
    ///
    /// `timestamp` — текущее время в секундах эпохи. Оно передаётся
    /// снаружи, а не берётся из системных часов: крейт не должен зависеть
    /// от источника времени, а тесты обязаны быть воспроизводимыми.
    ///
    /// # Errors
    ///
    /// [`Error::ShortIdTooLong`], если идентификатор длиннее восьми байт.
    pub fn new(
        server_public: [u8; 32],
        short_id: &[u8],
        version: [u8; 3],
        timestamp: u32,
    ) -> Result<Self> {
        Ok(Self {
            server_public,
            short_id: Marker::new(version, 0, short_id)?.short_id,
            version,
            timestamp,
            key: AuthKey::new(),
        })
    }

    /// Ячейка с ключом — её же получает проверка сервера.
    #[must_use]
    pub fn auth_key(&self) -> AuthKey {
        self.key.clone()
    }
}

impl HelloSealer for Sealer {
    fn seal(&self, handshake: &mut [u8], shares: &KeyShares) -> atlas_tls::Result<()> {
        // Классическая доля, а при её отсутствии — половина X25519
        // внутри гибридной. Такой же порядок у эталонной реализации: она
        // сперва ищет группу `x25519`, и лишь потом лезет в гибрид.
        // Отдельной пары для REALITY не заводится — иначе на проводе
        // появился бы открытый ключ, которого у браузера не бывает.
        let exchange = shares
            .find(X25519)
            .or_else(|| shares.find(X25519_MLKEM768))
            .ok_or(atlas_tls::Error::Protocol(
                "REALITY: в приветствии нет доли x25519",
            ))?;

        let secret = exchange.agree_x25519(&self.server_public)?;

        let random = auth::random_of_public(handshake)
            .map_err(|_| atlas_tls::Error::Malformed("REALITY: приветствие не той формы"))?;
        let key = auth::derive_auth_key(&secret, &random);
        self.key.set(key);

        let marker = Marker {
            version: self.version,
            timestamp: self.timestamp,
            short_id: self.short_id,
        };
        auth::seal(handshake, &key, marker)
            .map_err(|_| atlas_tls::Error::Malformed("REALITY: метка не запечаталась"))
    }
}

/// Проверка сервера по общему секрету вместо цепочки сертификатов.
#[derive(Debug, Clone)]
pub struct Verifier {
    key: AuthKey,
    mldsa65: Option<Vec<u8>>,
}

impl Verifier {
    /// Создать проверку, привязанную к ячейке ключа.
    #[must_use]
    pub const fn new(key: AuthKey) -> Self {
        Self { key, mldsa65: None }
    }

    /// Потребовать дополнительную подпись ML-DSA-65.
    ///
    /// Аргумент — открытый ключ точки выхода в постквантовой схеме. Без
    /// него подлинность держится только на X25519, то есть на
    /// доквантовом предположении.
    #[must_use]
    pub fn with_post_quantum(mut self, public_key: Vec<u8>) -> Self {
        self.mldsa65 = Some(public_key);
        self
    }
}

impl ServerVerifier for Verifier {
    fn verify(&self, peer: &PeerIdentity<'_>) -> atlas_tls::Result<()> {
        let outcome = self.check(peer);
        // Наружу уходит одна и та же ошибка независимо от причины:
        // «сертификат не разобрался», «ключ не Ed25519» и «HMAC не
        // сошёлся» снаружи обязаны выглядеть одинаково.
        outcome.map_err(|_| atlas_tls::Error::Untrusted("REALITY: сервер не наша точка выхода"))
    }
}

impl Verifier {
    fn check(&self, peer: &PeerIdentity<'_>) -> Result<()> {
        let key = self.key.get().ok_or(Error::NotOurServer)?;
        let der = peer.certificate.end_entity().ok_or(Error::NotOurServer)?;
        let certificate = TemporaryCertificate::parse(der)?;

        let Ok(mut mac) = SimpleHmac::<Sha512>::new_from_slice(&key) else {
            return Err(Error::NotOurServer);
        };
        mac.update(&certificate.public_key);

        // Значение снимается с копии: тот же самый HMAC продолжается
        // дальше записями рукопожатия для постквантовой проверки.
        let expected = mac.clone().finalize().into_bytes();
        if !constant_time_eq(&expected, &certificate.signature) {
            return Err(Error::NotOurServer);
        }

        let Some(public_key) = self.mldsa65.as_ref() else {
            return Ok(());
        };

        // Постквантовая половина: тот же HMAC, продолженный записями
        // рукопожатия, подписан ключом ML-DSA-65 и лежит в расширении.
        let extension = certificate
            .first_extension
            .as_ref()
            .ok_or(Error::NotOurServer)?;
        mac.update(peer.client_hello);
        mac.update(peer.server_hello);
        let message = mac.finalize().into_bytes();

        let verifying = atlas_crypto::sign::PostQuantumKey::from_bytes(public_key)
            .map_err(|_| Error::NotOurServer)?;
        if verifying.verify(&message, extension) {
            Ok(())
        } else {
            Err(Error::NotOurServer)
        }
    }
}

/// Сравнение, не зависящее от места первого расхождения.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
