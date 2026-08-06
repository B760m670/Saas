//! Расписание ключей TLS 1.3 (RFC 8446, раздел 7.1).
//!
//! Ключи рукопожатия выводятся цепочкой из трёх извлечений и множества
//! расширений. Ошибка в любом звене не проявляется как ошибка: соединение
//! просто не устанавливается, а причина оказывается в другом конце цепи.
//! Поэтому модуль целиком сверяется с эталонными векторами RFC 8448, где
//! расписаны все промежуточные значения.
//!
//! ```text
//!              0
//!              |
//!              v
//!    PSK ->  HKDF-Extract = Early Secret
//!              |
//!              +-> Derive-Secret(., "ext binder" | "res binder", "")
//!              +-> Derive-Secret(., "c e traffic", ClientHello)
//!              +-> Derive-Secret(., "e exp master", ClientHello)
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!  (EC)DHE -> HKDF-Extract = Handshake Secret
//!              |
//!              +-> Derive-Secret(., "c hs traffic", ClientHello..ServerHello)
//!              +-> Derive-Secret(., "s hs traffic", ClientHello..ServerHello)
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!    0 -> HKDF-Extract = Master Secret
//!              |
//!              +-> Derive-Secret(., "c ap traffic", ClientHello..server Finished)
//!              +-> Derive-Secret(., "s ap traffic", ClientHello..server Finished)
//!              +-> Derive-Secret(., "res master",   ClientHello..client Finished)
//! ```

use hkdf::Hkdf;
use sha2::{Digest as _, Sha256, Sha384};

/// Наибольший размер вывода хэша, с которым работает модуль.
pub const MAX_HASH_LEN: usize = 48;

/// Хэш-функция шифронабора.
///
/// TLS 1.3 привязывает хэш к шифронабору: `TLS_AES_128_GCM_SHA256` и
/// `TLS_CHACHA20_POLY1305_SHA256` используют SHA-256,
/// `TLS_AES_256_GCM_SHA384` — SHA-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// SHA-256, вывод 32 байта.
    Sha256,
    /// SHA-384, вывод 48 байт.
    Sha384,
}

impl Hash {
    /// Размер вывода в байтах.
    #[must_use]
    pub const fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// Хэш всегда непустой; метод существует ради пары к [`Self::len`].
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }

    /// Хэш-функция шифронабора по его номеру.
    #[must_use]
    pub const fn for_cipher_suite(suite: u16) -> Option<Self> {
        match suite {
            0x1301 | 0x1303 => Some(Self::Sha256),
            0x1302 => Some(Self::Sha384),
            _ => None,
        }
    }

    /// Хэш сообщения.
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    /// Хэш пустой строки — он часто нужен как контекст.
    #[must_use]
    pub fn empty_digest(self) -> Vec<u8> {
        self.digest(&[])
    }

    fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
            Self::Sha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
        }
    }

    fn expand(self, prk: &[u8], info: &[u8], out: &mut [u8]) {
        // Ошибка возможна только при запросе более 255 блоков хэша;
        // TLS столько никогда не запрашивает.
        let ok = match self {
            Self::Sha256 => Hkdf::<Sha256>::from_prk(prk).map(|h| h.expand(info, out)),
            Self::Sha384 => Hkdf::<Sha384>::from_prk(prk).map(|h| h.expand(info, out)),
        };
        if ok.is_err() {
            out.fill(0);
        }
    }
}

/// `HKDF-Expand-Label` из RFC 8446, раздел 7.1.
///
/// Структура `HkdfLabel`:
///
/// ```text
/// uint16 length;
/// opaque label<7..255> = "tls13 " + Label;
/// opaque context<0..255>;
/// ```
///
/// Приставка `tls13 ` разделяет назначения: тот же секрет в другом
/// протоколе даст другой ключ.
#[must_use]
pub fn expand_label(hash: Hash, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());

    // Длина запрашиваемого материала.
    info.extend_from_slice(&(u16::try_from(len).unwrap_or(u16::MAX)).to_be_bytes());

    let full_label_len = 6_usize.saturating_add(label.len());
    info.push(u8::try_from(full_label_len).unwrap_or(u8::MAX));
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());

    info.push(u8::try_from(context.len()).unwrap_or(u8::MAX));
    info.extend_from_slice(context);

    let mut out = vec![0_u8; len];
    hash.expand(secret, &info, &mut out);
    out
}

/// `Derive-Secret` — расширение с контекстом в виде хэша транскрипта.
#[must_use]
pub fn derive_secret(hash: Hash, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    expand_label(hash, secret, label, transcript_hash, hash.len())
}

/// Ключ и вектор инициализации для защиты записей.
#[derive(Clone, PartialEq, Eq)]
pub struct TrafficKeys {
    /// Ключ AEAD.
    pub key: Vec<u8>,
    /// Вектор инициализации, 12 байт.
    pub iv: [u8; 12],
}

// Производный `Debug` печатал бы ключ в логи.
impl core::fmt::Debug for TrafficKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TrafficKeys(<скрыто>)")
    }
}

/// Вывести ключ и IV из секрета трафика.
///
/// `key_len` задаётся шифронабором: 16 байт для AES-128-GCM, 32 для
/// AES-256-GCM и `ChaCha20-Poly1305`.
#[must_use]
pub fn traffic_keys(hash: Hash, secret: &[u8], key_len: usize) -> TrafficKeys {
    let key = expand_label(hash, secret, "key", &[], key_len);
    let raw_iv = expand_label(hash, secret, "iv", &[], 12);

    let mut iv = [0_u8; 12];
    if let Some(slice) = raw_iv.get(..12) {
        iv.copy_from_slice(slice);
    }
    TrafficKeys { key, iv }
}

/// Ключ для вычисления `Finished`.
#[must_use]
pub fn finished_key(hash: Hash, traffic_secret: &[u8]) -> Vec<u8> {
    expand_label(hash, traffic_secret, "finished", &[], hash.len())
}

/// Содержимое сообщения `Finished` — HMAC от хэша транскрипта.
#[must_use]
pub fn verify_data(hash: Hash, traffic_secret: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    use hmac::{KeyInit as _, Mac as _, SimpleHmac};

    let key = finished_key(hash, traffic_secret);
    match hash {
        Hash::Sha256 => {
            let Ok(mut mac) = SimpleHmac::<Sha256>::new_from_slice(&key) else {
                return Vec::new();
            };
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
        Hash::Sha384 => {
            let Ok(mut mac) = SimpleHmac::<Sha384>::new_from_slice(&key) else {
                return Vec::new();
            };
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Стадия расписания ключей.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Ранний секрет: получен из PSK или из нулей.
    Early,
    /// Секрет рукопожатия: подмешан общий секрет обмена ключами.
    Handshake,
    /// Мастер-секрет: из него выводятся ключи прикладных данных.
    Master,
}

/// Расписание ключей соединения.
///
/// Продвигается по стадиям только вперёд, что исключает вывод ключей
/// прикладных данных до того, как подмешан секрет обмена.
#[derive(Clone)]
pub struct KeySchedule {
    hash: Hash,
    stage: Stage,
    secret: Vec<u8>,
}

impl core::fmt::Debug for KeySchedule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "KeySchedule {{ hash: {:?}, stage: {:?}, secret: <скрыто> }}",
            self.hash, self.stage
        )
    }
}

impl KeySchedule {
    /// Начать расписание без заранее общего ключа.
    #[must_use]
    pub fn new(hash: Hash) -> Self {
        let zeros = vec![0_u8; hash.len()];
        Self {
            hash,
            stage: Stage::Early,
            secret: hash.extract(&zeros, &zeros),
        }
    }

    /// Начать расписание с заранее общим ключом (возобновление сессии).
    #[must_use]
    pub fn with_psk(hash: Hash, psk: &[u8]) -> Self {
        let zeros = vec![0_u8; hash.len()];
        Self {
            hash,
            stage: Stage::Early,
            secret: hash.extract(&zeros, psk),
        }
    }

    /// Текущая стадия.
    #[must_use]
    pub const fn stage(&self) -> Stage {
        self.stage
    }

    /// Хэш-функция расписания.
    #[must_use]
    pub const fn hash(&self) -> Hash {
        self.hash
    }

    /// Секрет текущей стадии.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Перейти к секрету рукопожатия, подмешав общий секрет обмена.
    pub fn enter_handshake(&mut self, shared_secret: &[u8]) {
        let derived = derive_secret(
            self.hash,
            &self.secret,
            "derived",
            &self.hash.empty_digest(),
        );
        self.secret = self.hash.extract(&derived, shared_secret);
        self.stage = Stage::Handshake;
    }

    /// Перейти к мастер-секрету.
    pub fn enter_master(&mut self) {
        let derived = derive_secret(
            self.hash,
            &self.secret,
            "derived",
            &self.hash.empty_digest(),
        );
        let zeros = vec![0_u8; self.hash.len()];
        self.secret = self.hash.extract(&derived, &zeros);
        self.stage = Stage::Master;
    }

    /// Вывести секрет с заданной меткой и хэшем транскрипта.
    #[must_use]
    pub fn derive(&self, label: &str, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, label, transcript_hash)
    }

    /// Секрет трафика рукопожатия для клиента.
    #[must_use]
    pub fn client_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        self.derive("c hs traffic", transcript_hash)
    }

    /// Секрет трафика рукопожатия для сервера.
    #[must_use]
    pub fn server_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        self.derive("s hs traffic", transcript_hash)
    }

    /// Секрет прикладного трафика для клиента.
    #[must_use]
    pub fn client_application_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        self.derive("c ap traffic", transcript_hash)
    }

    /// Секрет прикладного трафика для сервера.
    #[must_use]
    pub fn server_application_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        self.derive("s ap traffic", transcript_hash)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../testdata/rfc8448-simple-1rtt.json");

    fn vector(name: &str) -> Vec<u8> {
        let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let hex = doc[name].as_str().unwrap();
        hex.as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// Полный проход по эталонному следу RFC 8448.
    ///
    /// Проверяются не только конечные ключи, но и каждое промежуточное
    /// значение: ошибка в середине цепи иначе осталась бы незамеченной.
    #[test]
    fn matches_rfc8448_trace() {
        let hash = Hash::Sha256;
        let mut schedule = KeySchedule::new(hash);

        assert_eq!(schedule.secret(), vector("early_secret"), "ранний секрет");

        // Промежуточное значение перед извлечением секрета рукопожатия.
        let derived = derive_secret(hash, schedule.secret(), "derived", &hash.empty_digest());
        assert_eq!(
            derived,
            vector("derived_for_handshake"),
            "derived перед handshake"
        );

        schedule.enter_handshake(&vector("ecdhe_shared"));
        assert_eq!(
            schedule.secret(),
            vector("handshake_secret"),
            "секрет рукопожатия"
        );

        // Хэш транскрипта ClientHello..ServerHello.
        let mut transcript = vector("client_hello");
        transcript.extend(vector("server_hello"));
        let transcript_hash = hash.digest(&transcript);
        assert_eq!(
            transcript_hash,
            vector("transcript_hash_after_server_hello"),
            "хэш транскрипта"
        );

        let client_hs = schedule.client_handshake_traffic_secret(&transcript_hash);
        let server_hs = schedule.server_handshake_traffic_secret(&transcript_hash);
        assert_eq!(client_hs, vector("client_handshake_traffic_secret"));
        assert_eq!(server_hs, vector("server_handshake_traffic_secret"));

        // Ключи защиты записей сервера.
        let keys = traffic_keys(hash, &server_hs, 16);
        assert_eq!(keys.key, vector("server_handshake_key"), "ключ сервера");
        assert_eq!(
            keys.iv.to_vec(),
            vector("server_handshake_iv"),
            "IV сервера"
        );

        // Ключ Finished выводится из того же секрета.
        assert_eq!(
            finished_key(hash, &server_hs),
            vector("server_finished_key"),
            "ключ Finished"
        );

        // Сообщение Finished сервера считается по транскрипту,
        // включающему всё до CertificateVerify.
        transcript.extend(vector("encrypted_extensions"));
        transcript.extend(vector("certificate"));
        transcript.extend(vector("certificate_verify"));
        // Сам хэш транскрипта в следе не помечен отдельным блоком,
        // но совпадение verify_data доказывает, что он верен.
        let before_finished = hash.digest(&transcript);
        assert_eq!(
            verify_data(hash, &server_hs, &before_finished),
            vector("server_verify_data"),
            "содержимое Finished сервера"
        );

        let derived_master =
            derive_secret(hash, schedule.secret(), "derived", &hash.empty_digest());
        assert_eq!(
            derived_master,
            vector("derived_for_master"),
            "derived перед master"
        );

        schedule.enter_master();
        assert_eq!(schedule.secret(), vector("master_secret"), "мастер-секрет");

        // Секреты прикладного трафика выводятся из транскрипта,
        // включающего Finished сервера.
        let mut full = transcript.clone();
        full.extend(vector("server_finished_message"));
        let after_finished = hash.digest(&full);
        assert_eq!(
            after_finished,
            vector("transcript_hash_after_server_finished"),
            "хэш транскрипта после Finished сервера"
        );
        assert_eq!(
            schedule.client_application_traffic_secret(&after_finished),
            vector("client_application_traffic_secret"),
            "прикладной секрет клиента"
        );
        assert_eq!(
            schedule.server_application_traffic_secret(&after_finished),
            vector("server_application_traffic_secret"),
            "прикладной секрет сервера"
        );
    }

    #[test]
    fn expand_label_builds_the_documented_structure() {
        // Из следа RFC: info для метки "derived" с пустым контекстом.
        let hash = Hash::Sha256;
        let secret = vector("early_secret");
        let out = derive_secret(hash, &secret, "derived", &hash.empty_digest());
        assert_eq!(out.len(), 32);
        assert_eq!(out, vector("derived_for_handshake"));
    }

    #[test]
    fn label_prefix_separates_purposes() {
        let hash = Hash::Sha256;
        let secret = [0x42_u8; 32];
        // Метка входит в вывод: другая метка — другой ключ.
        assert_ne!(
            expand_label(hash, &secret, "key", &[], 16),
            expand_label(hash, &secret, "iv", &[], 16)
        );
        // И контекст тоже.
        assert_ne!(
            expand_label(hash, &secret, "key", b"a", 16),
            expand_label(hash, &secret, "key", b"b", 16)
        );
    }

    #[test]
    fn hash_is_bound_to_the_cipher_suite() {
        assert_eq!(Hash::for_cipher_suite(0x1301), Some(Hash::Sha256));
        assert_eq!(Hash::for_cipher_suite(0x1302), Some(Hash::Sha384));
        assert_eq!(Hash::for_cipher_suite(0x1303), Some(Hash::Sha256));
        assert_eq!(Hash::for_cipher_suite(0xc02b), None);
    }

    #[test]
    fn sha384_schedule_produces_longer_secrets() {
        let mut schedule = KeySchedule::new(Hash::Sha384);
        assert_eq!(schedule.secret().len(), 48);
        schedule.enter_handshake(&[0x11; 32]);
        assert_eq!(schedule.secret().len(), 48);
        assert_eq!(schedule.derive("c hs traffic", &[0x22; 48]).len(), 48);
    }

    #[test]
    fn stages_advance_in_order() {
        let mut schedule = KeySchedule::new(Hash::Sha256);
        assert_eq!(schedule.stage(), Stage::Early);
        schedule.enter_handshake(&[0x11; 32]);
        assert_eq!(schedule.stage(), Stage::Handshake);
        schedule.enter_master();
        assert_eq!(schedule.stage(), Stage::Master);
    }

    #[test]
    fn different_shared_secrets_diverge() {
        let mut a = KeySchedule::new(Hash::Sha256);
        let mut b = KeySchedule::new(Hash::Sha256);
        assert_eq!(a.secret(), b.secret(), "до обмена секреты совпадают");

        a.enter_handshake(&[0x01; 32]);
        b.enter_handshake(&[0x02; 32]);
        assert_ne!(a.secret(), b.secret());
    }

    #[test]
    fn psk_changes_the_early_secret() {
        let without = KeySchedule::new(Hash::Sha256);
        let with = KeySchedule::with_psk(Hash::Sha256, &[0x99; 32]);
        assert_ne!(without.secret(), with.secret());
    }

    #[test]
    fn traffic_keys_hide_material_in_debug() {
        let keys = traffic_keys(Hash::Sha256, &[0x33; 32], 16);
        assert_eq!(format!("{keys:?}"), "TrafficKeys(<скрыто>)");
        assert_eq!(keys.key.len(), 16);
    }

    #[test]
    fn verify_data_depends_on_transcript() {
        let hash = Hash::Sha256;
        let secret = [0x55_u8; 32];
        let first = verify_data(hash, &secret, &hash.digest(b"one"));
        let second = verify_data(hash, &secret, &hash.digest(b"two"));
        assert_eq!(first.len(), 32);
        assert_ne!(first, second);
    }
}
