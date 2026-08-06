//! Слой записей TLS 1.3 (RFC 8446, раздел 5).
//!
//! После рукопожатия всё уезжает в записях `TLSCiphertext`, у которых
//! снаружи всегда один и тот же тип — `application_data`. Настоящий тип
//! содержимого спрятан внутри шифрования, за полезной нагрузкой:
//!
//! ```text
//! внешняя запись:   17 03 03 <длина> <шифртекст+тег>
//!                   \__ AAD: эти пять байт ___/
//!
//! внутренний текст: <содержимое> <настоящий тип> <нули паддинга>
//! ```
//!
//! Такое устройство скрывает от наблюдателя, что именно едет —
//! рукопожатие, данные или предупреждение, — и позволяет добавлять
//! паддинг, не меняя разбор.
//!
//! Nonce получается сложением по модулю два счётчика записей с
//! вектором инициализации. Счётчик не передаётся: обе стороны ведут его
//! сами, и рассинхронизация означает, что расшифровать больше ничего не
//! удастся. Это же даёт защиту от повтора и перестановки записей.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::{Error, Result};
use crate::keyschedule::TrafficKeys;

/// Наибольший размер открытого содержимого одной записи.
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// Длина заголовка записи.
pub const HEADER_LEN: usize = 5;
/// Длина тега AEAD у всех поддерживаемых шифронаборов.
pub const TAG_LEN: usize = 16;
/// Версия в заголовке записи. В TLS 1.3 всегда одна и та же.
const RECORD_VERSION: u16 = 0x0303;

/// Тип содержимого записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// `change_cipher_spec`; в TLS 1.3 шлётся только ради совместимости
    /// с промежуточными узлами и содержательного смысла не несёт.
    ChangeCipherSpec,
    /// Предупреждение или ошибка.
    Alert,
    /// Сообщение рукопожатия.
    Handshake,
    /// Прикладные данные.
    ApplicationData,
}

impl ContentType {
    /// Числовой код.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
        }
    }

    /// Разобрать числовой код.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] для неизвестного кода.
    pub const fn from_code(code: u8) -> Result<Self> {
        match code {
            20 => Ok(Self::ChangeCipherSpec),
            21 => Ok(Self::Alert),
            22 => Ok(Self::Handshake),
            23 => Ok(Self::ApplicationData),
            _ => Err(Error::Malformed("неизвестный тип содержимого записи")),
        }
    }
}

/// Алгоритм аутентифицированного шифрования.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    /// AES-128-GCM, ключ 16 байт.
    Aes128Gcm,
    /// AES-256-GCM, ключ 32 байта.
    Aes256Gcm,
    /// `ChaCha20-Poly1305`, ключ 32 байта.
    ChaCha20Poly1305,
}

impl Aead {
    /// Длина ключа.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Алгоритм, привязанный к шифронабору.
    #[must_use]
    pub const fn for_cipher_suite(suite: u16) -> Option<Self> {
        match suite {
            0x1301 => Some(Self::Aes128Gcm),
            0x1302 => Some(Self::Aes256Gcm),
            0x1303 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    fn seal(self, key: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let sealed = match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .ok()
                .and_then(|c| c.encrypt(nonce.into(), payload).ok()),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .ok()
                .and_then(|c| c.encrypt(nonce.into(), payload).ok()),
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .ok()
                .and_then(|c| c.encrypt(nonce.into(), payload).ok()),
        };
        sealed.ok_or(Error::Aead)
    }

    fn open(self, key: &[u8], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let opened = match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .ok()
                .and_then(|c| c.decrypt(nonce.into(), payload).ok()),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .ok()
                .and_then(|c| c.decrypt(nonce.into(), payload).ok()),
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .ok()
                .and_then(|c| c.decrypt(nonce.into(), payload).ok()),
        };
        // Причину не уточняем: подробность здесь — оракул для атакующего.
        opened.ok_or(Error::Aead)
    }
}

/// Защита записей в одну сторону.
///
/// На каждое направление свой экземпляр: ключи и счётчики у сторон
/// разные.
pub struct Protection {
    aead: Aead,
    keys: TrafficKeys,
    sequence: u64,
}

impl core::fmt::Debug for Protection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Protection {{ aead: {:?}, sequence: {}, keys: <скрыто> }}",
            self.aead, self.sequence
        )
    }
}

impl Protection {
    /// Создать защиту с нулевым счётчиком.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если длина ключа не соответствует алгоритму.
    pub fn new(aead: Aead, keys: TrafficKeys) -> Result<Self> {
        if keys.key.len() != aead.key_len() {
            return Err(Error::Malformed("длина ключа не соответствует алгоритму"));
        }
        Ok(Self {
            aead,
            keys,
            sequence: 0,
        })
    }

    /// Текущее значение счётчика записей.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Установить счётчик — нужно только в тестах на эталонных следах.
    pub const fn set_sequence(&mut self, value: u64) {
        self.sequence = value;
    }

    /// Nonce записи: счётчик, дополненный слева нулями, сложенный по
    /// модулю два с вектором инициализации.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.keys.iv;
        let counter = self.sequence.to_be_bytes();
        // Счётчик занимает восемь младших байт двенадцатибайтового IV.
        for (slot, byte) in nonce.iter_mut().skip(4).zip(counter.iter()) {
            *slot ^= byte;
        }
        nonce
    }

    fn advance(&mut self) -> Result<()> {
        // Переполнение счётчика недопустимо: повтор nonce с тем же ключом
        // разрушает безопасность AEAD. RFC требует рвать соединение.
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Malformed("счётчик записей переполнен"))?;
        Ok(())
    }

    /// Зашифровать содержимое в готовую запись.
    ///
    /// `padding` — сколько нулевых байт добавить после типа содержимого.
    /// Паддинг скрывает настоящую длину сообщения и ничего не стоит,
    /// кроме трафика.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] при превышении предельного размера или
    /// переполнении счётчика, [`Error::Aead`] при отказе шифрования.
    pub fn encrypt(
        &mut self,
        content_type: ContentType,
        content: &[u8],
        padding: usize,
    ) -> Result<Vec<u8>> {
        let inner_len = content
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(padding))
            .ok_or(Error::Malformed("переполнение длины записи"))?;
        if inner_len > MAX_PLAINTEXT {
            return Err(Error::Malformed("запись превышает предельный размер"));
        }

        let mut inner = Vec::with_capacity(inner_len);
        inner.extend_from_slice(content);
        inner.push(content_type.code());
        inner.resize(inner_len, 0);

        let length = u16::try_from(inner_len + TAG_LEN)
            .map_err(|_| Error::Malformed("длина записи не помещается"))?;

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.push(ContentType::ApplicationData.code());
        header.extend_from_slice(&RECORD_VERSION.to_be_bytes());
        header.extend_from_slice(&length.to_be_bytes());

        let sealed = self
            .aead
            .seal(&self.keys.key, &self.nonce(), &header, &inner)?;
        self.advance()?;

        let mut record = header;
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    /// Расшифровать запись целиком, вернув тип содержимого и содержимое.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`], если запись короче объявленной длины;
    /// [`Error::Malformed`] при нарушении структуры; [`Error::Aead`],
    /// если проверка подлинности не прошла.
    pub fn decrypt(&mut self, record: &[u8]) -> Result<(ContentType, Vec<u8>)> {
        let header = record.get(..HEADER_LEN).ok_or(Error::Truncated)?;
        let declared = match header {
            [_, _, _, hi, lo] => usize::from(u16::from_be_bytes([*hi, *lo])),
            _ => return Err(Error::Truncated),
        };

        let body = record
            .get(HEADER_LEN..HEADER_LEN + declared)
            .ok_or(Error::Truncated)?;
        if body.len() <= TAG_LEN {
            return Err(Error::Malformed("запись короче тега"));
        }

        let inner = self
            .aead
            .open(&self.keys.key, &self.nonce(), header, body)?;
        self.advance()?;

        // Настоящий тип лежит за содержимым, перед нулями паддинга.
        let end = inner
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or(Error::Malformed("во внутреннем тексте только нули"))?;
        let content_type = ContentType::from_code(*inner.get(end).unwrap_or(&0))?;

        Ok((content_type, inner.get(..end).unwrap_or_default().to_vec()))
    }
}

#[cfg(test)]
// Вход тестов — эталонный след из testdata, а не сетевые данные.
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../testdata/rfc8448-records.json");

    fn doc() -> serde_json::Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn unhex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// Собрать защиту по имени набора ключей из эталона.
    fn protection(name: &str, sequence: u64) -> Protection {
        let d = doc();
        let key = unhex(d[format!("{name}_key")].as_str().unwrap());
        let iv_raw = unhex(d[format!("{name}_iv")].as_str().unwrap());
        let mut iv = [0_u8; 12];
        iv.copy_from_slice(&iv_raw);

        let mut p = Protection::new(Aead::Aes128Gcm, TrafficKeys { key, iv }).unwrap();
        p.set_sequence(sequence);
        p
    }

    fn record_case(name: &str) -> (Protection, Vec<u8>, Vec<u8>) {
        let d = doc();
        let case = &d["записи"][name];
        let keys = case["ключи"].as_str().unwrap();
        let seq = case["seq"].as_u64().unwrap();
        (
            protection(keys, seq),
            unhex(case["record"].as_str().unwrap()),
            unhex(case["payload"].as_str().unwrap()),
        )
    }

    /// Расшифровка настоящих записей из эталонного следа.
    #[test]
    fn decrypts_every_record_from_the_rfc_trace() {
        for (name, expected_type) in [
            ("server_handshake_flight", ContentType::Handshake),
            ("client_finished", ContentType::Handshake),
            ("server_new_session_ticket", ContentType::Handshake),
            ("client_app_data", ContentType::ApplicationData),
            ("server_app_data", ContentType::ApplicationData),
        ] {
            let (mut protection, record, expected) = record_case(name);
            let (kind, content) = protection.decrypt(&record).unwrap();
            assert_eq!(kind, expected_type, "{name}: тип содержимого");
            assert_eq!(content, expected, "{name}: содержимое");
        }
    }

    /// Обратная операция обязана давать те же байты.
    ///
    /// Это более сильная проверка, чем расшифровка: она ловит ошибки в
    /// сборке заголовка, в паддинге и в порядке полей.
    #[test]
    fn reencrypts_to_the_exact_same_bytes() {
        for (name, kind) in [
            ("server_handshake_flight", ContentType::Handshake),
            ("client_finished", ContentType::Handshake),
            ("client_app_data", ContentType::ApplicationData),
        ] {
            let (mut protection, record, payload) = record_case(name);
            let ours = protection.encrypt(kind, &payload, 0).unwrap();
            assert_eq!(ours, record, "{name}: побайтовое совпадение записи");
        }
    }

    #[test]
    fn sequence_number_is_part_of_the_nonce() {
        // Та же запись с другим счётчиком не расшифруется: nonce другой.
        let (mut protection, record, _) = record_case("client_finished");
        protection.set_sequence(1);
        assert_eq!(protection.decrypt(&record), Err(Error::Aead));
    }

    #[test]
    fn sequence_advances_on_every_record() {
        let (mut protection, record, _) = record_case("client_finished");
        assert_eq!(protection.sequence(), 0);
        protection.decrypt(&record).unwrap();
        assert_eq!(protection.sequence(), 1);
    }

    #[test]
    fn header_is_authenticated() {
        // Заголовок входит в аутентифицируемые данные, поэтому подмена
        // объявленной длины ломает проверку, а не приводит к разбору
        // другого куска.
        let (mut protection, record, _) = record_case("client_app_data");
        let mut tampered = record.clone();
        tampered[2] = 0x04; // была версия 0x0303
        assert_eq!(protection.decrypt(&tampered), Err(Error::Aead));
    }

    #[test]
    fn tampering_with_ciphertext_is_detected() {
        for index in [5_usize, 20, 40, 71] {
            // Счётчик у каждой попытки свой: расшифровка его продвигает.
            let (mut protection, record, _) = record_case("client_app_data");
            let mut tampered = record;
            tampered[index] ^= 0x01;
            assert_eq!(
                protection.decrypt(&tampered),
                Err(Error::Aead),
                "изменение байта {index}"
            );
        }
    }

    #[test]
    fn padding_hides_the_real_length_but_not_the_content() {
        let keys = TrafficKeys {
            key: vec![0x11; 16],
            iv: [0x22; 12],
        };
        let mut sender = Protection::new(Aead::Aes128Gcm, keys.clone()).unwrap();
        let mut receiver = Protection::new(Aead::Aes128Gcm, keys).unwrap();

        let short = sender
            .encrypt(ContentType::ApplicationData, b"ab", 0)
            .unwrap();
        sender.set_sequence(0);
        let padded = sender
            .encrypt(ContentType::ApplicationData, b"ab", 500)
            .unwrap();

        assert_eq!(padded.len(), short.len() + 500, "паддинг меняет длину");

        let (kind, content) = receiver.decrypt(&padded).unwrap();
        assert_eq!(kind, ContentType::ApplicationData);
        assert_eq!(content, b"ab", "содержимое не изменилось");
    }

    #[test]
    fn all_three_aeads_round_trip() {
        for aead in [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
            let keys = TrafficKeys {
                key: vec![0x5a; aead.key_len()],
                iv: [0x33; 12],
            };
            let mut sender = Protection::new(aead, keys.clone()).unwrap();
            let mut receiver = Protection::new(aead, keys).unwrap();

            let record = sender
                .encrypt(ContentType::Handshake, b"handshake bytes", 7)
                .unwrap();
            let (kind, content) = receiver.decrypt(&record).unwrap();
            assert_eq!(kind, ContentType::Handshake, "{aead:?}");
            assert_eq!(content, b"handshake bytes", "{aead:?}");
        }
    }

    #[test]
    fn aead_is_bound_to_the_cipher_suite() {
        assert_eq!(Aead::for_cipher_suite(0x1301), Some(Aead::Aes128Gcm));
        assert_eq!(Aead::for_cipher_suite(0x1302), Some(Aead::Aes256Gcm));
        assert_eq!(Aead::for_cipher_suite(0x1303), Some(Aead::ChaCha20Poly1305));
        assert_eq!(Aead::for_cipher_suite(0x009c), None);
    }

    #[test]
    fn rejects_wrong_key_length() {
        let keys = TrafficKeys {
            key: vec![0x11; 16],
            iv: [0x22; 12],
        };
        assert!(matches!(
            Protection::new(Aead::Aes256Gcm, keys),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn rejects_oversized_content() {
        let keys = TrafficKeys {
            key: vec![0x11; 16],
            iv: [0x22; 12],
        };
        let mut p = Protection::new(Aead::Aes128Gcm, keys).unwrap();
        let huge = vec![0_u8; MAX_PLAINTEXT];
        assert!(matches!(
            p.encrypt(ContentType::ApplicationData, &huge, 0),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn survives_arbitrary_garbage() {
        let keys = TrafficKeys {
            key: vec![0x11; 16],
            iv: [0x22; 12],
        };
        for seed in 0_u8..=255 {
            let mut p = Protection::new(Aead::Aes128Gcm, keys.clone()).unwrap();
            let noise: Vec<u8> = (0..seed).map(|i| i.wrapping_mul(seed) ^ 0x17).collect();
            let _ = p.decrypt(&noise);
        }
    }
}
