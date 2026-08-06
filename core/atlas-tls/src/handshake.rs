//! Сообщения рукопожатия TLS 1.3 и их разбор.
//!
//! Все сообщения после `ServerHello` едут внутри зашифрованных записей,
//! поэтому разбор здесь работает уже с открытым текстом. Границы записей
//! и границы сообщений не совпадают: одна запись может нести несколько
//! сообщений, а одно сообщение — растянуться на несколько записей.
//! Поэтому чтение потоковое.
//!
//! # Транскрипт
//!
//! Каждое сообщение рукопожатия дописывается в транскрипт, от которого
//! потом берётся хэш при выводе секретов и при проверке `Finished`.
//! Дописывается **сообщение целиком, вместе с заголовком** — на этом
//! месте легко ошибиться, и ошибка проявится лишь как несовпадение
//! `Finished` в самом конце.

use crate::bytes::{Reader, Writer};
use crate::error::{Error, Result};
use crate::hello::Extension;
use crate::keyschedule::Hash;

/// Предел длины одного сообщения рукопожатия.
///
/// Поле длины трёхбайтовое и формально разрешает шестнадцать мегабайт. Настоящее
/// сообщение таких размеров не бывает: самое большое — `Certificate` с
/// длинной цепочкой, метками SCT и вшитым OCSP — укладывается в десятки
/// килобайт. Без предела собеседник объявляет их все и заставляет нас
/// копить их в памяти по 16 килобайт за запись, ничего не нарушая
/// формально. Четверть мегабайта — с большим запасом над реальностью и
/// на два порядка ниже формального потолка.
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;

/// Особое значение поля `random`, которым сервер помечает
/// `HelloRetryRequest`.
///
/// Формально это `ServerHello`, отличается только этим значением.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Тип сообщения рукопожатия.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    /// Приветствие клиента.
    ClientHello,
    /// Приветствие сервера либо `HelloRetryRequest`.
    ServerHello,
    /// Билет для возобновления сессии.
    NewSessionTicket,
    /// Расширения, отправляемые под шифрованием.
    EncryptedExtensions,
    /// Запрос сертификата клиента.
    CertificateRequest,
    /// Цепочка сертификатов.
    Certificate,
    /// Сжатая цепочка сертификатов (RFC 8879).
    CompressedCertificate,
    /// Подпись над транскриптом.
    CertificateVerify,
    /// Завершение рукопожатия.
    Finished,
    /// Обновление ключей прикладного трафика.
    KeyUpdate,
    /// Тип, которого мы не знаем; сохраняем код, чтобы не терять транскрипт.
    Unknown(u8),
}

impl HandshakeType {
    /// Числовой код.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ClientHello => 1,
            Self::ServerHello => 2,
            Self::NewSessionTicket => 4,
            Self::EncryptedExtensions => 8,
            Self::Certificate => 11,
            Self::CompressedCertificate => 25,
            Self::CertificateRequest => 13,
            Self::CertificateVerify => 15,
            Self::Finished => 20,
            Self::KeyUpdate => 24,
            Self::Unknown(code) => code,
        }
    }

    /// Разобрать числовой код.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            4 => Self::NewSessionTicket,
            8 => Self::EncryptedExtensions,
            11 => Self::Certificate,
            25 => Self::CompressedCertificate,
            13 => Self::CertificateRequest,
            15 => Self::CertificateVerify,
            20 => Self::Finished,
            24 => Self::KeyUpdate,
            other => Self::Unknown(other),
        }
    }
}

/// Сообщение рукопожатия вместе с исходными байтами.
///
/// Байты хранятся потому, что в транскрипт идёт сообщение целиком,
/// а пересобирать его из разобранных полей — верный способ разойтись
/// с отправителем в паддинге или в порядке расширений.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Тип сообщения.
    pub msg_type: HandshakeType,
    /// Тело без четырёхбайтового заголовка.
    pub body: Vec<u8>,
    /// Полные байты, включая заголовок.
    pub raw: Vec<u8>,
}

/// Потоковый сборщик сообщений рукопожатия.
#[derive(Debug, Default)]
pub struct MessageReader {
    buffer: Vec<u8>,
}

impl MessageReader {
    /// Создать пустой сборщик.
    #[must_use]
    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Добавить открытый текст очередной записи.
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Сколько байт ещё не составили целого сообщения.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// Извлечь следующее полное сообщение.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если объявленная длина превышает
    /// [`MAX_MESSAGE_LEN`].
    pub fn next_message(&mut self) -> Result<Option<Message>> {
        let Some(header) = self.buffer.get(..4) else {
            return Ok(None);
        };
        let (code, len) = match header {
            [code, a, b, c] => (*code, u32::from_be_bytes([0, *a, *b, *c]) as usize),
            _ => return Ok(None),
        };

        if len > MAX_MESSAGE_LEN {
            return Err(Error::Malformed(
                "сообщение рукопожатия неправдоподобной длины",
            ));
        }

        let total = 4_usize
            .checked_add(len)
            .ok_or(Error::Malformed("переполнение длины сообщения"))?;
        if self.buffer.len() < total {
            return Ok(None);
        }

        let raw = self.buffer.get(..total).unwrap_or_default().to_vec();
        let body = raw.get(4..).unwrap_or_default().to_vec();
        self.buffer.drain(..total);

        Ok(Some(Message {
            msg_type: HandshakeType::from_code(code),
            body,
            raw,
        }))
    }
}

/// Транскрипт рукопожатия.
///
/// Хранит конкатенацию всех сообщений и умеет отдавать её хэш. Хранение
/// целиком, а не поточное хэширование, нужно потому, что хэш берётся
/// в нескольких точках от разных префиксов.
#[derive(Debug, Clone)]
pub struct Transcript {
    hash: Hash,
    data: Vec<u8>,
}

impl Transcript {
    /// Создать пустой транскрипт.
    #[must_use]
    pub const fn new(hash: Hash) -> Self {
        Self {
            hash,
            data: Vec::new(),
        }
    }

    /// Дописать сообщение целиком, вместе с заголовком.
    pub fn extend(&mut self, message_bytes: &[u8]) {
        self.data.extend_from_slice(message_bytes);
    }

    /// Привязать транскрипт к хэш-функции.
    ///
    /// Отдельный метод нужен потому, что хэш определяется шифронабором,
    /// а шифронабор становится известен только из `ServerHello` — то есть
    /// уже после того, как в транскрипт лёг `ClientHello`. Байты хранятся
    /// целиком, поэтому смена хэша ничего не портит.
    pub const fn set_hash(&mut self, hash: Hash) {
        self.hash = hash;
    }

    /// Заменить накопленное синтетическим сообщением `message_hash`.
    ///
    /// Требование RFC 8446, раздел 4.4.1: после `HelloRetryRequest`
    /// транскрипт начинается не с первого `ClientHello`, а с его хэша,
    /// обёрнутого в сообщение типа 254. Без этой замены `Finished` не
    /// сойдётся, причём только на тех серверах, которые запрашивают
    /// повторное приветствие, — то есть отладка была бы мучительной.
    pub fn replace_with_message_hash(&mut self) {
        const MESSAGE_HASH: u8 = 254;

        let digest = self.hash();
        let mut synthetic = Vec::with_capacity(4 + digest.len());
        synthetic.push(MESSAGE_HASH);
        synthetic.push(0);
        synthetic.push(0);
        // Длина хэша заведомо помещается в байт: 32 или 48.
        synthetic.push(u8::try_from(digest.len()).unwrap_or(0));
        synthetic.extend_from_slice(&digest);
        self.data = synthetic;
    }

    /// Хэш накопленного транскрипта.
    #[must_use]
    pub fn hash(&self) -> Vec<u8> {
        self.hash.digest(&self.data)
    }

    /// Накопленные байты — нужны при отладке расхождений.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Разобранное приветствие сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Поле `legacy_version`, всегда `0x0303`.
    pub legacy_version: u16,
    /// Случайное поле; особое значение означает `HelloRetryRequest`.
    pub random: [u8; 32],
    /// Эхо идентификатора сессии клиента.
    pub session_id: Vec<u8>,
    /// Выбранный шифронабор.
    pub cipher_suite: u16,
    /// Расширения.
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    /// Разобрать тело сообщения.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при обрыве, [`Error::Malformed`] при нарушении
    /// структуры.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let legacy_version = r.u16()?;
        let random: [u8; 32] = r
            .take(32)?
            .try_into()
            .map_err(|_| Error::Malformed("поле random не 32 байта"))?;
        let session_id = r.vec_u8()?.to_vec();
        let cipher_suite = r.u16()?;
        let _compression = r.u8()?;

        let mut extensions = Vec::new();
        if !r.is_empty() {
            let mut list = Reader::new(r.vec_u16()?);
            while !list.is_empty() {
                let ext_type = list.u16()?;
                let data = list.vec_u16()?;
                extensions.push(Extension::raw(ext_type, data.to_vec()));
            }
        }

        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suite,
            extensions,
        })
    }

    /// Является ли сообщение запросом повторного приветствия.
    ///
    /// Сервер отвечает так, когда не согласен с предложенной группой
    /// обмена ключами. Для нас это важный случай: повторный
    /// `ClientHello` обязан сохранить тот же отпечаток.
    #[must_use]
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }

    /// Найти расширение по типу.
    #[must_use]
    pub fn extension(&self, ext_type: u16) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.ext_type == ext_type)
    }

    /// Версия из расширения `supported_versions`.
    ///
    /// В `ServerHello` это одно значение, а не список.
    #[must_use]
    pub fn selected_version(&self) -> Option<u16> {
        let body = &self.extension(crate::ext::SUPPORTED_VERSIONS)?.body;
        match body.as_slice() {
            [hi, lo] => Some(u16::from_be_bytes([*hi, *lo])),
            _ => None,
        }
    }

    /// Доля сервера из расширения `key_share`: группа и открытый ключ.
    #[must_use]
    pub fn key_share(&self) -> Option<(u16, Vec<u8>)> {
        let body = &self.extension(crate::ext::KEY_SHARE)?.body;
        let mut r = Reader::new(body);
        let group = r.u16().ok()?;
        let key = r.vec_u16().ok()?;
        Some((group, key.to_vec()))
    }
}

/// Одна запись цепочки сертификатов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEntry {
    /// Сертификат в формате DER.
    pub data: Vec<u8>,
    /// Расширения записи.
    pub extensions: Vec<Extension>,
}

/// Сообщение `Certificate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// Контекст запроса; для сервера пустой.
    pub request_context: Vec<u8>,
    /// Цепочка: первый сертификат — конечный.
    pub entries: Vec<CertificateEntry>,
}

impl Certificate {
    /// Разобрать тело сообщения.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при обрыве, [`Error::Malformed`] при нарушении
    /// структуры.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let request_context = r.vec_u8()?.to_vec();

        let list_len = r.u24()? as usize;
        let list = r.take(list_len)?;
        let mut list = Reader::new(list);

        let mut entries = Vec::new();
        while !list.is_empty() {
            let cert_len = list.u24()? as usize;
            let data = list.take(cert_len)?.to_vec();

            let mut ext_reader = Reader::new(list.vec_u16()?);
            let mut extensions = Vec::new();
            while !ext_reader.is_empty() {
                let ext_type = ext_reader.u16()?;
                let ext_body = ext_reader.vec_u16()?;
                extensions.push(Extension::raw(ext_type, ext_body.to_vec()));
            }

            entries.push(CertificateEntry { data, extensions });
        }

        Ok(Self {
            request_context,
            entries,
        })
    }

    /// Конечный сертификат — тот, которым сервер подтверждает свою личность.
    #[must_use]
    pub fn end_entity(&self) -> Option<&[u8]> {
        self.entries.first().map(|e| e.data.as_slice())
    }
}

/// Сжатое сообщение `Certificate` (RFC 8879).
///
/// Расширение `compress_certificate` объявляет Chrome, и половина
/// интернета — весь Cloudflare — им пользуется. Отказаться от него
/// нельзя: расширение входит в отпечаток, и его отсутствие само по себе
/// признак. Значит, разжимать надо уметь.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedCertificate {
    /// Алгоритм: 1 — zlib, 2 — brotli, 3 — zstd.
    pub algorithm: u16,
    /// Длина исходного сообщения до сжатия.
    pub uncompressed_length: u32,
    /// Сжатое тело.
    pub compressed: Vec<u8>,
}

impl CompressedCertificate {
    /// Разобрать тело сообщения.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при обрыве.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let algorithm = r.u16()?;
        let uncompressed_length = r.u24()?;
        let compressed = {
            let len = r.u24()? as usize;
            r.take(len)?.to_vec()
        };
        Ok(Self {
            algorithm,
            uncompressed_length,
            compressed,
        })
    }
}

/// Сообщение `CertificateVerify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    /// Алгоритм подписи.
    pub algorithm: u16,
    /// Сама подпись.
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    /// Разобрать тело сообщения.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при обрыве.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        Ok(Self {
            algorithm: r.u16()?,
            signature: r.vec_u16()?.to_vec(),
        })
    }

    /// Данные, которые сервер подписывает.
    ///
    /// По RFC 8446, раздел 4.4.3: 64 пробела, строка контекста, нулевой
    /// байт и хэш транскрипта. Префикс из пробелов защищает от
    /// перепутывания с подписями других протоколов.
    #[must_use]
    pub fn signed_data(transcript_hash: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(130 + transcript_hash.len());
        out.extend(core::iter::repeat_n(0x20_u8, 64));
        out.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        out.push(0);
        out.extend_from_slice(transcript_hash);
        out
    }
}

/// Собрать сообщение рукопожатия из типа и тела.
///
/// # Errors
///
/// [`Error::TooLong`], если тело не помещается в трёхбайтовую длину.
pub fn build_message(msg_type: HandshakeType, body: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u8(msg_type.code());
    w.nested_u24(|inner| inner.bytes(body))?;
    Ok(w.finish())
}

#[cfg(test)]
// Вход тестов — эталонный след из testdata, а не сетевые данные.
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

    #[test]
    fn parses_the_reference_server_hello() {
        let raw = vector("server_hello");
        let mut reader = MessageReader::new();
        reader.push(&raw);
        let message = reader.next_message().unwrap().unwrap();

        assert_eq!(message.msg_type, HandshakeType::ServerHello);
        assert_eq!(
            message.raw, raw,
            "исходные байты сохраняются для транскрипта"
        );

        let hello = ServerHello::parse(&message.body).unwrap();
        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(hello.cipher_suite, 0x1301, "TLS_AES_128_GCM_SHA256");
        assert!(!hello.is_hello_retry_request());
        assert_eq!(hello.selected_version(), Some(0x0304), "TLS 1.3");

        let (group, key) = hello.key_share().unwrap();
        assert_eq!(group, 0x001d, "x25519");
        assert_eq!(key, vector("server_public_key"));
    }

    #[test]
    fn reader_splits_a_flight_into_messages() {
        // Пачка сервера — четыре сообщения подряд в одном потоке.
        let mut flight = vector("encrypted_extensions");
        flight.extend(vector("certificate"));
        flight.extend(vector("certificate_verify"));
        flight.extend(vector("server_finished_message"));

        let mut reader = MessageReader::new();
        reader.push(&flight);

        let types: Vec<HandshakeType> =
            core::iter::from_fn(|| reader.next_message().ok().flatten())
                .map(|m| m.msg_type)
                .collect();
        assert_eq!(
            types,
            vec![
                HandshakeType::EncryptedExtensions,
                HandshakeType::Certificate,
                HandshakeType::CertificateVerify,
                HandshakeType::Finished,
            ]
        );
        assert_eq!(reader.pending(), 0);
    }

    #[test]
    fn reader_reassembles_across_arbitrary_boundaries() {
        // Границы записей не совпадают с границами сообщений.
        let mut flight = vector("encrypted_extensions");
        flight.extend(vector("certificate_verify"));

        for chunk in [1_usize, 3, 17, 64, 500] {
            let mut reader = MessageReader::new();
            let mut count = 0;
            for part in flight.chunks(chunk) {
                reader.push(part);
                while reader.next_message().unwrap().is_some() {
                    count += 1;
                }
            }
            assert_eq!(count, 2, "куски по {chunk} байт");
        }
    }

    #[test]
    fn parses_the_reference_certificate() {
        let body = vector("certificate")[4..].to_vec();
        let certificate = Certificate::parse(&body).unwrap();
        assert!(
            certificate.request_context.is_empty(),
            "контекст сервера пуст"
        );
        assert_eq!(certificate.entries.len(), 1);
        // Сертификат DER начинается с последовательности.
        assert_eq!(
            certificate.end_entity().and_then(|c| c.first()),
            Some(&0x30)
        );
    }

    #[test]
    fn parses_the_reference_certificate_verify() {
        let body = vector("certificate_verify")[4..].to_vec();
        let verify = CertificateVerify::parse(&body).unwrap();
        assert_eq!(verify.algorithm, 0x0804, "rsa_pss_rsae_sha256");
        assert_eq!(verify.signature.len(), 128);
    }

    #[test]
    fn signed_data_has_the_documented_prefix() {
        let data = CertificateVerify::signed_data(&[0xaa; 32]);
        assert_eq!(&data[..64], &[0x20_u8; 64], "64 пробела");
        assert_eq!(&data[64..97], b"TLS 1.3, server CertificateVerify");
        assert_eq!(data[97], 0);
        assert_eq!(&data[98..], &[0xaa; 32]);
    }

    #[test]
    fn transcript_hashes_message_bytes_including_headers() {
        let mut transcript = Transcript::new(Hash::Sha256);
        transcript.extend(&vector("client_hello"));
        transcript.extend(&vector("server_hello"));
        assert_eq!(
            transcript.hash(),
            vector("transcript_hash_after_server_hello")
        );
    }

    #[test]
    fn build_message_round_trips() {
        let built = build_message(HandshakeType::Finished, &[0x11; 32]).unwrap();
        let mut reader = MessageReader::new();
        reader.push(&built);
        let message = reader.next_message().unwrap().unwrap();
        assert_eq!(message.msg_type, HandshakeType::Finished);
        assert_eq!(message.body, vec![0x11; 32]);
    }

    #[test]
    fn recognises_hello_retry_request() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        body.push(0); // пустой session_id
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(0); // сжатие
        body.extend_from_slice(&0_u16.to_be_bytes());

        assert!(ServerHello::parse(&body).unwrap().is_hello_retry_request());
    }

    #[test]
    fn unknown_message_types_are_preserved() {
        // Неизвестный тип не должен ломать разбор: сообщение обязано
        // попасть в транскрипт, даже если мы его не понимаем.
        let built = build_message(HandshakeType::Unknown(0x63), b"opaque").unwrap();
        let mut reader = MessageReader::new();
        reader.push(&built);
        let message = reader.next_message().unwrap().unwrap();
        assert_eq!(message.msg_type, HandshakeType::Unknown(0x63));
        assert_eq!(message.body, b"opaque");
    }

    #[test]
    fn an_implausibly_long_message_is_refused_before_it_is_buffered() {
        let mut reader = MessageReader::new();
        // Заголовок объявляет чуть больше предела; тела нет вовсе.
        let declared = u32::try_from(MAX_MESSAGE_LEN + 1).unwrap().to_be_bytes();
        reader.push(&[
            HandshakeType::Certificate.code(),
            declared[1],
            declared[2],
            declared[3],
        ]);

        assert!(
            reader.next_message().is_err(),
            "отказ обязан наступить по заголовку, а не после накопления тела"
        );
        assert_eq!(reader.pending(), 4, "тело копить мы даже не начали");
    }

    #[test]
    fn a_message_at_the_limit_is_still_accepted() {
        let body = vec![0x5a_u8; MAX_MESSAGE_LEN];
        let message = build_message(HandshakeType::Certificate, &body).unwrap();

        let mut reader = MessageReader::new();
        reader.push(&message);
        let parsed = reader.next_message().unwrap().unwrap();
        assert_eq!(parsed.body.len(), MAX_MESSAGE_LEN);
    }

    #[test]
    fn survives_arbitrary_garbage() {
        for seed in 0_u8..=255 {
            let noise: Vec<u8> = (0..seed).map(|i| i.wrapping_mul(seed) ^ 0x2b).collect();
            let mut reader = MessageReader::new();
            reader.push(&noise);
            let _ = reader.next_message();
            let _ = ServerHello::parse(&noise);
            let _ = Certificate::parse(&noise);
            let _ = CertificateVerify::parse(&noise);
        }
    }
}
