//! Модель, сериализация и разбор `ClientHello`.
//!
//! Расширения хранятся как пара «тип + тело», а не как типизированное
//! перечисление. Так сделано намеренно: для отпечатка важны тип, порядок и
//! точные байты тела, а попытка привести всё к типизированной модели
//! неизбежно нормализует то, что нормализовывать нельзя, — и отпечаток
//! разъезжается с оригиналом.

use crate::bytes::{Reader, Writer};
use crate::error::{Error, Result};
use crate::ext;

/// Тип handshake-сообщения `client_hello`.
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// Тип записи `handshake` на уровне записей TLS.
const RECORD_HANDSHAKE: u8 = 0x16;
/// Версия в заголовке записи — всегда TLS 1.0 ради совместимости.
const RECORD_VERSION: u16 = 0x0301;
/// Значение `legacy_version` внутри `ClientHello` — всегда TLS 1.2.
pub const LEGACY_VERSION: u16 = 0x0303;

/// Расширение: тип и точные байты тела.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Числовой идентификатор расширения.
    pub ext_type: u16,
    /// Тело расширения без префикса длины.
    pub body: Vec<u8>,
}

impl Extension {
    /// Расширение с произвольным телом.
    #[must_use]
    pub const fn raw(ext_type: u16, body: Vec<u8>) -> Self {
        Self { ext_type, body }
    }

    /// Расширение с пустым телом.
    #[must_use]
    pub const fn empty(ext_type: u16) -> Self {
        Self {
            ext_type,
            body: Vec::new(),
        }
    }
}

/// Сообщение `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Поле `legacy_version`; настоящая версия живёт в `supported_versions`.
    pub legacy_version: u16,
    /// 32 случайных байта.
    pub random: [u8; 32],
    /// `legacy_session_id`. TLS 1.3 требует 32 непустых байта для
    /// совместимости с промежуточными узлами; REALITY прячет в этом поле
    /// свою метку.
    pub session_id: Vec<u8>,
    /// Список шифронаборов в порядке предпочтения.
    pub cipher_suites: Vec<u16>,
    /// Методы сжатия. В TLS 1.3 всегда `[0]`.
    pub compression_methods: Vec<u8>,
    /// Расширения в порядке отправки.
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    /// Сериализовать в handshake-сообщение (с заголовком типа и длины).
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`], если какое-либо поле не помещается в свою длину.
    pub fn to_handshake(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(HANDSHAKE_CLIENT_HELLO);
        let mut outcome = Ok(());
        w.nested_u24(|body| outcome = self.write_body(body))?;
        outcome?;
        Ok(w.finish())
    }

    /// Обернуть handshake-сообщение в запись TLS.
    ///
    /// # Errors
    ///
    /// Те же условия, что и у [`Self::to_handshake`].
    pub fn to_record(&self) -> Result<Vec<u8>> {
        let handshake = self.to_handshake()?;
        let mut w = Writer::new();
        w.u8(RECORD_HANDSHAKE);
        w.u16(RECORD_VERSION);
        w.nested_u16(|body| body.bytes(&handshake))?;
        Ok(w.finish())
    }

    fn write_body(&self, w: &mut Writer) -> Result<()> {
        w.u16(self.legacy_version);
        w.bytes(&self.random);
        w.nested_u8(|body| body.bytes(&self.session_id))?;
        w.nested_u16(|body| body.list_u16(&self.cipher_suites))?;
        w.nested_u8(|body| body.bytes(&self.compression_methods))?;

        let mut outcome = Ok(());
        w.nested_u16(|list| {
            for extension in &self.extensions {
                list.u16(extension.ext_type);
                if let Err(err) = list.nested_u16(|body| body.bytes(&extension.body)) {
                    outcome = Err(err);
                    return;
                }
            }
        })?;
        outcome
    }

    /// Разобрать handshake-сообщение.
    ///
    /// Принимает как голое handshake-сообщение, так и запись TLS целиком —
    /// на практике байты приходят и в том, и в другом виде.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при обрыве, [`Error::Malformed`] при нарушении
    /// структуры, [`Error::UnexpectedMessage`] при другом типе сообщения.
    pub fn parse(input: &[u8]) -> Result<Self> {
        // Запись TLS начинается с типа 0x16 и версии 0x03xx; handshake —
        // с типа 0x01 и трёхбайтовой длины. Спутать их нельзя.
        let handshake = match input {
            [RECORD_HANDSHAKE, 0x03, _, ..] => {
                let mut r = Reader::new(input);
                r.take(3)?;
                r.vec_u16()?
            }
            _ => input,
        };

        let mut r = Reader::new(handshake);
        let msg_type = r.u8()?;
        if msg_type != HANDSHAKE_CLIENT_HELLO {
            return Err(Error::UnexpectedMessage(msg_type));
        }

        let declared = r.u24()? as usize;
        let body = r.take(declared)?;
        let mut r = Reader::new(body);

        let legacy_version = r.u16()?;
        let random: [u8; 32] = r
            .take(32)?
            .try_into()
            .map_err(|_| Error::Malformed("поле random не 32 байта"))?;
        let session_id = r.vec_u8()?.to_vec();
        let cipher_suites = r.list_u16()?;
        let compression_methods = r.vec_u8()?.to_vec();

        // Расширения формально необязательны — в TLS 1.3 их не бывает без,
        // но разбирать чужой ввод надо без предположений.
        let extensions = if r.is_empty() {
            Vec::new()
        } else {
            parse_extensions(r.vec_u16()?)?
        };

        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Найти расширение по типу.
    #[must_use]
    pub fn extension(&self, ext_type: u16) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.ext_type == ext_type)
    }

    /// Список имён протоколов из расширения ALPN.
    #[must_use]
    pub fn alpn(&self) -> Vec<String> {
        self.extension(ext::ALPN)
            .map(|e| ext::parse_alpn(&e.body))
            .unwrap_or_default()
    }

    /// Значение SNI, если расширение присутствует и содержит имя хоста.
    #[must_use]
    pub fn server_name(&self) -> Option<String> {
        self.extension(ext::SERVER_NAME)
            .and_then(|e| ext::parse_server_name(&e.body))
    }

    /// Версии из расширения `supported_versions`.
    #[must_use]
    pub fn supported_versions(&self) -> Vec<u16> {
        self.extension(ext::SUPPORTED_VERSIONS)
            .map(|e| ext::parse_u8_prefixed_u16_list(&e.body))
            .unwrap_or_default()
    }

    /// Алгоритмы подписи в порядке объявления.
    #[must_use]
    pub fn signature_algorithms(&self) -> Vec<u16> {
        self.extension(ext::SIGNATURE_ALGORITHMS)
            .map(|e| ext::parse_u16_prefixed_u16_list(&e.body))
            .unwrap_or_default()
    }

    /// Поддерживаемые группы.
    #[must_use]
    pub fn supported_groups(&self) -> Vec<u16> {
        self.extension(ext::SUPPORTED_GROUPS)
            .map(|e| ext::parse_u16_prefixed_u16_list(&e.body))
            .unwrap_or_default()
    }

    /// Форматы точек эллиптической кривой.
    #[must_use]
    pub fn ec_point_formats(&self) -> Vec<u8> {
        self.extension(ext::EC_POINT_FORMATS)
            .map(|e| {
                let mut r = Reader::new(&e.body);
                r.vec_u8().unwrap_or_default().to_vec()
            })
            .unwrap_or_default()
    }
}

fn parse_extensions(mut body: &[u8]) -> Result<Vec<Extension>> {
    let mut out = Vec::new();
    let mut r = Reader::new(body);
    while !r.is_empty() {
        let ext_type = r.u16()?;
        let data = r.vec_u16()?;
        out.push(Extension::raw(ext_type, data.to_vec()));
    }
    body = r.rest();
    debug_assert!(body.is_empty());
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample() -> ClientHello {
        ClientHello {
            legacy_version: LEGACY_VERSION,
            random: [7_u8; 32],
            session_id: vec![9_u8; 32],
            cipher_suites: vec![0x1301, 0x1302],
            compression_methods: vec![0],
            extensions: vec![
                ext::server_name("example.org"),
                ext::alpn(&["h2", "http/1.1"]),
                ext::supported_versions(&[0x0304, 0x0303]),
            ],
        }
    }

    #[test]
    fn handshake_round_trips() {
        let hello = sample();
        let parsed = ClientHello::parse(&hello.to_handshake().unwrap()).unwrap();
        assert_eq!(hello, parsed);
    }

    #[test]
    fn record_round_trips() {
        let hello = sample();
        let parsed = ClientHello::parse(&hello.to_record().unwrap()).unwrap();
        assert_eq!(hello, parsed);
    }

    #[test]
    fn handshake_header_is_well_formed() {
        let bytes = sample().to_handshake().unwrap();
        assert_eq!(bytes.first(), Some(&HANDSHAKE_CLIENT_HELLO));
        let declared = match bytes.get(1..4) {
            Some([a, b, c]) => u32::from_be_bytes([0, *a, *b, *c]) as usize,
            _ => 0,
        };
        assert_eq!(declared, bytes.len() - 4);
    }

    #[test]
    fn accessors_read_back_what_was_written() {
        let hello = sample();
        assert_eq!(hello.server_name().as_deref(), Some("example.org"));
        assert_eq!(hello.alpn(), vec!["h2".to_owned(), "http/1.1".to_owned()]);
        assert_eq!(hello.supported_versions(), vec![0x0304, 0x0303]);
    }

    #[test]
    fn rejects_wrong_message_type() {
        // 0x02 — ServerHello.
        let bytes = [0x02, 0x00, 0x00, 0x00];
        assert_eq!(
            ClientHello::parse(&bytes),
            Err(Error::UnexpectedMessage(0x02))
        );
    }

    #[test]
    fn rejects_truncated_input() {
        let full = sample().to_handshake().unwrap();
        for cut in [1_usize, 4, 10, 40] {
            let partial = full.get(..full.len() - cut).unwrap_or_default();
            assert!(
                ClientHello::parse(partial).is_err(),
                "обрезка на {cut} байт должна отвергаться"
            );
        }
    }

    #[test]
    fn survives_arbitrary_garbage() {
        // Разбор враждебного ввода не должен паниковать ни при каких данных.
        for seed in 0_u8..64 {
            let noise: Vec<u8> = (0..seed).map(|i| i.wrapping_mul(seed)).collect();
            let _ = ClientHello::parse(&noise);
        }
    }
}
