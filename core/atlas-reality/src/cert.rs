//! Ровно столько X.509, сколько нужно REALITY.
//!
//! # Почему свой разбор, а не библиотека
//!
//! Настоящей проверки сертификата здесь не происходит и происходить не
//! должно: цепочка сервера прикрытия всегда валидна и ничего не
//! доказывает. Подлинность точки выхода подтверждается тем, что подпись
//! во временном сертификате совпадает с `HMAC-SHA512` от общего секрета.
//!
//! Значит, нужны три поля, а не разбор X.509 целиком: открытый ключ
//! Ed25519, значение подписи и — для необязательной постквантовой
//! проверки — содержимое первого расширения. Тянуть ради этого полный
//! разборщик сертификатов означало бы затащить в ядро тысячи строк кода,
//! разбирающего враждебный ввод, ради полей, которые лежат на
//! фиксированных позициях структуры.
//!
//! # Что разбирается
//!
//! ```text
//! Certificate ::= SEQUENCE {
//!     tbsCertificate       TBSCertificate,      ← идём внутрь
//!     signatureAlgorithm   AlgorithmIdentifier, ← пропускаем
//!     signatureValue       BIT STRING           ← берём
//! }
//!
//! TBSCertificate ::= SEQUENCE {
//!     version         [0] EXPLICIT ... OPTIONAL, ← пропускаем, если есть
//!     serialNumber        INTEGER,               ← пропускаем
//!     signature           AlgorithmIdentifier,   ← пропускаем
//!     issuer              Name,                  ← пропускаем
//!     validity            Validity,              ← пропускаем
//!     subject             Name,                  ← пропускаем
//!     subjectPublicKeyInfo SubjectPublicKeyInfo, ← берём
//!     ...
//!     extensions      [3] EXPLICIT ... OPTIONAL  ← берём первое
//! }
//! ```
//!
//! Разбор устроен так, что не паникует ни на каком вводе: длины
//! проверяются, вложенность ограничена, срезы берутся через `get`.

use crate::error::{Error, Result};

/// OID `id-Ed25519` (1.3.101.112) в кодировке DER, целиком с заголовком.
const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// Длина открытого ключа Ed25519.
pub const ED25519_PUBLIC_LEN: usize = 32;

/// Тег DER: конструктор SEQUENCE.
const TAG_SEQUENCE: u8 = 0x30;
/// Тег DER: BIT STRING.
const TAG_BIT_STRING: u8 = 0x03;
/// Тег контекстного класса `[3]` в явной форме — расширения.
const TAG_EXTENSIONS: u8 = 0xa3;

/// Поля временного сертификата, которые нужны REALITY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporaryCertificate {
    /// Открытый ключ Ed25519 из `subjectPublicKeyInfo`.
    pub public_key: [u8; ED25519_PUBLIC_LEN],
    /// Значение `signatureValue`.
    ///
    /// У настоящего сертификата это подпись. У временного сертификата
    /// REALITY на этом месте лежит `HMAC-SHA512` — совпадение длин
    /// (шестьдесят четыре байта у обоих) не случайно, а именно то, что
    /// позволяет подделке выглядеть обычным сертификатом.
    pub signature: Vec<u8>,
    /// Содержимое первого расширения, если оно есть.
    ///
    /// Туда REALITY кладёт подпись ML-DSA-65 при включённой
    /// постквантовой проверке.
    pub first_extension: Option<Vec<u8>>,
}

impl TemporaryCertificate {
    /// Разобрать сертификат в формате DER.
    ///
    /// # Errors
    ///
    /// [`Error::BadCertificate`], если структура нарушена или открытый
    /// ключ не принадлежит Ed25519.
    pub fn parse(der: &[u8]) -> Result<Self> {
        let certificate = element(der, TAG_SEQUENCE)?;
        let mut rest = certificate.value;

        // tbsCertificate — заходим внутрь, но сначала запомним хвост.
        let tbs = element(rest, TAG_SEQUENCE)?;
        rest = rest.get(tbs.total..).ok_or(Error::BadCertificate)?;

        // signatureAlgorithm — пропускаем целиком.
        let algorithm = any(rest)?;
        rest = rest.get(algorithm.total..).ok_or(Error::BadCertificate)?;

        // signatureValue — BIT STRING, первый байт которого считает
        // неиспользованные биты. У подписи их не бывает, но проверить
        // надо: чужой ввод.
        let signature_bits = element(rest, TAG_BIT_STRING)?;
        let signature = strip_unused_bits(signature_bits.value)?.to_vec();

        let (public_key, first_extension) = parse_tbs(tbs.value)?;

        Ok(Self {
            public_key,
            signature,
            first_extension,
        })
    }
}

/// Достать из `tbsCertificate` открытый ключ и первое расширение.
fn parse_tbs(tbs: &[u8]) -> Result<([u8; ED25519_PUBLIC_LEN], Option<Vec<u8>>)> {
    /// Сколько полей идёт до `subjectPublicKeyInfo` при отсутствии
    /// необязательного `version`.
    const FIELDS_BEFORE_SPKI: usize = 5;

    let mut rest = tbs;

    // `version` необязателен и помечен `[0]`. Его отсутствие означает
    // сертификат первой версии — такие ещё встречаются.
    let first = any(rest)?;
    if first.tag == 0xa0 {
        rest = rest.get(first.total..).ok_or(Error::BadCertificate)?;
    }

    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..FIELDS_BEFORE_SPKI {
        let field = any(rest)?;
        rest = rest.get(field.total..).ok_or(Error::BadCertificate)?;
    }

    let spki = element(rest, TAG_SEQUENCE)?;
    let public_key = parse_spki(spki.value)?;
    rest = rest.get(spki.total..).ok_or(Error::BadCertificate)?;

    // Дальше идут необязательные `issuerUniqueID` `[1]`,
    // `subjectUniqueID` `[2]` и `extensions` `[3]`. Ищем последнее.
    let mut extensions = None;
    while !rest.is_empty() {
        let field = any(rest)?;
        if field.tag == TAG_EXTENSIONS {
            extensions = first_extension_value(field.value)?;
            break;
        }
        rest = rest.get(field.total..).ok_or(Error::BadCertificate)?;
    }

    Ok((public_key, extensions))
}

/// Достать открытый ключ Ed25519 из `subjectPublicKeyInfo`.
fn parse_spki(spki: &[u8]) -> Result<[u8; ED25519_PUBLIC_LEN]> {
    let algorithm = element(spki, TAG_SEQUENCE)?;

    // Алгоритм обязан быть именно Ed25519: REALITY подтверждает
    // подлинность через ключ этого типа, и принимать другой значило бы
    // сравнивать HMAC с чем попало.
    if algorithm.value.get(..OID_ED25519.len()) != Some(&OID_ED25519) {
        return Err(Error::BadCertificate);
    }

    let rest = spki.get(algorithm.total..).ok_or(Error::BadCertificate)?;
    let key_bits = element(rest, TAG_BIT_STRING)?;
    strip_unused_bits(key_bits.value)?
        .try_into()
        .map_err(|_| Error::BadCertificate)
}

/// Значение первого расширения из блока `[3] EXPLICIT Extensions`.
fn first_extension_value(body: &[u8]) -> Result<Option<Vec<u8>>> {
    let list = element(body, TAG_SEQUENCE)?;
    if list.value.is_empty() {
        return Ok(None);
    }

    let entry = element(list.value, TAG_SEQUENCE)?;
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
    //                          extnValue OCTET STRING }
    let mut rest = entry.value;
    let oid = any(rest)?;
    rest = rest.get(oid.total..).ok_or(Error::BadCertificate)?;

    let next = any(rest)?;
    // Пропускаем `critical`, если он есть.
    let value = if next.tag == 0x01 {
        let after = rest.get(next.total..).ok_or(Error::BadCertificate)?;
        any(after)?
    } else {
        next
    };

    Ok(Some(value.value.to_vec()))
}

/// Разобранный элемент DER.
struct Der<'a> {
    tag: u8,
    value: &'a [u8],
    /// Длина элемента целиком, вместе с тегом и длиной.
    total: usize,
}

/// Прочитать элемент с ожидаемым тегом.
fn element(input: &[u8], tag: u8) -> Result<Der<'_>> {
    let parsed = any(input)?;
    if parsed.tag != tag {
        return Err(Error::BadCertificate);
    }
    Ok(parsed)
}

/// Прочитать любой элемент DER.
fn any(input: &[u8]) -> Result<Der<'_>> {
    /// Наибольшее число байт в поле длины, которое мы допускаем.
    ///
    /// Четыре байта — это четыре гигабайта; сертификатов такого размера
    /// не бывает, а больший разбег позволил бы переполнить `usize` на
    /// тридцатидвухбитных платформах.
    const MAX_LENGTH_BYTES: usize = 4;

    let tag = *input.first().ok_or(Error::BadCertificate)?;
    let first_length = *input.get(1).ok_or(Error::BadCertificate)?;

    let (length, header) = if first_length < 0x80 {
        // Короткая форма: длина прямо в байте.
        (usize::from(first_length), 2)
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > MAX_LENGTH_BYTES {
            return Err(Error::BadCertificate);
        }
        let bytes = input.get(2..2 + count).ok_or(Error::BadCertificate)?;
        let length = bytes
            .iter()
            .try_fold(0_usize, |acc, byte| {
                acc.checked_mul(256)?.checked_add(usize::from(*byte))
            })
            .ok_or(Error::BadCertificate)?;
        (length, 2 + count)
    };

    let total = header.checked_add(length).ok_or(Error::BadCertificate)?;
    let value = input.get(header..total).ok_or(Error::BadCertificate)?;

    Ok(Der { tag, value, total })
}

/// Убрать счётчик неиспользованных битов из `BIT STRING`.
fn strip_unused_bits(value: &[u8]) -> Result<&[u8]> {
    match value.split_first() {
        // Ненулевой счётчик означает, что строка не кратна байту. Ни у
        // ключа, ни у подписи такого не бывает.
        Some((0, rest)) => Ok(rest),
        _ => Err(Error::BadCertificate),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Собрать элемент DER с длиной в короткой или длинной форме.
    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(u8::try_from(value.len()).unwrap());
        } else if value.len() < 0x100 {
            out.extend([0x81, u8::try_from(value.len()).unwrap()]);
        } else {
            let len = u16::try_from(value.len()).unwrap().to_be_bytes();
            out.extend([0x82, len[0], len[1]]);
        }
        out.extend_from_slice(value);
        out
    }

    fn bit_string(value: &[u8]) -> Vec<u8> {
        let mut body = vec![0_u8];
        body.extend_from_slice(value);
        der(TAG_BIT_STRING, &body)
    }

    /// Правдоподобный временный сертификат REALITY.
    fn build(public_key: &[u8; 32], signature: &[u8], extension: Option<&[u8]>) -> Vec<u8> {
        let mut tbs = Vec::new();
        tbs.extend(der(0xa0, &der(0x02, &[0x02]))); // version v3
        tbs.extend(der(0x02, &[0x01, 0x23])); // serialNumber
        tbs.extend(der(TAG_SEQUENCE, &OID_ED25519)); // signature
        tbs.extend(der(TAG_SEQUENCE, &der(0x31, &[]))); // issuer
        tbs.extend(der(TAG_SEQUENCE, &[])); // validity
        tbs.extend(der(TAG_SEQUENCE, &der(0x31, &[]))); // subject

        let mut spki = Vec::new();
        spki.extend(der(TAG_SEQUENCE, &OID_ED25519));
        spki.extend(bit_string(public_key));
        tbs.extend(der(TAG_SEQUENCE, &spki));

        if let Some(value) = extension {
            let mut entry = Vec::new();
            entry.extend(der(0x06, &[0x55, 0x1d, 0x0e])); // произвольный OID
            entry.extend(der(0x04, value)); // extnValue
            let list = der(TAG_SEQUENCE, &der(TAG_SEQUENCE, &entry));
            tbs.extend(der(TAG_EXTENSIONS, &list));
        }

        let mut certificate = Vec::new();
        certificate.extend(der(TAG_SEQUENCE, &tbs));
        certificate.extend(der(TAG_SEQUENCE, &OID_ED25519));
        certificate.extend(bit_string(signature));
        der(TAG_SEQUENCE, &certificate)
    }

    #[test]
    fn extracts_the_three_fields_it_needs() {
        let key = [0x5a_u8; 32];
        let signature = vec![0x11_u8; 64];
        let parsed = TemporaryCertificate::parse(&build(&key, &signature, None)).unwrap();

        assert_eq!(parsed.public_key, key);
        assert_eq!(parsed.signature, signature);
        assert_eq!(parsed.first_extension, None);
    }

    #[test]
    fn finds_the_post_quantum_extension() {
        let value = vec![0x33_u8; 3309]; // длина подписи ML-DSA-65
        let parsed =
            TemporaryCertificate::parse(&build(&[0x01; 32], &[0x22; 64], Some(&value))).unwrap();
        assert_eq!(parsed.first_extension, Some(value));
    }

    #[test]
    fn a_certificate_without_the_optional_version_still_parses() {
        // Сертификат первой версии: поля `[0] version` нет вовсе.
        let mut tbs = Vec::new();
        tbs.extend(der(0x02, &[0x01])); // serialNumber
        tbs.extend(der(TAG_SEQUENCE, &OID_ED25519));
        tbs.extend(der(TAG_SEQUENCE, &[]));
        tbs.extend(der(TAG_SEQUENCE, &[]));
        tbs.extend(der(TAG_SEQUENCE, &[]));

        let mut spki = Vec::new();
        spki.extend(der(TAG_SEQUENCE, &OID_ED25519));
        spki.extend(bit_string(&[0x77; 32]));
        tbs.extend(der(TAG_SEQUENCE, &spki));

        let mut certificate = Vec::new();
        certificate.extend(der(TAG_SEQUENCE, &tbs));
        certificate.extend(der(TAG_SEQUENCE, &OID_ED25519));
        certificate.extend(bit_string(&[0x88; 64]));

        let parsed = TemporaryCertificate::parse(&der(TAG_SEQUENCE, &certificate)).unwrap();
        assert_eq!(parsed.public_key, [0x77; 32]);
    }

    #[test]
    fn a_key_of_another_algorithm_is_refused() {
        // Настоящий сертификат сервера прикрытия — RSA или ECDSA.
        // Принять его значило бы сравнивать HMAC с чем попало.
        const OID_RSA: [u8; 11] = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ];
        let mut tbs = Vec::new();
        tbs.extend(der(0xa0, &der(0x02, &[0x02])));
        tbs.extend(der(0x02, &[0x01]));
        for _ in 0..4 {
            tbs.extend(der(TAG_SEQUENCE, &[]));
        }
        let mut spki = Vec::new();
        spki.extend(der(TAG_SEQUENCE, &OID_RSA));
        spki.extend(bit_string(&[0x99; 32]));
        tbs.extend(der(TAG_SEQUENCE, &spki));

        let mut certificate = Vec::new();
        certificate.extend(der(TAG_SEQUENCE, &tbs));
        certificate.extend(der(TAG_SEQUENCE, &OID_RSA));
        certificate.extend(bit_string(&[0xaa; 64]));

        assert_eq!(
            TemporaryCertificate::parse(&der(TAG_SEQUENCE, &certificate)),
            Err(Error::BadCertificate)
        );
    }

    #[test]
    fn long_form_lengths_are_handled() {
        // Подпись ML-DSA-65 в расширении делает сертификат длиннее 256
        // байт, то есть длинная форма длины обязана работать.
        let value = vec![0x44_u8; 3309];
        let der_bytes = build(&[0x02; 32], &[0x33; 64], Some(&value));
        assert!(der_bytes.len() > 3000);
        assert!(TemporaryCertificate::parse(&der_bytes).is_ok());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn survives_arbitrary_garbage() {
        // Вход — сертификат, присланный собеседником. Паниковать нельзя.
        for seed in 0_u16..=1000 {
            let noise: Vec<u8> = (0..(seed % 300))
                .map(|i| (i.wrapping_mul(seed) ^ 0x3d) as u8)
                .collect();
            let _ = TemporaryCertificate::parse(&noise);
        }
    }

    #[test]
    fn truncation_at_every_offset_is_refused_without_panic() {
        let full = build(&[0x03; 32], &[0x44; 64], Some(&[0x55; 40]));
        for cut in 0..full.len() {
            let _ = TemporaryCertificate::parse(&full[..cut]);
        }
        // А целый — разбирается.
        assert!(TemporaryCertificate::parse(&full).is_ok());
    }

    #[test]
    fn a_declared_length_beyond_the_input_is_refused() {
        // Заголовок обещает четыре гигабайта, тела нет.
        let bomb = [TAG_SEQUENCE, 0x84, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            TemporaryCertificate::parse(&bomb),
            Err(Error::BadCertificate)
        );
    }
}
