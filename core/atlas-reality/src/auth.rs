//! Запечатывание и проверка метки внутри сериализованного `ClientHello`.
//!
//! # Почему аутентифицируемые данные содержат нули
//!
//! Клиент шифрует метку, передавая в качестве AAD всё handshake-сообщение
//! целиком. Возникает вопрос: что в этот момент лежит на месте
//! `session_id` — открытый текст метки или нули?
//!
//! Ответ выводится из эталонной реализации. Там после шифрования стоит
//! `copy(hello.Raw[39:], hello.SessionId)` — а эта строка имела бы смысл
//! только если `SessionId` **не** является срезом `Raw`. Значит на момент
//! шифрования в `Raw` лежит то, что попало туда при сериализации, то есть
//! нули.
//!
//! Иначе и быть не может: сервер получает сообщение с шифртекстом и должен
//! восстановить те же AAD. Если бы туда входил открытый текст метки,
//! проверка была бы невозможна — сервер узнаёт метку только после
//! расшифровки.
//!
//! Отсюда правило, одинаковое для обеих сторон: **AAD — это сообщение,
//! в котором область `session_id` обнулена.**

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize as _;

use crate::error::{Error, Result};
use crate::marker::{Marker, PLAINTEXT_LEN};

/// Смещение поля `random` в handshake-сообщении.
///
/// Тип сообщения (1) + длина (3) + `legacy_version` (2).
pub const RANDOM_OFFSET: usize = 6;
/// Длина поля `random`.
pub const RANDOM_LEN: usize = 32;
/// Смещение байта длины `session_id`.
pub const SESSION_ID_LEN_OFFSET: usize = RANDOM_OFFSET + RANDOM_LEN;
/// Смещение самого поля `session_id`.
pub const SESSION_ID_OFFSET: usize = SESSION_ID_LEN_OFFSET + 1;
/// Длина `session_id`: шестнадцать байт метки плюс тег AEAD.
pub const SESSION_ID_LEN: usize = 32;

/// Строка контекста для вывода ключа. Менять нельзя.
const HKDF_INFO: &[u8] = b"REALITY";
/// Сколько байт `random` уходит в соль HKDF.
const SALT_LEN: usize = 20;

/// Тип handshake-сообщения `client_hello`.
const CLIENT_HELLO: u8 = 0x01;

/// Вывести ключ аутентификации из общего секрета.
///
/// Соль — первые двадцать байт `random`, контекст — строка `REALITY`.
/// Оставшиеся двенадцать байт `random` служат nonce, поэтому соль и nonce
/// берутся из непересекающихся частей поля.
#[must_use]
pub fn derive_auth_key(shared_secret: &[u8; 32], random: &[u8; RANDOM_LEN]) -> [u8; 32] {
    let salt = random.get(..SALT_LEN).unwrap_or(random);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);

    let mut key = [0_u8; 32];
    // Ошибка возможна только при запросе длины больше 255 блоков хэша.
    if hkdf.expand(HKDF_INFO, &mut key).is_err() {
        key.zeroize();
    }
    key
}

/// Запечатать метку в handshake-сообщение.
///
/// Сообщение изменяется на месте: область `session_id` заполняется
/// шифртекстом и тегом.
///
/// # Errors
///
/// [`Error::NotClientHello`], [`Error::TooShort`] или
/// [`Error::UnexpectedSessionIdLength`], если сообщение не является
/// пригодным `ClientHello`; [`Error::Aead`] при отказе шифрования.
pub fn seal(handshake: &mut [u8], auth_key: &[u8; 32], marker: Marker) -> Result<()> {
    validate(handshake)?;

    let random = random_of(handshake)?;
    let nonce = nonce_of(&random);

    // AAD — сообщение с обнулённой областью session_id. Обнуляем до
    // шифрования, а не после: иначе в AAD попадёт мусор от вызывающего.
    zero_session_id(handshake)?;

    let plaintext = marker.to_plaintext();
    let sealed = Aes256Gcm::new(auth_key.into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &plaintext,
                aad: handshake,
            },
        )
        .map_err(|_| Error::Aead)?;

    if sealed.len() != SESSION_ID_LEN {
        return Err(Error::Aead);
    }

    let slot = handshake
        .get_mut(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
        .ok_or(Error::TooShort)?;
    slot.copy_from_slice(&sealed);
    Ok(())
}

/// Проверить метку и вернуть её содержимое.
///
/// Сообщение не изменяется.
///
/// # Errors
///
/// [`Error::NotClientHello`], [`Error::TooShort`] или
/// [`Error::UnexpectedSessionIdLength`], если сообщение непригодно;
/// [`Error::Rejected`], если метка не открывается данным ключом.
pub fn open(handshake: &[u8], auth_key: &[u8; 32]) -> Result<Marker> {
    validate(handshake)?;

    let random = random_of(handshake)?;
    let nonce = nonce_of(&random);

    let ciphertext = handshake
        .get(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
        .ok_or(Error::TooShort)?
        .to_vec();

    // Восстанавливаем те же AAD, что были у клиента.
    let mut aad = handshake.to_vec();
    zero_session_id(&mut aad)?;

    let plaintext = Aes256Gcm::new(auth_key.into())
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        // Причину не уточняем: подробное сообщение об ошибке проверки —
        // канал утечки для атакующего.
        .map_err(|_| Error::Rejected)?;

    let bytes: [u8; PLAINTEXT_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::Rejected)?;
    Ok(Marker::from_plaintext(&bytes))
}

/// Убедиться, что перед нами `ClientHello` ожидаемой формы.
fn validate(handshake: &[u8]) -> Result<()> {
    match handshake.first() {
        Some(&CLIENT_HELLO) => {}
        Some(&other) => return Err(Error::NotClientHello(other)),
        None => return Err(Error::TooShort),
    }

    if handshake.len() < SESSION_ID_OFFSET + SESSION_ID_LEN {
        return Err(Error::TooShort);
    }

    // Метка занимает ровно 32 байта. Сообщение с другой длиной session_id
    // нам не подходит — и его не прислал бы браузер: TLS 1.3 требует
    // непустой идентификатор ради совместимости с промежуточными узлами.
    match handshake.get(SESSION_ID_LEN_OFFSET) {
        Some(&len) if usize::from(len) == SESSION_ID_LEN => Ok(()),
        Some(&len) => Err(Error::UnexpectedSessionIdLength(len)),
        None => Err(Error::TooShort),
    }
}

/// Прочитать поле `session_id` — саму запечатанную метку.
///
/// Это то, что видно на проводе открытым текстом, и одновременно —
/// естественный уникальный признак попытки подключения: метка получена
/// шифрованием на ключе, выведенном из эфемерной доли клиента, поэтому
/// два честных соединения совпасть не могут. На этом держится окно
/// повторов ([`crate::ReplayWindow`]).
///
/// # Errors
///
/// [`Error::TooShort`] или [`Error::NotClientHello`], если сообщение не
/// той формы.
pub fn session_id_of(handshake: &[u8]) -> Result<[u8; SESSION_ID_LEN]> {
    validate(handshake)?;
    handshake
        .get(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Error::TooShort)
}

/// Прочитать поле `random` из handshake-сообщения.
///
/// # Errors
///
/// [`Error::TooShort`], если сообщение короче раскладки.
pub fn random_of_public(handshake: &[u8]) -> Result<[u8; RANDOM_LEN]> {
    random_of(handshake)
}

fn random_of(handshake: &[u8]) -> Result<[u8; RANDOM_LEN]> {
    handshake
        .get(RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Error::TooShort)
}

fn nonce_of(random: &[u8; RANDOM_LEN]) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    if let Some(slice) = random.get(SALT_LEN..) {
        nonce.copy_from_slice(slice);
    }
    nonce
}

fn zero_session_id(handshake: &mut [u8]) -> Result<()> {
    handshake
        .get_mut(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
        .ok_or(Error::TooShort)?
        .fill(0);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Минимальное сообщение нужной формы: тип, длина, версия, random,
    /// длина `session_id`, само поле.
    fn sample_handshake() -> Vec<u8> {
        let mut out = vec![CLIENT_HELLO, 0x00, 0x00, 0x44, 0x03, 0x03];
        out.extend((0..RANDOM_LEN).map(|i| u8::try_from(i).unwrap_or(0)));
        out.push(u8::try_from(SESSION_ID_LEN).unwrap_or(32));
        out.extend(core::iter::repeat_n(0xcc_u8, SESSION_ID_LEN));
        out.extend_from_slice("остальное тело сообщения".as_bytes());
        out
    }

    #[test]
    fn offsets_match_tls_layout() {
        // 1 + 3 + 2 + 32 + 1 = 39 — то же смещение, что в эталонной
        // реализации.
        assert_eq!(SESSION_ID_OFFSET, 39);
        assert_eq!(RANDOM_OFFSET, 6);
    }

    #[test]
    fn seal_then_open_round_trips() {
        let key = [0x5a_u8; 32];
        let marker = Marker::new([25, 3, 27], 1_800_000_000, &[0xde, 0xad]).unwrap();

        let mut handshake = sample_handshake();
        seal(&mut handshake, &key, marker).unwrap();
        assert_eq!(open(&handshake, &key).unwrap(), marker);
    }

    #[test]
    fn sealed_region_looks_random() {
        let key = [0x11_u8; 32];
        let mut handshake = sample_handshake();
        let before = handshake.clone();
        seal(
            &mut handshake,
            &key,
            Marker::new([1, 2, 3], 42, &[9]).unwrap(),
        )
        .unwrap();

        let sealed = handshake
            .get(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
            .unwrap();
        let untouched = before
            .get(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
            .unwrap();
        assert_ne!(sealed, untouched);
        // Ни одного нулевого блока: шифртекст, а не забытая заготовка.
        assert!(sealed.iter().any(|b| *b != 0));
    }

    #[test]
    fn only_the_session_id_changes() {
        let key = [0x22_u8; 32];
        let mut handshake = sample_handshake();
        let before = handshake.clone();
        seal(
            &mut handshake,
            &key,
            Marker::new([1, 2, 3], 42, &[9]).unwrap(),
        )
        .unwrap();

        for (index, (old, new)) in before.iter().zip(handshake.iter()).enumerate() {
            if (SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN).contains(&index) {
                continue;
            }
            assert_eq!(old, new, "байт {index} не должен был меняться");
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let mut handshake = sample_handshake();
        seal(
            &mut handshake,
            &[0x01_u8; 32],
            Marker::new([1, 2, 3], 42, &[9]).unwrap(),
        )
        .unwrap();
        assert_eq!(open(&handshake, &[0x02_u8; 32]), Err(Error::Rejected));
    }

    #[test]
    fn any_modification_of_the_message_is_rejected() {
        // Это и есть смысл AAD: подделать любую часть ClientHello,
        // сохранив метку, нельзя.
        let key = [0x33_u8; 32];
        let mut sealed = sample_handshake();
        seal(&mut sealed, &key, Marker::new([1, 2, 3], 42, &[9]).unwrap()).unwrap();

        for index in [4_usize, 6, 20, 37, SESSION_ID_OFFSET + SESSION_ID_LEN + 1] {
            let mut tampered = sealed.clone();
            if let Some(byte) = tampered.get_mut(index) {
                *byte ^= 0x01;
            }
            assert_eq!(
                open(&tampered, &key),
                Err(Error::Rejected),
                "изменение байта {index} должно отвергаться"
            );
        }
    }

    #[test]
    fn random_participates_in_key_and_nonce_without_overlap() {
        let shared = [7_u8; 32];
        let mut random_a = [0_u8; RANDOM_LEN];
        let mut random_b = [0_u8; RANDOM_LEN];
        // Различаем только в области соли.
        if let Some(byte) = random_b.get_mut(0) {
            *byte = 1;
        }
        assert_ne!(
            derive_auth_key(&shared, &random_a),
            derive_auth_key(&shared, &random_b)
        );

        // Различие только в области nonce ключ не меняет.
        if let Some(byte) = random_a.get_mut(SALT_LEN) {
            *byte = 1;
        }
        random_b = [0_u8; RANDOM_LEN];
        let mut random_c = [0_u8; RANDOM_LEN];
        if let Some(byte) = random_c.get_mut(SALT_LEN + 5) {
            *byte = 9;
        }
        assert_eq!(
            derive_auth_key(&shared, &random_b),
            derive_auth_key(&shared, &random_c)
        );
    }

    #[test]
    fn rejects_malformed_messages() {
        let key = [0_u8; 32];

        let mut not_hello = sample_handshake();
        if let Some(byte) = not_hello.first_mut() {
            *byte = 0x02;
        }
        assert_eq!(open(&not_hello, &key), Err(Error::NotClientHello(0x02)));

        let short = sample_handshake();
        let truncated = short.get(..SESSION_ID_OFFSET + 4).unwrap_or_default();
        assert_eq!(open(truncated, &key), Err(Error::TooShort));

        let mut wrong_len = sample_handshake();
        if let Some(byte) = wrong_len.get_mut(SESSION_ID_LEN_OFFSET) {
            *byte = 16;
        }
        assert_eq!(
            open(&wrong_len, &key),
            Err(Error::UnexpectedSessionIdLength(16))
        );
    }

    #[test]
    fn survives_arbitrary_garbage() {
        let key = [0_u8; 32];
        for seed in 0_u8..=255 {
            let noise: Vec<u8> = (0..seed).map(|i| i.wrapping_mul(seed) ^ 0x33).collect();
            let _ = open(&noise, &key);
        }
    }
}
