//! Сквозной канал до края сети.
//!
//! # Зачем он нужен именно здесь
//!
//! Точка выхода на бесплатной площадке (Cloudflare Workers и подобных)
//! снимает главное препятствие проекта: она не требует ни аренды, ни
//! карты. Но у неё нет и того, на чём держалась вся наша скрытность.
//!
//! REALITY доказывал подлинность сервера **общим секретом из ключа** —
//! никакой PKI не участвовало. К площадке же мы приходим обычным
//! клиентом по её собственному TLS, и вопрос «а тот ли это сервер»
//! остаётся без ответа. Обычный ответ — проверять цепочку по
//! хранилищу корневых сертификатов — здесь плох дважды:
//!
//! 1. Это гора кода: разбор X.509, построение пути, ограничения имён,
//!    сроки, отзыв. Классический источник дыр в чужих реализациях.
//! 2. Он всё равно не отвечает на наш вопрос. Проверка цепочки
//!    доказывает, что **какой-то** удостоверяющий центр поручился за
//!    имя. Противник, у которого есть свой центр в системном
//!    хранилище, поручится за что угодно.
//!
//! Поэтому доверие строится тут же, внутри туннеля, на секрете, который
//! знают только клиент и его собственный край. Никакой центр к нему
//! отношения не имеет — ни честный, ни поддельный.
//!
//! # Чего этот слой **не** делает
//!
//! Он **не прячет назначение от самой площадки**. Край обязан знать,
//! куда соединяться, иначе он не соединится; секрет у него есть, и
//! трафик он видит открытым. Обещать здесь приватность от Cloudflare
//! было бы враньём.
//!
//! Он закрывает другое, и ровно то, что нам нужно: **посредника между
//! телефоном и площадкой**. ТСПУ с собственным удостоверяющим центром
//! может подменить TLS площадки — и не сможет ничего с этим каналом,
//! потому что секрета у него нет.
//!
//! # Устройство
//!
//! ```text
//! клиент                                   край
//!   e_pub ‖ время ‖ mac ────────────────────►   проверка mac и свежести
//!                          ◄──────────────── s_pub ‖ mac
//!   ─── AES-256-GCM, ключи из ECDH и секрета ───►
//! ```
//!
//! Обе стороны эфемерны, поэтому запись разговора, расшифровать которую
//! потом, зная секрет, нельзя: долговременного ключа в согласовании
//! нет.
//!
//! # Почему такой набор примитивов
//!
//! Вторая сторона — JavaScript внутри Worker, а там есть только
//! `WebCrypto`. Отсюда SHA-256 вместо blake3, которым пользуется
//! остальной проект, и AES-256-GCM вместо ChaCha20-Poly1305, которого
//! в `WebCrypto` нет. Выбор продиктован совместимостью, а не вкусом.

use std::io::{self, Read, Write};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::KeyInit as _;
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Mac as _, SimpleHmac};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use x25519_dalek::{EphemeralSecret, PublicKey};

use atlas_crypto::rng::OsRng;

/// Длина общего секрета.
pub const SECRET_LEN: usize = 32;

/// Длина открытой доли X25519.
const SHARE_LEN: usize = 32;

/// Длина отпечатка в приветствии.
const MAC_LEN: usize = 16;

/// Длина метки времени.
const TIME_LEN: usize = 8;

/// Приветствие клиента: доля, время, отпечаток.
pub const CLIENT_HELLO_LEN: usize = SHARE_LEN + TIME_LEN + MAC_LEN;

/// Ответ края: доля и отпечаток.
pub const SERVER_HELLO_LEN: usize = SHARE_LEN + MAC_LEN;

/// Наибольший размер полезной нагрузки одной записи.
pub const MAX_RECORD: usize = 16 * 1024;

/// Насколько метка времени может разойтись с часами края.
///
/// Пять минут в каждую сторону: часы на телефоне и на площадке не
/// синхронизованы, а слишком узкое окно отвергало бы своих. Слишком
/// широкое — продлевало бы срок годности перехваченного приветствия.
pub const CLOCK_SKEW_SECS: u64 = 300;

const CLIENT_LABEL: &[u8] = b"atlas-edge-client-v1";
const SERVER_LABEL: &[u8] = b"atlas-edge-server-v1";
const KDF_INFO: &[u8] = b"atlas-edge-v1";

/// Что пошло не так при согласовании или разборе записи.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EdgeError {
    /// Отпечаток не сошёлся: у собеседника нет общего секрета.
    #[error("отпечаток не сошёлся: у собеседника нет общего секрета")]
    BadMac,
    /// Метка времени вне допустимого окна.
    #[error("метка времени вне окна: приветствие устарело или подделано")]
    StaleTime,
    /// Сообщение короче, чем обязано быть.
    #[error("сообщение обрезано")]
    Truncated,
    /// Запись не расшифровалась: подмена или рассинхронизация счётчика.
    #[error("запись не расшифровалась")]
    BadRecord,
    /// Запись длиннее допустимого.
    #[error("запись длиннее допустимого")]
    TooLong,
    /// Счётчик записей исчерпан.
    #[error("счётчик записей исчерпан")]
    CounterExhausted,
}

impl From<EdgeError> for io::Error {
    fn from(error: EdgeError) -> Self {
        Self::new(io::ErrorKind::InvalidData, error)
    }
}

type HmacSha256 = SimpleHmac<Sha256>;

/// Отпечаток над частями, привязанный к общему секрету.
fn mac(secret: &[u8; SECRET_LEN], label: &[u8], parts: &[&[u8]]) -> [u8; MAC_LEN] {
    let mut hmac = HmacSha256::new_from_slice(secret)
        .unwrap_or_else(|_| unreachable!("длина секрета фиксирована"));
    hmac.update(label);
    for part in parts {
        hmac.update(part);
    }
    let full = hmac.finalize().into_bytes();
    let mut out = [0_u8; MAC_LEN];
    out.copy_from_slice(full.get(..MAC_LEN).unwrap_or_default());
    out
}

/// Ключи направлений, выведенные из ECDH и общего секрета.
///
/// Секрет входит **солью**, а не материалом: так знание одного лишь
/// секрета, без эфемерных долей, не даёт ключей сессии.
fn derive(
    shared: &[u8; 32],
    secret: &[u8; SECRET_LEN],
    client_share: &[u8; SHARE_LEN],
    server_share: &[u8; SHARE_LEN],
) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(secret.as_slice()), shared.as_slice());
    let mut info = Vec::with_capacity(KDF_INFO.len() + SHARE_LEN * 2 + 1);
    info.extend_from_slice(KDF_INFO);
    info.extend_from_slice(client_share);
    info.extend_from_slice(server_share);

    let mut to_edge = [0_u8; 32];
    let mut to_client = [0_u8; 32];
    info.push(0);
    hkdf.expand(&info, &mut to_edge)
        .unwrap_or_else(|_| unreachable!("длина вывода допустима"));
    let last = info.len() - 1;
    if let Some(slot) = info.get_mut(last) {
        *slot = 1;
    }
    hkdf.expand(&info, &mut to_client)
        .unwrap_or_else(|_| unreachable!("длина вывода допустима"));
    (to_edge, to_client)
}

/// Начатое клиентом согласование.
///
/// Хранит эфемерный секрет между отправкой приветствия и приходом
/// ответа. Отдельный тип, потому что `EphemeralSecret` расходуется при
/// вычислении — и это правильно: повторное использование эфемерной доли
/// уничтожило бы прямую секретность.
pub struct Handshake {
    secret: [u8; SECRET_LEN],
    ephemeral: EphemeralSecret,
    share: [u8; SHARE_LEN],
}

// Печатать сюда нечего: и секрет, и эфемерная доля — тайна, а
// напечатанная в журнале тайна перестаёт быть тайной.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for Handshake {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.write_str("Handshake { .. }")
    }
}

impl Handshake {
    /// Начать согласование и собрать приветствие.
    ///
    /// `now` — время в секундах эпохи Unix. Передаётся снаружи, а не
    /// берётся из часов, чтобы проверки не зависели от настоящего
    /// времени.
    #[must_use]
    pub fn start(secret: &[u8; SECRET_LEN], now: u64) -> (Self, [u8; CLIENT_HELLO_LEN]) {
        let ephemeral = EphemeralSecret::random_from_rng(&mut OsRng);
        let share = PublicKey::from(&ephemeral).to_bytes();

        let time = now.to_be_bytes();
        let tag = mac(secret, CLIENT_LABEL, &[&share, &time]);

        let mut hello = [0_u8; CLIENT_HELLO_LEN];
        if let Some(slot) = hello.get_mut(..SHARE_LEN) {
            slot.copy_from_slice(&share);
        }
        if let Some(slot) = hello.get_mut(SHARE_LEN..SHARE_LEN + TIME_LEN) {
            slot.copy_from_slice(&time);
        }
        if let Some(slot) = hello.get_mut(SHARE_LEN + TIME_LEN..) {
            slot.copy_from_slice(&tag);
        }

        (
            Self {
                secret: *secret,
                ephemeral,
                share,
            },
            hello,
        )
    }

    /// Принять ответ края и получить готовую сессию.
    ///
    /// # Errors
    ///
    /// [`EdgeError::Truncated`], если ответ короче положенного;
    /// [`EdgeError::BadMac`], если отвечает не тот, у кого наш секрет.
    pub fn finish(self, response: &[u8]) -> Result<Session, EdgeError> {
        let server_share: [u8; SHARE_LEN] = response
            .get(..SHARE_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(EdgeError::Truncated)?;
        let tag = response
            .get(SHARE_LEN..SERVER_HELLO_LEN)
            .ok_or(EdgeError::Truncated)?;

        let expected = mac(&self.secret, SERVER_LABEL, &[&self.share, &server_share]);
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            return Err(EdgeError::BadMac);
        }

        let shared = self
            .ephemeral
            .diffie_hellman(&PublicKey::from(server_share))
            .to_bytes();
        let (to_edge, to_client) = derive(&shared, &self.secret, &self.share, &server_share);
        Ok(Session::new(to_edge, to_client))
    }
}

/// Ответить на приветствие клиента.
///
/// Возвращает ответ и готовую сессию. Сторона края; в рабочем виде это
/// делает JavaScript внутри Worker, здесь — для проверок и для
/// собственной точки выхода.
///
/// # Errors
///
/// [`EdgeError::Truncated`], [`EdgeError::BadMac`] или
/// [`EdgeError::StaleTime`].
pub fn respond(
    secret: &[u8; SECRET_LEN],
    hello: &[u8],
    now: u64,
) -> Result<([u8; SERVER_HELLO_LEN], Session), EdgeError> {
    let client_share: [u8; SHARE_LEN] = hello
        .get(..SHARE_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(EdgeError::Truncated)?;
    let time_bytes: [u8; TIME_LEN] = hello
        .get(SHARE_LEN..SHARE_LEN + TIME_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(EdgeError::Truncated)?;
    let tag = hello
        .get(SHARE_LEN + TIME_LEN..CLIENT_HELLO_LEN)
        .ok_or(EdgeError::Truncated)?;

    // Отпечаток проверяется **до** метки времени: иначе разница в
    // ответах на «неверный секрет» и «верный секрет, старое время»
    // давала бы постороннему способ проверять секреты.
    let expected = mac(secret, CLIENT_LABEL, &[&client_share, &time_bytes]);
    if expected.ct_eq(tag).unwrap_u8() != 1 {
        return Err(EdgeError::BadMac);
    }

    let claimed = u64::from_be_bytes(time_bytes);
    if claimed.abs_diff(now) > CLOCK_SKEW_SECS {
        return Err(EdgeError::StaleTime);
    }

    let ephemeral = EphemeralSecret::random_from_rng(&mut OsRng);
    let server_share = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral
        .diffie_hellman(&PublicKey::from(client_share))
        .to_bytes();

    let reply_tag = mac(secret, SERVER_LABEL, &[&client_share, &server_share]);
    let mut response = [0_u8; SERVER_HELLO_LEN];
    if let Some(slot) = response.get_mut(..SHARE_LEN) {
        slot.copy_from_slice(&server_share);
    }
    if let Some(slot) = response.get_mut(SHARE_LEN..) {
        slot.copy_from_slice(&reply_tag);
    }

    let (to_edge, to_client) = derive(&shared, secret, &client_share, &server_share);
    // У края направления зеркальны: он читает то, что клиент пишет.
    Ok((response, Session::new(to_client, to_edge)))
}

/// Согласованная сессия: шифрует и расшифровывает записи.
pub struct Session {
    sending: Aes256Gcm,
    receiving: Aes256Gcm,
    sent: u64,
    received: u64,
}

// Ключи направлений в отладочный вывод не попадают намеренно.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for Session {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.debug_struct("Session")
            .field("sent", &self.sent)
            .field("received", &self.received)
            .finish()
    }
}

impl Session {
    fn new(sending: [u8; 32], receiving: [u8; 32]) -> Self {
        Self {
            // Длины проверены типом: обе доли ровно 32 байта.
            sending: Aes256Gcm::new_from_slice(&sending)
                .unwrap_or_else(|_| unreachable!("длина ключа фиксирована")),
            receiving: Aes256Gcm::new_from_slice(&receiving)
                .unwrap_or_else(|_| unreachable!("длина ключа фиксирована")),
            sent: 0,
            received: 0,
        }
    }

    /// Одноразовое число из счётчика.
    ///
    /// Счётчик, а не случайность: при 96-битном одноразовом числе
    /// случайный выбор столкнулся бы сам с собой раньше, чем кончился
    /// бы разумный объём разговора.
    fn nonce(counter: u64) -> Nonce<aes_gcm::aead::consts::U12> {
        let mut raw = [0_u8; 12];
        if let Some(slot) = raw.get_mut(4..) {
            slot.copy_from_slice(&counter.to_be_bytes());
        }
        Nonce::from(raw)
    }

    /// Зашифровать запись целиком, вместе с длиной.
    ///
    /// # Errors
    ///
    /// [`EdgeError::TooLong`], если нагрузка больше [`MAX_RECORD`];
    /// [`EdgeError::CounterExhausted`] после исчерпания счётчика.
    pub fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>, EdgeError> {
        if plain.len() > MAX_RECORD {
            return Err(EdgeError::TooLong);
        }
        let counter = self.sent;
        self.sent = self
            .sent
            .checked_add(1)
            .ok_or(EdgeError::CounterExhausted)?;

        // Длина идёт в связанные данные, а не только в заголовок:
        // иначе посредник мог бы переписать её, не тронув шифртекст.
        let len = u16::try_from(plain.len()).map_err(|_| EdgeError::TooLong)?;
        let header = len.to_be_bytes();

        let sealed = self
            .sending
            .encrypt(
                &Self::nonce(counter),
                Payload {
                    msg: plain,
                    aad: &header,
                },
            )
            .map_err(|_| EdgeError::BadRecord)?;

        let mut out = Vec::with_capacity(2 + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Расшифровать запись, у которой уже известна длина нагрузки.
    ///
    /// # Errors
    ///
    /// [`EdgeError::BadRecord`] при подмене или сбое счётчика.
    pub fn open(&mut self, header: [u8; 2], sealed: &[u8]) -> Result<Vec<u8>, EdgeError> {
        let counter = self.received;
        let plain = self
            .receiving
            .decrypt(
                &Self::nonce(counter),
                Payload {
                    msg: sealed,
                    aad: &header,
                },
            )
            .map_err(|_| EdgeError::BadRecord)?;
        self.received = self
            .received
            .checked_add(1)
            .ok_or(EdgeError::CounterExhausted)?;
        Ok(plain)
    }
}

/// Поток поверх сессии: снаружи обычные чтение и запись.
#[derive(Debug)]
pub struct EdgeStream<S> {
    inner: S,
    session: Session,
    ready: Vec<u8>,
    taken: usize,
    finished: bool,
}

impl<S: Read + Write> EdgeStream<S> {
    /// Обернуть поток согласованной сессией.
    pub const fn new(inner: S, session: Session) -> Self {
        Self {
            inner,
            session,
            ready: Vec::new(),
            taken: 0,
            finished: false,
        }
    }

    /// Подключиться как клиент: провести согласование поверх потока.
    ///
    /// # Errors
    ///
    /// Ошибка ввода-вывода или [`EdgeError`], если край не тот.
    pub fn connect(mut inner: S, secret: &[u8; SECRET_LEN], now: u64) -> io::Result<Self> {
        let (handshake, hello) = Handshake::start(secret, now);
        inner.write_all(&hello)?;
        inner.flush()?;

        let mut response = [0_u8; SERVER_HELLO_LEN];
        inner.read_exact(&mut response)?;
        let session = handshake.finish(&response)?;
        Ok(Self::new(inner, session))
    }

    /// Принять клиента: прочитать приветствие и ответить.
    ///
    /// # Errors
    ///
    /// Ошибка ввода-вывода или [`EdgeError`].
    pub fn accept(mut inner: S, secret: &[u8; SECRET_LEN], now: u64) -> io::Result<Self> {
        let mut hello = [0_u8; CLIENT_HELLO_LEN];
        inner.read_exact(&mut hello)?;
        let (response, session) = respond(secret, &hello, now)?;
        inner.write_all(&response)?;
        inner.flush()?;
        Ok(Self::new(inner, session))
    }

    /// Вернуть нижний слой.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Read + Write> Read for EdgeStream<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.taken == self.ready.len() {
            if self.finished {
                return Ok(0);
            }
            let mut header = [0_u8; 2];
            match self.inner.read_exact(&mut header) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    self.finished = true;
                    return Ok(0);
                }
                Err(error) => return Err(error),
            }

            let len = usize::from(u16::from_be_bytes(header));
            // Тег имитовставки идёт следом за нагрузкой.
            let total = len
                .checked_add(16)
                .ok_or_else(|| io::Error::from(EdgeError::TooLong))?;
            if len > MAX_RECORD {
                return Err(EdgeError::TooLong.into());
            }

            let mut sealed = vec![0_u8; total];
            self.inner.read_exact(&mut sealed)?;
            self.ready = self.session.open(header, &sealed)?;
            self.taken = 0;
        }

        let left = self.ready.len() - self.taken;
        let take = left.min(out.len());
        out.get_mut(..take)
            .zip(self.ready.get(self.taken..self.taken + take))
            .map(|(dst, src)| dst.copy_from_slice(src))
            .ok_or_else(|| io::Error::other("нарушен учёт готовых байт"))?;
        self.taken += take;
        Ok(take)
    }
}

impl<S: Read + Write> Write for EdgeStream<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let take = data.len().min(MAX_RECORD);
        let chunk = data.get(..take).unwrap_or_default();
        let sealed = self.session.seal(chunk)?;
        self.inner.write_all(&sealed)?;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const SECRET: [u8; SECRET_LEN] = [7; SECRET_LEN];
    const NOW: u64 = 1_800_000_000;

    fn agreed() -> (Session, Session) {
        let (handshake, hello) = Handshake::start(&SECRET, NOW);
        let (response, edge) = respond(&SECRET, &hello, NOW).expect("край отвечает");
        let client = handshake.finish(&response).expect("клиент принимает");
        (client, edge)
    }

    #[test]
    fn both_sides_arrive_at_the_same_keys() {
        let (mut client, mut edge) = agreed();

        let wire = client.seal("привет краю".as_bytes()).expect("шифрование");
        let header = [wire[0], wire[1]];
        let plain = edge.open(header, &wire[2..]).expect("расшифровка");
        assert_eq!(plain, "привет краю".as_bytes());

        let back = edge.seal("привет клиенту".as_bytes()).expect("шифрование");
        let header = [back[0], back[1]];
        let plain = client.open(header, &back[2..]).expect("расшифровка");
        assert_eq!(plain, "привет клиенту".as_bytes());
    }

    // Главное свойство: без секрета к краю не подступиться. Именно это
    // заменяет проверку цепочки сертификатов.
    #[test]
    fn a_stranger_without_the_secret_is_refused() {
        let (_, hello) = Handshake::start(&[9; SECRET_LEN], NOW);
        assert_eq!(
            respond(&SECRET, &hello, NOW).map(|_| ()),
            Err(EdgeError::BadMac)
        );
    }

    // Посредник, подменивший TLS площадки, не знает секрета — и его
    // ответ не проходит проверку у клиента.
    #[test]
    fn an_impostor_edge_is_caught_by_the_client() {
        let (handshake, _) = Handshake::start(&SECRET, NOW);

        // Подделыватель подменил TLS площадки и отвечает своей долей.
        // Секрета у него нет, поэтому отпечаток он считает по чужому.
        let forged_share = [3_u8; SHARE_LEN];
        let forged_tag = mac(
            &[9; SECRET_LEN],
            SERVER_LABEL,
            &[&handshake.share, &forged_share],
        );
        let mut forged = [0_u8; SERVER_HELLO_LEN];
        forged[..SHARE_LEN].copy_from_slice(&forged_share);
        forged[SHARE_LEN..].copy_from_slice(&forged_tag);

        assert_eq!(
            handshake.finish(&forged).map(|_| ()),
            Err(EdgeError::BadMac)
        );
    }

    // И обратное: посторонний, подключающийся к чужому краю, не может
    // даже начать — его приветствие не проходит проверку отпечатка.
    #[test]
    fn an_impostor_cannot_even_open_a_session() {
        let (_, hello) = Handshake::start(&[9; SECRET_LEN], NOW);
        assert_eq!(
            respond(&SECRET, &hello, NOW).map(|_| ()),
            Err(EdgeError::BadMac)
        );
    }

    #[test]
    fn a_stale_hello_is_refused() {
        let (_, hello) = Handshake::start(&SECRET, NOW);
        assert_eq!(
            respond(&SECRET, &hello, NOW + CLOCK_SKEW_SECS + 1).map(|_| ()),
            Err(EdgeError::StaleTime)
        );
        assert!(
            respond(&SECRET, &hello, NOW + CLOCK_SKEW_SECS).is_ok(),
            "внутри окна расхождение часов допустимо"
        );
    }

    // Перехваченное приветствие можно повторить — и это ничего не даёт:
    // край каждый раз берёт новую эфемерную долю, поэтому ключи сессии
    // у повторяющего не сходятся с теми, что были.
    #[test]
    fn replaying_a_hello_yields_no_usable_session() {
        let (handshake, hello) = Handshake::start(&SECRET, NOW);
        let (first, _) = respond(&SECRET, &hello, NOW).expect("первый ответ");
        let (second, mut second_edge) = respond(&SECRET, &hello, NOW).expect("повтор");
        assert_ne!(first, second, "край обязан отвечать новой долей");

        let mut client = handshake
            .finish(&first)
            .expect("клиент принял первый ответ");
        let wire = client.seal("тайна".as_bytes()).expect("шифрование");
        assert_eq!(
            second_edge.open([wire[0], wire[1]], &wire[2..]).map(|_| ()),
            Err(EdgeError::BadRecord),
            "ключи повторной сессии не подходят к первой"
        );
    }

    #[test]
    fn a_tampered_record_is_refused() {
        let (mut client, mut edge) = agreed();
        let mut wire = client.seal("исходное".as_bytes()).expect("шифрование");
        let last = wire.len() - 1;
        wire[last] ^= 1;
        assert_eq!(
            edge.open([wire[0], wire[1]], &wire[2..]).map(|_| ()),
            Err(EdgeError::BadRecord)
        );
    }

    // Длина лежит в связанных данных, поэтому переписать её молча
    // нельзя даже не трогая шифртекст.
    #[test]
    fn a_rewritten_length_is_refused() {
        let (mut client, mut edge) = agreed();
        let wire = client.seal("восемь!!".as_bytes()).expect("шифрование");
        assert_eq!(
            edge.open([0, 7], &wire[2..]).map(|_| ()),
            Err(EdgeError::BadRecord)
        );
    }

    // Счётчик направления — не украшение: без него запись можно было бы
    // переставить или повторить внутри одной сессии.
    #[test]
    fn records_out_of_order_are_refused() {
        let (mut client, mut edge) = agreed();
        let first = client.seal("раз".as_bytes()).expect("первая");
        let second = client.seal("два".as_bytes()).expect("вторая");

        assert_eq!(
            edge.open([second[0], second[1]], &second[2..]).map(|_| ()),
            Err(EdgeError::BadRecord),
            "вторую запись нельзя открыть вперёд первой"
        );
        // После отказа счётчик не сдвинулся, и порядок восстановим.
        assert_eq!(
            edge.open([first[0], first[1]], &first[2..])
                .expect("первая"),
            "раз".as_bytes()
        );
    }

    #[test]
    fn an_oversized_payload_is_refused() {
        let (mut client, _) = agreed();
        assert_eq!(
            client.seal(&vec![0_u8; MAX_RECORD + 1]).map(|_| ()),
            Err(EdgeError::TooLong)
        );
    }

    #[test]
    fn a_truncated_hello_is_refused() {
        let (_, hello) = Handshake::start(&SECRET, NOW);
        for cut in [0, 1, SHARE_LEN, CLIENT_HELLO_LEN - 1] {
            assert_eq!(
                respond(&SECRET, &hello[..cut], NOW).map(|_| ()),
                Err(EdgeError::Truncated),
                "обрезанное до {cut} байт приветствие обязано быть отклонено"
            );
        }
    }

    // Проверка живого потока, а не отдельных записей: границы записей
    // не совпадают с границами чтений точно так же, как у кадров.
    #[test]
    fn the_stream_carries_data_across_record_boundaries() {
        use std::io::{Read as _, Write as _};

        let (client_pipe, edge_pipe) = crate::testing::duplex();

        let worker = std::thread::spawn(move || {
            let mut edge = EdgeStream::accept(edge_pipe, &SECRET, NOW).expect("край принял");
            let mut got = Vec::new();
            let mut chunk = [0_u8; 7];
            while got.len() < "одиндватри".len() {
                let read = edge.read(&mut chunk).expect("чтение");
                assert_ne!(read, 0, "поток кончился раньше данных");
                got.extend_from_slice(&chunk[..read]);
            }
            edge.write_all("принято".as_bytes()).expect("ответ");
            got
        });

        let mut client = EdgeStream::connect(client_pipe, &SECRET, NOW).expect("клиент соединился");
        for part in ["один", "два", "три"] {
            client.write_all(part.as_bytes()).expect("запись");
        }

        let mut back = [0_u8; 32];
        let read = client.read(&mut back).expect("чтение ответа");
        assert_eq!(&back[..read], "принято".as_bytes());
        assert_eq!(
            String::from_utf8(worker.join().expect("поток края")).unwrap(),
            "одиндватри"
        );
    }
}
