//! Серверная сторона TLS 1.3.
//!
//! Зеркало [`crate::client`]: тот же слой записей, то же расписание
//! ключей, тот же транскрипт — только пачки идут в обратном порядке.
//!
//! # Зачем она нам
//!
//! Клиенту нужен собеседник. Пока его нет, весь стек проверяется либо
//! эталонными векторами, либо чужими серверами, к которым мы не имеем
//! отношения. Своя серверная сторона закрывает круг: она нужна и для
//! сквозных проверок на сборке, и — главное — для **точки выхода**,
//! которую разворачивает у себя сам пользователь.
//!
//! # Чем она сознательно ограничена
//!
//! Это не универсальный сервер TLS и не пытается им быть.
//!
//! * Подпись только Ed25519. Сертификат точка выхода генерирует сама, и
//!   выбирать алгоритм ей не у кого; тащить ради этого RSA и ECDSA
//!   значило бы утроить объём кода без единого нового сценария.
//! * Возобновления сессий нет — как и у клиента, и по той же причине:
//!   билет связывает соединения одного пользователя между собой.
//! * ALPS не согласовывается. Расширение полезно браузеру, а точке
//!   выхода не нужно; не отвечая на него, мы избавляем клиента от
//!   лишнего сообщения.
//! * Сжатие сертификата не применяется, хотя клиент его предлагает:
//!   RFC 8879 разрешает не пользоваться.
//!
//! Всё перечисленное — про **нашу** точку выхода. Маскировка под
//! браузер живёт на стороне клиента; сервер прикрытия, за которого мы
//! себя выдаём, — настоящий чужой сайт, и подделывать его отпечаток не
//! требуется.

use subtle::ConstantTimeEq as _;

use crate::bytes::Writer;
use crate::error::{Error, Result};
use crate::ext;
pub use crate::halves::{RecordReader, RecordWriter};
use crate::handshake::{
    build_message, CertificateVerify, HandshakeType, Message, MessageReader, Transcript,
};
use crate::hello::ClientHello;
use crate::keyexchange::{Group, KeyExchange};
use crate::keyschedule::{expand_label, traffic_keys, verify_data, Hash, KeySchedule};
use crate::record::{Aead, ContentType, Protection, HEADER_LEN, MAX_PLAINTEXT};

/// Алгоритм подписи `ed25519` в реестре `signature_algorithms`.
pub const ED25519: u16 = 0x0807;

/// Шифронаборы, которые мы готовы выбрать, в порядке предпочтения.
const SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];

/// Наибольший объём непрочитанного ввода.
const MAX_BUFFERED: usize = 1 << 20;

/// Учётные данные, которыми сервер доказывает свою личность.
#[derive(Debug)]
pub struct Credentials {
    /// Цепочка сертификатов в формате DER; первый — конечный.
    pub chain: Vec<Vec<u8>>,
    /// Ключ Ed25519, которым подписывается `CertificateVerify`.
    pub key: atlas_crypto::sign::ClassicKey,
}

/// Откуда сервер берёт сертификат для конкретного приветствия.
///
/// Не поле, а точка расширения: REALITY порождает **свой** сертификат
/// на каждое соединение, и порождает его из содержимого приветствия —
/// из метки, спрятанной в `session_id`.
///
/// # Почему два шага
///
/// Решение «наш ли это клиент» обязано быть принято **до** ответа:
/// постороннему соединению вообще не следует отвечать, его надо увести
/// на сайт прикрытия, и любой наш байт в ответ уже был бы отличием.
///
/// А сертификат, наоборот, может зависеть от `ServerHello`: в REALITY
/// постквантовая подпись покрывает оба приветствия сразу и потому
/// строится, когда ответ уже собран. Отсюда разделение: [`accept`]
/// решает, [`Pending::finish`] выпускает.
///
/// [`accept`]: CertificateSource::accept
pub trait CertificateSource: core::fmt::Debug + Send + Sync {
    /// Решить, обслуживаем ли мы этого клиента.
    ///
    /// `raw` — те самые байты сообщения, что пришли по проводу.
    /// Разобранного приветствия недостаточно: REALITY аутентифицирует
    /// метку по **всему сообщению целиком**, и пересборка из полей
    /// расходится с оригиналом в дополнении и порядке расширений.
    ///
    /// # Errors
    ///
    /// Отказ означает, что клиент нам незнаком. Вызывающий обязан
    /// поступить с соединением так же, как с любым посторонним, —
    /// для REALITY это увести его на сайт прикрытия.
    fn accept(&self, hello: &ClientHello, raw: &[u8]) -> Result<Box<dyn Pending>>;
}

/// Отложенный выпуск сертификата.
pub trait Pending: core::fmt::Debug + Send {
    /// Выпустить сертификат, когда `ServerHello` уже собран.
    ///
    /// # Errors
    ///
    /// Отказ выпуска — уже после того, как клиент признан своим.
    fn finish(self: Box<Self>, server_hello: &[u8]) -> Result<Credentials>;
}

/// Готовые учётные данные, не зависящие от `ServerHello`.
///
/// Обычный случай для всех, кроме REALITY.
#[derive(Debug)]
pub struct Ready(pub Credentials);

impl Pending for Ready {
    fn finish(self: Box<Self>, _server_hello: &[u8]) -> Result<Credentials> {
        Ok(self.0)
    }
}

/// Настройки сервера.
#[derive(Debug)]
pub struct ServerConfig {
    /// Источник сертификата.
    pub certificates: Box<dyn CertificateSource>,
    /// Протоколы прикладного уровня в порядке предпочтения сервера.
    ///
    /// Пусто — значит ALPN не согласовывается вовсе.
    pub alpn: Vec<String>,
}

impl ServerConfig {
    /// Настройки с указанным источником сертификата.
    #[must_use]
    pub fn new(certificates: Box<dyn CertificateSource>) -> Self {
        Self {
            certificates,
            alpn: Vec::new(),
        }
    }

    /// Задать список ALPN.
    #[must_use]
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    WaitClientHello,
    WaitFinished,
    Connected,
    Closed,
}

/// Соединение со стороны сервера, без ввода-вывода.
#[derive(Debug)]
pub struct ServerConnection {
    config: ServerConfig,
    state: State,

    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    plaintext: Vec<u8>,
    messages: MessageReader,
    transcript: Transcript,

    hash: Hash,
    aead: Aead,
    cipher_suite: Option<u16>,
    group: Option<Group>,
    schedule: Option<KeySchedule>,
    client_handshake_secret: Vec<u8>,
    server_handshake_secret: Vec<u8>,
    client_application_secret: Vec<u8>,
    server_application_secret: Vec<u8>,
    read: Option<Protection>,
    write: Option<Protection>,

    alpn: Option<String>,
    failure: Option<Error>,
    peer_closed: bool,
}

impl ServerConnection {
    /// Создать соединение, ожидающее приветствия клиента.
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            state: State::WaitClientHello,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            plaintext: Vec::new(),
            messages: MessageReader::new(),
            transcript: Transcript::new(Hash::Sha256),
            hash: Hash::Sha256,
            aead: Aead::Aes128Gcm,
            cipher_suite: None,
            group: None,
            schedule: None,
            client_handshake_secret: Vec::new(),
            server_handshake_secret: Vec::new(),
            client_application_secret: Vec::new(),
            server_application_secret: Vec::new(),
            read: None,
            write: None,
            alpn: None,
            failure: None,
            peer_closed: false,
        }
    }

    /// Принять байты от клиента.
    ///
    /// # Errors
    ///
    /// Сохранённая ошибка либо переполнение буфера.
    pub fn read_tls(&mut self, data: &[u8]) -> Result<()> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        if self.incoming.len().saturating_add(data.len()) > MAX_BUFFERED {
            return Err(self.fail(Error::Protocol("входной буфер переполнен")));
        }
        self.incoming.extend_from_slice(data);
        Ok(())
    }

    /// Забрать байты для отправки.
    #[must_use]
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }

    /// Есть ли что отправлять.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Забрать расшифрованные прикладные данные.
    #[must_use]
    pub fn take_plaintext(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.plaintext)
    }

    /// Идёт ли ещё рукопожатие.
    #[must_use]
    pub const fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Connected | State::Closed)
    }

    /// Закрыл ли клиент свою сторону.
    #[must_use]
    pub const fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Согласованный протокол прикладного уровня.
    #[must_use]
    pub fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    /// Выбранный шифронабор.
    #[must_use]
    pub const fn cipher_suite(&self) -> Option<u16> {
        self.cipher_suite
    }

    /// Группа обмена ключами, на которой сошлись.
    #[must_use]
    pub const fn group(&self) -> Option<Group> {
        self.group
    }

    /// Ошибка, которая убила соединение.
    #[must_use]
    pub const fn failure(&self) -> Option<Error> {
        self.failure
    }

    /// Продвинуть автомат.
    ///
    /// # Errors
    ///
    /// Любое нарушение протокола со стороны клиента.
    pub fn process(&mut self) -> Result<()> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        match self.advance() {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fail(error)),
        }
    }

    fn advance(&mut self) -> Result<()> {
        while let Some(record) = self.next_record() {
            self.handle_record(&record)?;
            if self.state == State::Closed {
                break;
            }
        }
        Ok(())
    }

    /// Похоронить соединение — по той же причине, что и у клиента.
    fn fail(&mut self, error: Error) -> Error {
        self.state = State::Closed;
        self.failure = Some(error);
        self.read = None;
        self.write = None;
        self.incoming.clear();
        self.messages = MessageReader::new();
        error
    }

    fn next_record(&mut self) -> Option<Vec<u8>> {
        let header = self.incoming.get(..HEADER_LEN)?;
        let declared = match header {
            [_, _, _, hi, lo] => usize::from(u16::from_be_bytes([*hi, *lo])),
            _ => return None,
        };
        let total = HEADER_LEN.checked_add(declared)?;
        if self.incoming.len() < total {
            return None;
        }
        let record = self.incoming.get(..total)?.to_vec();
        self.incoming.drain(..total);
        Some(record)
    }

    fn handle_record(&mut self, record: &[u8]) -> Result<()> {
        let outer = ContentType::from_code(*record.first().unwrap_or(&0))?;
        if outer == ContentType::ChangeCipherSpec {
            return Ok(());
        }

        let (content_type, body) = match self.read.as_mut() {
            None => (outer, record.get(HEADER_LEN..).unwrap_or_default().to_vec()),
            Some(protection) => {
                if outer != ContentType::ApplicationData {
                    return Err(Error::Protocol("открытая запись после установки ключей"));
                }
                protection.decrypt(record)?
            }
        };

        match content_type {
            ContentType::Handshake => {
                self.messages.push(&body);
                while let Some(message) = self.messages.next_message()? {
                    self.handle_message(&message)?;
                    if self.state == State::Closed {
                        break;
                    }
                }
                Ok(())
            }
            ContentType::ApplicationData => {
                if self.state == State::Connected {
                    self.plaintext.extend_from_slice(&body);
                    Ok(())
                } else {
                    Err(Error::Protocol("прикладные данные до конца рукопожатия"))
                }
            }
            ContentType::Alert => self.handle_alert(&body),
            ContentType::ChangeCipherSpec => Ok(()),
        }
    }

    fn handle_alert(&mut self, body: &[u8]) -> Result<()> {
        const CLOSE_NOTIFY: u8 = 0;
        match body {
            [_, CLOSE_NOTIFY] => {
                self.peer_closed = true;
                Ok(())
            }
            [_, description] => Err(Error::Alert(*description)),
            _ => Err(Error::Malformed("предупреждение неверной длины")),
        }
    }

    fn handle_message(&mut self, message: &Message) -> Result<()> {
        match self.state {
            State::WaitClientHello => self.handle_client_hello(message),
            State::WaitFinished => self.handle_client_finished(message),
            // Клиент вправе прислать `KeyUpdate`; сессионные билеты мы не
            // выдаём, поэтому больше ждать нечего.
            State::Connected => match message.msg_type {
                HandshakeType::KeyUpdate => self.handle_key_update(&message.body),
                _ => Err(Error::Protocol("недопустимое сообщение после рукопожатия")),
            },
            State::Closed => Err(Error::Closed),
        }
    }

    // ── Приветствие клиента и вся ответная пачка ─────────────────────

    fn handle_client_hello(&mut self, message: &Message) -> Result<()> {
        if message.msg_type != HandshakeType::ClientHello {
            return Err(Error::Protocol("ожидался ClientHello"));
        }
        let hello = ClientHello::parse(&message.raw)?;

        if !offers_tls13(&hello) {
            return Err(Error::Unsupported("клиент не предлагает TLS 1.3"));
        }

        let suite = choose_cipher_suite(&hello.cipher_suites)
            .ok_or(Error::Unsupported("ни один шифронабор не подходит"))?;
        let hash = Hash::for_cipher_suite(suite).ok_or(Error::Unsupported("шифронабор"))?;
        let aead = Aead::for_cipher_suite(suite).ok_or(Error::Unsupported("шифронабор"))?;
        self.hash = hash;
        self.aead = aead;
        self.cipher_suite = Some(suite);
        self.transcript.set_hash(hash);

        // Решение об обслуживании принимается **до** ответа: отказ
        // здесь означает, что клиент нам незнаком, и отвечать ему
        // нечего — соединение вообще не наше.
        let pending = self.config.certificates.accept(&hello, &message.raw)?;

        let (group, client_share) = choose_key_share(&hello)
            .ok_or(Error::Protocol("клиент не прислал пригодной доли обмена"))?;
        let (server_share, shared) = KeyExchange::respond(group, &client_share)?;
        self.group = Some(group);

        self.transcript.extend(&message.raw);
        let server_hello = self.send_server_hello(&hello, suite, group, &server_share)?;
        let credentials = pending.finish(&server_hello)?;

        let mut schedule = KeySchedule::new(hash);
        schedule.enter_handshake(&shared);
        let transcript_hash = self.transcript.hash();
        self.client_handshake_secret = schedule.client_handshake_traffic_secret(&transcript_hash);
        self.server_handshake_secret = schedule.server_handshake_traffic_secret(&transcript_hash);
        self.schedule = Some(schedule);

        self.read = Some(Protection::new(
            aead,
            traffic_keys(hash, &self.client_handshake_secret, aead.key_len()),
        )?);
        self.write = Some(Protection::new(
            aead,
            traffic_keys(hash, &self.server_handshake_secret, aead.key_len()),
        )?);

        // Запись совместимости — её шлют все настоящие серверы.
        self.outgoing.extend_from_slice(&[
            ContentType::ChangeCipherSpec.code(),
            0x03,
            0x03,
            0x00,
            0x01,
            0x01,
        ]);

        self.alpn = choose_alpn(&hello, &self.config.alpn);
        self.send_flight(&credentials)?;
        self.state = State::WaitFinished;
        Ok(())
    }

    fn send_server_hello(
        &mut self,
        hello: &ClientHello,
        suite: u16,
        group: Group,
        share: &[u8],
    ) -> Result<Vec<u8>> {
        let mut key_share = Writer::new();
        key_share.u16(group.code());
        key_share.nested_u16(|body| body.bytes(share))?;

        let mut extensions = Writer::new();
        extensions.u16(ext::SUPPORTED_VERSIONS);
        extensions.nested_u16(|body| body.u16(0x0304))?;
        extensions.u16(ext::KEY_SHARE);
        let share_bytes = key_share.finish();
        extensions.nested_u16(|body| body.bytes(&share_bytes))?;

        let mut body = Writer::new();
        body.u16(0x0303);
        body.bytes(&atlas_crypto::rng::OsRng::bytes::<32>());
        // Эхо идентификатора сессии обязательно: клиент сверяет его и
        // рвёт соединение при расхождении.
        body.nested_u8(|out| out.bytes(&hello.session_id))?;
        body.u16(suite);
        body.u8(0);
        let extension_bytes = extensions.finish();
        body.nested_u16(|out| out.bytes(&extension_bytes))?;

        let message = build_message(HandshakeType::ServerHello, &body.finish())?;
        self.transcript.extend(&message);

        let mut record = Vec::with_capacity(message.len() + HEADER_LEN);
        record.push(ContentType::Handshake.code());
        record.extend_from_slice(&0x0303_u16.to_be_bytes());
        let length = u16::try_from(message.len()).map_err(|_| Error::TooLong)?;
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(&message);
        self.outgoing.extend_from_slice(&record);
        Ok(message)
    }

    fn send_flight(&mut self, credentials: &Credentials) -> Result<()> {
        // EncryptedExtensions: только ALPN, если о нём договорились.
        let mut extensions = Writer::new();
        if let Some(name) = self.alpn.clone() {
            extensions.u16(ext::ALPN);
            let mut list = Writer::new();
            list.nested_u16(|names| {
                let _ = names.nested_u8(|item| item.bytes(name.as_bytes()));
            })?;
            let list_bytes = list.finish();
            extensions.nested_u16(|body| body.bytes(&list_bytes))?;
        }
        let mut encrypted = Writer::new();
        let extension_bytes = extensions.finish();
        encrypted.nested_u16(|body| body.bytes(&extension_bytes))?;
        self.emit(HandshakeType::EncryptedExtensions, &encrypted.finish())?;

        // Certificate: пустой контекст, затем цепочка.
        let mut certificate = Writer::new();
        certificate.nested_u8(|context| context.bytes(&[]))?;
        let mut list = Writer::new();
        for entry in &credentials.chain {
            list.nested_u24(|body| body.bytes(entry))?;
            list.nested_u16(|body| body.bytes(&[]))?;
        }
        let list_bytes = list.finish();
        certificate.nested_u24(|body| body.bytes(&list_bytes))?;
        self.emit(HandshakeType::Certificate, &certificate.finish())?;

        // CertificateVerify над транскриптом.
        let signed = CertificateVerify::signed_data(&self.transcript.hash());
        let signature = credentials.key.sign(&signed);
        let mut verify = Writer::new();
        verify.u16(ED25519);
        verify.nested_u16(|body| body.bytes(&signature))?;
        self.emit(HandshakeType::CertificateVerify, &verify.finish())?;

        let data = verify_data(
            self.hash,
            &self.server_handshake_secret,
            &self.transcript.hash(),
        );
        self.emit(HandshakeType::Finished, &data)?;

        // Секреты приложения — от транскрипта по нашему `Finished`.
        let after = self.transcript.hash();
        let schedule = self
            .schedule
            .as_mut()
            .ok_or(Error::Protocol("расписание ключей не заведено"))?;
        schedule.enter_master();
        self.client_application_secret = schedule.client_application_traffic_secret(&after);
        self.server_application_secret = schedule.server_application_traffic_secret(&after);
        Ok(())
    }

    fn emit(&mut self, msg_type: HandshakeType, body: &[u8]) -> Result<()> {
        let message = build_message(msg_type, body)?;
        self.transcript.extend(&message);
        let protection = self
            .write
            .as_mut()
            .ok_or(Error::Protocol("нет ключей для записи"))?;
        let record = protection.encrypt(ContentType::Handshake, &message, 0)?;
        self.outgoing.extend_from_slice(&record);
        Ok(())
    }

    fn handle_client_finished(&mut self, message: &Message) -> Result<()> {
        // Клиент вправе прислать перед `Finished` свой `Certificate` и
        // `EncryptedExtensions` (ALPS). Мы их не запрашивали и не
        // согласовывали, но в транскрипт они обязаны попасть.
        if message.msg_type != HandshakeType::Finished {
            self.transcript.extend(&message.raw);
            return Ok(());
        }

        let expected = verify_data(
            self.hash,
            &self.client_handshake_secret,
            &self.transcript.hash(),
        );
        if !bool::from(expected.ct_eq(&message.body)) {
            return Err(Error::Untrusted("Finished клиента не сошёлся"));
        }
        self.transcript.extend(&message.raw);

        let (hash, aead) = (self.hash, self.aead);
        self.read = Some(Protection::new(
            aead,
            traffic_keys(hash, &self.client_application_secret, aead.key_len()),
        )?);
        self.write = Some(Protection::new(
            aead,
            traffic_keys(hash, &self.server_application_secret, aead.key_len()),
        )?);

        self.state = State::Connected;
        Ok(())
    }

    fn handle_key_update(&mut self, body: &[u8]) -> Result<()> {
        const NOT_REQUESTED: u8 = 0;
        const REQUESTED: u8 = 1;

        let request = match body {
            [value] => *value,
            _ => return Err(Error::Malformed("KeyUpdate неверной длины")),
        };

        self.client_application_secret = expand_label(
            self.hash,
            &self.client_application_secret,
            "traffic upd",
            &[],
            self.hash.len(),
        );
        self.read = Some(Protection::new(
            self.aead,
            traffic_keys(
                self.hash,
                &self.client_application_secret,
                self.aead.key_len(),
            ),
        )?);

        match request {
            NOT_REQUESTED => Ok(()),
            REQUESTED => {
                let answer = build_message(HandshakeType::KeyUpdate, &[NOT_REQUESTED])?;
                let protection = self
                    .write
                    .as_mut()
                    .ok_or(Error::Protocol("нет ключей для записи"))?;
                let record = protection.encrypt(ContentType::Handshake, &answer, 0)?;
                self.outgoing.extend_from_slice(&record);

                self.server_application_secret = expand_label(
                    self.hash,
                    &self.server_application_secret,
                    "traffic upd",
                    &[],
                    self.hash.len(),
                );
                self.write = Some(Protection::new(
                    self.aead,
                    traffic_keys(
                        self.hash,
                        &self.server_application_secret,
                        self.aead.key_len(),
                    ),
                )?);
                Ok(())
            }
            _ => Err(Error::Malformed("неизвестное значение в KeyUpdate")),
        }
    }

    /// Разъять установленное соединение на две независимые половины.
    ///
    /// Нужно для перекачки в обе стороны: каждый поток получает свою
    /// половину и работает с ней без замка.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`], если рукопожатие ещё не завершено.
    pub fn into_halves(self) -> Result<(RecordReader, RecordWriter)> {
        if self.state != State::Connected {
            return Err(Error::Protocol("соединение не установлено"));
        }
        let (Some(read), Some(write)) = (self.read, self.write) else {
            return Err(Error::Protocol("ключи не поставлены"));
        };
        Ok((
            RecordReader {
                protection: read,
                buffer: self.incoming,
                closed: self.peer_closed,
            },
            RecordWriter { protection: write },
        ))
    }

    /// Зашифровать прикладные данные.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] до конца рукопожатия, [`Error::Closed`] после
    /// закрытия.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        match self.state {
            State::Connected => {}
            State::Closed => return Err(Error::Closed),
            _ => return Err(Error::Protocol("отправка до конца рукопожатия")),
        }

        for chunk in data.chunks(MAX_PLAINTEXT - 1) {
            let protection = self
                .write
                .as_mut()
                .ok_or(Error::Protocol("нет ключей для записи"))?;
            let record = protection.encrypt(ContentType::ApplicationData, chunk, 0)?;
            self.outgoing.extend_from_slice(&record);
        }
        Ok(())
    }
}

/// Предлагает ли клиент TLS 1.3 в `supported_versions`.
fn offers_tls13(hello: &ClientHello) -> bool {
    hello.supported_versions().contains(&0x0304)
}

/// Выбрать шифронабор: наше предпочтение среди предложенного клиентом.
fn choose_cipher_suite(offered: &[u16]) -> Option<u16> {
    SUITES.into_iter().find(|suite| offered.contains(suite))
}

/// Выбрать долю обмена среди присланных клиентом.
///
/// Предпочтение постквантовой группе: если клиент её прислал, брать
/// классическую было бы сознательным ослаблением.
fn choose_key_share(hello: &ClientHello) -> Option<(Group, Vec<u8>)> {
    let extension = hello.extension(ext::KEY_SHARE)?;
    let mut outer = crate::bytes::Reader::new(&extension.body);
    let mut list = crate::bytes::Reader::new(outer.vec_u16().ok()?);

    let mut best: Option<(Group, Vec<u8>)> = None;
    while !list.is_empty() {
        let code = list.u16().ok()?;
        let share = list.vec_u16().ok()?;
        let Some(group) = Group::from_code(code) else {
            continue;
        };
        if share.len() != group.client_share_len() {
            continue;
        }
        let better = match best {
            None => true,
            Some((current, _)) => rank(group) < rank(current),
        };
        if better {
            best = Some((group, share.to_vec()));
        }
    }
    best
}

/// Чем меньше, тем предпочтительнее.
const fn rank(group: Group) -> u8 {
    match group {
        Group::X25519MlKem768 => 0,
        Group::X25519 => 1,
        Group::Secp256r1 => 2,
        Group::Secp384r1 => 3,
    }
}

/// Выбрать протокол: первый из наших, который предложил клиент.
fn choose_alpn(hello: &ClientHello, preference: &[String]) -> Option<String> {
    if preference.is_empty() {
        return None;
    }
    let offered = hello.alpn();
    preference
        .iter()
        .find(|name| offered.iter().any(|other| other == *name))
        .cloned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{Chrome, HelloParams};

    #[test]
    fn the_strongest_offered_group_wins() {
        let params = HelloParams::new("example.org").with_key_shares(vec![
            (crate::profile::X25519, vec![0x11; 32]),
            (crate::profile::X25519_MLKEM768, vec![0x22; 1216]),
        ]);
        let hello = Chrome::v141().client_hello(&params).unwrap();
        let (group, share) = choose_key_share(&hello).unwrap();
        assert_eq!(
            group,
            Group::X25519MlKem768,
            "постквантовая предпочтительнее"
        );
        assert_eq!(share.len(), 1216);
    }

    #[test]
    fn a_share_of_the_wrong_length_is_ignored() {
        // В том числе фальшивая доля GREASE, которую шлёт браузер.
        let params = HelloParams::new("example.org")
            .with_key_shares(vec![(crate::profile::X25519, vec![0x11; 32])]);
        let hello = Chrome::v141().client_hello(&params).unwrap();
        let (group, share) = choose_key_share(&hello).unwrap();
        assert_eq!(group, Group::X25519);
        assert_eq!(share.len(), 32);
    }

    #[test]
    fn cipher_suites_follow_our_preference_not_theirs() {
        assert_eq!(choose_cipher_suite(&[0x1303, 0x1302, 0x1301]), Some(0x1301));
        assert_eq!(choose_cipher_suite(&[0x1303, 0x1302]), Some(0x1302));
        assert_eq!(choose_cipher_suite(&[0x009c]), None);
    }

    #[test]
    fn tls13_is_recognised_in_the_shuffled_extension_list() {
        let params = HelloParams::new("example.org");
        let hello = Chrome::v141().client_hello(&params).unwrap();
        assert!(offers_tls13(&hello));
    }

    #[test]
    fn alpn_is_only_selected_from_what_the_client_offered() {
        let params = HelloParams::new("example.org");
        let hello = Chrome::v141().client_hello(&params).unwrap();

        assert_eq!(
            choose_alpn(&hello, &["h2".to_owned()]),
            Some("h2".to_owned())
        );
        assert_eq!(choose_alpn(&hello, &["h3".to_owned()]), None);
        assert_eq!(choose_alpn(&hello, &[]), None);
    }
}
