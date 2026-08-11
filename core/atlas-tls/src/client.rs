//! Клиент TLS 1.3: конечный автомат рукопожатия и слой записей.
//!
//! # Почему без ввода-вывода
//!
//! Автомат не знает ни про сокеты, ни про время, ни про потоки. Наружу
//! он берёт байты ([`Connection::read_tls`]) и отдаёт байты
//! ([`Connection::take_output`]). Причина не в эстетике: клиент должен
//! одинаково работать поверх TCP на десктопе, поверх
//! `NEPacketTunnelProvider` на iOS, поверх WebSocket-кадров и поверх
//! WebRTC-канала, где «сокета» нет вовсе. Всё, что связано с настоящим
//! вводом-выводом, живёт отдельно — см. [`crate::stream`].
//!
//! # Что здесь происходит по шагам
//!
//! ```text
//! ClientHello                    ──►            (открытым текстом)
//!                                ◄──  ServerHello
//!   ↑ отсюда обе стороны знают общий секрет; ставятся ключи рукопожатия
//! (CCS, ради промежуточных узлов)  ──►
//!                                ◄──  EncryptedExtensions
//!                                ◄──  Certificate
//!                                ◄──  CertificateVerify
//!                                ◄──  Finished
//!   ↑ здесь проверяется Finished сервера и выводятся ключи приложения
//! Finished                       ──►
//!   ↑ после этого запись за записью идут прикладные данные
//! ```
//!
//! # Что сознательно не делается
//!
//! Цепочка сертификатов **не проверяется по системному хранилищу**. Для
//! нашего сценария это не упущение, а следствие устройства: сервер
//! прикрытия в REALITY — чужой настоящий сайт, его цепочка всегда
//! валидна и ничего не доказывает, а подлинность нашей точки выхода
//! подтверждается общим секретом, которого у чужого сервера нет.
//! Поэтому решение вынесено в [`ServerVerifier`], и в проекте будет
//! ровно одна честная реализация — REALITY.

use subtle::ConstantTimeEq as _;

use crate::error::{Error, Result};
use crate::ext;
use crate::halves::{RecordReader, RecordWriter};
use crate::handshake::{
    build_message, Certificate, CertificateVerify, CompressedCertificate, HandshakeType, Message,
    MessageReader, ServerHello, Transcript,
};
use crate::hello::ClientHello;
use crate::keyexchange::{Group, KeyShares};
use crate::keyschedule::{expand_label, traffic_keys, verify_data, Hash, KeySchedule};
use crate::profile::{HelloParams, Profile};
use crate::record::{Aead, ContentType, Protection, HEADER_LEN, MAX_PLAINTEXT};

/// Наибольшее число байт, которое мы готовы накопить, не увидев целой
/// записи. Защита от собеседника, который шлёт по байту.
const MAX_BUFFERED: usize = 1 << 20;

/// Версия в заголовке записи с первым приветствием.
///
/// Именно `0x0301`, а не `0x0303`: так делает `BoringSSL`, и значение
/// входит в то, что видит наблюдатель на первом же пакете.
const RECORD_VERSION_HELLO: u16 = 0x0301;

/// Сведения о сервере, по которым решается, доверять ли ему.
#[derive(Debug)]
pub struct PeerIdentity<'a> {
    /// Имя, которое мы отправили в SNI.
    pub server_name: &'a str,
    /// Цепочка сертификатов сервера; первый — конечный.
    pub certificate: &'a Certificate,
    /// Подпись сервера над транскриптом.
    pub certificate_verify: &'a CertificateVerify,
    /// Хэш транскрипта, над которым сделана подпись.
    pub transcript_hash: &'a [u8],
    /// Сырые байты нашего `ClientHello` — того, что реально ушло.
    ///
    /// Нужны REALITY: постквантовое подтверждение привязано к конкретному
    /// рукопожатию именно через них. После `HelloRetryRequest` здесь
    /// лежит второе приветствие.
    pub client_hello: &'a [u8],
    /// Сырые байты `ServerHello`.
    pub server_hello: &'a [u8],
}

/// Правило принятия сервера.
///
/// Заменяет проверку цепочки по системному хранилищу. Реализация решает
/// сама, что для неё доказательство подлинности: подпись по общему
/// секрету (REALITY), закреплённый ключ или что-то ещё.
pub trait ServerVerifier: core::fmt::Debug + Send + Sync {
    /// Принять или отвергнуть сервер.
    ///
    /// # Errors
    ///
    /// [`Error::Untrusted`], если сервер не тот, за кого себя выдаёт.
    fn verify(&self, peer: &PeerIdentity<'_>) -> Result<()>;
}

/// Принимает любой сервер.
///
/// Годится **только** для разведки и измерений: снять отпечаток, узнать
/// выбранный шифронабор, проверить, доходит ли рукопожатие до конца.
/// Для передачи данных не годится никогда — активный посредник
/// подменит сервер, и мы этого не заметим.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAnyServer;

impl ServerVerifier for AcceptAnyServer {
    fn verify(&self, _peer: &PeerIdentity<'_>) -> Result<()> {
        Ok(())
    }
}

/// Источник `legacy_session_id`.
///
/// Обычно это просто 32 случайных байта. REALITY кладёт туда
/// зашифрованную метку, и ключ для неё выводится из секретной части доли
/// `x25519` — поэтому источник получает доступ к уже сгенерированным
/// долям, а не наоборот.
pub trait SessionIdSource: core::fmt::Debug + Send + Sync {
    /// Выдать значение поля.
    ///
    /// # Errors
    ///
    /// Ошибка построения метки, если источник её строит.
    fn session_id(&self, shares: &KeyShares) -> Result<Vec<u8>>;
}

/// Правка готового `ClientHello` перед отправкой.
///
/// Существует ради REALITY и вряд ли понадобится кому-то ещё. Метка
/// REALITY лежит в `legacy_session_id`, но аутентифицирует **всё
/// сообщение целиком** — поэтому её нельзя выдать заранее, как обычное
/// значение поля: пока сообщение не собрано, шифровать нечего.
///
/// Отсюда правка на месте, уже над сериализованными байтами, и жёсткое
/// требование к реализации: **длина сообщения меняться не должна**.
/// Метка занимает ровно те же тридцать два байта, что и случайный
/// идентификатор сессии у браузера, — в этом весь смысл, отпечаток
/// обязан остаться браузерным.
pub trait HelloSealer: core::fmt::Debug + Send + Sync {
    /// Изменить сообщение на месте.
    ///
    /// `shares` даёт доступ к сгенерированным долям обмена: REALITY
    /// выводит ключ метки из секретной части доли `x25519`, и отдельной
    /// пары для этого не заводится — иначе на проводе появился бы лишний
    /// открытый ключ.
    ///
    /// # Errors
    ///
    /// Ошибка запечатывания.
    fn seal(&self, handshake: &mut [u8], shares: &KeyShares) -> Result<()>;
}

/// Случайный `session_id` — то, что шлёт обычный браузер.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomSessionId;

impl SessionIdSource for RandomSessionId {
    fn session_id(&self, _shares: &KeyShares) -> Result<Vec<u8>> {
        Ok(atlas_crypto::rng::OsRng::bytes::<32>().to_vec())
    }
}

/// Настройки клиента.
#[derive(Debug)]
pub struct ClientConfig {
    /// Значение SNI. Для REALITY — домен сайта прикрытия.
    pub server_name: String,
    /// Предлагаемые протоколы прикладного уровня.
    pub alpn: Vec<String>,
    /// Профиль отпечатка.
    pub profile: Profile,
    /// Группы обмена ключами в порядке предпочтения.
    pub groups: Vec<Group>,
    /// Кто решает, доверять ли серверу.
    pub verifier: Box<dyn ServerVerifier>,
    /// Откуда берётся `legacy_session_id`.
    pub session_id: Box<dyn SessionIdSource>,
    /// Правка готового приветствия перед отправкой — для REALITY.
    pub sealer: Option<Box<dyn HelloSealer>>,
    /// Содержимое нашей половины ALPS.
    ///
    /// Chrome объявляет `application_settings` и, когда сервер отвечает
    /// согласием, шлёт в ответ **пустые** настройки: полезная нагрузка
    /// в этом обмене идёт от сервера к клиенту (список `ACCEPT_CH`).
    /// Отсюда пустое значение по умолчанию.
    pub alps_settings: Vec<u8>,
}

impl ClientConfig {
    /// Настройки по умолчанию: профиль Firefox 148, его группы,
    /// случайный `session_id`, приём любого сервера.
    ///
    /// # Почему Firefox, а не Chrome
    ///
    /// По измерениям схемы фильтрации, действующей в России с июня
    /// 2026, отпечатки Chrome, Safari и iOS относятся к подозрительным,
    /// а Firefox, Android и Edge проходят. Прежний выбор Chrome ставил
    /// нас в подозрительное ведро без всякой пользы: сайту прикрытия
    /// безразлично, каким браузером к нему пришли.
    ///
    /// Проверку сервера обязан задать вызывающий — значение по умолчанию
    /// здесь небезопасно и годится только для разведки.
    #[must_use]
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            profile: Profile::default(),
            groups: vec![Group::X25519MlKem768, Group::X25519, Group::Secp256r1],
            verifier: Box::new(AcceptAnyServer),
            session_id: Box::new(RandomSessionId),
            sealer: None,
            alps_settings: Vec::new(),
        }
    }

    /// Задать проверку сервера.
    #[must_use]
    pub fn with_verifier(mut self, verifier: Box<dyn ServerVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Задать источник `session_id`.
    #[must_use]
    pub fn with_session_id(mut self, source: Box<dyn SessionIdSource>) -> Self {
        self.session_id = source;
        self
    }

    /// Задать правку готового приветствия.
    #[must_use]
    pub fn with_sealer(mut self, sealer: Box<dyn HelloSealer>) -> Self {
        self.sealer = Some(sealer);
        self
    }

    /// Задать профиль отпечатка.
    ///
    /// Вместе с профилем меняется и список групп обмена ключами: число
    /// долей в `key_share` — часть отпечатка, и у Chrome с Firefox оно
    /// разное. Оставить прежний список значило бы собрать приветствие,
    /// которого не бывает ни у одного браузера. Явный [`Self::groups`]
    /// после этого вызова по-прежнему имеет приоритет.
    #[must_use]
    pub fn with_profile(mut self, profile: impl Into<Profile>) -> Self {
        self.profile = profile.into();
        self.groups = self
            .profile
            .key_share_group_codes()
            .into_iter()
            .filter_map(Group::from_code)
            .collect();
        self
    }

    /// Задать список ALPN.
    #[must_use]
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn;
        self
    }
}

/// Состояние рукопожатия.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
    Closed,
}

/// Соединение TLS 1.3 без ввода-вывода.
// Четыре флага здесь — не разложенный конечный автомат, а четыре
// независимых факта о соединении: был ли повтор приветствия, ушла ли
// запись совместимости, просили ли у нас сертификат, закрыл ли
// собеседник свою сторону. Их произведение не образует осмысленных
// состояний, и сворачивать их в перечисление было бы хуже.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct Connection {
    config: ClientConfig,
    state: State,
    shares: KeyShares,
    hello: ClientHello,
    retried: bool,
    sealed: bool,
    sent_ccs: bool,
    certificate_requested: bool,

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

    /// Сырые байты отправленного приветствия и полученного ответа.
    /// Хранятся ради REALITY — см. [`PeerIdentity`].
    hello_raw: Vec<u8>,
    server_hello_raw: Vec<u8>,

    /// Причина, по которой соединение стало непригодным.
    ///
    /// Хранится, а не выводится заново: повторный вызов обязан вернуть
    /// **ту же** ошибку, иначе диагноз меняется от вызова к вызову и
    /// сбивает с толку — первая ошибка настоящая, последующие лишь
    /// следствия того, что автомат остался в промежуточном состоянии.
    failure: Option<Error>,
    certificate: Option<Certificate>,
    alpn: Option<String>,
    alps: Option<u16>,
    peer_closed: bool,
}

impl Connection {
    /// Начать соединение: сгенерировать доли, собрать `ClientHello` и
    /// положить его в исходящий буфер.
    ///
    /// # Errors
    ///
    /// Ошибка построения приветствия или источника `session_id`.
    pub fn new(config: ClientConfig) -> Result<Self> {
        if config.groups.is_empty() {
            return Err(Error::Protocol("не задано ни одной группы обмена ключами"));
        }

        let shares = KeyShares::generate(&config.groups);
        let session_id = config.session_id.session_id(&shares)?;

        if config.alpn.is_empty() {
            return Err(Error::Protocol("не задано ни одного протокола ALPN"));
        }

        let params = HelloParams::new(config.server_name.clone())
            .with_key_shares(shares.wire())
            .with_session_id(session_id)
            .with_alpn(config.alpn.clone());
        let hello = config.profile.client_hello(&params)?;

        let mut connection = Self {
            config,
            state: State::WaitServerHello,
            shares,
            hello,
            retried: false,
            sealed: false,
            sent_ccs: false,
            certificate_requested: false,

            incoming: Vec::new(),
            outgoing: Vec::new(),
            plaintext: Vec::new(),
            messages: MessageReader::new(),
            // Хэш неизвестен до ServerHello; байты копятся независимо
            // от него, а привязка произойдёт при выборе шифронабора.
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

            hello_raw: Vec::new(),
            server_hello_raw: Vec::new(),
            failure: None,
            certificate: None,
            alpn: None,
            alps: None,
            peer_closed: false,
        };

        connection.emit_client_hello()?;
        Ok(connection)
    }

    /// Отправить текущее приветствие: в транскрипт и в исходящий буфер.
    fn emit_client_hello(&mut self) -> Result<()> {
        let mut handshake = self.hello.to_handshake()?;

        // Печать ставится ровно один раз, на первом приветствии. Второе,
        // после `HelloRetryRequest`, обязано нести тот же `session_id`
        // (RFC 8446, раздел 4.1.2), поэтому запечатанное значение
        // возвращается в модель приветствия и переезжает во второй круг
        // как есть. Перепечатать его нельзя: аутентифицируется всё
        // сообщение, а оно изменилось.
        if !self.sealed {
            if let Some(sealer) = self.config.sealer.as_ref() {
                let before = handshake.len();
                sealer.seal(&mut handshake, &self.shares)?;
                if handshake.len() != before {
                    return Err(Error::Protocol("печать изменила длину приветствия"));
                }
                self.hello.session_id = session_id_of(&handshake)?;
            }
            self.sealed = true;
        }

        self.transcript.extend(&handshake);
        self.hello_raw.clone_from(&handshake);

        let mut record = Vec::with_capacity(handshake.len() + HEADER_LEN);
        record.push(ContentType::Handshake.code());
        record.extend_from_slice(&RECORD_VERSION_HELLO.to_be_bytes());
        let length = u16::try_from(handshake.len()).map_err(|_| Error::TooLong)?;
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(&handshake);
        self.outgoing.extend_from_slice(&record);
        Ok(())
    }

    /// Принять байты, пришедшие с той стороны.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`], если накопилось неправдоподобно много байт
    /// без единой целой записи; сохранённая ошибка, если соединение уже
    /// похоронено.
    pub fn read_tls(&mut self, data: &[u8]) -> Result<()> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        if self.incoming.len().saturating_add(data.len()) > MAX_BUFFERED {
            return Err(Error::Protocol("входной буфер переполнен"));
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

    /// Закрыл ли собеседник свою сторону.
    #[must_use]
    pub const fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Согласованный протокол прикладного уровня.
    #[must_use]
    pub fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    /// Цепочка сертификатов сервера, если она уже получена.
    #[must_use]
    pub const fn peer_certificate(&self) -> Option<&Certificate> {
        self.certificate.as_ref()
    }

    /// Отправленное приветствие — нужно для снятия собственного отпечатка.
    #[must_use]
    pub const fn client_hello(&self) -> &ClientHello {
        &self.hello
    }

    /// Выбранный сервером шифронабор.
    #[must_use]
    pub const fn cipher_suite(&self) -> Option<u16> {
        self.cipher_suite
    }

    /// Группа обмена ключами, на которой сошлись.
    #[must_use]
    pub const fn group(&self) -> Option<Group> {
        self.group
    }

    /// Понадобился ли `HelloRetryRequest`.
    #[must_use]
    pub const fn was_retried(&self) -> bool {
        self.retried
    }

    /// Продвинуть автомат по накопленным входным байтам.
    ///
    /// Вызывать после каждого [`Connection::read_tls`], пока он что-то
    /// делает. Возврат `Ok(())` не означает завершения рукопожатия —
    /// это показывает [`Connection::is_handshaking`].
    ///
    /// # Errors
    ///
    /// Любое нарушение протокола, отказ проверки подлинности или
    /// предупреждение от сервера.
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

    /// Похоронить соединение.
    ///
    /// В TLS любая ошибка разбора терминальна. Оставить автомат живым
    /// значило бы дать противнику право на вторую попытку в том же
    /// соединении: подобрать другую ветвь состояния, дослать другую
    /// запись, повторить с изменением. Поэтому ключи уничтожаются, а
    /// непрочитанный ввод — заведомо недоверенный — отбрасывается.
    fn fail(&mut self, error: Error) -> Error {
        self.state = State::Closed;
        self.failure = Some(error);
        self.read = None;
        self.write = None;
        self.incoming.clear();
        self.messages = MessageReader::new();
        error
    }

    /// Ошибка, которая убила соединение, если она была.
    #[must_use]
    pub const fn failure(&self) -> Option<Error> {
        self.failure
    }

    /// Отрезать от входного буфера одну целую запись.
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

        // `change_cipher_spec` в TLS 1.3 не значит ничего: его шлют, чтобы
        // промежуточные узлы приняли поток за старую версию протокола.
        if outer == ContentType::ChangeCipherSpec {
            return Ok(());
        }

        let (content_type, body) = match self.read.as_mut() {
            // Ключей ещё нет — всё открытое, включая предупреждения.
            // Сервер, отказавший на нашем `ClientHello`, шлёт причину
            // именно так, и разобрать её надо: иначе внятный отказ
            // превратился бы в невнятный обрыв.
            None => (outer, record.get(HEADER_LEN..).unwrap_or_default().to_vec()),
            // Ключи поставлены — открытых записей больше не бывает.
            // В TLS 1.3 всё зашифрованное помечено снаружи как
            // `application_data`, поэтому любой другой внешний тип здесь
            // означает вставку в поток. Принимать открытое предупреждение
            // на этой стадии значило бы дать любому, кто способен
            // вклиниться в TCP, гасить соединение одним пакетом.
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
        const USER_CANCELED: u8 = 90;

        // Уровень нас не интересует: в TLS 1.3 всё, кроме close_notify и
        // user_canceled, фатально независимо от объявленного уровня.
        let description = match body {
            [_, description] => *description,
            _ => return Err(Error::Malformed("предупреждение неверной длины")),
        };

        match description {
            CLOSE_NOTIFY => {
                self.peer_closed = true;
                Ok(())
            }
            USER_CANCELED => Ok(()),
            other => {
                self.state = State::Closed;
                Err(Error::Alert(other))
            }
        }
    }

    fn handle_message(&mut self, message: &Message) -> Result<()> {
        match self.state {
            State::WaitServerHello => self.handle_server_hello(message),
            State::WaitEncryptedExtensions => self.handle_encrypted_extensions(message),
            State::WaitCertificate => self.handle_certificate(message),
            State::WaitCertificateVerify => self.handle_certificate_verify(message),
            State::WaitFinished => self.handle_server_finished(message),
            State::Connected => self.handle_post_handshake(message),
            State::Closed => Err(Error::Closed),
        }
    }

    // ── ServerHello ──────────────────────────────────────────────────

    fn handle_server_hello(&mut self, message: &Message) -> Result<()> {
        if message.msg_type != HandshakeType::ServerHello {
            return Err(Error::Protocol("ожидался ServerHello"));
        }
        let hello = ServerHello::parse(&message.body)?;

        // Версия проверяется раньше эха `session_id`: сервер, оставшийся
        // на TLS 1.2, присылает свой идентификатор сессии, и без этой
        // проверки диагноз был бы «сервер не повторил session_id» вместо
        // настоящего «сервер не умеет TLS 1.3».
        if hello.selected_version() != Some(0x0304) {
            return Err(Error::Unsupported("сервер не выбрал TLS 1.3"));
        }
        if hello.session_id != self.hello.session_id {
            return Err(Error::Protocol("сервер не повторил legacy_session_id"));
        }

        let hash = Hash::for_cipher_suite(hello.cipher_suite)
            .ok_or(Error::Unsupported("шифронабор сервера"))?;
        let aead =
            Aead::for_cipher_suite(hello.cipher_suite).ok_or(Error::Unsupported("шифронабор"))?;
        self.hash = hash;
        self.aead = aead;
        self.cipher_suite = Some(hello.cipher_suite);
        self.transcript.set_hash(hash);

        if hello.is_hello_retry_request() {
            return self.handle_hello_retry_request(&hello, message);
        }

        self.transcript.extend(&message.raw);
        self.server_hello_raw.clone_from(&message.raw);

        let (group_code, peer_share) = hello
            .key_share()
            .ok_or(Error::Protocol("ServerHello без key_share"))?;
        let exchange = self.shares.find(group_code).ok_or(Error::Protocol(
            "сервер выбрал группу, которую мы не предлагали",
        ))?;
        self.group = Some(exchange.group());
        let shared = exchange.complete(&peer_share)?;

        let mut schedule = KeySchedule::new(hash);
        schedule.enter_handshake(&shared);

        let transcript_hash = self.transcript.hash();
        self.client_handshake_secret = schedule.client_handshake_traffic_secret(&transcript_hash);
        self.server_handshake_secret = schedule.server_handshake_traffic_secret(&transcript_hash);
        self.schedule = Some(schedule);

        self.read = Some(Protection::new(
            aead,
            traffic_keys(hash, &self.server_handshake_secret, aead.key_len()),
        )?);
        self.write = Some(Protection::new(
            aead,
            traffic_keys(hash, &self.client_handshake_secret, aead.key_len()),
        )?);

        self.emit_change_cipher_spec();
        self.state = State::WaitEncryptedExtensions;
        Ok(())
    }

    /// Пустая запись `change_cipher_spec` — дань промежуточным узлам.
    ///
    /// Браузеры её шлют, поэтому её отсутствие — отличие от браузера.
    /// Ровно одна на соединение, перед первой нашей записью после
    /// приветствия.
    fn emit_change_cipher_spec(&mut self) {
        if self.sent_ccs {
            return;
        }
        self.sent_ccs = true;
        self.outgoing.extend_from_slice(&[
            ContentType::ChangeCipherSpec.code(),
            0x03,
            0x03,
            0x00,
            0x01,
            0x01,
        ]);
    }

    // ── HelloRetryRequest ────────────────────────────────────────────

    /// Сервер не согласен с предложенными группами и просит повторить.
    ///
    /// Случай редкий — мы, как и Chrome, предлагаем сразу две группы, —
    /// но обязательный: без него клиент молча не соединится с сервером,
    /// настроенным на `secp256r1`. Тонкость в транскрипте: он
    /// заменяется синтетическим `message_hash`, и забыть об этом значит
    /// получить расхождение `Finished` в самом конце.
    fn handle_hello_retry_request(&mut self, hello: &ServerHello, message: &Message) -> Result<()> {
        if self.retried {
            return Err(Error::Protocol("второй HelloRetryRequest подряд"));
        }
        self.retried = true;

        let group_code = match hello.extension(ext::KEY_SHARE).map(|e| e.body.as_slice()) {
            Some([hi, lo]) => u16::from_be_bytes([*hi, *lo]),
            _ => return Err(Error::Protocol("HelloRetryRequest без запроса группы")),
        };
        let group = Group::from_code(group_code).ok_or(Error::Unsupported("запрошенная группа"))?;
        if self.shares.find(group_code).is_some() {
            return Err(Error::Protocol(
                "сервер запросил группу, долю которой мы уже прислали",
            ));
        }

        self.transcript.replace_with_message_hash();
        self.transcript.extend(&message.raw);

        // Прежние доли остаются: из секретной части `x25519` выводится
        // ключ метки REALITY, а `legacy_session_id` менять нельзя.
        self.shares.push(group);
        let share = self
            .shares
            .find(group_code)
            .ok_or(Error::Protocol("доля не сгенерировалась"))?;

        // Во втором приветствии — только запрошенная группа, без GREASE:
        // так делает BoringSSL, и повторение фальшивой доли выдало бы нас.
        let key_share = ext::key_share(&[(group_code, share.share().to_vec())]);
        let cookie = hello.extension(ext::COOKIE).cloned();
        crate::profile::rebuild_for_retry(&mut self.hello, &key_share, cookie.as_ref())?;

        // CCS уходит после второго приветствия, как у BoringSSL.
        self.emit_change_cipher_spec();
        self.emit_client_hello()?;
        self.state = State::WaitServerHello;
        Ok(())
    }

    // ── Пачка сервера ────────────────────────────────────────────────

    fn handle_encrypted_extensions(&mut self, message: &Message) -> Result<()> {
        if message.msg_type != HandshakeType::EncryptedExtensions {
            return Err(Error::Protocol("ожидались EncryptedExtensions"));
        }
        self.transcript.extend(&message.raw);

        let extensions = parse_extension_list(&message.body)?;
        self.alpn = extensions
            .iter()
            .find(|e| e.ext_type == ext::ALPN)
            .and_then(|e| first_alpn_name(&e.body));
        // RFC 7301 §3.2: выбранный протокол обязан быть одним из
        // предложенных. Без этой сверки вызывающий получает соединение,
        // на котором говорят не на том языке, о котором он просил, —
        // и узнаёт об этом только по молчанию собеседника.
        if let Some(selected) = self.alpn.as_deref() {
            if !self.config.alpn.iter().any(|offered| offered == selected) {
                return Err(Error::Protocol(
                    "сервер выбрал ALPN, которого мы не предлагали",
                ));
            }
        }
        // Согласие сервера на ALPS обязывает нас ответить собственным
        // `EncryptedExtensions`. Кодовая точка берётся из ответа: старая
        // и новая различаются, и промахнуться нельзя. Так же, как с
        // ALPN, отвечать можно только на то, что предлагали сами.
        self.alps = extensions
            .iter()
            .map(|e| e.ext_type)
            .filter(|t| *t == ext::APPLICATION_SETTINGS_V2 || *t == ext::APPLICATION_SETTINGS)
            .find(|t| self.hello.extension(*t).is_some());

        self.state = State::WaitCertificate;
        Ok(())
    }

    fn handle_certificate(&mut self, message: &Message) -> Result<()> {
        match message.msg_type {
            // Запрос клиентского сертификата: мы его не предъявляем, но
            // обязаны ответить пустым сообщением — иначе сервер решит,
            // что мы нарушили протокол.
            HandshakeType::CertificateRequest => {
                self.certificate_requested = true;
                self.transcript.extend(&message.raw);
                Ok(())
            }
            HandshakeType::Certificate => {
                self.certificate = Some(Certificate::parse(&message.body)?);
                self.transcript.extend(&message.raw);
                self.state = State::WaitCertificateVerify;
                Ok(())
            }
            // В транскрипт идёт **сжатое** сообщение, ровно как пришло:
            // разжатие — наше внутреннее дело, и подставить туда
            // разжатый вариант значит не сойтись по `Finished`.
            HandshakeType::CompressedCertificate => {
                let compressed = CompressedCertificate::parse(&message.body)?;
                let body = decompress_certificate(&compressed)?;
                self.certificate = Some(Certificate::parse(&body)?);
                self.transcript.extend(&message.raw);
                self.state = State::WaitCertificateVerify;
                Ok(())
            }
            _ => Err(Error::Protocol("ожидался Certificate")),
        }
    }

    fn handle_certificate_verify(&mut self, message: &Message) -> Result<()> {
        if message.msg_type != HandshakeType::CertificateVerify {
            return Err(Error::Protocol("ожидался CertificateVerify"));
        }
        let verify = CertificateVerify::parse(&message.body)?;
        let certificate = self
            .certificate
            .as_ref()
            .ok_or(Error::Protocol("CertificateVerify без Certificate"))?;

        // Подписан транскрипт **до** этого сообщения.
        let transcript_hash = self.transcript.hash();
        self.config.verifier.verify(&PeerIdentity {
            server_name: &self.config.server_name,
            certificate,
            certificate_verify: &verify,
            transcript_hash: &transcript_hash,
            client_hello: &self.hello_raw,
            server_hello: &self.server_hello_raw,
        })?;

        self.transcript.extend(&message.raw);
        self.state = State::WaitFinished;
        Ok(())
    }

    fn handle_server_finished(&mut self, message: &Message) -> Result<()> {
        if message.msg_type != HandshakeType::Finished {
            return Err(Error::Protocol("ожидался Finished"));
        }

        let before = self.transcript.hash();
        let expected = verify_data(self.hash, &self.server_handshake_secret, &before);
        if !bool::from(expected.ct_eq(&message.body)) {
            return Err(Error::Untrusted("Finished сервера не сошёлся"));
        }
        self.transcript.extend(&message.raw);

        // Секреты приложения выводятся от транскрипта, включающего
        // Finished сервера, но **не** наш Finished.
        let after_server = self.transcript.hash();
        let schedule = self
            .schedule
            .as_mut()
            .ok_or(Error::Protocol("расписание ключей не заведено"))?;
        schedule.enter_master();
        self.client_application_secret = schedule.client_application_traffic_secret(&after_server);
        self.server_application_secret = schedule.server_application_traffic_secret(&after_server);

        self.send_client_flight()?;

        // Читать и писать теперь ключами приложения; счётчики с нуля.
        let (hash, aead) = (self.hash, self.aead);
        self.read = Some(Protection::new(
            aead,
            traffic_keys(hash, &self.server_application_secret, aead.key_len()),
        )?);
        self.write = Some(Protection::new(
            aead,
            traffic_keys(hash, &self.client_application_secret, aead.key_len()),
        )?);

        self.state = State::Connected;
        Ok(())
    }

    /// Наша пачка: при необходимости пустой `Certificate` и настройки
    /// ALPS, затем `Finished` — всё ключами рукопожатия.
    fn send_client_flight(&mut self) -> Result<()> {
        if self.certificate_requested {
            // Пустой контекст запроса и пустой список сертификатов.
            let empty = build_message(HandshakeType::Certificate, &[0x00, 0x00, 0x00, 0x00])?;
            self.transcript.extend(&empty);
            self.write_handshake(&empty)?;
        }

        // ALPS: если сервер согласился, клиент обязан прислать свои
        // настройки отдельным `EncryptedExtensions` непосредственно перед
        // `Finished`. Пропуск этого сообщения выглядит для сервера как
        // нарушение порядка — Google отвечает `unexpected_message`, и
        // соединение, дошедшее до конца рукопожатия, всё равно умирает.
        if let Some(codepoint) = self.alps {
            let mut w = crate::bytes::Writer::new();
            let mut outcome = Ok(());
            w.nested_u16(|list| {
                list.u16(codepoint);
                outcome = list.nested_u16(|body| body.bytes(&self.config.alps_settings));
            })?;
            outcome?;

            let settings = build_message(HandshakeType::EncryptedExtensions, &w.finish())?;
            self.transcript.extend(&settings);
            self.write_handshake(&settings)?;
        }

        // Хэш берётся здесь, а не раньше: в `verify_data` клиента входит
        // всё, что мы успели отправить в этой пачке. Секреты приложения,
        // наоборот, выводятся от транскрипта по `Finished` сервера — две
        // разные точки, и путать их нельзя.
        let transcript_hash = self.transcript.hash();
        let data = verify_data(self.hash, &self.client_handshake_secret, &transcript_hash);
        let finished = build_message(HandshakeType::Finished, &data)?;
        self.transcript.extend(&finished);
        self.write_handshake(&finished)?;
        Ok(())
    }

    fn write_handshake(&mut self, message: &[u8]) -> Result<()> {
        let protection = self
            .write
            .as_mut()
            .ok_or(Error::Protocol("нет ключей для записи"))?;
        let record = protection.encrypt(ContentType::Handshake, message, 0)?;
        self.outgoing.extend_from_slice(&record);
        Ok(())
    }

    // ── После рукопожатия ────────────────────────────────────────────

    fn handle_post_handshake(&mut self, message: &Message) -> Result<()> {
        match message.msg_type {
            // Билеты возобновления пока не храним: возобновление сессии
            // даёт наблюдателю связь между соединениями одного клиента,
            // и включать его нужно осознанно, а не по умолчанию.
            HandshakeType::NewSessionTicket => Ok(()),
            HandshakeType::KeyUpdate => self.handle_key_update(&message.body),
            _ => Err(Error::Protocol("недопустимое сообщение после рукопожатия")),
        }
    }

    /// Обновление ключей: сервер сменил свой ключ записи и, возможно,
    /// просит сменить наш.
    fn handle_key_update(&mut self, body: &[u8]) -> Result<()> {
        const NOT_REQUESTED: u8 = 0;
        const REQUESTED: u8 = 1;

        let request = match body {
            [value] => *value,
            _ => return Err(Error::Malformed("KeyUpdate неверной длины")),
        };

        self.server_application_secret =
            next_traffic_secret(self.hash, &self.server_application_secret);
        self.read = Some(Protection::new(
            self.aead,
            traffic_keys(
                self.hash,
                &self.server_application_secret,
                self.aead.key_len(),
            ),
        )?);

        match request {
            NOT_REQUESTED => Ok(()),
            REQUESTED => {
                // Ответ уходит ещё старым ключом, и только потом меняется наш.
                let answer = build_message(HandshakeType::KeyUpdate, &[NOT_REQUESTED])?;
                self.write_handshake(&answer)?;

                self.client_application_secret =
                    next_traffic_secret(self.hash, &self.client_application_secret);
                self.write = Some(Protection::new(
                    self.aead,
                    traffic_keys(
                        self.hash,
                        &self.client_application_secret,
                        self.aead.key_len(),
                    ),
                )?);
                Ok(())
            }
            _ => Err(Error::Malformed("неизвестное значение в KeyUpdate")),
        }
    }

    // ── Прикладные данные ────────────────────────────────────────────

    /// Зашифровать прикладные данные и положить их в исходящий буфер.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`], если рукопожатие ещё не завершено,
    /// [`Error::Closed`] после закрытия.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        match self.state {
            State::Connected => {}
            State::Closed => return Err(Error::Closed),
            _ => return Err(Error::Protocol("отправка до конца рукопожатия")),
        }

        // Байт настоящего типа содержимого тоже занимает место в записи.
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

    /// Разъять установленное соединение на две независимые половины.
    ///
    /// Возвращается ещё и уже расшифрованное, но не отданное: иначе
    /// данные, приехавшие в одном чтении с последней пачкой
    /// рукопожатия, потерялись бы при разъятии — та же ошибка, что
    /// однажды уже стоила дня поисков.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`], если рукопожатие ещё не завершено.
    pub fn into_halves(self) -> Result<(RecordReader, RecordWriter, Vec<u8>)> {
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
            self.plaintext,
        ))
    }

    /// Сообщить о закрытии своей стороны.
    ///
    /// # Errors
    ///
    /// Отказ шифрования.
    pub fn send_close_notify(&mut self) -> Result<()> {
        if self.state != State::Connected {
            return Ok(());
        }
        let protection = self
            .write
            .as_mut()
            .ok_or(Error::Protocol("нет ключей для записи"))?;
        // warning(1), close_notify(0)
        let record = protection.encrypt(ContentType::Alert, &[0x01, 0x00], 0)?;
        self.outgoing.extend_from_slice(&record);
        self.state = State::Closed;
        Ok(())
    }
}

/// Разжать сообщение `CompressedCertificate`.
///
/// Мы объявляем один алгоритм — brotli, — поэтому только его и умеем.
/// Сервер не имеет права прислать другой: RFC 8879 разрешает выбирать
/// лишь из объявленных клиентом.
fn decompress_certificate(message: &CompressedCertificate) -> Result<Vec<u8>> {
    /// Кодовая точка brotli в реестре `certificate_compression_algorithm`.
    const BROTLI: u16 = 2;
    /// Верхняя граница разжатого сообщения.
    ///
    /// Без неё сервер разжимал бы нам память в сотни мегабайт из
    /// нескольких килобайт сжатого потока — классическая «зип-бомба».
    /// Настоящая цепочка сертификатов не превышает и сотни килобайт.
    const MAX_CERTIFICATE_MESSAGE: usize = 1 << 20;

    if message.algorithm != BROTLI {
        return Err(Error::Unsupported("алгоритм сжатия сертификата"));
    }

    let declared = message.uncompressed_length as usize;
    if declared == 0 || declared > MAX_CERTIFICATE_MESSAGE {
        return Err(Error::Malformed("неправдоподобная длина после разжатия"));
    }

    // Предел ставится **во время** разжатия, а не после: иначе
    // «зип-бомба» успела бы занять память до того, как мы её заметим.
    let mut sink = BoundedSink {
        data: Vec::with_capacity(declared),
        limit: declared,
    };
    let mut input = message.compressed.as_slice();
    brotli_decompressor::BrotliDecompress(&mut input, &mut sink)
        .map_err(|_| Error::Malformed("сертификат не разжимается"))?;

    // Длина объявлена отправителем и входит в транскрипт: расхождение
    // означает либо порчу данных, либо попытку что-то подсунуть.
    if sink.data.len() != declared {
        return Err(Error::Malformed("длина после разжатия не совпала"));
    }
    Ok(sink.data)
}

/// Приёмник с жёстким пределом — чтобы разжатие нельзя было превратить
/// в исчерпание памяти.
struct BoundedSink {
    data: Vec<u8>,
    limit: usize,
}

impl std::io::Write for BoundedSink {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        if self.data.len().saturating_add(chunk.len()) > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "разжатие вышло за объявленную длину",
            ));
        }
        self.data.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Следующий секрет трафика: `HKDF-Expand-Label(secret, "traffic upd", "", L)`.
fn next_traffic_secret(hash: Hash, secret: &[u8]) -> Vec<u8> {
    expand_label(hash, secret, "traffic upd", &[], hash.len())
}

/// Вытащить `legacy_session_id` из сериализованного приветствия.
///
/// Смещение фиксировано: тип, трёхбайтовая длина, версия, тридцать два
/// байта `random`, затем однобайтовая длина идентификатора.
fn session_id_of(handshake: &[u8]) -> Result<Vec<u8>> {
    /// Позиция байта длины `legacy_session_id`.
    const LENGTH_AT: usize = 4 + 2 + 32;

    let len = usize::from(*handshake.get(LENGTH_AT).ok_or(Error::Truncated)?);
    handshake
        .get(LENGTH_AT + 1..LENGTH_AT + 1 + len)
        .map(<[u8]>::to_vec)
        .ok_or(Error::Truncated)
}

/// Разобрать список расширений сообщения рукопожатия.
fn parse_extension_list(body: &[u8]) -> Result<Vec<crate::hello::Extension>> {
    let mut r = crate::bytes::Reader::new(body);
    let mut list = crate::bytes::Reader::new(r.vec_u16()?);
    let mut out = Vec::new();
    while !list.is_empty() {
        let ext_type = list.u16()?;
        let data = list.vec_u16()?;
        out.push(crate::hello::Extension::raw(ext_type, data.to_vec()));
    }
    Ok(out)
}

/// Первое (и единственное) имя из ответа ALPN сервера.
fn first_alpn_name(body: &[u8]) -> Option<String> {
    let mut outer = crate::bytes::Reader::new(body);
    let mut names = crate::bytes::Reader::new(outer.vec_u16().ok()?);
    let name = names.vec_u8().ok()?;
    core::str::from_utf8(name).ok().map(str::to_owned)
}
