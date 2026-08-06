//! Метка REALITY — аутентификация клиента внутри поля `session_id`.
//!
//! REALITY решает задачу, на которой ломаются остальные схемы: **что
//! увидит цензор, если сам подключится к нашему адресу**. Ответ — сервер
//! прозрачно передаст такое соединение настоящему постороннему сайту, и
//! пробующий получит подлинный сертификат подлинного сайта. Отличить
//! невозможно, потому что отличия нет.
//!
//! Клиент опознаёт себя тем, что кладёт в `session_id` шестнадцать байт
//! метки, зашифрованных на общем секрете. Снаружи это тридцать два байта,
//! неотличимых от случайных, — ровно там, где браузер держит идентификатор
//! сессии.
//!
//! # Что этот крейт делает и чего не делает
//!
//! Здесь только метка: вывод ключа, запечатывание, проверка. Ни TLS-
//! рукопожатия, ни подмены сертификата, ни проксирования чужих соединений
//! на сайт прикрытия здесь нет — это работа транспортного слоя и серверной
//! части.
//!
//! # Границы проверки
//!
//! Раскладка разобрана по исходнику эталонной реализации (см.
//! `docs/01-protocols.md`, раздел 3.5), обе стороны реализованы и сходятся
//! между собой в тестах. Но **совместимость с живым сервером Xray этим не
//! доказана** — для этого нужен реальный сервер. До такой проверки крейт
//! считать боеспособным нельзя.
//!
//! # Пример
//!
//! ```
//! use atlas_reality::{Client, Server};
//!
//! # fn main() -> Result<(), atlas_reality::Error> {
//! let mut server = Server::generate().with_short_id(&[0xde, 0xad])?;
//! let client = Client::new(server.public_key(), &[0xde, 0xad], [25, 3, 27])?;
//!
//! // Клиент готовит эфемерную пару; её публичная часть уходит в key_share.
//! let session = client.begin();
//! let client_public = session.public_key();
//!
//! // ... транспорт собирает ClientHello с этим key_share ...
//! # let mut handshake = vec![0x01, 0, 0, 0x44, 0x03, 0x03];
//! # handshake.extend([0x7f; 32]);
//! # handshake.push(32);
//! # handshake.extend([0; 32]);
//!
//! session.seal(&mut handshake, 1_800_000_000)?;
//!
//! let marker = server.authenticate(&handshake, &client_public, 1_800_000_000)?;
//! assert_eq!(marker.version, [25, 3, 27]);
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod auth;
pub mod cert;
mod error;
pub mod marker;
pub mod replay;
pub mod tls;

pub use error::{Error, Result};
pub use marker::Marker;
pub use replay::ReplayWindow;
pub use tls::{AuthKey, Sealer, Verifier};

use atlas_crypto::rng::OsRng;

/// Допустимое расхождение часов по умолчанию, секунды.
///
/// Записанный `ClientHello` старше этого срока сервер отвергает, что
/// закрывает повтор.
pub const DEFAULT_MAX_SKEW: u32 = 120;

/// Сколько секунд помнить метку при заданном расхождении часов.
///
/// Приветствие принимается, пока `|now - timestamp| <= skew`, то есть
/// одна и та же запись годится в интервале шириной `2 * skew`. Помнить
/// её дольше бессмысленно: за пределами интервала её отвергнет проверка
/// времени.
const fn replay_horizon(max_skew: u32) -> u32 {
    max_skew.saturating_mul(2)
}

/// Клиентская сторона.
#[derive(Debug, Clone)]
pub struct Client {
    server_public: [u8; 32],
    short_id: [u8; marker::SHORT_ID_LEN],
    version: [u8; 3],
}

impl Client {
    /// Создать клиента.
    ///
    /// `server_public` — публичный ключ X25519 точки выхода, тот самый,
    /// что в ключе доступа обозначается `pbk`.
    ///
    /// # Errors
    ///
    /// [`Error::ShortIdTooLong`], если идентификатор длиннее восьми байт.
    pub fn new(server_public: [u8; 32], short_id: &[u8], version: [u8; 3]) -> Result<Self> {
        let padded = Marker::new(version, 0, short_id)?.short_id;
        Ok(Self {
            server_public,
            short_id: padded,
            version,
        })
    }

    /// Начать сессию: сгенерировать эфемерную пару X25519.
    #[must_use]
    pub fn begin(&self) -> Session {
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Session {
            secret,
            public,
            short_id: self.short_id,
            version: self.version,
            server_public: self.server_public,
        }
    }
}

/// Одна попытка подключения. Эфемерная пара живёт ровно столько.
pub struct Session {
    secret: x25519_dalek::StaticSecret,
    public: [u8; 32],
    short_id: [u8; marker::SHORT_ID_LEN],
    version: [u8; 3],
    server_public: [u8; 32],
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Session(<эфемерный секрет скрыт>)")
    }
}

impl Session {
    /// Публичный ключ, который транспорт обязан положить в `key_share`.
    ///
    /// Сервер берёт его именно оттуда — отдельного канала для передачи нет.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Запечатать метку в собранное handshake-сообщение.
    ///
    /// Вызывается после того, как транспорт сформировал `ClientHello`
    /// целиком: в аутентифицируемые данные входит всё сообщение, поэтому
    /// после этого вызова его нельзя менять ни в одном байте.
    ///
    /// # Errors
    ///
    /// Ошибки разбора сообщения из [`auth::seal`].
    pub fn seal(&self, handshake: &mut [u8], timestamp: u32) -> Result<()> {
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(self.server_public));
        let random = auth::random_of_public(handshake)?;
        let key = auth::derive_auth_key(shared.as_bytes(), &random);
        let marker = Marker {
            version: self.version,
            timestamp,
            short_id: self.short_id,
        };
        auth::seal(handshake, &key, marker)
    }
}

/// Серверная сторона. Нужна для тестов и для собственной точки выхода.
pub struct Server {
    secret: x25519_dalek::StaticSecret,
    accepted: Vec<[u8; marker::SHORT_ID_LEN]>,
    max_skew: u32,
    seen: ReplayWindow,
}

impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Server(<приватный ключ скрыт>)")
    }
}

impl Server {
    /// Создать сервер со свежей парой ключей.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            secret: x25519_dalek::StaticSecret::random_from_rng(&mut OsRng),
            accepted: Vec::new(),
            max_skew: DEFAULT_MAX_SKEW,
            seen: ReplayWindow::new(replay_horizon(DEFAULT_MAX_SKEW)),
        }
    }

    /// Создать сервер с заданным приватным ключом.
    #[must_use]
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            secret: x25519_dalek::StaticSecret::from(secret),
            accepted: Vec::new(),
            max_skew: DEFAULT_MAX_SKEW,
            seen: ReplayWindow::new(replay_horizon(DEFAULT_MAX_SKEW)),
        }
    }

    /// Публичный ключ, который попадает в ключ доступа как `pbk`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.secret).to_bytes()
    }

    /// Разрешить ещё один `shortId`.
    ///
    /// Несколько идентификаторов на одной точке позволяют отозвать доступ
    /// одного пользователя, не трогая остальных.
    ///
    /// # Errors
    ///
    /// [`Error::ShortIdTooLong`], если идентификатор длиннее восьми байт.
    pub fn with_short_id(mut self, short_id: &[u8]) -> Result<Self> {
        self.accepted
            .push(Marker::new([0; 3], 0, short_id)?.short_id);
        Ok(self)
    }

    /// Задать допустимое расхождение часов.
    ///
    /// Окно повторов подстраивается следом: помнить метку дольше, чем её
    /// вообще может принять проверка времени, незачем.
    #[must_use]
    pub fn with_max_skew(mut self, seconds: u32) -> Self {
        self.max_skew = seconds;
        self.seen = ReplayWindow::new(replay_horizon(seconds));
        self
    }

    /// Сколько меток сейчас помнит окно повторов.
    ///
    /// Нужно для наблюдения за узлом: рост этого числа — прямая мера
    /// темпа подключений.
    #[must_use]
    pub fn tracked_connections(&self) -> usize {
        self.seen.len()
    }

    /// Вычислить общий ключ для этого приветствия.
    ///
    /// Точке выхода он нужен после приёма метки: временный сертификат,
    /// которым она доказывает себя клиенту, строится именно на нём.
    ///
    /// # Errors
    ///
    /// [`Error::TooShort`], если сообщение не той формы.
    pub fn auth_key_for(&self, handshake: &[u8], client_public: &[u8; 32]) -> Result<[u8; 32]> {
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*client_public));
        let random = auth::random_of_public(handshake)?;
        Ok(auth::derive_auth_key(shared.as_bytes(), &random))
    }

    /// Проверить метку.
    ///
    /// `client_public` транспорт берёт из `key_share` полученного
    /// `ClientHello`.
    ///
    /// # Errors
    ///
    /// [`Error::Rejected`], если метка не открывается, `shortId` не из
    /// разрешённых или расхождение часов слишком велико. Причина не
    /// уточняется намеренно.
    pub fn authenticate(
        &mut self,
        handshake: &[u8],
        client_public: &[u8; 32],
        now: u32,
    ) -> Result<Marker> {
        let key = self.auth_key_for(handshake, client_public)?;
        let marker = auth::open(handshake, &key)?;

        if marker.skew_from(now) > self.max_skew {
            return Err(Error::Rejected);
        }
        if !self.accepted.is_empty() && !self.accepted.contains(&marker.short_id) {
            return Err(Error::Rejected);
        }

        // Последней — проверка на повтор, и только для приветствий,
        // приемлемых во всём остальном: иначе поток заведомо негодных
        // забивал бы окно. Отказ здесь означает, что запись уже
        // проходила, и вызывающий обязан поступить с ней так же, как с
        // любым чужим соединением — увести на сайт прикрытия.
        let tag = auth::session_id_of(handshake)?;
        if !self.seen.accept(now, tag) {
            return Err(Error::Rejected);
        }

        Ok(marker)
    }
}
