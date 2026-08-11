//! Клиент TLS 1.3 с точным отпечатком браузера.
//!
//! Крейт делает две вещи, которые в обычной библиотеке TLS разнесены и
//! которые здесь обязаны сходиться: **говорит на TLS 1.3** и **выглядит
//! при этом как Chrome**. Отсюда его устройство — от разбора байт
//! ([`bytes`]) и профиля браузера ([`profile`]) до расписания ключей
//! ([`keyschedule`]), слоя записей ([`record`]) и конечного автомата
//! рукопожатия ([`client`]).
//!
//! Вторая половина — самая рискованная часть проекта. Ошибка в составе
//! или порядке полей не проявляется как сбой: соединение установится,
//! данные пойдут — но отпечаток TLS будет отличаться от браузерного, и
//! пользователь окажется помечен уже на первом пакете. Это хуже, чем
//! отсутствие обхода вовсе.
//!
//! Отсюда то, что вычисление JA3 и JA4 живёт здесь же, рядом со
//! сборщиком, а в CI отпечаток нашего `ClientHello` сравнивается с
//! эталоном живого Chrome: расхождение в одном символе роняет сборку.
//!
//! Правильность самого протокола проверяется тремя независимыми
//! способами: эталонными векторами RFC 8448 (арифметика), встречной
//! реализацией в `tests/loopback.rs` (редкие ветви автомата) и живыми
//! серверами через `examples/connect.rs` (совместимость).
//!
//! # Пример: отпечаток собираемого приветствия
//!
//! ```
//! use atlas_tls::{Chrome, HelloParams, Transport, fingerprint};
//!
//! let params = HelloParams::new("www.microsoft.com")
//!     .with_key_shares(vec![(atlas_tls::profile::X25519, vec![0x11; 32])]);
//! let hello = Chrome::classic().client_hello(&params)?;
//!
//! let fp = fingerprint::ja4(&hello, Transport::Tcp);
//! assert_eq!(fp.a, "t13d1516h2");
//! # Ok::<(), atlas_tls::Error>(())
//! ```
//!
//! # Пример: соединение
//!
//! ```no_run
//! use std::io::{Read, Write};
//! use atlas_tls::{ClientConfig, TlsStream};
//!
//! let socket = std::net::TcpStream::connect("example.org:443")?;
//! let mut tls = TlsStream::connect(socket, ClientConfig::new("example.org"))?;
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")?;
//!
//! let mut answer = Vec::new();
//! tls.read_to_end(&mut answer)?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Проверка подлинности сервера по умолчанию **никакая** — см.
//! [`client::AcceptAnyServer`]. Настоящее правило задаёт вызывающий; для
//! ATLAS это будет REALITY.
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod bytes;
pub mod client;
mod error;
pub mod ext;
pub mod fingerprint;
pub mod grease;
pub mod halves;
pub mod handshake;
mod hello;
pub mod keyexchange;
pub mod keyschedule;
pub mod profile;
pub mod record;
pub mod server;
pub mod stream;

pub use client::{
    AcceptAnyServer, ClientConfig, Connection, HelloSealer, PeerIdentity, RandomSessionId,
    ServerVerifier, SessionIdSource,
};
pub use error::{Error, Result};
pub use fingerprint::{Ja3, Ja4, Transport};
pub use hello::{ClientHello, Extension};
pub use keyexchange::{Group, KeyExchange, KeyShares};
pub use profile::{Chrome, Firefox, Generation, HelloParams, Profile};
pub use server::{
    CertificateSource, Credentials, Pending, Ready, RecordReader, RecordWriter, ServerConfig,
    ServerConnection,
};
pub use stream::TlsStream;
