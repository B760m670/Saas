//! Конструирование `ClientHello` с точным отпечатком браузера.
//!
//! Самый рискованный модуль проекта. Ошибка в составе или порядке полей
//! не проявляется как сбой: соединение установится, данные пойдут — но
//! отпечаток TLS будет отличаться от браузерного, и пользователь окажется
//! помечен уже на первом пакете. Это хуже, чем отсутствие обхода вовсе.
//!
//! Отсюда устройство крейта: вместе со сборщиком здесь же живёт
//! вычисление JA3 и JA4, а в CI отпечаток нашего `ClientHello`
//! сравнивается с эталоном настоящего Chrome. Расхождение в одном символе
//! роняет сборку.
//!
//! # Пример
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
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod bytes;
mod error;
pub mod ext;
pub mod fingerprint;
pub mod grease;
mod hello;
pub mod keyschedule;
pub mod profile;

pub use error::{Error, Result};
pub use fingerprint::{Ja3, Ja4, Transport};
pub use hello::{ClientHello, Extension};
pub use profile::{Chrome, Generation, HelloParams};
