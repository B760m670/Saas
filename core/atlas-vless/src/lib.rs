//! Протокол VLESS: кодирование и разбор заголовков.
//!
//! VLESS — тонкий адресный конверт без собственного шифрования. Это не
//! упущение, а решение авторов протокола: шифрованием занимается TLS, а
//! отсутствие своей криптографии означает отсутствие собственного
//! криптографического отпечатка и нулевой оверхед.
//!
//! Практическое следствие: **идентификатор пользователя передаётся
//! открытым текстом**. Без TLS или REALITY протокол вскрывается по первым
//! семнадцати байтам потока, поэтому [`atlas_types::ProxyKey::validate`]
//! отвергает VLESS без маскировки.
//!
//! Крейт содержит только кодек. Установление соединения, маскировка и
//! мультиплексирование живут в транспортном слое выше.
//!
//! # Пример
//!
//! ```
//! use atlas_vless::{Address, Endpoint, Request};
//!
//! let uuid = atlas_types::uuid_to_bytes("00112233-4455-6677-8899-aabbccddeeff")
//!     .expect("канонический UUID");
//!
//! let request = Request::tcp(uuid, Endpoint::new(Address::Domain("example.org".into()), 443))
//!     .with_flow("xtls-rprx-vision");
//!
//! let wire = request.encode()?;
//! let (parsed, payload) = Request::decode(&wire)?;
//!
//! assert_eq!(parsed, request);
//! assert!(payload.is_empty());
//! # Ok::<(), atlas_vless::Error>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod addons;
mod error;
mod request;
pub mod session;
pub mod udp;
pub mod vision;

pub use addons::Addons;
pub use error::{Error, Result};
pub use request::{Address, Command, Endpoint, Request, Response, VERSION};
pub use session::{Flow, Session};
