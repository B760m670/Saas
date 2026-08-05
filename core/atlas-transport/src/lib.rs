//! Транспорты ATLAS.
//!
//! Транспорт отвечает на вопрос «в чём едет прокси-протокол». Это
//! отдельная ось от самого протокола и от слоя маскировки — см.
//! `docs/01-protocols.md`.
//!
//! # Пример
//!
//! ```
//! use atlas_transport::ws::{ClientHandshake, Frame, Decoder};
//!
//! let handshake = ClientHandshake::new();
//! let request = handshake.request("worker.example.workers.dev", "/api");
//! assert!(request.starts_with("GET /api HTTP/1.1\r\n"));
//!
//! // Ответ сервера подтверждает переход на кадры.
//! let response = atlas_transport::ws::handshake::server_response(handshake.key());
//! let consumed = handshake.verify(response.as_bytes())?;
//! assert_eq!(consumed, response.len());
//!
//! // Дальше данные идут кадрами, клиентские — обязательно маскированными.
//! let wire = Frame::binary(b"vless payload".to_vec()).encode_masked()?;
//! let mut decoder = Decoder::new();
//! decoder.push(&wire);
//! assert_eq!(decoder.next_frame()?.map(|f| f.payload), Some(b"vless payload".to_vec()));
//! # Ok::<(), atlas_transport::Error>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

mod error;
pub mod ws;

pub use error::{Error, Result};
