//! Транспорт WebSocket.
//!
//! Нужен для яруса T1: serverless-платформы вроде Cloudflare Workers не
//! дают ни UDP, ни голого TCP — только HTTP. WebSocket остаётся
//! единственным способом получить там двунаправленный поток, а значит и
//! единственным способом развернуть точку выхода на бесплатном аккаунте
//! пользователя.
//!
//! Плата за это — заметность: WebSocket через CDN примелькался, и по
//! скрытности он уступает REALITY поверх голого TCP. Поэтому в матрице
//! стратегий он идёт не первым выбором, а резервом на случай, когда
//! чистый TCP не проходит.

pub mod frame;
pub mod handshake;
pub mod stream;

pub use frame::{Decoder, Frame, Opcode};
pub use handshake::{accept_for, ClientHandshake, DEFAULT_USER_AGENT};
pub use stream::{Role, Stream, DEFAULT_FRAME_LIMIT};
