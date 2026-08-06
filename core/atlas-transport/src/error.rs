//! Ошибки транспортного слоя.

/// Результат операции.
pub type Result<T> = core::result::Result<T, Error>;

/// Ошибка транспорта.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Данных пока недостаточно — не ошибка, а сигнал дочитать.
    #[error("данных недостаточно")]
    Incomplete,

    /// Нарушение правил протокола.
    #[error("нарушение протокола: {0}")]
    Protocol(&'static str),

    /// Рукопожатие не удалось.
    #[error("рукопожатие не удалось: {0}")]
    Handshake(&'static str),
}
