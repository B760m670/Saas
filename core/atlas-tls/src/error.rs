//! Ошибки разбора и построения `ClientHello`.

/// Результат операции над сообщением TLS.
pub type Result<T> = core::result::Result<T, Error>;

/// Ошибка разбора или построения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Ввод закончился раньше, чем требовала объявленная длина.
    #[error("сообщение обрывается на середине")]
    Truncated,

    /// Структура нарушена: несогласованные длины, недопустимые значения.
    #[error("некорректная структура: {0}")]
    Malformed(&'static str),

    /// Не тот тип сообщения — например, `ServerHello` вместо `ClientHello`.
    #[error("ожидался ClientHello, получен тип {0:#04x}")]
    UnexpectedMessage(u8),

    /// Значение не помещается в поле объявленной ширины.
    #[error("значение не помещается в поле длины")]
    TooLong,
}
