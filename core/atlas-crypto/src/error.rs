//! Ошибки криптографического слоя.

/// Результат криптографической операции.
pub type Result<T> = core::result::Result<T, Error>;

/// Ошибка криптографического слоя.
///
/// Формулировки намеренно скупые: подробность сообщения об ошибке проверки
/// подписи или расшифровки — это канал утечки для атакующего.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Подпись не прошла проверку.
    BadSignature,
    /// Байтовое представление некорректно: не та длина или неразбираемое значение.
    BadEncoding(&'static str),
    /// Значение параметра вне допустимого диапазона.
    OutOfRange(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSignature => f.write_str("подпись не прошла проверку"),
            Self::BadEncoding(what) => write!(f, "некорректное представление: {what}"),
            Self::OutOfRange(what) => write!(f, "значение вне допустимого диапазона: {what}"),
        }
    }
}

impl core::error::Error for Error {}
