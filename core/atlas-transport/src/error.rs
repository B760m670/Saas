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

/// Обернуть протокольную ошибку в ошибку ввода-вывода.
///
/// Нужно там, где транспорт выступает обычным потоком: снаружи он
/// [`std::io::Read`] и [`std::io::Write`], и городить рядом второй тип
/// ошибки значило бы заставить вызывающего разбирать два.
///
/// Причина при этом не теряется: она едет внутри и печатается вместе с
/// ошибкой ввода-вывода.
impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        let kind = match error {
            // «Дочитай» — не поломка, но если это всё-таки всплыло
            // наружу, значит данные кончились раньше времени.
            Error::Incomplete => std::io::ErrorKind::UnexpectedEof,
            Error::Protocol(_) | Error::Handshake(_) => std::io::ErrorKind::InvalidData,
        };
        Self::new(kind, error)
    }
}
