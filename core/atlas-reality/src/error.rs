//! Ошибки слоя REALITY.

/// Результат операции.
pub type Result<T> = core::result::Result<T, Error>;

/// Ошибка запечатывания или проверки метки.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Сообщение не является `ClientHello`.
    #[error("ожидался ClientHello, получен тип {0:#04x}")]
    NotClientHello(u8),

    /// Сообщение короче, чем требует раскладка.
    #[error("сообщение слишком короткое для метки")]
    TooShort,

    /// Длина `session_id` отличается от тридцати двух байт.
    #[error("длина session_id равна {0}, ожидалось 32")]
    UnexpectedSessionIdLength(u8),

    /// `shortId` длиннее восьми байт.
    #[error("shortId длиной {0} байт, максимум 8")]
    ShortIdTooLong(usize),

    /// Метка не открывается.
    ///
    /// Причина намеренно не уточняется: различать «не тот ключ», «не тот
    /// shortId» и «повреждённые данные» — значит дать атакующему оракул.
    #[error("метка отвергнута")]
    Rejected,

    /// Отказ примитива шифрования.
    #[error("сбой AEAD")]
    Aead,
}
