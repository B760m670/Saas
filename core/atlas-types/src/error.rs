//! Ошибки разбора и построения ключей.

/// Результат операции над ключом.
pub type Result<T> = core::result::Result<T, Error>;

/// Ошибка разбора или построения ключа доступа.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// В строке нет `://` или схема пустая.
    #[error("не удалось определить схему URI")]
    MissingScheme,

    /// Схема есть, но она нам неизвестна.
    #[error("неизвестная схема `{0}`")]
    UnknownScheme(String),

    /// Отсутствует обязательная часть URI.
    #[error("отсутствует обязательная часть: {0}")]
    Missing(&'static str),

    /// Часть URI присутствует, но синтаксически неверна.
    #[error("некорректное значение поля {field}: {reason}")]
    Invalid {
        /// Имя поля.
        field: &'static str,
        /// Человекочитаемая причина.
        reason: String,
    },

    /// Не удалось декодировать base64 ни одним из известных алфавитов.
    #[error("не удалось декодировать base64 в поле {0}")]
    Base64(&'static str),

    /// Полезная нагрузка не является корректным UTF-8.
    #[error("не UTF-8 в поле {0}")]
    Utf8(&'static str),

    /// Не удалось разобрать JSON (актуально для `vmess://`).
    #[error("некорректный JSON: {0}")]
    Json(String),

    /// Комбинация параметров синтаксически верна, но нерабочая.
    #[error("несовместимые параметры: {0}")]
    Incompatible(String),
}

impl Error {
    /// Хелпер для краткой записи [`Error::Invalid`].
    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field,
            reason: reason.into(),
        }
    }
}
