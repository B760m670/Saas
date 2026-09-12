//! Описание HTTP-обмена — без самого HTTP.
//!
//! Крейт намеренно не содержит клиента и не ходит в сеть. Адаптер сервиса
//! только собирает исходящий запрос и разбирает пришедший ответ, а выполняет
//! запрос вызывающий код.
//!
//! Причина практическая. Проверка подписи уведомления — место, где ошибка
//! стоит денег, а поймать её на живом сервисе нельзя: чтобы получить
//! настоящее уведомление, надо провести настоящий платёж, и увидеть при этом
//! можно только то, что подпись подошла, а не то, что негодная была бы
//! отвергнута. Без ввода-вывода и то и другое проверяется обычным тестом на
//! готовых байтах.

/// Метод запроса.
///
/// Список ровно такой, какой нужен внешним службам, с которыми мы говорим:
/// платёжным сервисам хватает двух, панели нужен ещё `PATCH` для изменения
/// уже заведённого пользователя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Запрос без тела.
    Get,
    /// Создание.
    Post,
    /// Изменение существующего.
    Patch,
}

impl Method {
    /// Имя метода для HTTP-клиента.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
        }
    }
}

/// Исходящий запрос к платёжному сервису, готовый к отправке.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Метод.
    pub method: Method,
    /// Полный адрес.
    pub url: String,
    /// Заголовки в порядке добавления.
    pub headers: Vec<(String, String)>,
    /// Тело. Пустое для `GET`.
    pub body: Vec<u8>,
}

/// Входящее уведомление от сервиса.
///
/// Ровно то, что пришло по сети: заголовки и нетронутое тело. Тело хранится
/// байтами, а не разобранной структурой, потому что подпись считается по
/// исходным байтам. Разобрать JSON и собрать его обратно — значит изменить
/// порядок ключей и пробелы, и подпись перестанет сходиться.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    /// Заголовки запроса.
    pub headers: Vec<(String, String)>,
    /// Тело запроса ровно как получено.
    pub body: Vec<u8>,
}

impl Callback {
    /// Собрать уведомление.
    #[must_use]
    pub fn new(headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self { headers, body }
    }

    /// Найти заголовок по имени без учёта регистра.
    ///
    /// Регистр имён заголовков в HTTP не значим, и сервисы этим пользуются:
    /// один и тот же присылает то `X-Api-Signature`, то `x-api-signature`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Что делать, чтобы получить с человека деньги.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checkout {
    /// Обращаться никуда не надо: показать покупателю текст и ждать, пока
    /// платёж подтвердят вручную.
    Offline(String),
    /// Ссылка на оплату известна сразу — отправить покупателя по ней.
    Page(String),
    /// Выполнить запрос, ответ передать в [`crate::Provider::checkout_page`].
    Request(Request),
}

#[cfg(test)]
mod tests {
    use super::Callback;

    #[test]
    fn header_lookup_ignores_case() {
        let callback = Callback::new(
            vec![("X-Api-Signature".to_owned(), "abc".to_owned())],
            Vec::new(),
        );
        assert_eq!(callback.header("x-api-signature"), Some("abc"));
        assert_eq!(callback.header("X-API-SIGNATURE"), Some("abc"));
        assert_eq!(callback.header("x-api-sign"), None);
    }
}
