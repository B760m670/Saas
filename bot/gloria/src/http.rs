//! Исполнитель запросов.
//!
//! Все внешние службы — Telegram, панель, платёжный сервис — описывают свои
//! обращения одним типом [`Request`]. Здесь единственное место во всём боте,
//! которое действительно ходит в сеть. Остальное поэтому проверяется
//! обычными тестами.

use atlas_billing::http::{Method, Request};

/// Чем кончился запрос.
#[derive(Debug)]
pub struct Response {
    /// Код ответа.
    pub status: u16,
    /// Тело.
    pub body: Vec<u8>,
}

impl Response {
    /// Успешен ли ответ по коду.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// Отказ на уровне сети.
#[derive(Debug)]
pub enum Error {
    /// Не удалось выполнить запрос.
    ///
    /// Текст уже очищен от секретов вызывающим: адрес запроса к Telegram
    /// содержит токен, и сообщения клиентов HTTP обычно содержат адрес.
    Transport(String),
    /// Тело ответа не прочиталось.
    Body(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(what) => write!(f, "запрос не выполнен: {what}"),
            Self::Body(what) => write!(f, "ответ не прочитан: {what}"),
        }
    }
}

impl core::error::Error for Error {}

/// Выполнить запрос.
///
/// Ответы с кодом ошибки возвращаются, а не превращаются в отказ: тело
/// такого ответа обычно содержит причину словами службы, и она полезнее
/// нашего «что-то пошло не так».
pub fn send(request: &Request) -> Result<Response, Error> {
    let agent = agent();

    // Запросы с телом и без него у ureq — разные типы, поэтому ветки
    // разведены, а общее вынесено в две небольшие вспомогательные функции.
    let result = match request.method {
        Method::Get => {
            let mut call = agent.get(&request.url);
            for (name, value) in &request.headers {
                call = call.header(name, value);
            }
            call.call()
        }
        Method::Post => {
            let mut call = agent.post(&request.url);
            for (name, value) in &request.headers {
                call = call.header(name, value);
            }
            call.send(&request.body[..])
        }
        Method::Patch => {
            let mut call = agent.patch(&request.url);
            for (name, value) in &request.headers {
                call = call.header(name, value);
            }
            call.send(&request.body[..])
        }
    };

    let mut response = match result {
        Ok(response) => response,
        // Сюда ответ с кодом ошибки не попадает — см. [`agent`]. Ветка
        // остаётся на случай, если настройка когда-нибудь потеряется: код
        // без тела всё же лучше, чем «сбой связи» вместо ответа службы.
        Err(ureq::Error::StatusCode(status)) => {
            return Ok(Response {
                status,
                body: Vec::new(),
            })
        }
        Err(error) => return Err(Error::Transport(error.to_string())),
    };

    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_vec()
        .map_err(|error| Error::Body(error.to_string()))?;

    Ok(Response { status, body })
}

/// Общий исполнитель, настроенный **не** считать код ошибки сбоем.
///
/// По умолчанию ureq превращает любой ответ с кодом 4xx или 5xx в ошибку, и
/// тело такого ответа до нас не доходит. Мы честно возвращали код — но без
/// причины, и в журнале появлялось «Панель отказала, код 400:» с пустотой
/// после двоеточия.
///
/// Это стоило дорого: очередь дат сутками падала с `400`, а понять, почему
/// панель отказывает, было нечем. Причина, сказанная службой своими словами,
/// — самое ценное, что есть в неудачном ответе.
///
/// Исполнитель один на весь процесс: он держит пул соединений, и создавать
/// его на каждый запрос значило бы каждый раз заново устанавливать TLS.
fn agent() -> &'static ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into()
    })
}
