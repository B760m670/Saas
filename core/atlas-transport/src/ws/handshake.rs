//! Рукопожатие WebSocket (RFC 6455).
//!
//! # Заголовки — это тоже отпечаток
//!
//! Соблазн велик: отправить минимальный набор из четырёх обязательных
//! заголовков, ведь протоколу этого достаточно. Но обычный `ClientHello`
//! с браузерным JA4, за которым следует HTTP-запрос из четырёх строк, —
//! сочетание, которого у настоящего браузера не бывает. Мы бы аккуратно
//! замаскировали TLS и тут же выдали себя на следующем уровне.
//!
//! Поэтому по умолчанию отправляется полный набор в том же порядке, в
//! каком его шлёт Chrome, включая заголовки, которые протоколу не нужны:
//! `Pragma`, `Cache-Control`, `Accept-Encoding`, `Accept-Language`,
//! `Origin`.
//!
//! Отдельный случай — `Sec-WebSocket-Extensions`. Браузер всегда
//! предлагает `permessage-deflate`, поэтому предлагаем и мы. Сжатие при
//! этом не реализовано, и если сервер расширение **примет**, продолжать
//! нельзя — данные пойдут в непонятном нам виде. Такой ответ считается
//! ошибкой: оба конца соединения наши, и наша сторона расширение не
//! согласовывает.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use core::fmt::Write as _;

use sha1::{Digest as _, Sha1};

use atlas_crypto::rng::OsRng;

use crate::error::{Error, Result};

/// Константа из RFC 6455, подмешиваемая при вычислении ответа.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Значение `User-Agent` по умолчанию.
///
/// Обязано соответствовать профилю TLS: `ClientHello` от Chrome и
/// `User-Agent` от Firefox — это расхождение, которое видно.
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Вычислить значение `Sec-WebSocket-Accept` для заданного ключа.
#[must_use]
pub fn accept_for(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(GUID);
    STANDARD.encode(hasher.finalize())
}

/// Клиентское рукопожатие.
#[derive(Debug, Clone)]
pub struct ClientHandshake {
    key: String,
    user_agent: String,
    origin: Option<String>,
    extra: Vec<(String, String)>,
}

impl ClientHandshake {
    /// Создать рукопожатие со свежим случайным ключом.
    ///
    /// Ключ — шестнадцать случайных байт в base64, как требует RFC.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key: STANDARD.encode(OsRng::bytes::<16>()),
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            origin: None,
            extra: Vec::new(),
        }
    }

    /// Задать `User-Agent`.
    #[must_use]
    pub fn with_user_agent(mut self, value: impl Into<String>) -> Self {
        self.user_agent = value.into();
        self
    }

    /// Задать `Origin`.
    #[must_use]
    pub fn with_origin(mut self, value: impl Into<String>) -> Self {
        self.origin = Some(value.into());
        self
    }

    /// Добавить дополнительный заголовок.
    ///
    /// Ставится перед `Sec-WebSocket-Key`, как поступают браузеры
    /// с прикладными заголовками.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push((name.into(), value.into()));
        self
    }

    /// Значение `Sec-WebSocket-Key` этого рукопожатия.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Собрать текст HTTP-запроса.
    ///
    /// Порядок заголовков повторяет браузерный и значим: перестановка
    /// сама по себе является отличием.
    #[must_use]
    /// Пишем через `write!`, а не через `push_str(&format!(..))`:
    /// промежуточные строки здесь ни к чему.
    pub fn request(&self, host: &str, path: &str) -> String {
        let origin = self
            .origin
            .clone()
            .unwrap_or_else(|| format!("https://{host}"));

        let mut out = String::with_capacity(512);
        // Запись в String инфаллибельна, обрабатывать ошибку неоткуда.
        let _ = write!(out, "GET {path} HTTP/1.1\r\n");
        let _ = write!(out, "Host: {host}\r\n");
        out.push_str("Connection: Upgrade\r\n");
        out.push_str("Pragma: no-cache\r\n");
        out.push_str("Cache-Control: no-cache\r\n");
        let _ = write!(out, "User-Agent: {}\r\n", self.user_agent);
        out.push_str("Upgrade: websocket\r\n");
        let _ = write!(out, "Origin: {origin}\r\n");
        out.push_str("Sec-WebSocket-Version: 13\r\n");
        out.push_str("Accept-Encoding: gzip, deflate, br, zstd\r\n");
        out.push_str("Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n");
        for (name, value) in &self.extra {
            let _ = write!(out, "{name}: {value}\r\n");
        }
        let _ = write!(out, "Sec-WebSocket-Key: {}\r\n", self.key);
        out.push_str("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n");
        out.push_str("\r\n");
        out
    }

    /// Проверить ответ сервера.
    ///
    /// Возвращает длину заголовочной части: всё, что идёт после неё, —
    /// уже кадры, и это надо передать сборщику.
    ///
    /// # Errors
    ///
    /// [`Error::Incomplete`], если ответ ещё не дочитан;
    /// [`Error::Handshake`] при неверном статусе, отсутствующих или
    /// неверных заголовках, а также если сервер согласовал расширение.
    pub fn verify(&self, response: &[u8]) -> Result<usize> {
        // Границу ищем по байтам: сразу за заголовками может идти
        // первый кадр, а он двоичный и в UTF-8 не разбирается.
        let Some(end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
            return Err(Error::Incomplete);
        };
        let head = core::str::from_utf8(response.get(..end).unwrap_or_default())
            .map_err(|_| Error::Handshake("заголовки ответа не в UTF-8"))?;

        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap_or_default();
        if !is_switching_protocols(status) {
            return Err(Error::Handshake("ожидался ответ 101 Switching Protocols"));
        }

        let mut upgrade_ok = false;
        let mut connection_ok = false;
        let mut accept_ok = false;

        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();

            match name.as_str() {
                "upgrade" => upgrade_ok = value.eq_ignore_ascii_case("websocket"),
                // Значение может быть списком: `keep-alive, Upgrade`.
                "connection" => {
                    connection_ok = value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case("upgrade"));
                }
                "sec-websocket-accept" => accept_ok = value == accept_for(&self.key),
                "sec-websocket-extensions" if !value.is_empty() => {
                    return Err(Error::Handshake(
                        "сервер согласовал расширение, которое мы не реализуем",
                    ));
                }
                _ => {}
            }
        }

        if !upgrade_ok {
            return Err(Error::Handshake("отсутствует заголовок Upgrade"));
        }
        if !connection_ok {
            return Err(Error::Handshake("отсутствует заголовок Connection"));
        }
        if !accept_ok {
            // Несовпадение означает, что отвечает не тот, кому мы писали,
            // либо ответ подделан.
            return Err(Error::Handshake("неверный Sec-WebSocket-Accept"));
        }

        Ok(end + 4)
    }
}

impl Default for ClientHandshake {
    fn default() -> Self {
        Self::new()
    }
}

fn is_switching_protocols(status: &str) -> bool {
    let mut parts = status.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    version.starts_with("HTTP/1.") && code == "101"
}

/// Собрать ответ сервера на рукопожатие.
///
/// Нужен для тестов и для собственной точки выхода.
#[must_use]
pub fn server_response(key: &str) -> String {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_for(key)
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accept_matches_rfc_example() {
        // Пример из RFC 6455, раздел 1.3.
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn key_is_sixteen_random_bytes() {
        let handshake = ClientHandshake::new();
        assert_eq!(STANDARD.decode(handshake.key()).unwrap().len(), 16);

        let keys: std::collections::HashSet<String> = (0..64)
            .map(|_| ClientHandshake::new().key().to_owned())
            .collect();
        assert!(keys.len() > 60, "ключи рукопожатия повторяются");
    }

    #[test]
    fn request_carries_the_browser_header_set() {
        let request = ClientHandshake::new().request("cdn.example.com", "/api/v1");

        for expected in [
            "GET /api/v1 HTTP/1.1",
            "Host: cdn.example.com",
            "Connection: Upgrade",
            "Upgrade: websocket",
            "Sec-WebSocket-Version: 13",
            "Origin: https://cdn.example.com",
            // Протоколу не нужны, но браузер их шлёт.
            "Pragma: no-cache",
            "Cache-Control: no-cache",
            "Accept-Encoding:",
            "Accept-Language:",
            "User-Agent: Mozilla/5.0",
        ] {
            assert!(request.contains(expected), "нет строки `{expected}`");
        }
        assert!(request.ends_with("\r\n\r\n"));
    }

    #[test]
    fn header_order_follows_the_browser() {
        let request = ClientHandshake::new().request("example.com", "/");
        let position = |needle: &str| request.find(needle).unwrap_or(usize::MAX);

        assert!(position("Host:") < position("Connection:"));
        assert!(position("Connection:") < position("User-Agent:"));
        assert!(position("User-Agent:") < position("Upgrade:"));
        assert!(position("Upgrade:") < position("Sec-WebSocket-Version:"));
        assert!(position("Sec-WebSocket-Version:") < position("Sec-WebSocket-Key:"));
    }

    #[test]
    fn extra_headers_precede_the_key() {
        let request = ClientHandshake::new()
            .with_header("X-Forwarded-Proto", "https")
            .request("example.com", "/");
        assert!(
            request.find("X-Forwarded-Proto").unwrap_or(usize::MAX)
                < request.find("Sec-WebSocket-Key").unwrap_or(0)
        );
    }

    #[test]
    fn accepts_a_correct_response() {
        let handshake = ClientHandshake::new();
        let response = server_response(handshake.key());
        assert_eq!(
            handshake.verify(response.as_bytes()).unwrap(),
            response.len()
        );
    }

    #[test]
    fn returns_offset_so_trailing_frames_are_not_lost() {
        // Сервер вправе прислать первые кадры в том же пакете.
        let handshake = ClientHandshake::new();
        let mut wire = server_response(handshake.key()).into_bytes();
        let header_len = wire.len();
        wire.extend_from_slice(b"\x82\x03abc");

        assert_eq!(handshake.verify(&wire).unwrap(), header_len);
    }

    #[test]
    fn waits_for_the_full_header_block() {
        let handshake = ClientHandshake::new();
        let response = server_response(handshake.key());
        let partial = response.get(..response.len() - 2).unwrap_or_default();
        assert_eq!(handshake.verify(partial.as_bytes()), Err(Error::Incomplete));
    }

    #[test]
    fn rejects_wrong_accept_value() {
        let handshake = ClientHandshake::new();
        let response = server_response("dGhlIHNhbXBsZSBub25jZQ==");
        assert!(matches!(
            handshake.verify(response.as_bytes()),
            Err(Error::Handshake(_))
        ));
    }

    #[test]
    fn rejects_non_101_status() {
        let handshake = ClientHandshake::new();
        for status in ["HTTP/1.1 200 OK", "HTTP/1.1 400 Bad Request"] {
            let response = format!("{status}\r\nUpgrade: websocket\r\n\r\n");
            assert!(matches!(
                handshake.verify(response.as_bytes()),
                Err(Error::Handshake(_))
            ));
        }
    }

    #[test]
    fn rejects_negotiated_extension() {
        // Расширение мы предлагаем ради отпечатка, но не реализуем.
        let handshake = ClientHandshake::new();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            accept_for(handshake.key())
        );
        assert!(matches!(
            handshake.verify(response.as_bytes()),
            Err(Error::Handshake(_))
        ));
    }

    #[test]
    fn accepts_connection_header_as_a_list() {
        let handshake = ClientHandshake::new();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            accept_for(handshake.key())
        );
        assert!(handshake.verify(response.as_bytes()).is_ok());
    }

    #[test]
    fn survives_arbitrary_garbage() {
        let handshake = ClientHandshake::new();
        for seed in 0_u8..=255 {
            let noise: Vec<u8> = (0..seed).map(|i| i.wrapping_mul(seed) | 0x20).collect();
            let _ = handshake.verify(&noise);
        }
    }
}
