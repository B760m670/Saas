//! Терпимый разбор URI.
//!
//! Стандартный URL-парсер здесь не годится: ключи прокси-протоколов формально
//! не являются валидными URI. `ss://` кладёт base64 в userinfo, `vmess://`
//! кладёт base64-JSON вместо всего authority, разные клиенты по-разному
//! экранируют параметры. Нормализующий парсер такие строки портит, поэтому
//! режем вручную и максимально терпимо.

use std::borrow::Cow;
use std::collections::BTreeMap;

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};

use crate::error::{Error, Result};

/// Символы, экранируемые при построении значения query-параметра.
///
/// Набор намеренно шире необходимого: разные клиенты по-разному терпимы
/// к неэкранированным символам, а лишнее экранирование понимают все.
const QUERY_ESCAPE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'&')
    .add(b'+')
    .add(b'/')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Разобранный на части URI ключа.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawUri {
    /// Схема в нижнем регистре, без `://`.
    pub scheme: String,
    /// Всё до `@`, если `@` есть. Не декодируется — смысл зависит от схемы.
    pub userinfo: Option<String>,
    /// Хост без квадратных скобок для IPv6.
    pub host: String,
    /// Порт, если указан явно.
    pub port: Option<u16>,
    /// Параметры запроса, значения уже percent-декодированы.
    pub query: BTreeMap<String, String>,
    /// Фрагмент после `#`, percent-декодированный. Обычно это имя точки.
    pub fragment: Option<String>,
}

impl RawUri {
    /// Разобрать строку ключа на составные части.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::MissingScheme`], если в строке нет `://`,
    /// и [`Error::Invalid`], если порт не является числом.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let (scheme, rest) = input.split_once("://").ok_or(Error::MissingScheme)?;
        if scheme.is_empty() {
            return Err(Error::MissingScheme);
        }

        // Порядок важен: сначала отрезаем фрагмент, иначе `#` внутри имени
        // точки утащит за собой часть query.
        let (rest, fragment) = match rest.split_once('#') {
            Some((head, tail)) => (head, Some(decode(tail).into_owned())),
            None => (rest, None),
        };

        let (rest, query) = match rest.split_once('?') {
            Some((head, tail)) => (head, parse_query(tail)),
            None => (rest, BTreeMap::new()),
        };

        // `rsplit_once`, а не `split_once`: пароль может содержать `@`,
        // а хост — нет.
        let (userinfo, authority) = match rest.rsplit_once('@') {
            Some((user, host)) => (Some(user.to_owned()), host),
            None => (None, rest),
        };

        let (host, port) = split_host_port(authority)?;

        Ok(Self {
            scheme: scheme.to_ascii_lowercase(),
            userinfo,
            host,
            port,
            query,
            fragment,
        })
    }

    /// Значение параметра запроса, если оно есть и непустое.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    /// Значение первого из перечисленных параметров, который присутствует.
    ///
    /// Нужно из-за разнобоя в именах: `pbk`/`publicKey`, `sni`/`peer`/`host`.
    #[must_use]
    pub fn param_any(&self, names: &[&str]) -> Option<&str> {
        names.iter().find_map(|n| self.param(n))
    }

    /// Булев параметр. Истиной считаются `1`, `true`, `yes`.
    #[must_use]
    pub fn param_bool(&self, name: &str) -> bool {
        self.param(name)
            .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
    }
}

/// Разделить `host:port`, корректно обработав IPv6 в квадратных скобках.
fn split_host_port(authority: &str) -> Result<(String, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6: `[::1]:443` либо `[::1]`.
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| Error::invalid("host", "незакрытая скобка в IPv6-адресе"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) if !p.is_empty() => Some(parse_port(p)?),
            _ => None,
        };
        return Ok((host.to_owned(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() => Ok((host.to_owned(), Some(parse_port(port)?))),
        _ => Ok((authority.to_owned(), None)),
    }
}

fn parse_port(raw: &str) -> Result<u16> {
    raw.parse::<u16>()
        .map_err(|_| Error::invalid("port", format!("`{raw}` не является номером порта")))
}

/// Разобрать строку запроса в отображение с percent-декодированными значениями.
///
/// При повторе ключа побеждает первое вхождение — так же ведут себя
/// распространённые клиенты.
fn parse_query(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in raw.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode(key).into_owned();
        if key.is_empty() {
            continue;
        }
        out.entry(key).or_insert_with(|| decode(value).into_owned());
    }
    out
}

/// Percent-декодирование с откатом на исходную строку при неверном UTF-8.
///
/// Терять весь ключ из-за одного битого байта в имени точки нельзя.
fn decode(raw: &str) -> Cow<'_, str> {
    percent_decode_str(raw)
        .decode_utf8()
        .unwrap_or(Cow::Borrowed(raw))
}

/// Percent-декодировать компонент URI.
///
/// Применяется к userinfo, которое [`RawUri`] намеренно оставляет сырым:
/// его семантика зависит от схемы. Для base64-userinfo (`ss://`) вызов
/// безопасен — ни один из алфавитов base64 не содержит `%`.
#[must_use]
pub fn decode_component(value: &str) -> String {
    decode(value).into_owned()
}

/// Экранировать значение для подстановки в строку запроса.
#[must_use]
pub fn encode_param(value: &str) -> String {
    utf8_percent_encode(value, QUERY_ESCAPE).to_string()
}

/// Собрать `host:port`, обрамив IPv6 квадратными скобками.
#[must_use]
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_uri() {
        let uri = RawUri::parse("vless://uuid-here@example.com:443?type=tcp&sni=a.b#Моя%20точка")
            .unwrap();
        assert_eq!(uri.scheme, "vless");
        assert_eq!(uri.userinfo.as_deref(), Some("uuid-here"));
        assert_eq!(uri.host, "example.com");
        assert_eq!(uri.port, Some(443));
        assert_eq!(uri.param("type"), Some("tcp"));
        assert_eq!(uri.fragment.as_deref(), Some("Моя точка"));
    }

    #[test]
    fn handles_ipv6_authority() {
        let uri = RawUri::parse("trojan://pass@[2001:db8::1]:8443#v6").unwrap();
        assert_eq!(uri.host, "2001:db8::1");
        assert_eq!(uri.port, Some(8443));
    }

    #[test]
    fn password_may_contain_at_sign() {
        let uri = RawUri::parse("trojan://p@ss@example.com:443").unwrap();
        assert_eq!(uri.userinfo.as_deref(), Some("p@ss"));
        assert_eq!(uri.host, "example.com");
    }

    #[test]
    fn fragment_is_split_before_query() {
        let uri = RawUri::parse("vless://u@h:443?a=1#name?with?marks").unwrap();
        assert_eq!(uri.param("a"), Some("1"));
        assert_eq!(uri.fragment.as_deref(), Some("name?with?marks"));
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(RawUri::parse("example.com:443"), Err(Error::MissingScheme));
    }

    #[test]
    fn rejects_bad_port() {
        assert!(RawUri::parse("vless://u@example.com:99999").is_err());
    }

    #[test]
    fn joins_ipv6_back() {
        assert_eq!(join_host_port("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(join_host_port("example.com", 443), "example.com:443");
    }
}
