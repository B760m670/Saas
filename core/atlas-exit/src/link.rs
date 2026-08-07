//! Ключ доступа: строка `vless://`, которую вставляют в клиент.
//!
//! # Зачем отдельный модуль
//!
//! Ключ печатался прямо в `main`, и туда подставлялся **адрес
//! прослушивания**. Для запуска по замыслу проекта — «точка выхода на
//! своей машине, клиент на телефоне» — это давало заведомо нерабочий
//! ключ: при `--listen 0.0.0.0:443` в ссылку попадало `0.0.0.0:443`.
//!
//! Отказ при этом выглядел бы как отказ **туннеля**, а не как ошибка в
//! одной строке: телефон честно попробовал бы соединиться с `0.0.0.0`,
//! получил бы отказ, и приложение показало бы «не удалось
//! подключиться». Искать причину пришлось бы в TLS, REALITY и ТСПУ —
//! то есть где угодно, кроме места, где она есть.
//!
//! Поэтому выбор адреса вынесен сюда: у него есть правило, и правило
//! проверяется.
//!
//! # Правило
//!
//! | Адрес прослушивания | Что попадает в ключ |
//! |---|---|
//! | указан `--host` | он, и только он |
//! | конкретный адрес (`203.0.113.7:443`) | он же |
//! | неопределённый (`0.0.0.0`, `::`) | **ничего: это ошибка** |
//!
//! Неопределённый адрес значит «слушаю на всех сетевых картах». Какой
//! из адресов машины виден снаружи, программа не знает и узнать не
//! может, не спросив у третьей стороны, — а лишний запрос наружу с
//! точки выхода это ровно то, чего здесь быть не должно.

use core::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::is_public;

/// Куда клиенту идти за туннелем.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Имя или адрес, как его напишут в ключе.
    pub host: String,
    /// Порт.
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Литерал IPv6 в URL обязан быть в скобках, иначе двоеточия
        // адреса неотличимы от двоеточия перед портом.
        if self.host.contains(':') && !self.host.starts_with('[') {
            write!(out, "[{}]:{}", self.host, self.port)
        } else {
            write!(out, "{}:{}", self.host, self.port)
        }
    }
}

/// Почему адрес для ключа выбрать не удалось.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointError {
    /// Слушаем на всех картах — какая из них видна снаружи, неизвестно.
    Unspecified,
    /// `--host` задан, но не разбирается.
    BadHost(String),
}

impl fmt::Display for EndpointError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => out.write_str(
                "точка выхода слушает на всех сетевых картах, поэтому адрес \
                 для ключа неизвестен.\nУкажите его сами: --host АДРЕС \
                 (внешний IP машины или доменное имя).",
            ),
            Self::BadHost(text) => write!(out, "--host: не разбирается как адрес или имя: {text}"),
        }
    }
}

impl core::error::Error for EndpointError {}

/// Насколько далеко достанет этот ключ.
///
/// Не влияет на сам ключ — только на то, что сказать человеку. Молча
/// выдать ключ с адресом `192.168.1.5` значит обречь его на отладку
/// туннеля вместо чтения одной строки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Адрес виден из интернета — работает и на мобильном интернете.
    Internet,
    /// Адрес частный: только в той же локальной сети.
    LocalNetwork,
    /// Петля: только на этой же машине.
    SameMachine,
    /// Имя, а не адрес. Куда оно указывает, здесь не проверяется.
    Name,
}

impl Reach {
    /// Что сказать человеку про такой ключ.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::Internet => "адрес виден из интернета",
            Self::LocalNetwork => {
                "адрес частный: ключ сработает только с устройств этой же \
                 локальной сети. Из интернета — нет"
            }
            Self::SameMachine => {
                "адрес петлевой: ключ сработает только на этой же машине. \
                 С телефона — нет"
            }
            Self::Name => "доменное имя: убедитесь, что оно указывает на эту машину",
        }
    }
}

/// Разобрать `--host`: `имя`, `адрес`, `имя:порт` или `[v6]:порт`.
///
/// Порт из `--host` важнее порта прослушивания: пробрасывая порт на
/// домашнем маршрутизаторе, снаружи почти всегда открывают не тот
/// номер, что занят внутри.
fn parse_host(text: &str, fallback_port: u16) -> Option<Endpoint> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    // Сначала целый адрес с портом: так `[::1]:443` и `10.0.0.1:443`
    // разбираются стандартными средствами, без ручного счёта скобок.
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Some(Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
        });
    }

    // Голый литерал IPv6 — двоеточий много, но порта нет.
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(Endpoint {
            host: ip.to_string(),
            port: fallback_port,
        });
    }

    // `[::1]` без порта.
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        let ip = inner.parse::<IpAddr>().ok()?;
        return Some(Endpoint {
            host: ip.to_string(),
            port: fallback_port,
        });
    }

    // Имя, возможно с портом.
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok()?),
        None => (text, fallback_port),
    };
    if host.is_empty() || !host.chars().all(is_name_char) {
        return None;
    }
    Some(Endpoint {
        host: host.to_owned(),
        port,
    })
}

/// Допустимый в имени узла знак.
///
/// Проверка списком разрешённого, а не запрещённого: имя попадает в
/// URL, и знак вроде `?` или `#` разрезал бы ключ пополам.
const fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
}

/// Выбрать адрес для ключа.
///
/// # Errors
///
/// Вернёт [`EndpointError`], если `--host` не разбирается или если он
/// не задан, а слушаем мы на неопределённом адресе.
pub fn endpoint(bound: SocketAddr, host: Option<&str>) -> Result<(Endpoint, Reach), EndpointError> {
    if let Some(text) = host {
        let endpoint = parse_host(text, bound.port())
            .ok_or_else(|| EndpointError::BadHost(text.to_owned()))?;
        let reach = endpoint
            .host
            .parse::<IpAddr>()
            .map_or(Reach::Name, reach_of);
        return Ok((endpoint, reach));
    }

    if bound.ip().is_unspecified() {
        return Err(EndpointError::Unspecified);
    }

    Ok((
        Endpoint {
            host: bound.ip().to_string(),
            port: bound.port(),
        },
        reach_of(bound.ip()),
    ))
}

fn reach_of(ip: IpAddr) -> Reach {
    if ip.is_loopback() {
        Reach::SameMachine
    } else if is_public(ip) {
        Reach::Internet
    } else {
        Reach::LocalNetwork
    }
}

/// Всё, из чего складывается ключ доступа.
#[derive(Debug, Clone)]
pub struct AccessKey<'a> {
    /// Куда идти.
    pub endpoint: &'a Endpoint,
    /// Имя пользователя VLESS.
    pub uuid: &'a str,
    /// Имя сайта прикрытия — оно же SNI.
    pub sni: &'a str,
    /// Публичный ключ REALITY, base64url без выравнивания.
    pub public_key: &'a str,
    /// Короткий идентификатор, hex.
    pub short_id: &'a str,
}

impl AccessKey<'_> {
    /// Собрать строку `vless://`.
    #[must_use]
    pub fn to_link(&self) -> String {
        format!(
            "vless://{uuid}@{endpoint}?type=tcp&security=reality&sni={sni}\
             &pbk={pbk}&sid={sid}&fp=chrome&flow=xtls-rprx-vision#atlas",
            uuid = self.uuid,
            endpoint = self.endpoint,
            sni = self.sni,
            pbk = self.public_key,
            sid = self.short_id,
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn bound(text: &str) -> SocketAddr {
        text.parse().expect("адрес разбирается")
    }

    // Та самая ошибка, ради которой написан модуль: ключ с `0.0.0.0`
    // выглядит настоящим и не работает никогда.
    #[test]
    fn the_wildcard_address_never_reaches_the_key() {
        let error = endpoint(bound("0.0.0.0:443"), None).expect_err("должно быть отказом");
        assert_eq!(error, EndpointError::Unspecified);
        assert!(
            error.to_string().contains("--host"),
            "отказ обязан называть выход: {error}"
        );

        assert_eq!(
            endpoint(bound("[::]:443"), None),
            Err(EndpointError::Unspecified),
            "у IPv6 неопределённый адрес такой же нерабочий"
        );
    }

    #[test]
    fn an_explicit_host_wins_over_the_listening_address() {
        let (chosen, reach) =
            endpoint(bound("0.0.0.0:8443"), Some("93.184.216.34")).expect("адрес задан явно");
        assert_eq!(chosen.host, "93.184.216.34");
        assert_eq!(chosen.port, 8443, "порт берётся от прослушивания");
        assert_eq!(reach, Reach::Internet);
    }

    // Проброс порта на домашнем маршрутизаторе почти всегда меняет
    // номер: снаружи 443, внутри 8443.
    #[test]
    fn the_port_from_host_overrides_the_listening_port() {
        let (chosen, _) =
            endpoint(bound("0.0.0.0:8443"), Some("93.184.216.34:443")).expect("порт задан явно");
        assert_eq!(chosen.to_string(), "93.184.216.34:443");
    }

    #[test]
    fn a_name_is_accepted_and_marked_as_unverified() {
        let (chosen, reach) =
            endpoint(bound("0.0.0.0:443"), Some("exit.example.com")).expect("имя разбирается");
        assert_eq!(chosen.to_string(), "exit.example.com:443");
        assert_eq!(reach, Reach::Name);
    }

    // Ключ идёт в URL. Знак `#` в имени отрезал бы у ссылки всё
    // после себя, и клиент получил бы огрызок без публичного ключа.
    #[test]
    fn a_host_that_would_break_the_url_is_refused() {
        for bad in ["exit#atlas", "exit?a=1", "exit/../x", "прим.рф", " ", ""] {
            assert!(
                matches!(
                    endpoint(bound("0.0.0.0:443"), Some(bad)),
                    Err(EndpointError::BadHost(_))
                ),
                "имя {bad:?} обязано быть отклонено"
            );
        }
    }

    #[test]
    fn a_literal_address_is_taken_as_is() {
        let (chosen, reach) = endpoint(bound("192.168.1.5:443"), None).expect("адрес конкретный");
        assert_eq!(chosen.to_string(), "192.168.1.5:443");
        assert_eq!(reach, Reach::LocalNetwork);

        let (_, reach) = endpoint(bound("127.0.0.1:8443"), None).expect("петля тоже конкретна");
        assert_eq!(reach, Reach::SameMachine);
    }

    // Без скобок `2606:4700::1:443` разбирается как что угодно, только
    // не как адрес с портом.
    #[test]
    fn an_ipv6_literal_is_bracketed_in_the_link() {
        let (chosen, reach) = endpoint(bound("[2606:4700::1]:443"), None).expect("адрес IPv6");
        assert_eq!(chosen.to_string(), "[2606:4700::1]:443");
        assert_eq!(reach, Reach::Internet);

        let (chosen, _) =
            endpoint(bound("0.0.0.0:443"), Some("[2606:4700::1]")).expect("голый литерал в --host");
        assert_eq!(chosen.to_string(), "[2606:4700::1]:443");
    }

    #[test]
    fn the_link_carries_everything_the_client_needs() {
        let endpoint = Endpoint {
            host: "93.184.216.34".to_owned(),
            port: 443,
        };
        let link = AccessKey {
            endpoint: &endpoint,
            uuid: "5c1f0e4e-0000-4000-8000-000000000001",
            sni: "www.microsoft.com",
            public_key: "AbCd_-01",
            short_id: "dead",
        }
        .to_link();

        for part in [
            "vless://5c1f0e4e-0000-4000-8000-000000000001@93.184.216.34:443",
            "security=reality",
            "sni=www.microsoft.com",
            "pbk=AbCd_-01",
            "sid=dead",
            "flow=xtls-rprx-vision",
        ] {
            assert!(link.contains(part), "в ключе нет {part}: {link}");
        }
        assert!(
            !link.contains(' '),
            "пробел в ключе оборвёт вставку из буфера: {link}"
        );
    }
}
