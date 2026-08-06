//! Соединение целиком: от ключа доступа до работающего туннеля.
//!
//! Крейт ничего не изобретает — он складывает уже готовые части в том
//! порядке, в каком они лежат на проводе:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │ TCP к точке выхода                                      │
//! │ ┌─────────────────────────────────────────────────────┐ │
//! │ │ TLS 1.3 с отпечатком браузера, метка REALITY внутри │ │
//! │ │ ┌─────────────────────────────────────────────────┐ │ │
//! │ │ │ VLESS: заголовок назначения, обрамление Vision  │ │ │
//! │ │ │ ┌─────────────────────────────────────────────┐ │ │ │
//! │ │ │ │ трафик пользователя                         │ │ │ │
//! │ │ │ └─────────────────────────────────────────────┘ │ │ │
//! │ │ └─────────────────────────────────────────────────┘ │ │
//! │ └─────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! Наружу отдаётся обычный `Read + Write`, за которым лежит соединение
//! до заданного адреса — как если бы туда открыли простой сокет.
//!
//! # Пример
//!
//! ```no_run
//! use std::io::{Read, Write};
//! use atlas_dial::{dial, Target};
//! use atlas_types::ProxyKey;
//!
//! let key = ProxyKey::parse("vless://…")?;
//! let mut tunnel = dial(&key, &Target::domain("example.org", 443))?;
//!
//! tunnel.write_all(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")?;
//! let mut answer = Vec::new();
//! tunnel.read_to_end(&mut answer)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Чего здесь нет
//!
//! Выбора стратегии, повторов, миграции при деградации, разбора
//! маршрутов. Всё это — задача оркестратора, который встанет над этим
//! крейтом. Здесь ровно одна попытка ровно по одному ключу: если она не
//! удалась, наружу уходит внятная причина, а решать, что делать дальше,
//! будет вызывающий.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

mod error;

pub use error::{Error, Result};

use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atlas_tls::client::{ClientConfig, HelloSealer, ServerVerifier};
use atlas_tls::{Chrome, TlsStream};
use atlas_types::{Credentials, Flow as KeyFlow, Protocol, ProxyKey, SecurityKind};
use atlas_vless::session::{Flow, Session};
use atlas_vless::{Address, Endpoint};

/// Готовый туннель до адреса назначения.
pub type Tunnel = Session<TlsStream<TcpStream>>;

/// Куда именно соединяться через точку выхода.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target(Endpoint);

impl Target {
    /// Доменное имя и порт.
    ///
    /// Предпочтительно адресам: имя разрешает точка выхода, а значит
    /// запрос DNS не покидает туннель и не виден оператору.
    #[must_use]
    pub fn domain(name: impl Into<String>, port: u16) -> Self {
        Self(Endpoint::new(Address::Domain(name.into()), port))
    }

    /// Адрес IPv4 и порт.
    #[must_use]
    pub const fn ipv4(octets: [u8; 4], port: u16) -> Self {
        Self(Endpoint::new(Address::Ipv4(octets), port))
    }

    /// Адрес IPv6 и порт.
    #[must_use]
    pub const fn ipv6(octets: [u8; 16], port: u16) -> Self {
        Self(Endpoint::new(Address::Ipv6(octets), port))
    }

    /// Точка назначения в терминах VLESS.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.0
    }
}

/// Настройки одной попытки соединения.
#[derive(Debug, Clone)]
pub struct DialOptions {
    /// Предел ожидания при установлении TCP.
    pub connect_timeout: Duration,
    /// Предел ожидания чтения.
    pub read_timeout: Option<Duration>,
    /// Текущее время в секундах эпохи.
    ///
    /// Метка REALITY несёт отметку времени, и сервер сверяет её со
    /// своими часами. Значение передаётся снаружи, чтобы крейт не
    /// зависел от источника времени, а тесты были воспроизводимы;
    /// [`DialOptions::default`] берёт системные часы.
    pub now: u32,
    /// Слать ли `encrypted_client_hello`.
    ///
    /// По умолчанию да — так делает Chrome. Отключается там, где
    /// промежуточный узел рвёт соединение при виде этого расширения
    /// (см. `docs/09-lab.md`).
    pub ech: bool,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Some(Duration::from_secs(30)),
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| u32::try_from(elapsed.as_secs()).unwrap_or(0)),
            ech: true,
        }
    }
}

/// Открыть туннель до адреса назначения через точку выхода из ключа.
///
/// # Errors
///
/// [`Error::Unsupported`], если ключ описывает схему, которую мы пока не
/// собираем; [`Error::Key`] при нехватке или некорректности полей;
/// [`Error::Io`] при отказе сети или рукопожатия.
pub fn dial(key: &ProxyKey, target: &Target) -> Result<Tunnel> {
    dial_with(key, target, &DialOptions::default())
}

/// То же, но с явными настройками попытки.
///
/// # Errors
///
/// Те же условия, что и у [`dial`].
pub fn dial_with(key: &ProxyKey, target: &Target, options: &DialOptions) -> Result<Tunnel> {
    let plan = Plan::from_key(key)?;
    let socket = connect_tcp(&key.host, key.port, options)?;
    let stream = plan.wrap_tls(socket, options)?;
    Session::connect(stream, plan.uuid, target.endpoint().clone(), plan.flow).map_err(Error::Io)
}

/// Разобранный ключ в том виде, в каком он нужен для соединения.
struct Plan {
    uuid: [u8; 16],
    flow: Flow,
    server_name: String,
    alpn: Vec<String>,
    reality_public: [u8; 32],
    short_id: Vec<u8>,
}

impl Plan {
    /// Проверить, что ключ описывает схему, которую мы умеем собирать.
    ///
    /// Проверки идут до открытия сокета: соединяться, чтобы потом
    /// выяснить нехватку поля, — значит светить попытку впустую.
    fn from_key(key: &ProxyKey) -> Result<Self> {
        if key.protocol != Protocol::Vless {
            return Err(Error::Unsupported("пока собирается только VLESS"));
        }
        if key.security.kind != SecurityKind::Reality {
            return Err(Error::Unsupported("пока собирается только REALITY"));
        }

        let Credentials::Uuid { uuid } = &key.credentials else {
            return Err(Error::Key("для VLESS нужен идентификатор пользователя"));
        };
        let uuid = atlas_types::uuid_to_bytes(uuid)
            .ok_or(Error::Key("идентификатор пользователя не разбирается"))?;

        let reality = key
            .security
            .reality
            .as_ref()
            .ok_or(Error::Key("в ключе нет параметров REALITY"))?;

        let server_name = key
            .security
            .sni
            .clone()
            .ok_or(Error::Key("REALITY требует SNI сайта прикрытия"))?;

        let reality_public = decode_public_key(&reality.public_key)?;
        let short_id = decode_short_id(&reality.short_id)?;

        let alpn = if key.security.alpn.is_empty() {
            vec!["h2".to_owned(), "http/1.1".to_owned()]
        } else {
            key.security.alpn.clone()
        };

        Ok(Self {
            uuid,
            flow: match key.flow {
                KeyFlow::XtlsRprxVision => Flow::Vision,
                KeyFlow::None => Flow::Plain,
            },
            server_name,
            alpn,
            reality_public,
            short_id,
        })
    }

    /// Поднять TLS с меткой REALITY поверх сокета.
    fn wrap_tls(&self, socket: TcpStream, options: &DialOptions) -> Result<TlsStream<TcpStream>> {
        let sealer = atlas_reality::Sealer::new(
            self.reality_public,
            &self.short_id,
            CLIENT_VERSION,
            options.now,
        )
        .map_err(|_| Error::Key("shortId длиннее восьми байт"))?;
        let verifier = atlas_reality::Verifier::new(sealer.auth_key());

        let profile = if options.ech {
            Chrome::v141()
        } else {
            Chrome::v141().without_ech()
        };

        let config = ClientConfig::new(self.server_name.clone())
            .with_profile(profile)
            .with_alpn(self.alpn.clone())
            .with_sealer(Box::new(sealer) as Box<dyn HelloSealer>)
            .with_verifier(Box::new(verifier) as Box<dyn ServerVerifier>);

        TlsStream::connect(socket, config).map_err(Error::Io)
    }
}

/// Версия клиента в метке REALITY.
///
/// Сервер вправе отвергать слишком старые версии, поэтому значение
/// осмысленное, а не нулевое.
const CLIENT_VERSION: [u8; 3] = [26, 3, 27];

/// Открыть TCP с ограничением времени.
fn connect_tcp(host: &str, port: u16, options: &DialOptions) -> Result<TcpStream> {
    use std::net::ToSocketAddrs as _;

    let addresses: Vec<_> = (host, port).to_socket_addrs().map_err(Error::Io)?.collect();
    let first = addresses
        .first()
        .ok_or(Error::Key("адрес точки выхода не разрешается"))?;

    let socket = TcpStream::connect_timeout(first, options.connect_timeout).map_err(Error::Io)?;
    socket
        .set_read_timeout(options.read_timeout)
        .map_err(Error::Io)?;
    // Задержка Нейгла ради нескольких байт заголовка ломает
    // интерактивность и сдвигает тайминги, по которым нас узнают.
    socket.set_nodelay(true).map_err(Error::Io)?;
    Ok(socket)
}

/// Разобрать публичный ключ REALITY из base64url без паддинга.
fn decode_public_key(text: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;

    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text))
        .map_err(|_| Error::Key("публичный ключ REALITY не разбирается"))?;
    raw.try_into()
        .map_err(|_| Error::Key("публичный ключ REALITY не 32 байта"))
}

/// Разобрать `shortId` из шестнадцатеричной записи.
fn decode_short_id(text: &str) -> Result<Vec<u8>> {
    if text.is_empty() {
        // Пустой идентификатор допустим: сервер, у которого разрешён
        // пустой `shortId`, принимает всех, кто знает публичный ключ.
        return Ok(Vec::new());
    }
    if text.len() % 2 != 0 || text.len() > 16 {
        return Err(Error::Key("shortId не является hex длиной до 16 знаков"));
    }

    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            core::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or(Error::Key("shortId не является шестнадцатеричным"))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const KEY: &str = "vless://11111111-2222-3333-4444-555555555555@198.51.100.7:443\
        ?type=tcp&security=reality&sni=www.microsoft.com\
        &pbk=4QYPIu_pmCTct6m9UyB99TlHxg94cY5H29zTHBfOEyc&sid=dead\
        &fp=chrome&flow=xtls-rprx-vision#tochka";

    #[test]
    fn a_complete_key_yields_a_usable_plan() {
        let key = ProxyKey::parse(KEY).unwrap();
        let plan = Plan::from_key(&key).unwrap();

        assert_eq!(plan.uuid[0], 0x11);
        assert_eq!(plan.flow, Flow::Vision);
        assert_eq!(plan.server_name, "www.microsoft.com");
        assert_eq!(plan.short_id, vec![0xde, 0xad]);
        assert_eq!(plan.reality_public.len(), 32);
        assert_eq!(plan.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
    }

    #[test]
    fn a_key_without_reality_is_refused_before_the_socket_opens() {
        // Соединяться, чтобы потом выяснить нехватку поля, — значит
        // светить попытку впустую.
        let uri = KEY.replace("&security=reality", "&security=tls");
        let key = ProxyKey::parse(&uri).unwrap();
        assert!(matches!(
            Plan::from_key(&key),
            Err(Error::Unsupported(_) | Error::Key(_))
        ));
    }

    #[test]
    fn a_key_without_sni_is_refused() {
        let uri = KEY.replace("&sni=www.microsoft.com", "");
        let key = ProxyKey::parse(&uri).unwrap();
        assert!(matches!(Plan::from_key(&key), Err(Error::Key(_))));
    }

    #[test]
    fn short_ids_are_decoded_and_validated() {
        assert_eq!(decode_short_id("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_short_id("dead").unwrap(), vec![0xde, 0xad]);
        assert_eq!(decode_short_id("0123456789abcdef").unwrap().len(), 8);

        assert!(decode_short_id("abc").is_err(), "нечётная длина");
        assert!(decode_short_id("zz").is_err(), "не hex");
        assert!(
            decode_short_id("0123456789abcdef00").is_err(),
            "длиннее 8 байт"
        );
    }

    #[test]
    fn public_keys_are_accepted_in_both_base64_alphabets() {
        // Ключи в обращении встречаются и в url-safe, и в обычном
        // алфавите. Отвергать половину из-за алфавита — не дело.
        let url_safe = "4QYPIu_pmCTct6m9UyB99TlHxg94cY5H29zTHBfOEyc";
        let standard = url_safe.replace('_', "/").replace('-', "+");
        assert_eq!(
            decode_public_key(url_safe).unwrap(),
            decode_public_key(&standard).unwrap()
        );
        assert!(decode_public_key("не base64").is_err());
        assert!(decode_public_key("aGVsbG8").is_err(), "не 32 байта");
    }

    #[test]
    fn a_plain_flow_key_produces_a_plain_session() {
        let uri = KEY.replace("&flow=xtls-rprx-vision", "");
        let key = ProxyKey::parse(&uri).unwrap();
        assert_eq!(Plan::from_key(&key).unwrap().flow, Flow::Plain);
    }

    #[test]
    fn targets_carry_the_address_untouched() {
        assert_eq!(
            Target::domain("example.org", 443).endpoint().address,
            Address::Domain("example.org".to_owned())
        );
        assert_eq!(Target::ipv4([1, 2, 3, 4], 80).endpoint().port, 80);
    }
}
