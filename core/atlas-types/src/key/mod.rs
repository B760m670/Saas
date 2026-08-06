//! Ключ доступа к точке выхода: разбор, построение, проверка.
//!
//! Единая модель для всех схем — `vless://`, `vmess://`, `trojan://`, `ss://`,
//! `hysteria2://`, `tuic://`, `anytls://`. Разбор терпимый (принимаем всё, что
//! принимают распространённые клиенты), построение — каноническое.

mod build;
mod parse;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::protocol::{Fingerprint, Flow, Protocol, SecurityKind, TransportKind};

/// Учётные данные для аутентификации на точке выхода.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Credentials {
    /// VLESS, `VMess`: единственный идентификатор, передаётся внутри TLS.
    Uuid {
        /// Идентификатор в каноническом виде 8-4-4-4-12.
        uuid: String,
    },
    /// Trojan, Hysteria2, `AnyTLS`: общий секрет.
    Password {
        /// Секрет в открытом виде.
        password: String,
    },
    /// TUIC v5: пара идентификатор + секрет.
    UuidPassword {
        /// Идентификатор пользователя.
        uuid: String,
        /// Секрет.
        password: String,
    },
    /// Shadowsocks: шифр задаётся вместе с ключом.
    Shadowsocks {
        /// Имя шифра, например `2022-blake3-aes-128-gcm`.
        method: String,
        /// Пароль либо base64-ключ для ветки 2022.
        password: String,
    },
}

impl Credentials {
    /// Идентификатор в виде 16 байт, если учётные данные его содержат.
    ///
    /// VLESS и `VMess` передают UUID по проводу в бинарном виде, поэтому
    /// разбор шестнадцатеричной записи нужен транспортному слою.
    #[must_use]
    pub fn uuid_bytes(&self) -> Option<[u8; 16]> {
        let text = match self {
            Self::Uuid { uuid } | Self::UuidPassword { uuid, .. } => uuid,
            Self::Password { .. } | Self::Shadowsocks { .. } => return None,
        };
        uuid_to_bytes(text)
    }

    /// Признак пустых учётных данных — такой ключ нерабочий.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Uuid { uuid } => uuid.is_empty(),
            Self::Password { password } => password.is_empty(),
            Self::UuidPassword { uuid, password } => uuid.is_empty() || password.is_empty(),
            Self::Shadowsocks { method, password } => method.is_empty() || password.is_empty(),
        }
    }
}

/// Параметры транспортного слоя.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Вид транспорта.
    pub kind: TransportKind,
    /// Путь для WebSocket / XHTTP / `HTTPUpgrade`.
    pub path: Option<String>,
    /// Значение заголовка `Host`, если отличается от адреса подключения.
    pub host: Option<String>,
    /// Имя сервиса gRPC.
    pub service_name: Option<String>,
    /// Режим транспорта: `packet-up` / `stream-up` / `stream-one` для XHTTP,
    /// `gun` / `multi` для gRPC.
    pub mode: Option<String>,
    /// Тип обфускации заголовка для TCP и mKCP (например `http`).
    pub header_type: Option<String>,
    /// Seed для mKCP.
    pub seed: Option<String>,
}

/// Параметры REALITY.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityConfig {
    /// Публичный ключ X25519 сервера, base64url без паддинга.
    pub public_key: String,
    /// Короткий идентификатор, hex, 0–16 символов.
    pub short_id: String,
    /// Путь для имитации браузинга по сайту прикрытия.
    pub spider_x: Option<String>,
}

/// Параметры маскировки.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Вид маскировки.
    pub kind: SecurityKind,
    /// Значение SNI. Для REALITY это домен сайта прикрытия.
    pub sni: Option<String>,
    /// Список ALPN в порядке предпочтения.
    pub alpn: Vec<String>,
    /// Имитируемый TLS-отпечаток.
    pub fingerprint: Fingerprint,
    /// Отключение проверки сертификата.
    ///
    /// Всегда признак неправильной настройки: открывает MITM и не нужен ни
    /// для REALITY, ни для корректного TLS.
    pub allow_insecure: bool,
    /// Параметры REALITY, если он используется.
    pub reality: Option<RealityConfig>,
}

/// Дополнительная обфускация поверх протокола (Hysteria2 Salamander и т. п.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfsConfig {
    /// Тип обфускации, например `salamander`.
    pub kind: String,
    /// Пароль обфускации.
    pub password: String,
}

/// Полностью разобранный ключ доступа.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyKey {
    /// Прокси-протокол.
    pub protocol: Protocol,
    /// Адрес подключения: домен, IPv4 или IPv6 без скобок.
    pub host: String,
    /// Порт подключения.
    pub port: u16,
    /// Учётные данные.
    pub credentials: Credentials,
    /// Транспортный слой.
    pub transport: TransportConfig,
    /// Слой маскировки.
    pub security: SecurityConfig,
    /// Режим потока XTLS.
    pub flow: Flow,
    /// Дополнительная обфускация.
    pub obfs: Option<ObfsConfig>,
    /// Имя точки для показа пользователю.
    pub tag: String,
    /// Нераспознанные параметры.
    ///
    /// Сохраняются, чтобы обратное построение URI не теряло данные, которые
    /// понимает сервер, но пока не понимаем мы.
    pub extra: BTreeMap<String, String>,
}

impl ProxyKey {
    /// Разобрать ключ из URI.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownScheme`] для нераспознанной схемы, [`Error::Missing`]
    /// при отсутствии обязательных частей, [`Error::Invalid`] при некорректных
    /// значениях.
    pub fn parse(uri: &str) -> Result<Self> {
        parse::parse(uri)
    }

    /// Построить канонический URI.
    #[must_use]
    pub fn to_uri(&self) -> String {
        build::to_uri(self)
    }

    /// Проверить ключ на пригодность к использованию.
    ///
    /// Ловит не синтаксис, а смысловые ошибки — те, из-за которых ключ
    /// разбирается, но не работает или работает небезопасно.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] при отсутствии обязательных значений,
    /// [`Error::Incompatible`] при несочетаемых параметрах.
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            return Err(Error::Missing("адрес точки"));
        }
        if self.port == 0 {
            return Err(Error::Missing("порт"));
        }
        if self.credentials.is_empty() {
            return Err(Error::Missing("учётные данные"));
        }

        if let Some(reality) = &self.security.reality {
            if self.security.kind != SecurityKind::Reality {
                return Err(Error::Incompatible(
                    "параметры REALITY заданы, но security не равен reality".into(),
                ));
            }
            if reality.public_key.is_empty() {
                return Err(Error::Missing("публичный ключ REALITY (pbk)"));
            }
            if self.security.sni.is_none() {
                return Err(Error::Missing("SNI сайта прикрытия для REALITY"));
            }
            // shortId — hex чётной длины до 8 байт.
            if !reality.short_id.is_empty()
                && (reality.short_id.len() > 16
                    || reality.short_id.len() % 2 != 0
                    || !reality.short_id.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Err(Error::invalid(
                    "sid",
                    "shortId должен быть hex чётной длины не более 16 символов",
                ));
            }
        } else if self.security.kind == SecurityKind::Reality {
            return Err(Error::Missing("параметры REALITY"));
        }

        // Vision работает только поверх TLS-подобного слоя на голом TCP:
        // на CDN-транспортах splice невозможен.
        if self.flow == Flow::XtlsRprxVision {
            if self.transport.kind != TransportKind::Tcp {
                return Err(Error::Incompatible(format!(
                    "flow=xtls-rprx-vision несовместим с транспортом {}",
                    self.transport.kind.as_str()
                )));
            }
            if self.security.kind == SecurityKind::None {
                return Err(Error::Incompatible(
                    "flow=xtls-rprx-vision требует tls или reality".into(),
                ));
            }
        }

        if self.protocol == Protocol::Vless && self.security.kind == SecurityKind::None {
            return Err(Error::Incompatible(
                "VLESS без маскировки передаёт UUID открытым текстом".into(),
            ));
        }

        if self.protocol.is_udp_based() && self.transport.kind.cdn_compatible() {
            return Err(Error::Incompatible(format!(
                "{} работает поверх QUIC и не может идти через {}",
                self.protocol.scheme(),
                self.transport.kind.as_str()
            )));
        }

        Ok(())
    }

    /// Замечания, не делающие ключ нерабочим, но ухудшающие скрытность.
    ///
    /// Показываются пользователю при импорте чужого ключа.
    #[must_use]
    pub fn warnings(&self) -> Vec<Warning> {
        let mut out = Vec::new();

        if self.security.allow_insecure {
            out.push(Warning::InsecureTls);
        }
        if self.protocol == Protocol::Vmess {
            out.push(Warning::ObsoleteProtocol);
        }
        if self.security.kind == SecurityKind::Reality && self.flow != Flow::XtlsRprxVision {
            out.push(Warning::RealityWithoutVision);
        }
        if self.security.fingerprint == Fingerprint::Random {
            out.push(Warning::RandomFingerprint);
        }
        if self.protocol == Protocol::Shadowsocks {
            if let Credentials::Shadowsocks { method, .. } = &self.credentials {
                if !method.starts_with("2022-") {
                    out.push(Warning::LegacyShadowsocks);
                }
            }
        }

        out
    }
}

/// Замечание к ключу: работать будет, но хуже, чем мог бы.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Warning {
    /// Отключена проверка сертификата — открыт MITM.
    InsecureTls,
    /// `VMess` устарел и детектируется.
    ObsoleteProtocol,
    /// REALITY без Vision уязвим к детекту TLS-in-TLS.
    RealityWithoutVision,
    /// Случайный отпечаток сам по себе является аномалией.
    RandomFingerprint,
    /// Классический Shadowsocks — поток без заголовков, яркий флаг для DPI.
    LegacyShadowsocks,
}

impl Warning {
    /// Пояснение для показа пользователю.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InsecureTls => {
                "Отключена проверка сертификата. Соединение уязвимо к перехвату — \
                 для REALITY и корректного TLS это не требуется."
            }
            Self::ObsoleteProtocol => {
                "VMess устарел: первые 16 байт потока имеют максимальную энтропию, \
                 что само по себе выдаёт прокси. Предпочтительнее VLESS + REALITY."
            }
            Self::RealityWithoutVision => {
                "REALITY без flow=xtls-rprx-vision оставляет характерный паттерн \
                 размеров TLS-записей (TLS-in-TLS)."
            }
            Self::RandomFingerprint => {
                "Случайный TLS-отпечаток даёт нестабильный и редкий JA4, который \
                 сам становится признаком. Лучше зафиксировать chrome."
            }
            Self::LegacyShadowsocks => {
                "Классический Shadowsocks выглядит как поток случайных байт без \
                 заголовков. Предпочтительнее ветка 2022-blake3-* с ShadowTLS."
            }
        }
    }
}

/// Разобрать каноническую запись UUID в 16 байт.
///
/// Дефисы игнорируются, регистр не важен. Возвращает `None`, если строка
/// не состоит ровно из 32 шестнадцатеричных цифр.
#[must_use]
pub fn uuid_to_bytes(text: &str) -> Option<[u8; 16]> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| *b != b'-')
        .map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .collect::<Option<Vec<u8>>>()?;

    if digits.len() != 32 {
        return None;
    }

    let mut out = [0_u8; 16];
    for (slot, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        match pair {
            [hi, lo] => *slot = (hi << 4) | lo,
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod uuid_tests {
    use super::*;

    #[test]
    fn parses_canonical_form() {
        let bytes = uuid_to_bytes("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
    }

    #[test]
    fn ignores_case_and_separators() {
        assert_eq!(
            uuid_to_bytes("00112233445566778899AABBCCDDEEFF"),
            uuid_to_bytes("00112233-4455-6677-8899-aabbccddeeff")
        );
    }

    #[test]
    fn rejects_wrong_length_and_bad_digits() {
        assert!(uuid_to_bytes("").is_none());
        assert!(uuid_to_bytes("00112233-4455-6677-8899-aabbccddee").is_none());
        assert!(uuid_to_bytes("zz112233-4455-6677-8899-aabbccddeeff").is_none());
    }

    #[test]
    fn credentials_expose_bytes_only_where_meaningful() {
        let uuid = Credentials::Uuid {
            uuid: "00112233-4455-6677-8899-aabbccddeeff".into(),
        };
        assert!(uuid.uuid_bytes().is_some());

        let password = Credentials::Password {
            password: "secret".into(),
        };
        assert!(password.uuid_bytes().is_none());
    }
}
