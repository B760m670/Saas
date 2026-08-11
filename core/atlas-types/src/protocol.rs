//! Три независимые оси конфигурации: протокол, транспорт, маскировка.
//!
//! Разделение принципиальное — см. `docs/01-protocols.md`. Смысл имеет только
//! комбинация целиком: `VLESS + TCP + REALITY + Vision` — это одна точка в
//! трёхмерном пространстве, а не «протокол VLESS».

use serde::{Deserialize, Serialize};

/// Прокси-протокол: как клиент аутентифицируется и как кодирует адрес назначения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Наследник `VMess` от XTLS. Нулевой оверхед, своего шифрования нет.
    Vless,
    /// Историческая база `V2Ray`. Поддерживается только ради совместимости.
    Vmess,
    /// Притворяется веб-сервером, откатывается на настоящий сайт при неверном пароле.
    Trojan,
    /// Включая ветку Shadowsocks-2022 (`2022-blake3-*`).
    Shadowsocks,
    /// QUIC, ставка на скорость на потерянных каналах.
    Hysteria2,
    /// QUIC, честный congestion control, хороший нативный UDP-релей.
    Tuic,
    /// Свежая схема с паддингом против детекта TLS-in-TLS.
    AnyTls,
    /// `WireGuard` с обфускацией (мусорные пакеты, подменённые magic-заголовки).
    AmneziaWg,
}

impl Protocol {
    /// Схемы URI, которые распознаются как данный протокол.
    ///
    /// Первая в списке — каноническая, она же используется при сериализации.
    #[must_use]
    pub const fn schemes(self) -> &'static [&'static str] {
        match self {
            Self::Vless => &["vless"],
            Self::Vmess => &["vmess"],
            Self::Trojan => &["trojan", "trojan-go"],
            Self::Shadowsocks => &["ss"],
            Self::Hysteria2 => &["hysteria2", "hy2"],
            Self::Tuic => &["tuic"],
            Self::AnyTls => &["anytls"],
            Self::AmneziaWg => &["awg", "amneziawg"],
        }
    }

    /// Каноническая схема для построения URI.
    #[must_use]
    pub const fn scheme(self) -> &'static str {
        match self.schemes() {
            [first, ..] => first,
            // Недостижимо: `schemes()` всегда возвращает непустой срез.
            [] => "unknown",
        }
    }

    /// Распознать протокол по схеме URI (регистронезависимо).
    #[must_use]
    pub fn from_scheme(scheme: &str) -> Option<Self> {
        const ALL: &[Protocol] = &[
            Protocol::Vless,
            Protocol::Vmess,
            Protocol::Trojan,
            Protocol::Shadowsocks,
            Protocol::Hysteria2,
            Protocol::Tuic,
            Protocol::AnyTls,
            Protocol::AmneziaWg,
        ];
        let lower = scheme.to_ascii_lowercase();
        ALL.iter()
            .copied()
            .find(|p| p.schemes().contains(&lower.as_str()))
    }

    /// Работает ли протокол поверх QUIC/UDP.
    ///
    /// Важно на практике: такие протоколы недоступны на serverless-ярусах
    /// (Cloudflare Workers и аналоги не дают UDP) и часто режутся мобильными
    /// операторами.
    #[must_use]
    pub const fn is_udp_based(self) -> bool {
        matches!(self, Self::Hysteria2 | Self::Tuic | Self::AmneziaWg)
    }

    /// Устойчивость к активному зондированию.
    ///
    /// Оценка не абсолютная, а сравнительная — используется оркестратором как
    /// априорное значение до накопления собственной статистики.
    #[must_use]
    pub const fn probe_resistance(self) -> Resistance {
        match self {
            // С REALITY проба получает настоящий чужой сайт
            // с настоящим сертификатом — отличить нечем.
            Self::Vless => Resistance::High,

            // Trojan и AnyTLS откатываются на настоящий веб-сервер, но свой
            // домен и свой сертификат остаются видны. Hysteria2 и AmneziaWG
            // ломают сигнатуру обфускацией, но поведение остаётся аномальным.
            Self::Trojan | Self::AnyTls | Self::Hysteria2 | Self::AmneziaWg => Resistance::Medium,

            // Shadowsocks — поток без заголовков, TUIC — узнаваемый
            // QUIC-отпечаток, VMess — HMAC от времени в первых 16 байтах.
            // Во всех трёх случаях аномалия видна пассивно.
            Self::Shadowsocks | Self::Tuic | Self::Vmess => Resistance::Low,
        }
    }
}

/// Грубая оценка устойчивости к обнаружению.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Resistance {
    /// Обнаруживается пассивно или подтверждается активной пробой.
    Low,
    /// Сигнатуры нет, но поведение или метаданные выдают.
    Medium,
    /// Активная проба неотличима от обращения к постороннему сайту.
    High,
}

/// Транспорт — в чём едет прокси-протокол.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    /// Голый TCP. База, пока чистый TCP:443 проходит.
    #[default]
    Tcp,
    /// Классика для CDN, но уже примелькалась DPI.
    WebSocket,
    /// Выглядит как API-трафик.
    Grpc,
    /// Ключевой транспорт 2026: проходит через CDN, умеет h1/h2/h3.
    XHttp,
    /// Легче WebSocket, меньше оверхеда.
    HttpUpgrade,
    /// Для Hysteria2 / TUIC.
    Quic,
    /// Только для очень потерянных каналов — сильно шумит.
    Kcp,
}

impl TransportKind {
    /// Значение параметра `type` в URI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::WebSocket => "ws",
            Self::Grpc => "grpc",
            Self::XHttp => "xhttp",
            Self::HttpUpgrade => "httpupgrade",
            Self::Quic => "quic",
            Self::Kcp => "kcp",
        }
    }

    /// Разобрать значение параметра `type`, включая исторические синонимы.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" | "raw" | "none" => Some(Self::Tcp),
            "ws" | "websocket" => Some(Self::WebSocket),
            "grpc" | "gun" => Some(Self::Grpc),
            // `splithttp` — прежнее имя XHTTP, встречается в старых ключах.
            "xhttp" | "splithttp" => Some(Self::XHttp),
            "httpupgrade" => Some(Self::HttpUpgrade),
            "quic" => Some(Self::Quic),
            "kcp" | "mkcp" => Some(Self::Kcp),
            _ => None,
        }
    }

    /// Может ли транспорт пройти через обычный HTTP-CDN.
    ///
    /// Определяет пригодность для яруса T1 (serverless edge).
    #[must_use]
    pub const fn cdn_compatible(self) -> bool {
        matches!(
            self,
            Self::WebSocket | Self::Grpc | Self::XHttp | Self::HttpUpgrade
        )
    }
}

/// Слой маскировки — как соединение выглядит для DPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityKind {
    /// Без маскировки. Для VLESS равносильно передаче UUID открытым текстом.
    #[default]
    None,
    /// Обычный TLS: нужен свой домен и свой сертификат.
    Tls,
    /// Переиспользование TLS-личности чужого сайта.
    Reality,
}

impl SecurityKind {
    /// Значение параметра `security` в URI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::Reality => "reality",
        }
    }

    /// Разобрать значение параметра `security`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "" | "none" => Some(Self::None),
            "tls" | "xtls" => Some(Self::Tls),
            "reality" => Some(Self::Reality),
            _ => None,
        }
    }
}

/// Имитируемый TLS-отпечаток (uTLS).
///
/// Без имитации `ClientHello` выдаёт язык реализации и помечает пользователя
/// с первого пакета — см. `docs/00-threat-model.md`, раздел 2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fingerprint {
    /// Самый распространённый профиль.
    Chrome,
    /// Второй по распространённости — и значение по умолчанию.
    ///
    /// Распространённость здесь не главный довод. По измерениям схемы
    /// фильтрации, действующей в России с июня 2026, отпечатки Chrome,
    /// Safari и iOS относятся к подозрительным, а Firefox, Android и
    /// Edge проходят. Ключ, выданный без явного `fp`, не должен ставить
    /// человека в подозрительное ведро — сайту прикрытия всё равно,
    /// каким браузером к нему пришли.
    #[default]
    Firefox,
    /// Профиль Safari на macOS.
    Safari,
    /// Профиль Safari на iOS.
    Ios,
    /// Профиль Edge.
    Edge,
    /// Случайный выбор при каждом подключении.
    ///
    /// Внешне привлекательно, на практике вредно: даёт нестабильный и редкий
    /// JA4, что само по себе аномалия. Не использовать по умолчанию.
    Random,
}

impl Fingerprint {
    /// Значение параметра `fp` в URI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Ios => "ios",
            Self::Edge => "edge",
            Self::Random => "random",
        }
    }

    /// Разобрать значение параметра `fp`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "chrome" => Some(Self::Chrome),
            "firefox" => Some(Self::Firefox),
            "safari" => Some(Self::Safari),
            "ios" | "ionos" => Some(Self::Ios),
            "edge" => Some(Self::Edge),
            "random" | "randomized" => Some(Self::Random),
            _ => None,
        }
    }
}

/// Режим потока XTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Flow {
    /// Без XTLS.
    #[default]
    None,
    /// Единственный актуальный режим: паддинг против детекта TLS-in-TLS
    /// и splice после хэндшейка.
    XtlsRprxVision,
}

impl Flow {
    /// Значение параметра `flow` в URI (пустая строка, если режим не задан).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::XtlsRprxVision => "xtls-rprx-vision",
        }
    }

    /// Разобрать значение параметра `flow`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "" | "none" => Some(Self::None),
            // `-udp443` — исторический суффикс, семантики для клиента не несёт.
            "xtls-rprx-vision" | "xtls-rprx-vision-udp443" => Some(Self::XtlsRprxVision),
            _ => None,
        }
    }
}
