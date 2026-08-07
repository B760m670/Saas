//! Профиль конфигурации iOS: прокси на Wi-Fi без всякого VPN.
//!
//! Это уровень 2 из `docs/05-clients.md`: приложение выдаёт
//! `.mobileconfig`, пользователь ставит его в один тап, и **весь
//! системный трафик Wi-Fi** идёт через наше ядро — Safari, почта,
//! мессенджеры, всё на `URLSession`. Ни платного аккаунта, ни
//! entitlements, ни supervised-режима.
//!
//! # Чего этот способ не делает
//!
//! Профиль настраивает **конкретную сеть Wi-Fi по её имени**. Это
//! следствие устройства iOS: поля прокси живут в настройках сети, а не
//! системы. Сотовую связь он не покрывает вовсе — поля прокси там нет
//! (payload `com.apple.cellular` требует supervised-устройства либо
//! подписи оператора). Смена сети означает новый профиль.
//!
//! # Предупреждение о защищённых сетях
//!
//! Payload Wi-Fi описывает сеть целиком, а не только прокси в ней.
//! Поэтому для сети с паролем пароль **обязан** быть указан: иначе
//! устройство может перестать к ней подключаться, и чинить это придётся
//! руками, уже без интернета. Отсюда [`Profile::with_password`] и
//! [`Encryption`] — умолчание `Encryption::None` выбрано намеренно,
//! чтобы забытый пароль был виден как явно неверная настройка, а не
//! проявился на устройстве.
//!
//! # Что здесь не проверено
//!
//! Профиль разбирается как plist и содержит поля, описанные Apple. Но
//! **на настоящем устройстве он не проверялся** — в этом окружении
//! iPhone нет. Это записано в реестре слабых мест и не должно
//! выдаваться за проверенное.

use core::fmt::Write as _;

use atlas_crypto::rng::OsRng;

use crate::pac;
use crate::{Error, Result};

/// Вид защиты сети Wi-Fi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encryption {
    /// Открытая сеть.
    #[default]
    None,
    /// WPA/WPA2/WPA3 Personal.
    Wpa,
    /// Любая — устройство решает само.
    Any,
}

impl Encryption {
    /// Значение поля `EncryptionType`.
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Wpa => "WPA",
            Self::Any => "Any",
        }
    }
}

/// Как задан прокси в профиле.
#[derive(Debug, Clone)]
pub enum Proxy {
    /// Один адрес на всё.
    ///
    /// Просто и предсказуемо, но мимо туннеля не пойдёт ничего, включая
    /// локальные адреса.
    Manual {
        /// Адрес прокси.
        host: String,
        /// Порт прокси.
        port: u16,
    },
    /// Адрес PAC-скрипта.
    ///
    /// Скрипт наш прокси отдаёт сам по `/proxy.pac`, поэтому адрес
    /// обычно указывает на него же: правила меняются вместе с
    /// настройками и не требуют переустановки профиля.
    Auto {
        /// Адрес, по которому лежит скрипт.
        url: String,
    },
}

/// Что именно накрывает профиль.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Одна сеть Wi-Fi по имени.
    ///
    /// Никаких прав не требует: обычный профиль, который ставится в
    /// один тап. Сотовую связь не покрывает — поля прокси живут в
    /// настройках сети, а у сотовой их нет.
    Network,
    /// Всё устройство целиком.
    ///
    /// Payload `com.apple.proxy.http.global`. По спецификации Apple он
    /// **требует, чтобы устройство было supervised** — то есть заведено
    /// через Apple Configurator. Платного аккаунта разработчика при
    /// этом не нужно: надзор бесплатен, но требует Mac и стирания
    /// устройства.
    ///
    /// Взамен даёт то, чего не даёт ни один другой путь без
    /// entitlement: прокси на **всё**, включая мобильный интернет.
    ///
    /// Отдельная оговорка: такой payload на устройстве может быть
    /// только один.
    Everything,
}

/// Профиль конфигурации.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Что именно накрывает профиль.
    pub coverage: Coverage,
    /// Имя сети Wi-Fi, к которой относится настройка.
    ///
    /// Осмысленно только при [`Coverage::Network`].
    pub ssid: String,
    /// Защита сети.
    pub encryption: Encryption,
    /// Пароль сети, если она защищена.
    pub password: Option<String>,
    /// Как задан прокси.
    pub proxy: Proxy,
    /// Имя, которое увидит пользователь в настройках.
    pub display_name: String,
    /// Обратное доменное имя профиля.
    pub identifier: String,
}

impl Profile {
    /// Профиль с PAC-скриптом, который отдаёт наш же прокси.
    ///
    /// # Errors
    ///
    /// [`Error::Key`], если адрес прокси не разбирается.
    pub fn automatic(ssid: impl Into<String>, proxy_address: &str) -> Result<Self> {
        let (host, port) = proxy_address
            .rsplit_once(':')
            .ok_or(Error::Key("в адресе прокси нет порта"))?;
        if port.parse::<u16>().is_err() {
            return Err(Error::Key("порт прокси не число"));
        }
        Ok(Self {
            coverage: Coverage::Network,
            ssid: ssid.into(),
            encryption: Encryption::None,
            password: None,
            proxy: Proxy::Auto {
                url: format!("http://{host}:{port}{}", pac::URL_PATH),
            },
            display_name: "ATLAS".to_owned(),
            identifier: "org.atlas.proxy".to_owned(),
        })
    }

    /// Профиль на всё устройство, включая сотовую связь.
    ///
    /// Требует, чтобы устройство было supervised (см. [`Coverage`]).
    /// Проверить это из кода нельзя — отказ придёт от самой iOS при
    /// установке, и он будет внятным.
    ///
    /// # Errors
    ///
    /// [`Error::Key`], если адрес прокси не разбирается.
    pub fn everything(proxy_address: &str) -> Result<Self> {
        let mut profile = Self::automatic("", proxy_address)?;
        profile.coverage = Coverage::Everything;
        "org.atlas.proxy.global".clone_into(&mut profile.identifier);
        Ok(profile)
    }

    /// Профиль с одним адресом прокси на всё.
    ///
    /// # Errors
    ///
    /// [`Error::Key`], если адрес прокси не разбирается.
    pub fn manual(ssid: impl Into<String>, proxy_address: &str) -> Result<Self> {
        let (host, port) = proxy_address
            .rsplit_once(':')
            .ok_or(Error::Key("в адресе прокси нет порта"))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| Error::Key("порт прокси не число"))?;
        Ok(Self {
            coverage: Coverage::Network,
            ssid: ssid.into(),
            encryption: Encryption::None,
            password: None,
            proxy: Proxy::Manual {
                host: host.to_owned(),
                port,
            },
            display_name: "ATLAS".to_owned(),
            identifier: "org.atlas.proxy".to_owned(),
        })
    }

    /// Указать защиту и пароль сети.
    #[must_use]
    pub fn with_password(mut self, encryption: Encryption, password: impl Into<String>) -> Self {
        self.encryption = encryption;
        self.password = Some(password.into());
        self
    }

    /// Задать имя, видимое пользователю.
    #[must_use]
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    /// Собрать профиль в XML.
    ///
    /// Каждая выдача получает свежие `PayloadUUID`. Постоянным остаётся
    /// `PayloadIdentifier` — по нему iOS понимает, что профиль надо
    /// заменить, а не поставить рядом второй.
    ///
    /// # Errors
    ///
    /// [`Error::Key`], если имя сети пустое.
    pub fn build(&self) -> Result<String> {
        if self.coverage == Coverage::Network && self.ssid.is_empty() {
            return Err(Error::Key("имя сети Wi-Fi пустое"));
        }
        if self.encryption != Encryption::None && self.password.is_none() {
            return Err(Error::Key(
                "у защищённой сети обязан быть указан пароль, иначе устройство к ней не вернётся",
            ));
        }

        let outer_uuid = uuid_v4();
        let inner_uuid = uuid_v4();
        let mut out = String::new();

        let mut build = || -> core::fmt::Result {
            out.push_str(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                 \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\">\n<dict>\n",
            );
            writeln!(
                out,
                "\t<key>PayloadType</key>\n\t<string>Configuration</string>"
            )?;
            writeln!(out, "\t<key>PayloadVersion</key>\n\t<integer>1</integer>")?;
            writeln!(
                out,
                "\t<key>PayloadIdentifier</key>\n\t<string>{}</string>",
                escape(&self.identifier)
            )?;
            writeln!(
                out,
                "\t<key>PayloadUUID</key>\n\t<string>{outer_uuid}</string>"
            )?;
            writeln!(
                out,
                "\t<key>PayloadDisplayName</key>\n\t<string>{}</string>",
                escape(&self.display_name)
            )?;
            writeln!(
                out,
                "\t<key>PayloadDescription</key>\n\t<string>{}</string>",
                escape(&self.description())
            )?;
            // Профиль обязан сниматься пользователем. Инструмент обхода
            // цензуры, который нельзя выключить, — это не инструмент.
            writeln!(out, "\t<key>PayloadRemovalDisallowed</key>\n\t<false/>")?;
            writeln!(out, "\t<key>PayloadContent</key>\n\t<array>\n\t<dict>")?;
            match self.coverage {
                Coverage::Network => self.write_wifi_payload(&mut out, &inner_uuid)?,
                Coverage::Everything => self.write_global_payload(&mut out, &inner_uuid)?,
            }
            out.push_str("\t</dict>\n\t</array>\n</dict>\n</plist>\n");
            Ok(())
        };
        build().map_err(|_| Error::Key("профиль не собрался"))?;
        Ok(out)
    }

    /// Описание профиля для показа пользователю.
    fn description(&self) -> String {
        match self.coverage {
            Coverage::Network => format!("Прокси ATLAS для сети {}", self.ssid),
            Coverage::Everything => "Прокси ATLAS на всё устройство".to_owned(),
        }
    }

    /// Записать payload прокси на всё устройство.
    ///
    /// Требует supervised-устройства; см. [`Coverage::Everything`].
    /// `ProxyPACFallbackAllowed` здесь так же `false`, как и в сетевом
    /// профиле: молчаливый уход мимо туннеля означал бы, что
    /// пользователь считает себя защищённым, не будучи защищённым.
    ///
    /// `ProxyCaptiveLoginAllowed` — единственное послабление, и оно
    /// вынужденное: без него не войти в сеть отеля или кафе, где вход
    /// идёт через страницу-перехватчик, а значит не выйти в интернет
    /// вовсе.
    fn write_global_payload(&self, out: &mut String, uuid: &str) -> core::fmt::Result {
        writeln!(
            out,
            "\t\t<key>PayloadType</key>\n\t\t<string>com.apple.proxy.http.global</string>"
        )?;
        writeln!(
            out,
            "\t\t<key>PayloadVersion</key>\n\t\t<integer>1</integer>"
        )?;
        writeln!(
            out,
            "\t\t<key>PayloadIdentifier</key>\n\t\t<string>{}.global</string>",
            escape(&self.identifier)
        )?;
        writeln!(
            out,
            "\t\t<key>PayloadUUID</key>\n\t\t<string>{uuid}</string>"
        )?;
        writeln!(
            out,
            "\t\t<key>PayloadDisplayName</key>\n\t\t<string>Прокси на всё устройство</string>"
        )?;

        match &self.proxy {
            Proxy::Manual { host, port } => {
                writeln!(out, "\t\t<key>ProxyType</key>\n\t\t<string>Manual</string>")?;
                writeln!(
                    out,
                    "\t\t<key>ProxyServer</key>\n\t\t<string>{}</string>",
                    escape(host)
                )?;
                writeln!(
                    out,
                    "\t\t<key>ProxyServerPort</key>\n\t\t<integer>{port}</integer>"
                )?;
            }
            Proxy::Auto { url } => {
                writeln!(out, "\t\t<key>ProxyType</key>\n\t\t<string>Auto</string>")?;
                writeln!(
                    out,
                    "\t\t<key>ProxyPACURL</key>\n\t\t<string>{}</string>",
                    escape(url)
                )?;
                writeln!(out, "\t\t<key>ProxyPACFallbackAllowed</key>\n\t\t<false/>")?;
            }
        }
        writeln!(out, "\t\t<key>ProxyCaptiveLoginAllowed</key>\n\t\t<true/>")?;
        Ok(())
    }

    /// Записать payload сети Wi-Fi — тот, где и живут поля прокси.
    fn write_wifi_payload(&self, out: &mut String, uuid: &str) -> core::fmt::Result {
        writeln!(
            out,
            "\t\t<key>PayloadType</key>\n\t\t<string>com.apple.wifi.managed</string>"
        )?;
        writeln!(
            out,
            "\t\t<key>PayloadVersion</key>\n\t\t<integer>1</integer>"
        )?;
        writeln!(
            out,
            "\t\t<key>PayloadIdentifier</key>\n\t\t<string>{}.wifi</string>",
            escape(&self.identifier)
        )?;
        writeln!(
            out,
            "\t\t<key>PayloadUUID</key>\n\t\t<string>{uuid}</string>"
        )?;
        writeln!(
            out,
            "\t\t<key>PayloadDisplayName</key>\n\t\t<string>Wi-Fi: {}</string>",
            escape(&self.ssid)
        )?;
        writeln!(
            out,
            "\t\t<key>SSID_STR</key>\n\t\t<string>{}</string>",
            escape(&self.ssid)
        )?;
        writeln!(
            out,
            "\t\t<key>EncryptionType</key>\n\t\t<string>{}</string>",
            self.encryption.as_str()
        )?;
        if let Some(password) = self.password.as_ref() {
            writeln!(
                out,
                "\t\t<key>Password</key>\n\t\t<string>{}</string>",
                escape(password)
            )?;
        }
        writeln!(out, "\t\t<key>HIDDEN_NETWORK</key>\n\t\t<false/>")?;
        writeln!(out, "\t\t<key>AutoJoin</key>\n\t\t<true/>")?;

        match &self.proxy {
            Proxy::Manual { host, port } => {
                writeln!(out, "\t\t<key>ProxyType</key>\n\t\t<string>Manual</string>")?;
                writeln!(
                    out,
                    "\t\t<key>ProxyServer</key>\n\t\t<string>{}</string>",
                    escape(host)
                )?;
                writeln!(
                    out,
                    "\t\t<key>ProxyServerPort</key>\n\t\t<integer>{port}</integer>"
                )?;
            }
            Proxy::Auto { url } => {
                writeln!(out, "\t\t<key>ProxyType</key>\n\t\t<string>Auto</string>")?;
                writeln!(
                    out,
                    "\t\t<key>ProxyPACURL</key>\n\t\t<string>{}</string>",
                    escape(url)
                )?;
                // Разрешение обходиться без PAC, если он недоступен.
                // Ставится `false` намеренно: молчаливый уход в прямое
                // соединение означал бы, что пользователь считает себя
                // защищённым, не будучи защищённым.
                writeln!(out, "\t\t<key>ProxyPACFallbackAllowed</key>\n\t\t<false/>")?;
            }
        }
        Ok(())
    }
}

/// Экранировать текст для XML.
///
/// Имя сети приходит от пользователя, и апостроф в нём — обычное дело.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for symbol in text.chars() {
        match symbol {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Управляющие знаки в XML 1.0 недопустимы вовсе; выбросить
            // их безопаснее, чем выдать неразбираемый профиль.
            other if (other as u32) < 0x20 && other != '\t' && other != '\n' && other != '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// Случайный UUID версии 4 в обычной записи.
fn uuid_v4() -> String {
    let mut bytes = OsRng::bytes::<16>();
    // Версия 4 и вариант RFC 4122.
    if let Some(byte) = bytes.get_mut(6) {
        *byte = (*byte & 0x0f) | 0x40;
    }
    if let Some(byte) = bytes.get_mut(8) {
        *byte = (*byte & 0x3f) | 0x80;
    }
    let mut hex = String::with_capacity(32);
    for byte in &bytes {
        // Запись в строку не отказывает; молча игнорировать всё равно
        // нельзя, поэтому отказ превратился бы в укороченный UUID.
        let _ = write!(hex, "{byte:02X}");
    }
    let piece = |from: usize, to: usize| hex.get(from..to).unwrap_or_default();
    format!(
        "{}-{}-{}-{}-{}",
        piece(0, 8),
        piece(8, 12),
        piece(12, 16),
        piece(16, 20),
        piece(20, 32)
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_secured_network_without_a_password_is_refused() {
        let profile = Profile::manual("Дом", "127.0.0.1:1080").unwrap();
        let secured = Profile {
            encryption: Encryption::Wpa,
            ..profile
        };
        assert!(
            secured.build().is_err(),
            "сеть с защитой и без пароля обязана быть отвергнута"
        );
    }

    #[test]
    fn an_empty_network_name_is_refused() {
        let profile = Profile::manual("", "127.0.0.1:1080").unwrap();
        assert!(profile.build().is_err());
    }

    #[test]
    fn each_build_gets_a_fresh_uuid_but_keeps_the_identifier() {
        let profile = Profile::automatic("Дом", "127.0.0.1:1080").unwrap();
        let first = profile.build().unwrap();
        let second = profile.build().unwrap();
        assert_ne!(first, second, "UUID обязан быть свежим");
        assert!(first.contains("org.atlas.proxy"));
        assert!(second.contains("org.atlas.proxy"));
    }

    #[test]
    fn a_uuid_looks_like_a_uuid() {
        let value = uuid_v4();
        assert_eq!(value.len(), 36);
        let parts: Vec<&str> = value.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(
            value.get(14..15) == Some("4"),
            "версия обязана быть 4: {value}"
        );
        let variant = value.get(19..20).unwrap_or_default();
        assert!(
            ["8", "9", "A", "B"].contains(&variant),
            "вариант обязан быть RFC 4122: {value}"
        );
    }
}
