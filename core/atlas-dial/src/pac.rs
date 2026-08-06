//! Правила маршрутизации в виде PAC-скрипта.
//!
//! iOS понимает Proxy Auto-Config нативно, и для сборки `lite` это
//! единственный способ развести трафик: что идёт через туннель, что
//! напрямую. Никакого VPN, никаких прав — просто поле в настройках
//! Wi-Fi, которое заполняет профиль конфигурации
//! (см. [`crate::mobileconfig`]).
//!
//! # Почему имена проверяются, а не экранируются
//!
//! Скрипт — это исполняемый JavaScript, и правила попадают в него
//! строками. Экранирование кавычек закрыло бы очевидный путь внедрения
//! и оставило бы неочевидные: комментарии, юникодные разделители строк
//! `U+2028`, суррогатные пары. Поэтому имена не экранируются, а
//! **проверяются**: всё, что не похоже на доменное имя, отвергается с
//! ошибкой ещё до сборки скрипта.
//!
//! Правило ценно не столько от злого умысла, сколько от опечатки:
//! испорченный PAC iOS молча игнорирует, и пользователь остаётся без
//! туннеля, не понимая почему.

use core::fmt::Write as _;

use crate::{Error, Result};

/// Путь, по которому наш прокси отдаёт скрипт.
///
/// Постоянный: он попадает в профиль конфигурации, а профиль
/// переустанавливают руками.
pub const URL_PATH: &str = "/proxy.pac";

/// Правила маршрутизации.
#[derive(Debug, Clone)]
pub struct Rules {
    /// Адрес локального прокси, например `127.0.0.1:1080`.
    pub proxy: String,
    /// Домены, идущие мимо туннеля.
    ///
    /// Суффиксы: `example.org` покрывает и `www.example.org`.
    pub direct: Vec<String>,
    /// Домены, которым отказывается в соединении вовсе.
    pub blocked: Vec<String>,
}

impl Rules {
    /// Правила по умолчанию: всё через туннель, кроме локального.
    ///
    /// Пустые списки — не упущение: разумное умолчание для инструмента
    /// обхода цензуры — гнать через туннель **всё**. Список исключений
    /// заводит пользователь, и каждое исключение — это осознанное
    /// решение показать оператору связи, что он ходит на этот сайт.
    #[must_use]
    pub fn new(proxy: impl Into<String>) -> Self {
        Self {
            proxy: proxy.into(),
            direct: Vec::new(),
            blocked: Vec::new(),
        }
    }

    /// Добавить домены, идущие напрямую.
    #[must_use]
    pub fn with_direct(mut self, domains: Vec<String>) -> Self {
        self.direct = domains;
        self
    }

    /// Добавить домены, которым отказано.
    #[must_use]
    pub fn with_blocked(mut self, domains: Vec<String>) -> Self {
        self.blocked = domains;
        self
    }
}

/// Собрать PAC-скрипт.
///
/// # Errors
///
/// [`Error::Key`], если адрес прокси или доменное имя не проходят
/// проверку.
pub fn script(rules: &Rules) -> Result<String> {
    check_authority(&rules.proxy)?;
    for domain in rules.direct.iter().chain(rules.blocked.iter()) {
        check_domain(domain)?;
    }

    let mut out = String::new();
    // Форматирование в строку не отказывает; ошибку всё равно не
    // проглатываем, чтобы `write!` не пришлось игнорировать молча.
    let mut build = || -> core::fmt::Result {
        out.push_str(
            "// Порождено ATLAS. Правки будут потеряны при следующей выдаче.\n\
             function FindProxyForURL(url, host) {\n\
             \x20   var DIRECT = \"DIRECT\";\n",
        );
        writeln!(out, "    var TUNNEL = \"PROXY {}\";", rules.proxy)?;
        out.push_str(
            // Отказ выражается несуществующим прокси: своего слова
            // «запретить» в PAC нет, а `DIRECT` для заблокированного
            // домена означал бы «пустить мимо туннеля» — ровно
            // наоборот.
            "    var BLOCK = \"PROXY 0.0.0.0:0\";\n\
             \n\
             \x20   host = host.toLowerCase();\n\
             \n\
             \x20   // Своё же устройство и локальная сеть — мимо туннеля.\n\
             \x20   // Иначе прокси попробует соединиться сам с собой.\n\
             \x20   if (isPlainHostName(host)) return DIRECT;\n\
             \x20   if (host === \"localhost\" || shExpMatch(host, \"*.local\")) return DIRECT;\n\
             \x20   if (isInNet(host, \"127.0.0.0\", \"255.0.0.0\")) return DIRECT;\n\
             \x20   if (isInNet(host, \"10.0.0.0\", \"255.0.0.0\")) return DIRECT;\n\
             \x20   if (isInNet(host, \"172.16.0.0\", \"255.240.0.0\")) return DIRECT;\n\
             \x20   if (isInNet(host, \"192.168.0.0\", \"255.255.0.0\")) return DIRECT;\n\
             \x20   if (isInNet(host, \"169.254.0.0\", \"255.255.0.0\")) return DIRECT;\n",
        );

        if !rules.blocked.is_empty() {
            out.push_str("\n    // Отказано.\n");
            for domain in &rules.blocked {
                writeln!(
                    out,
                    "    if (host === \"{domain}\" || dnsDomainIs(host, \".{domain}\")) return BLOCK;"
                )?;
            }
        }

        if !rules.direct.is_empty() {
            out.push_str("\n    // Мимо туннеля по решению пользователя.\n");
            for domain in &rules.direct {
                writeln!(
                    out,
                    "    if (host === \"{domain}\" || dnsDomainIs(host, \".{domain}\")) return DIRECT;"
                )?;
            }
        }

        out.push_str("\n    return TUNNEL;\n}\n");
        Ok(())
    };
    build().map_err(|_| Error::Key("PAC-скрипт не собрался"))?;
    Ok(out)
}

/// Проверить `хост:порт`.
fn check_authority(authority: &str) -> Result<()> {
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or(Error::Key("в адресе прокси нет порта"))?;
    if port.parse::<u16>().is_err() {
        return Err(Error::Key("порт прокси не число"));
    }
    check_host(host)
}

/// Проверить доменное имя правила.
fn check_domain(domain: &str) -> Result<()> {
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(Error::Key("доменное имя начинается или кончается точкой"));
    }
    check_host(domain)
}

/// Разрешено ли имя к подстановке в скрипт.
///
/// Список разрешённого, а не запрещённого: при списке запрещённого
/// забытый символ становится дырой, при списке разрешённого — всего
/// лишь неудобством.
fn check_host(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(Error::Key("пустое имя в правилах PAC"));
    }
    if host.len() > 253 {
        return Err(Error::Key("имя в правилах PAC длиннее 253 знаков"));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return Err(Error::Key("имя в правилах PAC содержит недопустимые знаки"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_that_could_break_out_of_the_script_is_refused() {
        // Всё это — попытки выйти из строкового литерала JavaScript
        // либо просто мусор, который сделал бы скрипт нерабочим.
        for bad in [
            "example.org\" ; return \"DIRECT",
            "example.org\\",
            "exa\u{2028}mple.org",
            "example.org\n",
            "приме́р.рф",
            "",
            ".example.org",
            "example.org.",
            "a b.org",
            "<script>",
        ] {
            let rules = Rules::new("127.0.0.1:1080").with_direct(vec![bad.to_owned()]);
            assert!(
                script(&rules).is_err(),
                "имя {bad:?} обязано быть отвергнуто"
            );
        }
    }

    #[test]
    fn a_broken_proxy_address_is_refused() {
        for bad in [
            "127.0.0.1",
            "127.0.0.1:",
            "127.0.0.1:пять",
            "127.0.0.1:99999",
        ] {
            assert!(
                script(&Rules::new(bad)).is_err(),
                "адрес {bad:?} обязан быть отвергнут"
            );
        }
    }

    #[test]
    fn ordinary_names_are_accepted() {
        let rules = Rules::new("127.0.0.1:1080")
            .with_direct(vec!["example.org".to_owned(), "gosuslugi.ru".to_owned()])
            .with_blocked(vec!["ads.example.com".to_owned()]);
        let text = script(&rules).unwrap();
        assert!(text.contains("PROXY 127.0.0.1:1080"));
        assert!(text.contains("gosuslugi.ru"));
        assert!(text.contains("ads.example.com"));
    }
}
