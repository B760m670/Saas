//! Настройки из переменных окружения.
//!
//! Секреты живут только здесь и только в памяти процесса: в репозиторий они
//! не попадают, в журнал — тоже (см. [`Config`] и его отладочную печать).

use std::collections::HashMap;

/// Чего не хватает или что негодно.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Переменная не задана.
    Missing(&'static str),
    /// Задана, но значение не годится.
    Invalid {
        name: &'static str,
        why: &'static str,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "не задана переменная {name}"),
            Self::Invalid { name, why } => write!(f, "переменная {name} негодна: {why}"),
        }
    }
}

impl core::error::Error for Error {}

/// Всё, что нужно боту для работы.
pub struct Config {
    /// Токен бота от @BotFather.
    pub bot_token: String,
    /// Адрес панели.
    pub panel_url: String,
    /// Токен панели.
    pub panel_token: String,
    /// Строка подключения к базе.
    pub database_url: String,
    /// Отряды, в которые попадает новый пользователь панели.
    pub squads: Vec<String>,
    /// Кому разрешены админские действия.
    pub admins: Vec<i64>,
    /// Номер для перевода по СБП, если приём оплаты уже настроен.
    pub sbp_phone: Option<String>,
    /// Имя получателя, как его покажет банк плательщика.
    pub sbp_name: Option<String>,
    /// Где слушать мини-приложение. Только петля: наружу выставляет Caddy.
    pub api_addr: String,
    /// Имя бота без «@» — из него строится реферальная ссылка.
    pub bot_username: Option<String>,
    /// Магазин в ЮKassa, если приём оплаты картой уже подключён.
    pub yookassa_shop_id: Option<String>,
    /// Секретный ключ магазина.
    pub yookassa_secret: Option<String>,
}

impl core::fmt::Debug for Config {
    /// Ни один секрет не печатается. Отладочный вывод уходит в журнал, а
    /// журнал читают, пересылают и прикладывают к обращениям в поддержку.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("bot_token", &"<скрыт>")
            .field("panel_url", &self.panel_url)
            .field("panel_token", &"<скрыт>")
            .field("database_url", &"<скрыт>")
            .field("squads", &self.squads.len())
            .field("admins", &self.admins.len())
            .field("мини-приложение", &self.api_addr)
            .field("принимает переводы", &self.accepts_transfers())
            .field("принимает карты", &self.accepts_cards())
            .finish()
    }
}

/// Имена переменных — в одном месте, чтобы совпадали с описанием в README.
pub const BOT_TOKEN: &str = "GLORIA_BOT_TOKEN";
pub const PANEL_URL: &str = "GLORIA_PANEL_URL";
pub const PANEL_TOKEN: &str = "GLORIA_PANEL_TOKEN";
pub const DATABASE_URL: &str = "GLORIA_DATABASE_URL";
pub const SQUADS: &str = "GLORIA_SQUADS";
pub const ADMINS: &str = "GLORIA_ADMINS";
pub const SBP_PHONE: &str = "GLORIA_SBP_PHONE";
pub const SBP_NAME: &str = "GLORIA_SBP_NAME";
pub const API_ADDR: &str = "GLORIA_API_ADDR";
pub const BOT_USERNAME: &str = "GLORIA_BOT_USERNAME";
pub const YOOKASSA_SHOP_ID: &str = "GLORIA_YOOKASSA_SHOP_ID";
pub const YOOKASSA_SECRET: &str = "GLORIA_YOOKASSA_SECRET";

/// Куда встаёт мини-приложение, если адрес не задан.
///
/// Петля намеренно: наружу его выставляет Caddy на том же домене, где лежит
/// сама страница. Слушать все адреса значило бы открыть выдачу ссылок на
/// подписки всему интернету — подпись Telegram их защищает, но выставлять
/// наружу то, чему незачем быть снаружи, не следует.
pub const DEFAULT_API_ADDR: &str = "127.0.0.1:8081";

impl Config {
    /// Собрать настройки из окружения процесса.
    pub fn from_env() -> Result<Self, Error> {
        let vars: HashMap<String, String> = std::env::vars().collect();
        Self::from_map(&vars)
    }

    /// То же, но из готового набора, — чтобы это можно было проверить
    /// тестом, не трогая окружение процесса.
    pub fn from_map(vars: &HashMap<String, String>) -> Result<Self, Error> {
        let get = |name: &'static str| -> Result<String, Error> {
            match vars.get(name) {
                Some(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
                _ => Err(Error::Missing(name)),
            }
        };

        let panel_url = get(PANEL_URL)?;
        if !panel_url.starts_with("https://") && !is_loopback(&panel_url) {
            return Err(Error::Invalid {
                name: PANEL_URL,
                why: "адрес обязан быть https или петлевым: по нему ходит токен панели",
            });
        }

        let squads: Vec<String> = vars
            .get(SQUADS)
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        if squads.is_empty() {
            return Err(Error::Invalid {
                name: SQUADS,
                why: "без отряда пользователь заведётся, но ходить ему будет некуда",
            });
        }

        let mut admins = Vec::new();
        if let Some(value) = vars.get(ADMINS) {
            for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let Ok(id) = part.parse::<i64>() else {
                    return Err(Error::Invalid {
                        name: ADMINS,
                        why: "номера через запятую, только цифры",
                    });
                };
                admins.push(id);
            }
        }

        Ok(Self {
            bot_token: get(BOT_TOKEN)?,
            panel_url,
            panel_token: get(PANEL_TOKEN)?,
            database_url: get(DATABASE_URL)?,
            squads,
            admins,
            sbp_phone: optional(vars, SBP_PHONE),
            sbp_name: optional(vars, SBP_NAME),
            api_addr: optional(vars, API_ADDR).unwrap_or_else(|| DEFAULT_API_ADDR.to_owned()),
            bot_username: optional(vars, BOT_USERNAME).map(|name| {
                // «@» люди дописывают по привычке, а в ссылке он лишний.
                name.trim_start_matches('@').to_owned()
            }),
            yookassa_shop_id: optional(vars, YOOKASSA_SHOP_ID),
            yookassa_secret: optional(vars, YOOKASSA_SECRET),
        })
    }

    /// Настроен ли приём оплаты переводом.
    #[must_use]
    pub fn accepts_transfers(&self) -> bool {
        self.sbp_phone.is_some() && self.sbp_name.is_some()
    }

    /// Подключён ли приём оплаты картой и СБП через ЮKassa.
    ///
    /// Нужны оба ключа: с одним из них запрос уйдёт и получит отказ, а
    /// человек увидит «оплата не работает» вместо страницы оплаты.
    #[must_use]
    pub fn accepts_cards(&self) -> bool {
        self.yookassa_shop_id.is_some() && self.yookassa_secret.is_some()
    }

    /// Разрешены ли этому человеку админские действия.
    #[must_use]
    pub fn is_admin(&self, telegram_id: i64) -> bool {
        self.admins.contains(&telegram_id)
    }
}

/// Обращение к панели по петлевому адресу — единственный случай, когда
/// `http` допустим.
///
/// Требование `https` существует ради одного: токен панели даёт власть над
/// всеми узлами, и по сети он ходить открытым не должен. По `127.0.0.1`
/// он по сети и не ходит — запрос не покидает машину. Зато `http` туда
/// снимает целый слой чужих настроек: панель за Caddy закрывает `/api/*`
/// от внешнего мира, и обращение по публичному адресу упирается в 404 при
/// живом и правильном токене.
///
/// Проверяется именно **начало адреса**, а не вхождение подстроки:
/// `http://127.0.0.1.attacker.example` начинается с `http://127.0.0.1`, но
/// петлевым не является, поэтому за адресом обязан идти конец строки,
/// двоеточие с портом или косая черта.
fn is_loopback(url: &str) -> bool {
    const HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];

    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };

    HOSTS.iter().any(|host| {
        rest.strip_prefix(host)
            .is_some_and(|tail| tail.is_empty() || tail.starts_with(':') || tail.starts_with('/'))
    })
}

/// Необязательное значение: пустое считается незаданным.
fn optional(vars: &HashMap<String, String>, name: &str) -> Option<String> {
    vars.get(name)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::{Config, Error, ADMINS, BOT_TOKEN, DATABASE_URL, PANEL_TOKEN, PANEL_URL, SQUADS};
    use std::collections::HashMap;

    fn full() -> HashMap<String, String> {
        [
            (BOT_TOKEN, "123456:AAHkTestToken"),
            (PANEL_URL, "https://panel.example.org"),
            (PANEL_TOKEN, "panel-token"),
            (DATABASE_URL, "postgres://gloria@localhost/gloria"),
            (SQUADS, "b6f5d810-8ef3-4be9-9012-3456789abcde"),
            (ADMINS, "42, 43"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    #[test]
    fn a_complete_environment_is_accepted() {
        let Ok(config) = Config::from_map(&full()) else {
            return;
        };
        assert_eq!(config.squads.len(), 1);
        assert!(config.is_admin(42));
        assert!(config.is_admin(43));
        assert!(!config.is_admin(44));
    }

    /// Каждая недостающая переменная называется по имени. «Что-то не
    /// настроено» в четыре часа ночи — это час поисков.
    #[test]
    fn every_missing_variable_is_named() {
        for name in [BOT_TOKEN, PANEL_URL, PANEL_TOKEN, DATABASE_URL] {
            let mut vars = full();
            vars.remove(name);
            assert!(
                matches!(Config::from_map(&vars), Err(Error::Missing(missing)) if missing == name),
                "переменная {name} не названа"
            );
        }
    }

    /// Пустое значение — то же, что отсутствие: пустой токен даёт отказ от
    /// Telegram, который в журнале выглядит как «Unauthorized» и не
    /// подсказывает, где искать.
    #[test]
    fn an_empty_value_counts_as_missing() {
        let mut vars = full();
        vars.insert(BOT_TOKEN.to_owned(), "   ".to_owned());
        assert!(matches!(
            Config::from_map(&vars),
            Err(Error::Missing(BOT_TOKEN))
        ));
    }

    /// По адресу панели ходит токен, дающий власть над всеми узлами.
    #[test]
    fn a_panel_without_tls_is_refused() {
        let mut vars = full();
        vars.insert(PANEL_URL.to_owned(), "http://panel.example.org".to_owned());
        assert!(matches!(
            Config::from_map(&vars),
            Err(Error::Invalid {
                name: PANEL_URL,
                ..
            })
        ));
    }

    /// Панель за Caddy закрывает `/api/*` снаружи, а бот стоит на той же
    /// машине. По петле токен по сети не идёт, поэтому `http` там уместен.
    #[test]
    fn a_panel_on_the_loopback_may_be_plain_http() {
        for address in [
            "http://127.0.0.1:3000",
            "http://127.0.0.1",
            "http://localhost:3000",
            "http://[::1]:3000",
            "http://127.0.0.1:3000/",
        ] {
            let mut vars = full();
            vars.insert(PANEL_URL.to_owned(), address.to_owned());
            assert!(
                Config::from_map(&vars).is_ok(),
                "петлевой адрес {address} отвергнут"
            );
        }
    }

    /// Проверка идёт по началу адреса, а не по вхождению подстроки: имя
    /// `127.0.0.1.attacker.example` разрешается во что угодно, и открытый
    /// токен ушёл бы туда.
    #[test]
    fn a_hostname_that_merely_starts_with_the_loopback_is_refused() {
        for address in [
            "http://127.0.0.1.attacker.example",
            "http://localhost.attacker.example",
            "http://attacker.example/127.0.0.1",
            "http://127.0.0.10",
        ] {
            let mut vars = full();
            vars.insert(PANEL_URL.to_owned(), address.to_owned());
            assert!(
                matches!(
                    Config::from_map(&vars),
                    Err(Error::Invalid {
                        name: PANEL_URL,
                        ..
                    })
                ),
                "адрес {address} принят за петлевой"
            );
        }
    }

    /// Пользователь без отряда заводится, но ходить ему некуда: ровно та
    /// ошибка, на которую мы потеряли вечер при настройке узла.
    #[test]
    fn no_squad_is_refused_up_front() {
        let mut vars = full();
        vars.remove(SQUADS);
        assert!(matches!(
            Config::from_map(&vars),
            Err(Error::Invalid { name: SQUADS, .. })
        ));
    }

    #[test]
    fn several_squads_are_split_on_commas() {
        let mut vars = full();
        vars.insert(SQUADS.to_owned(), "aaa, bbb ,ccc,".to_owned());
        let Ok(config) = Config::from_map(&vars) else {
            return;
        };
        assert_eq!(config.squads, vec!["aaa", "bbb", "ccc"]);
    }

    #[test]
    fn a_non_numeric_admin_is_refused() {
        let mut vars = full();
        vars.insert(ADMINS.to_owned(), "42,я".to_owned());
        assert!(matches!(
            Config::from_map(&vars),
            Err(Error::Invalid { name: ADMINS, .. })
        ));
    }

    /// Без админов бот работает — просто некому подтверждать оплаты вручную.
    #[test]
    fn admins_are_optional() {
        let mut vars = full();
        vars.remove(ADMINS);
        let Ok(config) = Config::from_map(&vars) else {
            return;
        };
        assert!(config.admins.is_empty());
        assert!(!config.is_admin(42));
    }

    /// Секреты не должны попадать в журнал через отладочную печать.
    #[test]
    fn no_secret_shows_up_in_debug_output() {
        let Ok(config) = Config::from_map(&full()) else {
            return;
        };
        let printed = format!("{config:?}");
        for secret in ["123456:AAHkTestToken", "panel-token", "postgres://gloria"] {
            assert!(
                !printed.contains(secret),
                "в выводе видно {secret}: {printed}"
            );
        }
        assert!(
            printed.contains("panel.example.org"),
            "адрес панели полезен в журнале"
        );
    }
}
