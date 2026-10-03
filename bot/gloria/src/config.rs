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
    /// Ссылка на перевод — та, что стоит за QR-кодом в банковском
    /// приложении. Заменяет собой номер телефона: покупатель открывает её
    /// и видит уже готовую форму перевода, не набирая никаких реквизитов.
    pub pay_link: Option<String>,
    /// Показывать ли способ «перевод по ссылке». Сама `pay_link` может быть
    /// задана и готова, но способ скрыт, пока это выключено, — и включается
    /// обратно одной переменной, без переписывания ссылки. По умолчанию да.
    pub manual_transfer: bool,
    /// Где слушать мини-приложение. Только петля: наружу выставляет Caddy.
    pub api_addr: String,
    /// Имя бота без «@» — из него строится реферальная ссылка.
    pub bot_username: Option<String>,
    /// Магазин в ЮKassa, если приём оплаты картой уже подключён.
    pub yookassa_shop_id: Option<String>,
    /// Секретный ключ магазина.
    pub yookassa_secret: Option<String>,
    /// Токен терминала WATA, если приём оплаты идёт через неё.
    pub wata_token: Option<String>,
    /// Номер магазина Freekassa и два его секрета. Все три вместе или
    /// никак — с неполным набором счёт выставится, а подпись не сойдётся.
    pub freekassa_merchant: Option<String>,
    /// Секретное слово 1 — подпись формы оплаты.
    pub freekassa_form_secret: Option<String>,
    /// Секретное слово 2 — проверка уведомления.
    pub freekassa_notice_secret: Option<String>,
    /// Ключ API Freekassa. Задан — счёт создаётся запросом к API (этого
    /// требует Freekassa), не задан — старой формой SCI.
    pub freekassa_api_key: Option<String>,
    /// Публичный IP сервера. Freekassa требует в заказе IP покупателя или
    /// сервера, а бот за Caddy видит только `127.0.0.1`, который она
    /// отвергает. Обязателен, когда задан ключ API.
    pub server_ip: Option<String>,
    /// Комиссия Freekassa за СБП в сотых долях процента (600 = 6%).
    /// Её платит покупатель сверх цены, и он видит её до оплаты: из этого
    /// числа бот считает, сколько выйдет итого.
    pub freekassa_fee_bp: u32,
    /// Адрес мини-приложения. Из него делается кнопка «Меню» у поля ввода.
    pub miniapp_url: Option<String>,
    /// Токен бота поддержки. Свой, отдельный от основного.
    ///
    /// Нет — поддержка не поднимается, и всё остальное работает как
    /// работало. Обращения тогда идут туда, куда указывает кнопка в
    /// кабинете, и это ответственность настроек, а не кода.
    pub support_token: Option<String>,
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
            .field("принимает WATA", &self.accepts_wata())
            .field("принимает Freekassa", &self.accepts_freekassa())
            .field("Freekassa через API", &self.freekassa_api_key.is_some())
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
pub const PAY_LINK: &str = "GLORIA_PAY_LINK";
pub const MANUAL_TRANSFER: &str = "GLORIA_MANUAL_TRANSFER";
pub const API_ADDR: &str = "GLORIA_API_ADDR";
pub const BOT_USERNAME: &str = "GLORIA_BOT_USERNAME";
pub const YOOKASSA_SHOP_ID: &str = "GLORIA_YOOKASSA_SHOP_ID";
pub const YOOKASSA_SECRET: &str = "GLORIA_YOOKASSA_SECRET";
pub const WATA_TOKEN: &str = "GLORIA_WATA_TOKEN";
pub const FREEKASSA_MERCHANT: &str = "GLORIA_FREEKASSA_MERCHANT";
pub const FREEKASSA_FORM_SECRET: &str = "GLORIA_FREEKASSA_SECRET1";
pub const FREEKASSA_NOTICE_SECRET: &str = "GLORIA_FREEKASSA_SECRET2";
pub const FREEKASSA_API_KEY: &str = "GLORIA_FREEKASSA_API_KEY";
pub const SERVER_IP: &str = "GLORIA_SERVER_IP";
pub const FREEKASSA_FEE: &str = "GLORIA_FREEKASSA_FEE";

/// Комиссия Freekassa за СБП, если не задана: 6%, как в первом же заказе
/// (199 ₽ превратились у покупателя в 210,94 ₽).
pub const DEFAULT_FREEKASSA_FEE_BP: u32 = 600;
pub const MINIAPP_URL: &str = "GLORIA_MINIAPP_URL";
const SUPPORT_TOKEN: &str = "GLORIA_SUPPORT_TOKEN";

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

        // Ссылка уходит в кнопку Telegram, а он принимает там только адрес.
        // Номер телефона или строка вида `+7…`, вписанные по привычке от
        // прежних переводов по СБП, дали бы отказ Telegram на каждом счёте —
        // и человек увидел бы не оплату, а «попробуйте позже». Лучше
        // отказаться при запуске, где ошибка названа по имени.
        let pay_link = optional(vars, PAY_LINK);
        if let Some(link) = &pay_link {
            if !link.starts_with("https://") {
                return Err(Error::Invalid {
                    name: PAY_LINK,
                    why: "нужен адрес https — тот, что стоит за QR-кодом перевода, а не номер",
                });
            }

            // Раньше здесь стоял отказ. Владелец решил, что видимый номер его
            // устраивает, — а у Т-Банка постоянной ссылки на перевод без
            // номера попросту нет: тот QR, который он даёт, и есть платёжный
            // QR СБП, а номер в нём не оформление, а содержимое.
            //
            // Поэтому предупреждение, а не запрет. Сказать стоит всё равно:
            // решение принималось один раз, а читать журнал будут и потом.
            if carries_a_phone_number(link) {
                eprintln!(
                    "Внимание: в {PAY_LINK} виден номер телефона. \
                     Его увидит каждый покупатель, открывший ссылку."
                );
            }
        }

        // Кнопка «Меню» ведёт в мини-приложение, а Telegram принимает там
        // только https. Негодный адрес он отвергнет при установке кнопки —
        // то есть при запуске, куда никто не смотрит. Лучше сказать сразу.
        // Ключ API без адреса сервера — заказ, который Freekassa отвергнет на
        // каждой оплате. Лучше сказать при запуске, чем на первом покупателе.
        let freekassa_api_key = optional(vars, FREEKASSA_API_KEY);
        let server_ip = optional(vars, SERVER_IP);
        if let Some(ip) = &server_ip {
            match ip.parse::<std::net::IpAddr>() {
                Ok(addr) if !addr.is_loopback() && !addr.is_unspecified() => {}
                _ => {
                    return Err(Error::Invalid {
                        name: SERVER_IP,
                        why: "нужен публичный IP сервера; 127.0.0.1 Freekassa отвергает",
                    })
                }
            }
        }
        if freekassa_api_key.is_some() && server_ip.is_none() {
            return Err(Error::Invalid {
                name: SERVER_IP,
                why: "с ключом API Freekassa нужен публичный IP сервера для заказа",
            });
        }

        // Покупателю показывается и процент, и итог. Неверная ставка — значит
        // обещание суммы, которой на странице оплаты не будет; лучше отказ
        // при запуске, чем расхождение у покупателя.
        let freekassa_fee_bp = match optional(vars, FREEKASSA_FEE) {
            None => DEFAULT_FREEKASSA_FEE_BP,
            Some(value) => parse_percent(&value).ok_or(Error::Invalid {
                name: FREEKASSA_FEE,
                why: "процент числом от 0 до 50, например 6 или 6,5",
            })?,
        };

        let miniapp_url = optional(vars, MINIAPP_URL);
        if let Some(url) = &miniapp_url {
            if !url.starts_with("https://") {
                return Err(Error::Invalid {
                    name: MINIAPP_URL,
                    why: "адрес кабинета обязан быть https: другого Telegram не примет",
                });
            }
        }

        // Показывать ли перевод по ссылке. По умолчанию да — поведение
        // прежнее. Выключается явным «off» (а также 0/false/no/нет/выкл) и
        // так же включается обратно; сама ссылка при этом остаётся в
        // окружении готовой, просто способ скрыт.
        let manual_transfer = vars.get(MANUAL_TRANSFER).is_none_or(|value| {
            !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "off" | "0" | "false" | "no" | "нет" | "выкл"
            )
        });

        Ok(Self {
            bot_token: get(BOT_TOKEN)?,
            panel_url,
            panel_token: get(PANEL_TOKEN)?,
            database_url: get(DATABASE_URL)?,
            squads,
            admins,
            pay_link,
            manual_transfer,
            api_addr: optional(vars, API_ADDR).unwrap_or_else(|| DEFAULT_API_ADDR.to_owned()),
            bot_username: optional(vars, BOT_USERNAME).map(|name| {
                // «@» люди дописывают по привычке, а в ссылке он лишний.
                name.trim_start_matches('@').to_owned()
            }),
            yookassa_shop_id: optional(vars, YOOKASSA_SHOP_ID),
            yookassa_secret: optional(vars, YOOKASSA_SECRET),
            wata_token: optional(vars, WATA_TOKEN),
            freekassa_merchant: optional(vars, FREEKASSA_MERCHANT),
            freekassa_form_secret: optional(vars, FREEKASSA_FORM_SECRET),
            freekassa_notice_secret: optional(vars, FREEKASSA_NOTICE_SECRET),
            freekassa_api_key,
            server_ip,
            freekassa_fee_bp,
            miniapp_url,
            support_token: optional(vars, SUPPORT_TOKEN),
        })
    }

    /// Настроен ли приём оплаты переводом по ссылке.
    #[must_use]
    pub fn accepts_transfers(&self) -> bool {
        self.manual_transfer && self.pay_link.is_some()
    }

    /// Подключён ли приём оплаты картой и СБП через ЮKassa.
    ///
    /// Нужны оба ключа: с одним из них запрос уйдёт и получит отказ, а
    /// человек увидит «оплата не работает» вместо страницы оплаты.
    #[must_use]
    pub fn accepts_cards(&self) -> bool {
        self.yookassa_shop_id.is_some() && self.yookassa_secret.is_some()
    }

    /// Подключён ли приём оплаты через WATA.
    ///
    /// Если заданы ключи обоих сервисов, счёт открывает WATA: она отдаёт
    /// СБП, карты, T-Pay и SberPay одной ссылкой. Выбор делается здесь, а не
    /// в основном цикле, чтобы правило было записано в одном месте.
    #[must_use]
    pub fn accepts_wata(&self) -> bool {
        self.wata_token.is_some()
    }

    /// Подключён ли приём оплаты через Freekassa.
    ///
    /// Нужны все три реквизита: номер магазина и оба секретных слова.
    /// С неполным набором форма выставится, но подпись уведомления не
    /// сойдётся — то есть деньги придут, а подписка не включится.
    #[must_use]
    pub fn accepts_freekassa(&self) -> bool {
        self.freekassa_merchant.is_some()
            && self.freekassa_form_secret.is_some()
            && self.freekassa_notice_secret.is_some()
    }

    /// Собрать клиента Freekassa, если реквизиты полны и годны.
    #[must_use]
    pub fn freekassa(&self) -> Option<atlas_billing::Freekassa> {
        let service = atlas_billing::Freekassa::new(
            self.freekassa_merchant.as_deref()?,
            self.freekassa_form_secret.as_deref()?,
            self.freekassa_notice_secret.as_deref()?,
        )?;
        match &self.freekassa_api_key {
            Some(key) => service.with_api_key(key),
            None => Some(service),
        }
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

/// Видно ли в ссылке номер телефона.
///
/// Ссылку на перевод легко перепутать со ссылкой на QR-код СБП: в
/// приложении банка они лежат рядом и обе ведут к переводу. Разница в том,
/// что вторая несёт номер прямо в адресе —
/// `…/c2c-qr-choose-bank?requisiteNumber=+79001234567&bankCode=…`. Такая
/// ссылка раскрывает номер надёжнее, чем прежний текст в счёте: она видна
/// в адресной строке, остаётся в истории браузера и пересылается дальше.
///
/// Отказом это не считается. У Т-Банка постоянной ссылки на перевод без
/// номера нет вовсе: тот QR, который он даёт, и есть платёжный QR СБП, а
/// номер в нём — не оформление, а содержимое. Владелец это взвесил и решил,
/// что видимый номер его устраивает. Но сказать при запуске стоит: решение
/// принималось однажды, а журнал читают и потом.
///
/// Считаем номером цепочку цифр, в которую укладывается российский
/// мобильный: одиннадцать и больше подряд (`79001234567`) или ровно
/// десять, начинающиеся с девятки (`9001234567`). Разделители внутри
/// номера цепочку разорвут, и такую запись проверка пропустит — она ловит
/// обычный случай, а не всякий мыслимый.
///
/// Ошибиться она может и в другую сторону: у ссылки бывает числовой
/// признак подходящей длины. Тогда предупреждение окажется ложным — цена
/// невелика, но лишние предупреждения перестают читать, и потому проверка
/// не ловит всё подряд.
fn carries_a_phone_number(link: &str) -> bool {
    let mut digits = 0usize;
    let mut starts_with_nine = false;

    // Цепочка заканчивается и на последнем символе, поэтому к строке
    // приписывается заведомо не-цифра: иначе номер в самом конце адреса
    // остался бы непроверенным.
    for symbol in link.chars().chain(core::iter::once(' ')) {
        if symbol.is_ascii_digit() {
            if digits == 0 {
                starts_with_nine = symbol == '9';
            }
            digits += 1;
            continue;
        }

        if digits >= 11 || (digits == 10 && starts_with_nine) {
            return true;
        }
        digits = 0;
    }

    false
}

/// Необязательное значение: пустое считается незаданным.
/// Процент в сотых долях: «6» → 600, «6,5» и «6.5» → 650, «6.25» → 625.
/// Больше двух знаков после запятой и больше 50% — отказ: такая ставка
/// почти наверняка опечатка.
fn parse_percent(value: &str) -> Option<u32> {
    let normalized = value.trim().replace(',', ".");
    let (whole, fraction) = normalized.split_once('.').unwrap_or((&normalized, ""));
    if whole.is_empty() || fraction.len() > 2 {
        return None;
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: u32 = whole.parse().ok()?;
    let fraction: u32 = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<u32>().ok()? * 10,
        _ => fraction.parse().ok()?,
    };
    let total = whole.checked_mul(100)?.checked_add(fraction)?;
    (total <= 5_000).then_some(total)
}

fn optional(vars: &HashMap<String, String>, name: &str) -> Option<String> {
    vars.get(name)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::{
        Config, Error, ADMINS, BOT_TOKEN, DATABASE_URL, FREEKASSA_API_KEY, FREEKASSA_FORM_SECRET,
        FREEKASSA_MERCHANT, FREEKASSA_NOTICE_SECRET, MANUAL_TRANSFER, PANEL_TOKEN, PANEL_URL,
        PAY_LINK, SERVER_IP, SQUADS,
    };
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
        assert_eq!(config.admins.len(), 0);
        assert!(!config.is_admin(42));
    }

    /// Ссылка на перевод уходит в кнопку Telegram, а туда годится только
    /// адрес. Номер, вписанный по привычке от прежних переводов по СБП, дал
    /// бы отказ на каждом счёте — и ошибка вылезла бы у покупателя, а не при
    /// запуске.
    #[test]
    fn a_transfer_link_that_is_not_an_address_is_refused() {
        for value in ["+79001234567", "79001234567", "http://bank.example/x"] {
            let mut vars = full();
            vars.insert(PAY_LINK.to_owned(), value.to_owned());
            assert!(
                matches!(
                    Config::from_map(&vars),
                    Err(Error::Invalid { name: PAY_LINK, .. })
                ),
                "значение {value} принято за ссылку на перевод"
            );
        }
    }

    /// Ссылка на QR-код СБП несёт номер прямо в адресе. Отказом это больше
    /// не считается: у Т-Банка постоянной ссылки на перевод без номера нет
    /// вовсе, и владелец решил, что видимый номер его устраивает. Но принять
    /// такую ссылку бот обязан — иначе приём оплаты не запустится.
    #[test]
    fn a_link_carrying_the_phone_number_is_accepted_with_a_warning() {
        for value in [
            "https://t.tb.ru/c2c-qr-choose-bank?requisiteNumber=+79001234567&bankCode=100000000004",
            "https://bank.example/pay?phone=79001234567",
            "https://bank.example/pay?phone=9001234567",
            "https://bank.example/89001234567",
        ] {
            let mut vars = full();
            vars.insert(PAY_LINK.to_owned(), value.to_owned());
            assert!(
                Config::from_map(&vars).is_ok(),
                "ссылка с номером отвергнута: {value}"
            );
            assert!(
                super::carries_a_phone_number(value),
                "номер в {value} не замечен — предупреждения не будет"
            );
        }
    }

    /// Обратная сторона: обычная ссылка на перевод цифры тоже содержит, и
    /// принимать за номер её не следует — иначе предупреждение печаталось бы
    /// впустую и его перестали бы читать.
    #[test]
    fn an_ordinary_transfer_link_carries_no_phone_number() {
        for value in [
            "https://www.tbank.ru/rm/ivanov.ivan1/AbCdE12345",
            "https://bank.example/rm/abc",
            "https://bank.example/pay/2026090812",
        ] {
            let mut vars = full();
            vars.insert(PAY_LINK.to_owned(), value.to_owned());
            assert!(
                Config::from_map(&vars).is_ok(),
                "обычная ссылка отвергнута: {value}"
            );
            assert!(
                !super::carries_a_phone_number(value),
                "в обычной ссылке померещился номер: {value}"
            );
        }
    }

    /// Номер в самом конце адреса — цепочка цифр, которую нечем закрыть.
    /// Без приписанного разделителя она осталась бы непроверенной.
    #[test]
    fn a_phone_number_at_the_very_end_is_still_seen() {
        assert!(super::carries_a_phone_number(
            "https://bank.example/pay?phone=79001234567"
        ));
    }

    /// Без ссылки бот работает: счёт просто выставляется, а оплату
    /// подтверждает владелец вручную.
    #[test]
    fn a_transfer_link_is_optional() {
        let Ok(config) = Config::from_map(&full()) else {
            return;
        };
        assert!(!config.accepts_transfers());

        let mut vars = full();
        vars.insert(
            PAY_LINK.to_owned(),
            "https://bank.example/rm/abc".to_owned(),
        );
        let Ok(config) = Config::from_map(&vars) else {
            return;
        };
        assert!(config.accepts_transfers());
    }

    /// Способ перевода можно скрыть, не убирая ссылку: `off` выключает его, а
    /// обратное значение включает назад. Это и есть «спрятать, но вернуть
    /// в любой момент».
    #[test]
    fn a_transfer_can_be_hidden_by_flag() {
        let mut vars = full();
        vars.insert(
            PAY_LINK.to_owned(),
            "https://bank.example/rm/abc".to_owned(),
        );

        let Ok(config) = Config::from_map(&vars) else {
            return;
        };
        assert!(config.accepts_transfers(), "по умолчанию перевод включён");

        vars.insert(MANUAL_TRANSFER.to_owned(), "off".to_owned());
        let Ok(config) = Config::from_map(&vars) else {
            return;
        };
        assert!(
            !config.accepts_transfers(),
            "off обязан скрыть перевод даже при заданной ссылке"
        );

        vars.insert(MANUAL_TRANSFER.to_owned(), "on".to_owned());
        let Ok(config) = Config::from_map(&vars) else {
            return;
        };
        assert!(config.accepts_transfers(), "on обязан вернуть перевод");
    }

    fn with_freekassa() -> HashMap<String, String> {
        let mut vars = full();
        for (name, value) in [
            (FREEKASSA_MERCHANT, "76467"),
            (FREEKASSA_FORM_SECRET, "secret-one"),
            (FREEKASSA_NOTICE_SECRET, "secret-two"),
        ] {
            vars.insert(name.to_owned(), value.to_owned());
        }
        vars
    }

    /// С ключом API без IP сервера бот не запускается: такой заказ Freekassa
    /// отвергла бы на каждой оплате, и узнали бы об этом от покупателя.
    #[test]
    fn an_api_key_needs_the_server_ip() {
        let mut vars = with_freekassa();
        vars.insert(FREEKASSA_API_KEY.to_owned(), "api-key".to_owned());
        assert!(matches!(
            Config::from_map(&vars),
            Err(Error::Invalid {
                name: SERVER_IP,
                ..
            })
        ));
    }

    /// Петлевой адрес Freekassa отвергает — отказ при запуске.
    #[test]
    fn a_loopback_server_ip_is_refused() {
        let mut vars = with_freekassa();
        vars.insert(SERVER_IP.to_owned(), "127.0.0.1".to_owned());
        assert!(matches!(
            Config::from_map(&vars),
            Err(Error::Invalid {
                name: SERVER_IP,
                ..
            })
        ));
    }

    /// Ключ и публичный IP вместе включают создание счёта через API, а ключ
    /// в отладочную печать не попадает.
    #[test]
    fn an_api_key_with_a_public_ip_switches_to_the_api() {
        let mut vars = with_freekassa();
        vars.insert(FREEKASSA_API_KEY.to_owned(), "api-key-secret".to_owned());
        vars.insert(SERVER_IP.to_owned(), "193.109.69.126".to_owned());
        let Ok(config) = Config::from_map(&vars) else {
            unreachable!("настройки обязаны собраться");
        };
        assert!(config.freekassa().is_some_and(|service| service.uses_api()));
        assert!(!format!("{config:?}").contains("api-key-secret"));
    }

    /// Ставка комиссии читается в привычной записи и отвергает опечатки.
    #[test]
    fn a_fee_is_read_as_a_percent() {
        assert_eq!(super::parse_percent("6"), Some(600));
        assert_eq!(super::parse_percent("6,5"), Some(650));
        assert_eq!(super::parse_percent("6.25"), Some(625));
        assert_eq!(super::parse_percent("0"), Some(0));
        assert_eq!(super::parse_percent("6.255"), None);
        assert_eq!(super::parse_percent("60"), None);
        assert_eq!(super::parse_percent("шесть"), None);
        assert_eq!(super::parse_percent(".5"), None);
    }

    /// Не задана — 6%, как в первом заказе.
    #[test]
    fn the_fee_defaults_to_six_percent() {
        let Ok(config) = Config::from_map(&full()) else {
            unreachable!("настройки обязаны собраться");
        };
        assert_eq!(config.freekassa_fee_bp, 600);
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
