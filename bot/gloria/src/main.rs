//! Бот Gloria VPN.
//!
//! Здесь только соединение проводов: логика разговора живёт в `atlas-bot`,
//! деньги в `atlas-billing`, хранилище в `atlas-store`, панель в
//! `atlas-panel`, а разбор обновлений в `atlas-tg`. Всё это проверено
//! тестами по отдельности; этот файл намеренно оставлен настолько глупым,
//! насколько получилось, потому что проверить его можно только запуском.
//!
//! Порядок работы простой: спросить обновления, на каждое ответить, повторить.

#![forbid(unsafe_code)]

mod config;
mod http;

use std::process::ExitCode;

use atlas_billing::invoice;
use atlas_bot::{catalog, flow, Action, Unknown};
use atlas_panel::{NewUser, Panel};
use atlas_store::{Settled, Store, Trial};
use atlas_tg::{next_offset, Incoming, Telegram};

use config::Config;

/// Сколько секунд Telegram держит соединение, ожидая обновлений.
const LONG_POLL: u16 = 30;

/// Пауза после сбоя связи, чтобы не колотиться в упавшую службу.
const RETRY_PAUSE: std::time::Duration = std::time::Duration::from_secs(5);

fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Настройки: {error}");
            eprintln!("См. bot/README.md — там перечислено, что нужно задать.");
            return ExitCode::FAILURE;
        }
    };

    let Some(telegram) = Telegram::new(&config.bot_token) else {
        eprintln!("Настройки: токен бота имеет недопустимый вид");
        return ExitCode::FAILURE;
    };

    let Some(panel) = Panel::new(&config.panel_url, &config.panel_token) else {
        eprintln!("Настройки: адрес или токен панели негодны");
        return ExitCode::FAILURE;
    };

    let mut store = match Store::connect(&config.database_url) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("База: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("Бот запущен. {config:?}");
    run(&config, &telegram, &panel, &mut store);
    ExitCode::SUCCESS
}

/// Основной цикл. Из него не выходят: любая ошибка — повод подождать и
/// попробовать снова, а не остановиться.
fn run(config: &Config, telegram: &Telegram, panel: &Panel, store: &mut Store) {
    let mut offset: Option<i64> = None;

    loop {
        let request = telegram.get_updates(offset, LONG_POLL);
        let response = match http::send(&request) {
            Ok(response) => response,
            Err(error) => {
                // Обязательно через redact: адрес запроса содержит токен.
                eprintln!(
                    "Telegram недоступен: {}",
                    telegram.redact(&error.to_string())
                );
                std::thread::sleep(RETRY_PAUSE);
                continue;
            }
        };

        let batch = match telegram.parse_updates(&response.body) {
            Ok(batch) => batch,
            Err(error) => {
                eprintln!("Ответ Telegram: {}", telegram.redact(&error.to_string()));
                std::thread::sleep(RETRY_PAUSE);
                continue;
            }
        };

        for update in &batch.updates {
            if let Err(error) = handle(config, telegram, panel, store, &update.incoming) {
                eprintln!("Обновление {}: {}", update.id, telegram.redact(&error));
            }
        }

        // Сдвиг двигается даже когда обработка не удалась. Иначе одно
        // упрямое обновление приходило бы вечно и загораживало остальные:
        // человек, чей запрос не удалось выполнить, напишет снова, а
        // застрявший бот не поможет никому.
        offset = next_offset(&batch, offset);
    }
}

/// Ответить на одно обновление.
fn handle(
    config: &Config,
    telegram: &Telegram,
    panel: &Panel,
    store: &mut Store,
    incoming: &Incoming,
) -> Result<(), String> {
    let telegram_id = incoming.from();
    let now = unix_now();

    // На нажатие отвечаем сразу, не дожидаясь остального: иначе у человека
    // кнопка крутится, пока мы ходим в базу и панель.
    if let Incoming::Button { callback_id, .. } = incoming {
        let _ = http::send(&telegram.answer_callback(callback_id, None));
    }

    // Админские команды идут в обход обычного разговора: они не про
    // подписку, а про чужие платежи, и показывать их всем нельзя.
    if let Incoming::Message { text, .. } = incoming {
        if config.is_admin(telegram_id) {
            if let Some(answer) = admin(store, text, now)? {
                let request = telegram
                    .send_message(incoming.chat(), &answer, None)
                    .map_err(|error| format!("сообщение: {error}"))?;
                http::send(&request).map_err(|error| format!("отправка: {error}"))?;
                return Ok(());
            }
        }
    }

    let mut subscriber = store
        .ensure_subscriber(telegram_id)
        .map_err(|error| format!("база: {error}"))?;

    // Подписка есть, а ссылки нет — значит панель отказала в тот раз, когда
    // мы заводили человека. Само это не исправится: проба выдаётся один раз,
    // и ветка с созданием в панели больше не отработает никогда. Чиним при
    // следующем же обращении, иначе оплативший останется без ссылки навсегда.
    if subscriber.subscription_url.is_none() {
        if let Some(expires_at) = subscriber.expires_at {
            match ensure_panel_user(config, panel, store, telegram_id, expires_at) {
                Ok(url) => subscriber.subscription_url = Some(url),
                // Разговор не прерываем. Меню без ссылки — плохо, молчащий
                // бот — хуже: человек не поймёт, сломалось у него или у нас.
                Err(error) => eprintln!("Панель для {telegram_id}: {error}"),
            }
        }
    }

    let view = flow::View {
        expires_at: subscriber.expires_at,
        trial_used: subscriber.trial_granted_at.is_some(),
        subscription_url: subscriber.subscription_url.as_deref(),
        now,
    };

    let (reply, effect) = match incoming {
        Incoming::Message { text, .. } => flow::on_message(text, &view),
        Incoming::Button { data, .. } => match Action::decode(data) {
            Ok(action) => flow::on_action(&action, &view),
            // Нажатие, которого мы не понимаем, — либо старая кнопка, либо
            // изменённый клиент. И то и другое лечится показом меню.
            Err(Unknown::NoSuchAction | Unknown::BadPlanName) => flow::on_message("", &view),
        },
    };

    let extra = apply(config, panel, store, telegram_id, &effect, now)?;

    let text = match extra {
        Some(extra) => format!("{}\n\n{extra}", reply.text),
        None => reply.text,
    };

    let request = telegram
        .send_message(incoming.chat(), &text, reply.keyboard.as_ref())
        .map_err(|error| format!("сообщение: {error}"))?;

    let response = http::send(&request).map_err(|error| format!("отправка: {error}"))?;
    if !response.is_ok() {
        return Err(format!(
            "Telegram отверг сообщение, код {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        ));
    }
    Ok(())
}

/// Выполнить намерение и вернуть то, что надо дописать к ответу.
fn apply(
    config: &Config,
    panel: &Panel,
    store: &mut Store,
    telegram_id: i64,
    effect: &flow::Effect,
    now: i64,
) -> Result<Option<String>, String> {
    match effect {
        flow::Effect::None => Ok(None),

        flow::Effect::GrantTrial => {
            let Trial::Granted { expires_at } = store
                .grant_trial(telegram_id, catalog::TRIAL_DAYS, now)
                .map_err(|error| format!("выдача пробы: {error}"))?
            else {
                // Проба уже выдавалась. Молча: человек об этом знает.
                return Ok(None);
            };

            let url = ensure_panel_user(config, panel, store, telegram_id, expires_at)?;
            Ok(Some(format!(
                "Ваша ссылка — одна на все устройства:\n<code>{url}</code>"
            )))
        }

        flow::Effect::OpenOrder { plan } => {
            let Some(plan) = catalog::plan(plan) else {
                return Ok(None);
            };

            let taken = store
                .taken_amounts(now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("занятые суммы: {error}"))?;

            let amount = invoice::allocate(plan.price, &taken)
                .map_err(|_| "сейчас слишком много открытых счетов, попробуйте через минуту")?;

            // Номер заказа: кто, что и когда. Набор символов проверяется
            // и здесь, и в базе — он уходит в подпись платёжного сервиса.
            let order_id = format!("u{telegram_id}-{}-{now}", plan.id);
            store
                .open_order(&order_id, telegram_id, &plan.id, plan.days, amount, now)
                .map_err(|error| format!("счёт: {error}"))?;

            Ok(Some(invoice_text(config, amount)))
        }
    }
}

/// Админские команды. `None` означает «это не админская команда».
///
/// Подтверждение вручную — то, чем рублёвый канал живёт, пока не одобрен
/// процессинг: банк не сообщает программе о зачислении, знает о нём только
/// владелец счёта.
fn admin(store: &mut Store, text: &str, now: i64) -> Result<Option<String>, String> {
    let mut parts = text.split_whitespace();
    let command = parts.next().unwrap_or("").split('@').next().unwrap_or("");

    match command {
        "/pending" => {
            let pending = store
                .pending_orders(now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("база: {error}"))?;

            if pending.is_empty() {
                return Ok(Some("Открытых счетов нет.".to_owned()));
            }

            let mut answer = String::from("Ожидают оплаты:\n");
            for order in pending {
                answer.push_str(&format!(
                    "\n<code>{}</code> · {} · {}\n  подтвердить: /ok {}",
                    atlas_bot::menu::price_label(order.amount),
                    order.plan,
                    order.telegram_id,
                    order.amount.to_decimal(),
                ));
            }
            Ok(Some(answer))
        }

        "/ok" => {
            let Some(sum) = parts.next() else {
                return Ok(Some("Укажите сумму: /ok 198.99".to_owned()));
            };
            let Some(amount) =
                atlas_billing::Money::parse_decimal(sum, atlas_billing::Currency::Rub)
            else {
                return Ok(Some("Сумма не разобралась. Пример: /ok 198.99".to_owned()));
            };

            let found = store
                .order_by_amount(amount, now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("база: {error}"))?;
            let Some(order_id) = found else {
                return Ok(Some(
                    "Открытого счёта на такую сумму нет. Проверьте /pending.".to_owned(),
                ));
            };

            // Номер платежа собирается из суммы и времени: повторное
            // подтверждение того же счёта упрётся в UNIQUE и не продлит
            // подписку дважды.
            let reference = format!("{}-{order_id}", amount.minor());
            let settled = store
                .settle(&order_id, "manual", &reference, amount, "{}", now)
                .map_err(|error| format!("зачисление: {error}"))?;

            Ok(Some(match settled {
                Settled::Extended { expires_at } => format!(
                    "Зачислено. Подписка до {}.",
                    atlas_panel::to_iso8601(expires_at)
                ),
                Settled::AlreadyCounted => "Этот платёж уже был учтён.".to_owned(),
                Settled::OrderAlreadyPaid => "Счёт уже закрыт другим платежом.".to_owned(),
                Settled::Underpaid => "Сумма меньше выставленной — не зачислено.".to_owned(),
                Settled::NoSuchOrder => "Такого заказа нет.".to_owned(),
            }))
        }

        _ => Ok(None),
    }
}

/// Завести человека в панели, если его там ещё нет, и запомнить ссылку.
fn ensure_panel_user(
    config: &Config,
    panel: &Panel,
    store: &mut Store,
    telegram_id: i64,
    expires_at: i64,
) -> Result<String, String> {
    let request = panel
        .create(&NewUser {
            telegram_id,
            expires_at,
            squads: config.squads.clone(),
            device_limit: catalog::DEVICES,
        })
        .map_err(|error| format!("панель: {error}"))?;

    let response = http::send(&request).map_err(|error| format!("панель: {error}"))?;

    // Человек мог остаться в панели от прошлого раза — например, если наша
    // база пересоздавалась. Тогда создание не проходит, и надо просто найти
    // его по имени: оно выводится из номера Telegram и не меняется.
    let body = if response.is_ok() {
        response.body
    } else {
        // Ответ на неудачное создание запоминаем до второй попытки: именно
        // он объясняет причину. Код от поиска не объясняет ничего — 404 там
        // означает обычное «такого пользователя нет», то есть в точности то,
        // ради чего мы и создавали.
        let refused_with = response.status;
        let refusal = excerpt(&response.body);

        let request = panel
            .find(telegram_id)
            .map_err(|error| format!("панель: {error}"))?;
        let found = http::send(&request).map_err(|error| format!("панель: {error}"))?;
        if !found.is_ok() {
            return Err(format!(
                "панель не завела ({refused_with}) и не нашла ({}) пользователя; \
                 адрес {}; ответ на создание: {refusal}",
                found.status, request.url
            ));
        }
        found.body
    };

    let user = panel
        .parse_user(&body)
        .map_err(|error| format!("панель: {error}"))?;

    store
        .link_to_panel(telegram_id, user.id, &user.subscription_url)
        .map_err(|error| format!("база: {error}"))?;

    Ok(user.subscription_url)
}

/// Что показать покупателю после выставления счёта.
fn invoice_text(config: &Config, amount: atlas_billing::Money) -> String {
    let sum = atlas_bot::menu::price_label(amount);

    match (&config.sbp_phone, &config.sbp_name) {
        (Some(phone), Some(name)) => format!(
            "К оплате: <b>{sum}</b>\n\n\
             Переведите по СБП на номер\n<code>{phone}</code>\nПолучатель: {name}\n\n\
             Сумма должна совпасть до копейки — по ней я нахожу ваш платёж.\n\
             Счёт действует 20 минут.",
        ),
        _ => format!(
            "К оплате: <b>{sum}</b>\n\n\
             Приём оплаты ещё настраивается — напишите @GloriaVPNSupport, \
             и подписку выдадут вручную."
        ),
    }
}

/// Текущий момент в секундах эпохи.
///
/// Часы одни на весь бот: то же число уходит в базу, в расчёт сроков и в
/// проверку подписи мини-приложения.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Начало ответа панели — для журнала.
///
/// Панель объясняет отказ в теле, а не в коде: `500` с `A018 Failed to create
/// user` чаще всего означает несуществующий UUID отряда. Печатать одно число
/// значит выбросить объяснение и искать его потом руками.
///
/// Обрезаем по символам, а не по байтам: тело приходит извне, разрез посреди
/// многобайтового символа испортил бы строку.
fn excerpt(body: &[u8]) -> String {
    const LIMIT: usize = 300;

    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    match text.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod excerpt_tests {
    use super::excerpt;

    #[test]
    fn a_short_answer_is_shown_whole() {
        let body = br#"{"message":"Failed to create user","errorCode":"A018"}"#;
        assert_eq!(
            excerpt(body),
            r#"{"message":"Failed to create user","errorCode":"A018"}"#
        );
    }

    #[test]
    fn an_empty_answer_does_not_become_noise() {
        assert_eq!(excerpt(b""), "");
        assert_eq!(excerpt(b"  \n "), "");
    }

    /// Тело приходит извне: разрез посреди многобайтового символа выдал бы
    /// в журнал испорченную строку, а то и панику при делении по байтам.
    #[test]
    fn a_long_answer_is_cut_on_a_character_boundary() {
        let body = "щ".repeat(500);
        let cut = excerpt(body.as_bytes());
        assert!(cut.ends_with('…'));
        assert_eq!(cut.chars().count(), 301);
    }

    /// Панель может ответить и не текстом — например, страницей ошибки от
    /// промежуточного сервера. Журнал от этого не должен ломаться.
    #[test]
    fn bytes_that_are_not_text_do_not_break_anything() {
        assert!(!excerpt(&[0xff, 0xfe, 0x00, 0x41]).is_empty());
    }
}
