//! Админка: те же мини-приложение и подпись Telegram, что у кабинета, но
//! только для владельцев (`GLORIA_ADMINS`).
//!
//! # Почему не секретный адрес и пароль
//!
//! Адрес админки не секрет и секретом быть не обязан. Пускает не он, а
//! подпись Telegram: строку `initData` подписывает токен бота, и подделать
//! её, не зная токена, нельзя. Номер того, кто открыл, берётся из
//! подписанной строки — а не из запроса, где его подставил бы кто угодно.
//! Дальше номер сверяется со списком владельцев.
//!
//! Пароля нет вовсе — значит, его нечем подобрать, негде забыть и неоткуда
//! украсть.
//!
//! # Пути
//!
//! ```text
//! GET  /api/admin/summary                  сводка
//! GET  /api/admin/users                    список людей с их статусом
//! GET  /api/admin/user/<номер>             карточка покупателя
//! POST /api/admin/user/<номер>/extend/<дней>  продлить руками
//! POST /api/admin/message                  написать выбранным людям
//! ```
//!
//! Всё, что меняет состояние, — только `POST`: ссылкой из чата или
//! предзагрузкой браузера оно случаться не должно.

use std::collections::HashMap;

use atlas_store::{Card, Extended, Payment, Summary, UserRow};

use crate::api::{day_month_year, Shared};

/// Что спросили.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    Summary,
    Users,
    Message,
    Card(i64),
    Extend(i64, u32),
    Community(crate::community::AdminRoute),
}

/// Разобрать путь и способ. Чистая функция: всё, что стоит проверить
/// тестом, — здесь, без сети и базы.
///
/// Отказ — готовые код и текст ответа.
pub(crate) fn route(method: &str, path: &str) -> Result<Route, (u16, &'static str)> {
    let Some(rest) = path.strip_prefix("/api/admin/") else {
        return Err((404, r#"{"error":"нет такого пути"}"#));
    };
    let parts: Vec<&str> = rest.split('/').collect();

    if let Some(found) = crate::community::admin_route(parts.as_slice()) {
        let (route, wants) = found?;
        if method != wants {
            return Err((405, r#"{"error":"не тот способ"}"#));
        }
        return Ok(Route::Community(route));
    }

    let (route, wants) = match parts.as_slice() {
        ["summary"] => (Route::Summary, "GET"),
        ["users"] => (Route::Users, "GET"),
        ["message"] => (Route::Message, "POST"),
        ["user", id] => (Route::Card(telegram_id(id)?), "GET"),
        ["user", id, "extend", days] => {
            let days = days
                .parse::<u32>()
                .ok()
                .filter(|days| (1..=atlas_store::MAX_MANUAL_DAYS).contains(days))
                .ok_or((400, r#"{"error":"дней — от 1 до 3650"}"#))?;
            (Route::Extend(telegram_id(id)?, days), "POST")
        }
        _ => return Err((404, r#"{"error":"нет такого пути"}"#)),
    };

    if method != wants {
        return Err((405, r#"{"error":"не тот способ"}"#));
    }
    Ok(route)
}

/// Номер Telegram из пути: только цифры, только положительный.
fn telegram_id(raw: &str) -> Result<i64, (u16, &'static str)> {
    raw.parse::<i64>()
        .ok()
        .filter(|id| *id > 0 && raw.bytes().all(|b| b.is_ascii_digit()))
        .ok_or((400, r#"{"error":"номер Telegram — одни цифры"}"#))
}

/// Ответ админки: код и тело.
pub(crate) fn answer(
    shared: &Shared,
    admin_id: i64,
    route: Route,
    body: &[u8],
    now: i64,
) -> (u16, String) {
    if let Route::Community(route) = route {
        return match crate::community::admin_answer(shared, admin_id, route, body, now) {
            Ok(json) => (200, json.to_string()),
            Err((status, why)) => (status, serde_json::json!({ "error": why }).to_string()),
        };
    }
    if route == Route::Message {
        return match message(shared, admin_id, body) {
            Ok(json) => (200, json.to_string()),
            Err((status, why)) => (status, serde_json::json!({ "error": why }).to_string()),
        };
    }
    match run(shared, admin_id, route, now) {
        Ok(body) => (200, body),
        Err((status, why)) => (status, serde_json::json!({ "error": why }).to_string()),
    }
}

fn run(shared: &Shared, admin_id: i64, route: Route, now: i64) -> Result<String, (u16, String)> {
    let internal = |what: &str, error: &dyn core::fmt::Display| {
        eprintln!("Админка, {what}: {error}");
        (500, "внутренняя ошибка".to_owned())
    };

    match route {
        Route::Summary => {
            let summary = lock(shared)?
                .admin_summary(now)
                .map_err(|error| internal("сводка", &error))?;
            Ok(summary_json(&summary).to_string())
        }

        Route::Users => {
            let rows = lock(shared)?
                .admin_users()
                .map_err(|error| internal("список", &error))?;
            // Панель спрашиваем без замка базы: это поход по сети.
            let connections = connections(&shared.panel);
            let users: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| user_json(row, connections.as_ref(), now))
                .collect();
            Ok(serde_json::json!({
                "users": users,
                "limit": atlas_store::USERS_LIMIT,
                "panel": connections.is_some(),
            })
            .to_string())
        }

        // Разобран выше, в `answer`.
        Route::Message => Err((404, "нет такого пути".to_owned())),

        Route::Card(id) => {
            let card = lock(shared)?
                .admin_card(id)
                .map_err(|error| internal("карточка", &error))?;
            match card {
                Some(card) => Ok(card_json(&card, now).to_string()),
                None => Err((404, "такой в бота не заходил".to_owned())),
            }
        }

        // Разобран выше, в `answer`.
        Route::Community(_) => Err((404, "нет такого пути".to_owned())),

        Route::Extend(id, days) => {
            let extended = lock(shared)?
                .admin_extend(admin_id, id, days, now)
                .map_err(|error| internal("продление", &error))?;
            let Extended::Until(expires_at) = extended else {
                return Err((404, "такой в бота не заходил".to_owned()));
            };
            println!("Админка: {admin_id} продлил {id} на {days} дн.");

            // Человеку — сообщение: тишина после продления читается как «ничего
            // не произошло», и следующим будет вопрос в поддержку. Не дошло —
            // не беда: срок уже записан, и кабинет покажет его сам.
            if let Some(telegram) = shared.telegram.as_ref() {
                let text = format!("✅ Подписка продлена до {}.", day_month_year(expires_at));
                if let Ok(request) = telegram.send_message(id, &text, None) {
                    let _ = crate::http::send(&request);
                }
            }

            Ok(serde_json::json!({ "expiresAt": day_month_year(expires_at) }).to_string())
        }
    }
}

/// Самое длинное сообщение. У Telegram предел 4096 знаков, а экранирование
/// разметки удлиняет текст — оставляем запас.
const MESSAGE_MAX: usize = 3500;

/// Больше получателей за раз не бывает: людей в списке и то меньше.
const RECIPIENTS_MAX: usize = 5000;

/// Написать выбранным людям от имени бота.
///
/// Номера присылает страница, поэтому сообщение уходит лишь тем из них, кто
/// заходил в бота: незнакомым писать нельзя. Текст уходит как есть, без
/// разметки, — что владелец набрал, то человек и прочтёт.
fn message(
    shared: &Shared,
    admin_id: i64,
    body: &[u8],
) -> Result<serde_json::Value, (u16, String)> {
    let draft: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| (400, "нужны поля ids и text".to_owned()))?;
    let text = draft
        .get("text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim();
    if text.is_empty() || text.chars().count() > MESSAGE_MAX {
        return Err((400, format!("текст — от 1 до {MESSAGE_MAX} знаков")));
    }
    let mut ids: Vec<i64> = draft
        .get("ids")
        .and_then(serde_json::Value::as_array)
        .map(|ids| ids.iter().filter_map(serde_json::Value::as_i64).collect())
        .unwrap_or_default();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() || ids.len() > RECIPIENTS_MAX {
        return Err((400, format!("получателей — от 1 до {RECIPIENTS_MAX}")));
    }
    let Some(telegram) = shared.telegram.clone() else {
        return Err((503, "бот не подключён к Telegram".to_owned()));
    };

    let recipients = {
        let mut store = lock(shared)?;
        let known = store.admin_known(&ids).map_err(|error| {
            eprintln!("Админка, получатели: {error}");
            (500, "внутренняя ошибка".to_owned())
        })?;
        if known.is_empty() {
            return Err((400, "никто из выбранных в бота не заходил".to_owned()));
        }
        store
            .admin_log_message(admin_id, text, known.len())
            .map_err(|error| {
                eprintln!("Админка, журнал рассылки: {error}");
                (500, "внутренняя ошибка".to_owned())
            })?;
        known
    };

    let sent_to = recipients.len();
    crate::community::broadcast(telegram, recipients, atlas_tg::escape_html(text));
    println!("Админка: {admin_id} написал {sent_to} людям");
    Ok(serde_json::json!({ "sentTo": sent_to }))
}

/// Сколько людей спрашивать у панели за раз и сколько раз самое большее.
const PANEL_PAGE: u32 = 500;
const PANEL_PAGES: u32 = 10;

/// Кто подключался хоть раз, по данным панели. `None` — панель не ответила:
/// список всё равно покажем, только без этой отметки.
fn connections(panel: &atlas_panel::Panel) -> Option<HashMap<i64, Option<bool>>> {
    let mut seen = HashMap::new();
    for page in 0..PANEL_PAGES {
        let start = page * PANEL_PAGE;
        let request = panel.list_users(start, PANEL_PAGE);
        let response = match crate::http::send(&request) {
            Ok(response) if response.status == 200 => response,
            Ok(response) => {
                eprintln!("Админка, панель: список, код {}", response.status);
                return None;
            }
            Err(error) => {
                eprintln!("Админка, панель: список: {error}");
                return None;
            }
        };
        let parsed = match panel.parse_connections(&response.body) {
            Ok(parsed) => parsed,
            Err(error) => {
                eprintln!("Админка, панель: список не разобран: {error}");
                return None;
            }
        };
        for connection in &parsed.connections {
            seen.insert(connection.telegram_id, connection.connected);
        }
        let fetched = u64::from(start) + parsed.received as u64;
        if parsed.received < PANEL_PAGE as usize
            || parsed.total.is_some_and(|total| fetched >= total)
        {
            break;
        }
    }
    Some(seen)
}

/// Положение человека одним словом — для фильтров и значков на странице.
fn user_status(row: &UserRow, now: i64) -> &'static str {
    let active = atlas_billing::subscription::is_active(row.expires_at, now);
    match (row.expires_at, active, row.has_paid) {
        (None, _, _) => "new",
        (Some(_), true, true) => "paid",
        (Some(_), true, false) => "trial",
        (Some(_), false, true) => "lapsed",
        (Some(_), false, false) => "trial_over",
    }
}

fn user_json(
    row: &UserRow,
    connections: Option<&HashMap<i64, Option<bool>>>,
    now: i64,
) -> serde_json::Value {
    // Нет в панели вовсе — значит, и подключаться было не к чему.
    let connected =
        connections.map(|seen| seen.get(&row.telegram_id).copied().unwrap_or(Some(false)));
    serde_json::json!({
        "id": row.telegram_id,
        "panelId": row.panel_id,
        "name": row.name,
        "since": day_month_year(row.created_at),
        "sinceTs": row.created_at,
        "invitedBy": row.invited_by,
        "status": user_status(row, now),
        "until": row.expires_at.map(day_month_year),
        "daysLeft": atlas_billing::subscription::days_left(row.expires_at, now),
        "connected": connected.flatten(),
    })
}

fn lock(shared: &Shared) -> Result<std::sync::MutexGuard<'_, atlas_store::Store>, (u16, String)> {
    shared
        .store
        .lock()
        .map_err(|_| (500, "замок базы испорчен".to_owned()))
}

fn payment_json(payment: &Payment) -> serde_json::Value {
    serde_json::json!({
        "userId": payment.telegram_id,
        "plan": payment.plan,
        "amount": payment.amount,
        "provider": payment.provider,
        "at": day_month_year(payment.at),
    })
}

fn summary_json(summary: &Summary) -> serde_json::Value {
    serde_json::json!({
        "users": summary.users,
        "activePaid": summary.active_paid,
        "activeTrial": summary.active_trial,
        "expired": summary.expired,
        "never": summary.never,
        "revenueToday": summary.revenue_today,
        "revenueMonth": summary.revenue_month,
        "paymentsToday": summary.payments_today,
        "paymentsMonth": summary.payments_month,
        "recent": summary.recent.iter().map(payment_json).collect::<Vec<_>>(),
    })
}

fn card_json(card: &Card, now: i64) -> serde_json::Value {
    let subscriber = &card.subscriber;
    let active = atlas_billing::subscription::is_active(subscriber.expires_at, now);
    let status = match (active, subscriber.has_paid, subscriber.expires_at) {
        (true, true, _) => "active",
        (true, false, _) => "trial",
        (false, _, Some(_)) => "expired",
        (false, _, None) => "never",
    };

    serde_json::json!({
        "userId": subscriber.telegram_id,
        "status": status,
        "expiresAt": subscriber.expires_at.map(day_month_year),
        "daysLeft": atlas_billing::subscription::days_left(subscriber.expires_at, now),
        "hasPaid": subscriber.has_paid,
        "tier": subscriber.tier,
        "trialGranted": subscriber.trial_granted_at.map(day_month_year),
        "since": day_month_year(card.created_at),
        "invitedBy": card.invited_by,
        "panelPlan": card.panel_plan,
        "inPanel": subscriber.panel_id.is_some(),
        "subscriptionUrl": subscriber.subscription_url,
        "payments": card.payments.iter().map(payment_json).collect::<Vec<_>>(),
        "log": card.log.iter().map(|entry| serde_json::json!({
            "adminId": entry.admin_id,
            "action": entry.action,
            "detail": entry.detail,
            "at": day_month_year(entry.at),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::{route, user_status, Route};
    use atlas_store::UserRow;

    /// Пять положений человека — по сроку и оплатам.
    #[test]
    fn a_status_is_read_from_the_term_and_payments() {
        const NOW: i64 = 1_760_000_000;
        let row = |expires_at: Option<i64>, has_paid: bool| UserRow {
            telegram_id: 1,
            panel_id: None,
            name: None,
            created_at: NOW - 86_400,
            invited_by: None,
            expires_at,
            trial_granted_at: None,
            has_paid,
        };
        assert_eq!(user_status(&row(None, false), NOW), "new");
        assert_eq!(user_status(&row(Some(NOW + 60), false), NOW), "trial");
        assert_eq!(user_status(&row(Some(NOW + 60), true), NOW), "paid");
        assert_eq!(user_status(&row(Some(NOW - 60), false), NOW), "trial_over");
        assert_eq!(user_status(&row(Some(NOW - 60), true), NOW), "lapsed");
    }

    #[test]
    fn the_paths_are_read() {
        assert_eq!(route("GET", "/api/admin/summary"), Ok(Route::Summary));
        assert_eq!(route("GET", "/api/admin/users"), Ok(Route::Users));
        assert_eq!(route("POST", "/api/admin/message"), Ok(Route::Message));
        assert!(matches!(route("GET", "/api/admin/message"), Err((405, _))));
        assert_eq!(route("GET", "/api/admin/user/42"), Ok(Route::Card(42)));
        assert_eq!(
            route("POST", "/api/admin/user/42/extend/30"),
            Ok(Route::Extend(42, 30))
        );
    }

    /// Меняющее состояние — только POST: ссылкой из чата или предзагрузкой
    /// браузера продление случаться не должно.
    #[test]
    fn a_change_needs_post_and_a_look_needs_get() {
        assert!(matches!(
            route("GET", "/api/admin/user/42/extend/30"),
            Err((405, _))
        ));
        assert!(matches!(route("POST", "/api/admin/summary"), Err((405, _))));
    }

    /// Лишний ноль в поле «дней» не дарит подписку на век.
    #[test]
    fn absurd_days_are_refused() {
        for days in ["0", "3651", "-5", "30.5", "abc", ""] {
            assert!(
                matches!(
                    route("POST", &format!("/api/admin/user/42/extend/{days}")),
                    Err((400 | 404, _))
                ),
                "принято «{days}»"
            );
        }
    }

    #[test]
    fn a_number_is_only_digits() {
        for id in ["-1", "0", "+42", "42abc", "4 2", "99999999999999999999"] {
            assert!(
                route("GET", &format!("/api/admin/user/{id}")).is_err(),
                "принят номер «{id}»"
            );
        }
    }

    #[test]
    fn unknown_paths_are_not_found() {
        for path in [
            "/api/admin/",
            "/api/admin/user",
            "/api/admin/user/42/reissue",
            "/api/admin/user/42/delete",
        ] {
            assert!(matches!(route("GET", path), Err((404, _))), "{path}");
        }
    }
}
