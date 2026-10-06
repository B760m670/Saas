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
//! GET  /api/admin/user/<номер>             карточка покупателя
//! POST /api/admin/user/<номер>/extend/<дней>  продлить руками
//! ```
//!
//! Всё, что меняет состояние, — только `POST`: ссылкой из чата или
//! предзагрузкой браузера оно случаться не должно.

use atlas_store::{Card, Extended, Payment, Summary};

use crate::api::{day_month_year, Shared};

/// Что спросили.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    Summary,
    Card(i64),
    Extend(i64, u32),
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

    let (route, wants) = match parts.as_slice() {
        ["summary"] => (Route::Summary, "GET"),
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
pub(crate) fn answer(shared: &Shared, admin_id: i64, route: Route, now: i64) -> (u16, String) {
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

        Route::Card(id) => {
            let card = lock(shared)?
                .admin_card(id)
                .map_err(|error| internal("карточка", &error))?;
            match card {
                Some(card) => Ok(card_json(&card, now).to_string()),
                None => Err((404, "такой в бота не заходил".to_owned())),
            }
        }

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
    use super::{route, Route};

    #[test]
    fn the_paths_are_read() {
        assert_eq!(route("GET", "/api/admin/summary"), Ok(Route::Summary));
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
            "/api/admin/users",
            "/api/admin/user/42/reissue",
            "/api/admin/user/42/delete",
        ] {
            assert!(matches!(route("GET", path), Err((404, _))), "{path}");
        }
    }
}
