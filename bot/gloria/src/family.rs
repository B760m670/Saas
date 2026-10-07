//! Семья в кабинете: пригласить близкого, отключить его и показать, кто
//! подключён.
//!
//! # Пути
//!
//! ```text
//! POST /api/family/invite           новое приглашение — ссылка в бота
//! POST /api/family/remove/<номер>   отключить гостя
//! ```
//!
//! Оба меняют состояние, поэтому только `POST`. Кто спрашивает, берётся из
//! подписи Telegram, а не из пути: отключить можно лишь своего гостя, и
//! проверяет это база (`remove_guest` ищет гостя *этого* владельца).

use std::io::Read;

use atlas_bot::catalog::{self, Tier};
use atlas_store::{Invited, Subscriber};

use crate::api::{day_month_year, Shared};

/// Что спросили.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    Invite,
    Remove(i64),
}

/// Разобрать путь. `None` — это не путь семьи.
pub(crate) fn route(path: &str) -> Option<Result<Route, (u16, &'static str)>> {
    let rest = path.strip_prefix("/api/family/")?;
    Some(match rest.split('/').collect::<Vec<_>>().as_slice() {
        ["invite"] => Ok(Route::Invite),
        // Число сверяется с исходной строкой: `+42` и `042` разбираются в
        // то же число, но номером не являются.
        ["remove", id] => id
            .parse::<i64>()
            .ok()
            .filter(|number| *number > 0 && number.to_string() == *id)
            .map(Route::Remove)
            .ok_or((400, r#"{"error":"номер Telegram — одни цифры"}"#)),
        _ => Err((404, r#"{"error":"нет такого пути"}"#)),
    })
}

/// Выполнить и вернуть код и тело ответа.
pub(crate) fn answer(shared: &Shared, owner_id: i64, route: Route, now: i64) -> (u16, String) {
    let internal = |what: &str, error: &dyn core::fmt::Display| {
        eprintln!("Семья, {what} для {owner_id}: {error}");
        (500, r#"{"error":"внутренняя ошибка"}"#.to_owned())
    };
    let Ok(mut store) = shared.store.lock() else {
        return (500, r#"{"error":"замок базы испорчен"}"#.to_owned());
    };

    match route {
        Route::Invite => {
            // Без имени бота ссылку не построить, а выдуманная вела бы в
            // никуда — её бы разослали родным.
            let Some(bot) = shared.bot_username.as_deref() else {
                return (503, r#"{"error":"имя бота не задано"}"#.to_owned());
            };
            let code = match invite_code() {
                Ok(code) => code,
                Err(error) => return internal("код", &error),
            };
            match store.create_invite(owner_id, &code, now) {
                Ok(Invited::Created) => (
                    200,
                    serde_json::json!({ "link": format!("https://t.me/{bot}?start=fam_{code}") })
                        .to_string(),
                ),
                Ok(Invited::NoSlots) => (409, r#"{"error":"все места заняты"}"#.to_owned()),
                Ok(Invited::NotEligible) => (
                    409,
                    r#"{"error":"приглашать можно с тарифом «Личный» или «Семья»"}"#.to_owned(),
                ),
                Err(error) => internal("приглашение", &error),
            }
        }

        Route::Remove(guest_id) => match store.remove_guest(owner_id, guest_id, now) {
            Ok(true) => {
                drop(store);
                println!("Семья: {owner_id} отключил гостя {guest_id}");
                if let Some(telegram) = shared.telegram.as_ref() {
                    let text = "Владелец семейной подписки отключил вас от неё. \
                                Telegram продолжит работать бесплатно, а VPN целиком \
                                можно вернуть своей подпиской.";
                    if let Ok(request) = telegram.send_message(guest_id, text, None) {
                        let _ = crate::http::send(&request);
                    }
                }
                (200, r#"{"ok":true}"#.to_owned())
            }
            Ok(false) => (404, r#"{"error":"это не ваш гость"}"#.to_owned()),
            Err(error) => internal("отключение", &error),
        },
    }
}

/// Случайный код приглашения: 20 букв и цифр, около 119 бит.
///
/// Из `/dev/urandom` — тот же источник, что у ядра для ключей. Байты не
/// берутся по модулю целиком: 256 на 62 не делится, и первые буквы
/// выпадали бы чаще. Байты от 248 отбрасываются — 248 делится на 62 нацело.
fn invite_code() -> std::io::Result<String> {
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut source = std::fs::File::open("/dev/urandom")?;
    let mut code = String::with_capacity(20);
    let mut buffer = [0_u8; 64];
    while code.len() < 20 {
        source.read_exact(&mut buffer)?;
        for byte in buffer {
            if byte >= 248 || code.len() >= 20 {
                continue;
            }
            if let Some(letter) = ALPHABET.get(usize::from(byte % 62)) {
                code.push(char::from(*letter));
            }
        }
    }
    Ok(code)
}

/// Сколько устройств у человека сейчас. То же правило, что у очереди в
/// панель (`panel_plan`), — здесь оно для показа.
pub(crate) fn device_limit(subscriber: &Subscriber, active: bool) -> u8 {
    if !active {
        return catalog::TRIAL_DEVICES;
    }
    if subscriber.owner_id.is_some() {
        return catalog::GUEST_DEVICES;
    }
    match subscriber.tier.as_deref().and_then(Tier::parse) {
        Some(tier) => tier.devices(),
        None if subscriber.has_paid => catalog::DEVICES,
        None => catalog::TRIAL_DEVICES,
    }
}

/// Сколько трафика осталось у человека, по панели. `None` — потолка нет
/// или панель не ответила.
pub(crate) fn traffic_left(shared: &Shared, telegram_id: i64) -> Option<u64> {
    let request = shared.panel.find(telegram_id).ok()?;
    let response = crate::http::send(&request).ok()?;
    if !response.is_ok() {
        return None;
    }
    shared.panel.parse_user(&response.body).ok()?.traffic_left()
}

/// Раздел «Семья» для кабинета: места, гости, их расход.
pub(crate) fn section(shared: &Shared, subscriber: &Subscriber, active: bool) -> serde_json::Value {
    let tier = subscriber.tier.as_deref().and_then(Tier::parse);
    let slots = if active && subscriber.owner_id.is_none() {
        tier.map_or(0, Tier::guests)
    } else {
        0
    };

    let guests = shared
        .store
        .lock()
        .ok()
        .and_then(|mut store| store.guests_of(subscriber.telegram_id).ok())
        .unwrap_or_default();

    let guests: Vec<_> = guests
        .iter()
        .map(|guest| {
            // Расход гостя — из панели: у неё эти байты и живут. Не ответила —
            // показываем гостя без цифры, а не ноль: ноль был бы неправдой.
            let left = traffic_left(shared, guest.telegram_id);
            serde_json::json!({
                "id": guest.telegram_id,
                "since": day_month_year(guest.since),
                "left": left.map(atlas_bot::gigabytes),
            })
        })
        .collect();

    serde_json::json!({
        "slots": slots,
        "guests": guests,
        "canInvite": slots > 0 && guests.len() < usize::from(slots),
        "guestTotal": atlas_bot::gigabytes(catalog::GUEST_BYTES),
        "ownerId": subscriber.owner_id,
    })
}

#[cfg(test)]
mod tests {
    use super::{invite_code, route, Route};

    #[test]
    fn the_paths_are_read() {
        assert_eq!(route("/api/family/invite"), Some(Ok(Route::Invite)));
        assert_eq!(route("/api/family/remove/42"), Some(Ok(Route::Remove(42))));
        assert_eq!(route("/api/me"), None);
    }

    #[test]
    fn a_guest_number_is_only_digits() {
        for id in ["-1", "0", "+42", "042", "42abc", ""] {
            assert!(
                matches!(route(&format!("/api/family/remove/{id}")), Some(Err(_))),
                "принят номер «{id}»"
            );
        }
        assert!(matches!(route("/api/family/"), Some(Err((404, _)))));
    }

    /// Код обязан пройти проверку базы (`^[A-Za-z0-9]{16,32}$`) и разбор
    /// ссылки ботом — иначе приглашение не принять.
    #[test]
    fn an_invite_code_fits_the_link_and_the_database() {
        let Ok(first) = invite_code() else {
            return;
        };
        assert_eq!(first.len(), 20);
        assert!(first.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_eq!(
            atlas_bot::parse_family_invite(&format!("/start fam_{first}")),
            Some(first.clone())
        );
        assert_ne!(invite_code().ok(), Some(first));
    }
}
