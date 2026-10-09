//! Новости и турниры приглашений: фоновые задачи бота, пути кабинета и
//! админки.
//!
//! # Пути кабинета
//!
//! ```text
//! GET  /api/news               лента
//! POST /api/news/seen          лента открыта — непрочитанных больше нет
//! POST /api/news/mute/<0|1>    новости сообщением в бот: включить или выключить
//! GET  /api/tournament         идущий турнир, таблица и своё место
//! ```
//!
//! # Пути админки
//!
//! ```text
//! POST /api/admin/news                          опубликовать: {title, body, push}
//! GET  /api/admin/tournament                    турнир целиком, без сокращения имён
//! POST /api/admin/tournament/start/<дней>/<порог>  начать
//! POST /api/admin/tournament/finish             подвести итоги сейчас
//! ```

use atlas_store::{prize_days, Prize, Standing, Started, Store, Tournament, PRIZE_PLACES};
use atlas_tg::{escape_html, Telegram};

use crate::api::{day_month_year, Shared};
use crate::http;
use atlas_panel::Panel;

/// Сколько приглашённых проверять в панели за круг. Круг идёт раз в
/// полминуты; больше — лишняя нагрузка на панель, меньше — таблица
/// отстаёт от жизни.
const CHECK_PER_ROUND: i64 = 10;

/// Сколько новостей показывать в ленте.
const NEWS_IN_FEED: i64 = 30;

/// Сколько строк таблицы видят участники: призовые места и ещё немного.
const TABLE_ROWS: usize = 20;

// --- фоновые задачи -----------------------------------------------------------

/// Один круг: проверить, кто из приглашённых подключился, и подвести итоги
/// турнира, если срок вышел.
pub(crate) fn tick(panel: &Panel, telegram: &Telegram, store: &mut Store, now: i64) {
    check_connections(panel, store, now);

    match store.due_tournament(now) {
        Ok(Some(id)) => finish(store, Some(telegram), id, now),
        Ok(None) => {}
        Err(error) => eprintln!("Турнир: {error}"),
    }
}

/// Подключился ли приглашённый: панель видит его трафик.
fn check_connections(panel: &Panel, store: &mut Store, now: i64) {
    let pending = match store.unconfirmed_invitees(now, CHECK_PER_ROUND) {
        Ok(pending) => pending,
        Err(error) => {
            eprintln!("Турнир, приглашённые: {error}");
            return;
        }
    };

    for telegram_id in pending {
        let Ok(request) = panel.find(telegram_id) else {
            continue;
        };
        let Ok(response) = http::send(&request) else {
            continue;
        };
        if !response.is_ok() {
            continue;
        }
        let Ok(user) = panel.parse_user(&response.body) else {
            continue;
        };
        if user.used_traffic > 0 {
            if let Err(error) = store.mark_connected(telegram_id, now) {
                eprintln!("Турнир, подключение {telegram_id}: {error}");
            }
        }
    }
}

/// Подвести итоги: выдать призы, написать победителям, опубликовать итоги в
/// ленте.
pub(crate) fn finish(store: &mut Store, telegram: Option<&Telegram>, id: i64, now: i64) {
    let prizes = match store.finish_tournament(id, now) {
        Ok(Some(prizes)) => prizes,
        Ok(None) => return,
        Err(error) => {
            eprintln!("Турнир {id}, итоги: {error}");
            return;
        }
    };
    println!("Турнир {id} завершён, призов: {}", prizes.len());

    let names: Vec<(i64, Option<String>)> = store
        .standings(id)
        .map(|table| table.into_iter().map(|s| (s.telegram_id, s.name)).collect())
        .unwrap_or_default();
    let name_of = |telegram_id: i64| {
        names
            .iter()
            .find(|(id, _)| *id == telegram_id)
            .and_then(|(_, name)| name.clone())
    };

    if let Some(telegram) = telegram {
        for prize in &prizes {
            let text = format!(
                "🏆 Турнир приглашений завершён — у вас {} место ({} {}).\n\n\
                 Приз: {} дней подписки. Подписка продлена до {}.",
                prize.place,
                prize.score,
                atlas_bot::flow::plural(
                    prize.score,
                    "приглашённый",
                    "приглашённых",
                    "приглашённых"
                ),
                prize.days,
                day_month_year(prize.expires_at),
            );
            send(telegram, prize.telegram_id, &text);
        }
    }

    let body = if prizes.is_empty() {
        "Призовые места в этот раз никто не занял: нужно было набрать порог. \
         Следующий турнир — скоро."
            .to_owned()
    } else {
        let lines: Vec<String> = prizes
            .iter()
            .map(|prize| {
                format!(
                    "{} место — {} · {} · {} дней подписки",
                    prize.place,
                    mask(name_of(prize.telegram_id).as_deref()),
                    prize.score,
                    prize.days
                )
            })
            .collect();
        format!(
            "{}\n\nСпасибо всем участникам! Следующий турнир — скоро.",
            lines.join("\n")
        )
    };
    if let Err(error) = store.publish_news(0, "Итоги турнира приглашений", &body, false, now)
    {
        eprintln!("Турнир {id}, новость: {error}");
    }
}

/// Отправить одно сообщение. Ошибка — только в журнал: человек мог
/// заблокировать бота.
fn send(telegram: &Telegram, chat: i64, text: &str) {
    match telegram.send_message(chat, text, None) {
        Ok(request) => {
            if let Err(error) = http::send(&request) {
                eprintln!(
                    "Сообщение для {chat}: {}",
                    telegram.redact(&error.to_string())
                );
            }
        }
        Err(error) => eprintln!("Сообщение для {chat}: {error}"),
    }
}

/// Разослать новость в фоне. Telegram ограничивает рассылку примерно 30
/// сообщениями в секунду; держимся с запасом.
fn broadcast(telegram: Telegram, recipients: Vec<i64>, text: String) {
    std::thread::spawn(move || {
        for chat in recipients {
            send(&telegram, chat, &text);
            std::thread::sleep(std::time::Duration::from_millis(60));
        }
        println!("Рассылка новости закончена");
    });
}

// --- оформление ---------------------------------------------------------------

/// Имя для чужих глаз: две первые буквы и звёздочки. Полное имя видит
/// только сам человек.
#[must_use]
pub(crate) fn mask(name: Option<&str>) -> String {
    let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) else {
        return "Участник".to_owned();
    };
    let head: String = name.chars().take(2).collect();
    format!("{head}***")
}

fn prizes_json() -> serde_json::Value {
    serde_json::json!([
        { "places": "1", "days": prize_days(1) },
        { "places": "2–3", "days": prize_days(2) },
        { "places": format!("4–{PRIZE_PLACES}"), "days": prize_days(4) },
    ])
}

fn tournament_json(t: &Tournament) -> serde_json::Value {
    serde_json::json!({
        "id": t.id,
        "startsAt": t.starts_at,
        "endsAt": t.ends_at,
        "endsLabel": day_month_year(t.ends_at),
        "minScore": t.min_score,
    })
}

/// Таблица для участника: имена сокращены, своя строка помечена.
fn table_json(table: &[Standing], me: i64, min_score: i32) -> serde_json::Value {
    serde_json::Value::Array(
        table
            .iter()
            .take(TABLE_ROWS)
            .map(|row| {
                serde_json::json!({
                    "place": row.place,
                    "name": if row.telegram_id == me {
                        "Вы".to_owned()
                    } else {
                        mask(row.name.as_deref())
                    },
                    "score": row.score,
                    "me": row.telegram_id == me,
                    "qualified": row.score >= i64::from(min_score),
                })
            })
            .collect(),
    )
}

// --- пути кабинета ------------------------------------------------------------

/// Что спросил кабинет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    News,
    NewsSeen,
    Mute(bool),
    Tournament,
}

/// Разобрать путь кабинета. `None` — это не наш путь.
pub(crate) fn route(method: &str, path: &str) -> Option<Result<Route, (u16, &'static str)>> {
    let (route, wants) = match path {
        "/api/news" => (Route::News, "GET"),
        "/api/news/seen" => (Route::NewsSeen, "POST"),
        "/api/news/mute/1" => (Route::Mute(true), "POST"),
        "/api/news/mute/0" => (Route::Mute(false), "POST"),
        "/api/tournament" => (Route::Tournament, "GET"),
        _ if path.starts_with("/api/news/") => {
            return Some(Err((404, r#"{"error":"нет такого пути"}"#)))
        }
        _ => return None,
    };
    Some(if method == wants {
        Ok(route)
    } else {
        Err((405, r#"{"error":"не тот способ"}"#))
    })
}

/// Ответ кабинету: код и тело.
pub(crate) fn answer(shared: &Shared, me: i64, route: Route, now: i64) -> (u16, String) {
    let Ok(mut store) = shared.store.lock() else {
        return (500, r#"{"error":"замок базы испорчен"}"#.to_owned());
    };
    let result = match route {
        Route::News => store.latest_news(NEWS_IN_FEED).map(|news| {
            serde_json::json!({
                "news": news.iter().map(|n| serde_json::json!({
                    "id": n.id,
                    "title": n.title,
                    "body": n.body,
                    "date": day_month_year(n.created_at),
                })).collect::<Vec<_>>(),
            })
        }),
        Route::NewsSeen => store
            .mark_news_seen(me, now)
            .map(|()| serde_json::json!({ "ok": true })),
        Route::Mute(muted) => store
            .set_news_muted(me, muted)
            .map(|()| serde_json::json!({ "ok": true, "muted": muted })),
        Route::Tournament => tournament_for(&mut store, me, now),
    };
    match result {
        Ok(body) => (200, body.to_string()),
        Err(error) => {
            eprintln!("Кабинет, новости/турнир для {me}: {error}");
            (500, r#"{"error":"внутренняя ошибка"}"#.to_owned())
        }
    }
}

fn tournament_for(
    store: &mut Store,
    me: i64,
    now: i64,
) -> Result<serde_json::Value, atlas_store::Error> {
    if let Some(t) = store.open_tournament()? {
        let table = store.standings(t.id)?;
        let mine = table.iter().find(|row| row.telegram_id == me);
        return Ok(serde_json::json!({
            "active": tournament_json(&t),
            "secondsLeft": (t.ends_at - now).max(0),
            "prizes": prizes_json(),
            "table": table_json(&table, me, t.min_score),
            "me": {
                "place": mine.map(|row| row.place),
                "score": mine.map_or(0, |row| row.score),
            },
            "participants": table.len(),
        }));
    }

    // Турнира нет — итоги прошлого, если он был.
    let last = match store.last_finished_tournament()? {
        Some(t) => {
            let prizes = store.prizes_of(t.id)?;
            let table = store.standings(t.id)?;
            let name_of = |id: i64| {
                table
                    .iter()
                    .find(|row| row.telegram_id == id)
                    .and_then(|row| row.name.clone())
            };
            Some(serde_json::json!({
                "endsLabel": day_month_year(t.ends_at),
                "winners": prizes.iter().map(|p: &Prize| serde_json::json!({
                    "place": p.place,
                    "name": if p.telegram_id == me { "Вы".to_owned() } else { mask(name_of(p.telegram_id).as_deref()) },
                    "score": p.score,
                    "days": p.days,
                    "me": p.telegram_id == me,
                })).collect::<Vec<_>>(),
            }))
        }
        None => None,
    };
    Ok(serde_json::json!({ "active": null, "last": last, "prizes": prizes_json() }))
}

// --- пути админки -------------------------------------------------------------

/// Что спросила админка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminRoute {
    PublishNews,
    Tournament,
    Start { days: u32, min_score: i32 },
    Finish,
}

/// Отказ: код и готовое тело ответа.
type Refusal = (u16, &'static str);

/// Разобрать путь админки, если он наш. Части пути — после `/api/admin/`.
pub(crate) fn admin_route(parts: &[&str]) -> Option<Result<(AdminRoute, &'static str), Refusal>> {
    Some(Ok(match parts {
        ["news"] => (AdminRoute::PublishNews, "POST"),
        ["tournament"] => (AdminRoute::Tournament, "GET"),
        ["tournament", "finish"] => (AdminRoute::Finish, "POST"),
        ["tournament", "start", days, min] => {
            let days = days.parse::<u32>().ok().filter(|d| (1..=60).contains(d));
            let min = min.parse::<i32>().ok().filter(|m| (1..=1000).contains(m));
            let (Some(days), Some(min_score)) = (days, min) else {
                return Some(Err((400, r#"{"error":"дней — от 1 до 60, порог — от 1"}"#)));
            };
            (AdminRoute::Start { days, min_score }, "POST")
        }
        _ => return None,
    }))
}

/// Ответ админке.
pub(crate) fn admin_answer(
    shared: &Shared,
    admin_id: i64,
    route: AdminRoute,
    body: &[u8],
    now: i64,
) -> Result<serde_json::Value, (u16, String)> {
    let internal = |what: &str, error: &dyn core::fmt::Display| {
        eprintln!("Админка, {what}: {error}");
        (500, "внутренняя ошибка".to_owned())
    };
    let mut store = shared
        .store
        .lock()
        .map_err(|_| (500, "замок базы испорчен".to_owned()))?;

    match route {
        AdminRoute::PublishNews => {
            let draft: serde_json::Value = serde_json::from_slice(body)
                .map_err(|_| (400, "нужны поля title и body".to_owned()))?;
            let field = |name: &str| draft.get(name).and_then(serde_json::Value::as_str);
            let title = field("title").unwrap_or("").trim();
            let text = field("body").unwrap_or("").trim();
            let push = draft
                .get("push")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if title.is_empty() || title.chars().count() > 120 {
                return Err((400, "заголовок — от 1 до 120 знаков".to_owned()));
            }
            if text.is_empty() || text.chars().count() > 2000 {
                return Err((400, "текст — от 1 до 2000 знаков".to_owned()));
            }
            let id = store
                .publish_news(admin_id, title, text, push, now)
                .map_err(|error| internal("новость", &error))?;
            let mut sent_to = 0;
            if push {
                if let Some(telegram) = shared.telegram.clone() {
                    let recipients = store
                        .news_recipients()
                        .map_err(|error| internal("получатели", &error))?;
                    sent_to = recipients.len();
                    let message = format!(
                        "📰 <b>{}</b>\n\n{}\n\n<i>Выключить такие сообщения можно в кабинете, в настройках.</i>",
                        escape_html(title),
                        escape_html(text)
                    );
                    broadcast(telegram, recipients, message);
                }
            }
            println!("Админка: {admin_id} опубликовал новость {id}, рассылка: {sent_to}");
            Ok(serde_json::json!({ "id": id, "sentTo": sent_to }))
        }

        AdminRoute::Tournament => {
            let open = store
                .open_tournament()
                .map_err(|error| internal("турнир", &error))?;
            let Some(t) = open else {
                return Ok(serde_json::json!({ "active": null }));
            };
            let table = store
                .standings(t.id)
                .map_err(|error| internal("таблица", &error))?;
            Ok(serde_json::json!({
                "active": tournament_json(&t),
                "table": table.iter().map(|row| serde_json::json!({
                    "place": row.place,
                    "userId": row.telegram_id,
                    "name": row.name,
                    "score": row.score,
                })).collect::<Vec<_>>(),
            }))
        }

        AdminRoute::Start { days, min_score } => {
            match store
                .start_tournament(admin_id, days, min_score, now)
                .map_err(|error| internal("начало турнира", &error))?
            {
                Started::AlreadyRunning => Err((409, "турнир уже идёт".to_owned())),
                Started::Started(id) => {
                    let ends = now + i64::from(days) * 24 * 60 * 60;
                    let body = format!(
                        "Приглашайте друзей по своей ссылке из вкладки «Турнир» — до {}.\n\n\
                         Засчитывается друг, который пришёл по ссылке и подключился к VPN \
                         через приложение. Призы: 1 место — 3 месяца подписки, 2–3 — по \
                         2 месяца, 4–10 — по месяцу. Чтобы попасть в призы, нужно привести \
                         не меньше {min_score}.",
                        day_month_year(ends)
                    );
                    if let Err(error) = store.publish_news(
                        admin_id,
                        "Начался турнир приглашений",
                        &body,
                        false,
                        now,
                    ) {
                        eprintln!("Турнир {id}, новость: {error}");
                    }
                    println!("Админка: {admin_id} начал турнир {id} на {days} дн.");
                    Ok(serde_json::json!({ "id": id }))
                }
            }
        }

        AdminRoute::Finish => {
            let open = store
                .open_tournament()
                .map_err(|error| internal("турнир", &error))?;
            let Some(t) = open else {
                return Err((404, "турнир не идёт".to_owned()));
            };
            finish(&mut store, shared.telegram.as_ref(), t.id, now);
            let prizes = store
                .prizes_of(t.id)
                .map_err(|error| internal("призы", &error))?;
            println!("Админка: {admin_id} завершил турнир {}", t.id);
            Ok(serde_json::json!({ "prizes": prizes.len() }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{admin_route, mask, route, AdminRoute, Route};

    #[test]
    fn names_are_masked() {
        assert_eq!(mask(Some("Алексей")), "Ал***");
        assert_eq!(mask(Some("  Я ")), "Я***");
        assert_eq!(mask(None), "Участник");
        assert_eq!(mask(Some("  ")), "Участник");
    }

    #[test]
    fn cabinet_paths_are_read() {
        assert_eq!(route("GET", "/api/news"), Some(Ok(Route::News)));
        assert_eq!(route("POST", "/api/news/seen"), Some(Ok(Route::NewsSeen)));
        assert_eq!(
            route("POST", "/api/news/mute/1"),
            Some(Ok(Route::Mute(true)))
        );
        assert_eq!(route("GET", "/api/tournament"), Some(Ok(Route::Tournament)));
        assert!(matches!(
            route("GET", "/api/news/seen"),
            Some(Err((405, _)))
        ));
        assert!(matches!(
            route("POST", "/api/news/mute/2"),
            Some(Err((404, _)))
        ));
        assert_eq!(route("GET", "/api/me"), None);
    }

    #[test]
    fn admin_paths_are_read() {
        assert_eq!(
            admin_route(&["tournament", "start", "14", "3"]),
            Some(Ok((
                AdminRoute::Start {
                    days: 14,
                    min_score: 3
                },
                "POST"
            )))
        );
        assert!(matches!(
            admin_route(&["tournament", "start", "0", "3"]),
            Some(Err((400, _)))
        ));
        assert!(matches!(
            admin_route(&["tournament", "start", "14", "0"]),
            Some(Err((400, _)))
        ));
        assert_eq!(admin_route(&["users"]), None);
    }
}
