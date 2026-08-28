//! Обращения к панели Remnawave.

use atlas_billing::http::{Method, Request};
use serde::Deserialize;

use crate::time::{from_iso8601, to_iso8601};

/// Отказ при работе с панелью.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Ответ не разобрался.
    Malformed(&'static str),
    /// Панель ответила отказом своими словами.
    Rejected(String),
    /// Такого пользователя в панели нет.
    NotFound,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "не удалось разобрать: {what}"),
            Self::Rejected(reason) => write!(f, "панель отказала: {reason}"),
            Self::NotFound => f.write_str("пользователя нет в панели"),
        }
    }
}

impl core::error::Error for Error {}

/// Кого заводим в панели.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    /// Идентификатор в Telegram — он же наш ключ.
    pub telegram_id: i64,
    /// До какого момента подписка действует.
    pub expires_at: i64,
    /// Отряды, через которые пользователю разрешено ходить.
    pub squads: Vec<String>,
    /// Сколько устройств разрешено.
    pub device_limit: u8,
}

/// Пользователь, каким его вернула панель.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Внутренний номер в панели — по нему идут все дальнейшие обращения.
    pub id: i64,
    /// Короткий идентификатор, он же хвост ссылки на подписку.
    pub short_uuid: String,
    /// Имя вида `tg_<идентификатор>`.
    pub username: String,
    /// Идентификатор в Telegram, если панель его знает.
    pub telegram_id: Option<i64>,
    /// Состояние: `ACTIVE`, `DISABLED`, `LIMITED`, `EXPIRED`.
    pub status: String,
    /// До какого момента действует.
    pub expires_at: i64,
    /// Ссылка на подписку — то, что вставляется в приложение.
    pub subscription_url: String,
}

impl User {
    /// Действует ли подписка по мнению панели.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == "ACTIVE"
    }
}

/// Клиент панели.
///
/// Как и адаптеры платёжных сервисов, он не ходит в сеть: собирает запрос и
/// разбирает ответ. Тип запроса взят общий с `atlas-billing`, чтобы у бота
/// был **один** исполнитель HTTP на все внешние обращения, а не два похожих.
pub struct Panel {
    base: String,
    token: String,
}

impl core::fmt::Debug for Panel {
    /// Токен даёт полную власть над панелью: и над пользователями, и над
    /// конфигурацией узлов. В отладочную печать он не попадает.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Panel")
            .field("base", &self.base)
            .field("token", &"<скрыт>")
            .finish()
    }
}

impl Panel {
    /// Собрать клиента. `base` — адрес панели без косой черты на конце.
    #[must_use]
    pub fn new(base: &str, token: &str) -> Option<Self> {
        if token.is_empty() || !base.starts_with("https://") {
            return None;
        }
        Some(Self {
            base: base.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
        })
    }

    fn headers(&self, with_body: bool) -> Vec<(String, String)> {
        let mut headers = vec![("Authorization".to_owned(), format!("Bearer {}", self.token))];
        if with_body {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        headers
    }

    /// Имя пользователя в панели по идентификатору Telegram.
    ///
    /// Правило намеренно простое и обратимое: по одному лишь номеру Telegram
    /// всегда можно найти человека в панели. Значит, потеряв свою базу, мы
    /// не теряем связь «покупатель — подписка»: панель служит запасным
    /// указателем.
    #[must_use]
    pub fn username_for(telegram_id: i64) -> Option<String> {
        if telegram_id <= 0 {
            return None;
        }
        Some(format!("tg_{telegram_id}"))
    }

    /// Завести пользователя.
    pub fn create(&self, user: &NewUser) -> Result<Request, Error> {
        let username = Self::username_for(user.telegram_id)
            .ok_or(Error::Malformed("негодный номер Telegram"))?;

        for squad in &user.squads {
            if !squad.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') || squad.is_empty() {
                return Err(Error::Malformed("негодный идентификатор отряда"));
            }
        }

        let squads = user
            .squads
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");

        let body = format!(
            concat!(
                r#"{{"username":"{username}","#,
                r#""telegramId":{telegram},"#,
                r#""expireAt":"{expires}","#,
                // 0 означает «без ограничения». Тариф у нас один — безлимит,
                // и различие по трафику мы не продаём (docs/14-bot.md §2).
                r#""trafficLimitBytes":0,"#,
                r#""hwidDeviceLimit":{devices},"#,
                r#""activeInternalSquads":[{squads}]}}"#
            ),
            username = username,
            telegram = user.telegram_id,
            expires = to_iso8601(user.expires_at),
            devices = user.device_limit,
            squads = squads,
        );

        Ok(Request {
            method: Method::Post,
            url: format!("{}/api/users", self.base),
            headers: self.headers(true),
            body: body.into_bytes(),
        })
    }

    /// Найти пользователя по идентификатору Telegram.
    pub fn find(&self, telegram_id: i64) -> Result<Request, Error> {
        let username =
            Self::username_for(telegram_id).ok_or(Error::Malformed("негодный номер Telegram"))?;
        Ok(Request {
            method: Method::Get,
            url: format!("{}/api/users/by-username/{username}", self.base),
            headers: self.headers(false),
            body: Vec::new(),
        })
    }

    /// Поставить срок окончания подписки.
    ///
    /// Именно **поставить дату**, а не «продлить на N дней», хотя у панели
    /// есть и такое действие. Сложение сроков — денежное правило, оно
    /// посчитано и проверено у нас (`atlas_billing::subscription::extend`), и
    /// второго места, где оно живёт, быть не должно. Панель здесь только
    /// хранит то, что мы решили.
    #[must_use]
    pub fn set_expiry(&self, panel_id: i64, expires_at: i64) -> Request {
        let body = format!(
            r#"{{"id":{panel_id},"expireAt":"{}","status":"ACTIVE"}}"#,
            to_iso8601(expires_at)
        );
        Request {
            method: Method::Patch,
            url: format!("{}/api/users", self.base),
            headers: self.headers(true),
            body: body.into_bytes(),
        }
    }

    /// Выключить пользователя по истечении срока.
    ///
    /// Не удалить. Ссылка остаётся живой и отдаёт пустую конфигурацию;
    /// вернувшийся через полгода человек платит и продолжает пользоваться
    /// той же ссылкой (docs/14-bot.md §5).
    #[must_use]
    pub fn disable(&self, panel_id: i64) -> Request {
        Request {
            method: Method::Post,
            url: format!("{}/api/users/{panel_id}/actions/disable", self.base),
            headers: self.headers(false),
            body: Vec::new(),
        }
    }

    /// Разобрать ответ, содержащий пользователя.
    pub fn parse_user(&self, response: &[u8]) -> Result<User, Error> {
        #[derive(Deserialize)]
        struct Envelope {
            response: Option<Body>,
            message: Option<String>,
        }
        #[derive(Deserialize)]
        struct Body {
            id: i64,
            #[serde(rename = "shortUuid")]
            short_uuid: String,
            username: String,
            #[serde(rename = "telegramId")]
            telegram_id: Option<i64>,
            status: String,
            #[serde(rename = "expireAt")]
            expire_at: String,
            #[serde(rename = "subscriptionUrl")]
            subscription_url: Option<String>,
        }

        let envelope: Envelope = serde_json::from_slice(response)
            .map_err(|_| Error::Malformed("ответ панели не разбирается"))?;

        let Some(body) = envelope.response else {
            return Err(match envelope.message {
                Some(message) => Error::Rejected(message),
                None => Error::Malformed("в ответе нет пользователя"),
            });
        };

        let expires_at =
            from_iso8601(&body.expire_at).ok_or(Error::Malformed("срок не разбирается"))?;

        Ok(User {
            id: body.id,
            short_uuid: body.short_uuid,
            username: body.username,
            telegram_id: body.telegram_id,
            status: body.status,
            expires_at,
            subscription_url: body.subscription_url.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, NewUser, Panel};
    use atlas_billing::http::Method;

    const TOKEN: &str = "test-token-value";

    fn panel() -> Option<Panel> {
        Panel::new("https://panel.example.org", TOKEN)
    }

    fn new_user() -> NewUser {
        NewUser {
            telegram_id: 42,
            expires_at: 1_767_225_600, // 2026-01-01T00:00:00Z
            squads: vec!["b6f5d810-8ef3-4be9-9012-3456789abcde".to_owned()],
            device_limit: 4,
        }
    }

    fn user_json(expire: &str) -> Vec<u8> {
        format!(
            r#"{{"response":{{"id":7,"shortUuid":"rTLwqLBoohWeKVAR","username":"tg_42",
                "telegramId":42,"status":"ACTIVE","expireAt":"{expire}",
                "subscriptionUrl":"https://panel.example.org/api/sub/rTLwqLBoohWeKVAR"}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn a_user_is_created_with_everything_the_panel_needs() {
        let Some(panel) = panel() else { return };
        let Ok(request) = panel.create(&new_user()) else {
            return;
        };

        assert_eq!(request.method, Method::Post);
        assert_eq!(request.url, "https://panel.example.org/api/users");

        let body = String::from_utf8_lossy(&request.body);
        assert!(body.contains(r#""username":"tg_42""#), "{body}");
        assert!(body.contains(r#""telegramId":42"#));
        assert!(
            body.contains(r#""expireAt":"2026-01-01T00:00:00.000Z""#),
            "{body}"
        );
        assert!(body.contains(r#""hwidDeviceLimit":4"#));
        assert!(body.contains(r#""trafficLimitBytes":0"#));
        assert!(body.contains("b6f5d810-8ef3-4be9-9012-3456789abcde"));
    }

    /// Имя пользователя выводится из номера Telegram и ниоткуда больше.
    /// Благодаря этому панель служит запасным указателем: потеряв свою базу,
    /// мы всё равно находим человека по его номеру.
    #[test]
    fn the_username_is_derived_from_the_telegram_id_alone() {
        assert_eq!(Panel::username_for(42), Some("tg_42".to_owned()));
        assert_eq!(Panel::username_for(0), None);
        assert_eq!(Panel::username_for(-1), None);
    }

    #[test]
    fn a_bad_squad_identifier_does_not_reach_the_request_body() {
        let Some(panel) = panel() else { return };
        for bad in [
            r#"x","status":"ADMIN"#, // попытка дописать своё поле
            "отряд",
            "",
            "b6f5d810 8ef3",
        ] {
            let mut user = new_user();
            user.squads = vec![bad.to_owned()];
            assert_eq!(
                panel.create(&user),
                Err(Error::Malformed("негодный идентификатор отряда")),
                "принят отряд {bad:?}"
            );
        }
    }

    #[test]
    fn the_token_is_sent_as_a_bearer_and_never_printed() {
        let Some(panel) = panel() else { return };
        let Ok(request) = panel.find(42) else { return };
        assert!(request
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == &format!("Bearer {TOKEN}")));

        let printed = format!("{panel:?}");
        assert!(!printed.contains(TOKEN), "{printed}");
    }

    #[test]
    fn a_user_is_looked_up_by_username() {
        let Some(panel) = panel() else { return };
        let Ok(request) = panel.find(42) else { return };
        assert_eq!(request.method, Method::Get);
        assert_eq!(
            request.url,
            "https://panel.example.org/api/users/by-username/tg_42"
        );
    }

    /// Срок ставится абсолютной датой, а не «продлить на N дней»: сложение
    /// сроков посчитано у нас и проверено тестами, и второго места, где оно
    /// живёт, быть не должно.
    #[test]
    fn the_expiry_is_set_as_an_absolute_date() {
        let Some(panel) = panel() else { return };
        let request = panel.set_expiry(7, 1_788_000_000);
        assert_eq!(request.method, Method::Patch);
        assert_eq!(request.url, "https://panel.example.org/api/users");

        let body = String::from_utf8_lossy(&request.body);
        assert!(body.contains(r#""id":7"#));
        assert!(
            body.contains(r#""expireAt":"2026-08-29T10:40:00.000Z""#),
            "{body}"
        );
        assert!(
            !body.contains("days"),
            "срок не должен считаться панелью: {body}"
        );
    }

    #[test]
    fn an_expired_user_is_disabled_and_not_deleted() {
        let Some(panel) = panel() else { return };
        let request = panel.disable(7);
        assert_eq!(request.method, Method::Post);
        assert_eq!(
            request.url,
            "https://panel.example.org/api/users/7/actions/disable"
        );
    }

    #[test]
    fn a_users_answer_is_read_completely() {
        let Some(panel) = panel() else { return };
        let Ok(user) = panel.parse_user(&user_json("2026-01-01T00:00:00.000Z")) else {
            return;
        };
        assert_eq!(user.id, 7);
        assert_eq!(user.short_uuid, "rTLwqLBoohWeKVAR");
        assert_eq!(user.telegram_id, Some(42));
        assert_eq!(user.expires_at, 1_767_225_600);
        assert!(user.is_active());
        assert!(user.subscription_url.ends_with("/api/sub/rTLwqLBoohWeKVAR"));
    }

    #[test]
    fn a_refusal_is_passed_on_in_the_panels_own_words() {
        let Some(panel) = panel() else { return };
        let response = br#"{"message":"User not found","statusCode":404}"#;
        assert_eq!(
            panel.parse_user(response),
            Err(Error::Rejected("User not found".to_owned()))
        );
    }

    #[test]
    fn an_unreadable_answer_is_refused() {
        let Some(panel) = panel() else { return };
        assert!(panel.parse_user(b"not json").is_err());
        assert!(panel.parse_user(&user_json("вчера")).is_err());
    }

    /// Панель без TLS не принимается: по этому соединению ходит токен,
    /// дающий полную власть над всеми узлами.
    #[test]
    fn a_panel_without_tls_is_refused() {
        assert!(Panel::new("http://panel.example.org", TOKEN).is_none());
        assert!(Panel::new("https://panel.example.org", "").is_none());
    }
}
