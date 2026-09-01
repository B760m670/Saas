//! Обращения к панели Remnawave.

use atlas_billing::http::{Method, Request};
use serde::Deserialize;

use crate::time::{from_iso8601, to_iso8601};

/// Отказ при работе с панелью.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Ответ не разобрался.
    Malformed(&'static str),
    /// Ответ не разобрался, и разборщик объяснил почему.
    ///
    /// Отдельно от [`Self::Malformed`] потому, что «ответ панели не
    /// разбирается» — сообщение, по которому нечего делать: оно не отличает
    /// сломанный JSON от переименованного поля и от массива вместо объекта.
    /// А различаются они починкой в разных местах.
    Unreadable(String),
    /// Панель ответила отказом своими словами.
    Rejected(String),
    /// Такого пользователя в панели нет.
    NotFound,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "не удалось разобрать: {what}"),
            Self::Unreadable(why) => write!(f, "ответ панели не разбирается: {why}"),
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
    /// Внутренний номер в панели — по нему идут продление и выключение.
    pub id: i64,
    /// Он же, но в виде UUID.
    ///
    /// Панель принимает то один, то другой: срок ставится по номеру, а
    /// перевыпуск ссылки — только по UUID. Приходится держать оба.
    pub uuid: String,
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
#[derive(Clone)]
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
        if token.is_empty() || !(base.starts_with("https://") || Self::is_loopback(base)) {
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

    /// Обращение по петлевому адресу — единственный случай, когда `http` годится.
    ///
    /// Требование `https` стоит ради токена: он даёт власть над всеми узлами и по
    /// сети открытым идти не должен. По `127.0.0.1` он по сети и не идёт.
    ///
    /// Та же проверка есть в настройках бота, и это намеренное повторение: там
    /// она объясняет человеку, что не так, здесь — не пускает негодный адрес в
    /// библиотеку, которую можно вызвать и мимо настроек.
    ///
    /// Сверяется **начало** адреса: `http://127.0.0.1.чужое.example` начинается с
    /// петлевого, но петлевым не является.
    fn is_loopback(url: &str) -> bool {
        const HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];

        let Some(rest) = url.strip_prefix("http://") else {
            return false;
        };

        HOSTS.iter().any(|host| {
            rest.strip_prefix(host).is_some_and(|tail| {
                tail.is_empty() || tail.starts_with(':') || tail.starts_with('/')
            })
        })
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

    /// Перевыпустить ссылку на подписку.
    ///
    /// Панель выдаёт новый `shortUuid`, и прежняя ссылка перестаёт работать
    /// немедленно. Это единственный ответ на утечку: адрес подписки — сам по
    /// себе пропуск, отозвать его иначе нельзя.
    ///
    /// По UUID, а не по номеру: этот путь панель принимает только так.
    pub fn revoke(&self, uuid: &str) -> Result<Request, Error> {
        // UUID уходит в адрес запроса. Набор символов проверяется здесь, а не
        // надеждой на то, что панель прислала разумное: в путь запроса нельзя
        // пускать ничего, что способно его изменить.
        if uuid.is_empty()
            || uuid.len() > 64
            || !uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            return Err(Error::Malformed("негодный UUID пользователя"));
        }

        Ok(Request {
            method: Method::Post,
            url: format!("{}/api/users/{uuid}/actions/revoke", self.base),
            headers: self.headers(false),
            body: Vec::new(),
        })
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
    ///
    /// Разбор идёт в два приёма: сначала конверт, потом пользователь внутри
    /// него. Это не лишний шаг. Разбор одним куском отвечает на любую беду
    /// одинаковым «не разбирается»: и на оборванный ответ, и на
    /// переименованное поле, и на массив там, где ждали объект. Чинятся они
    /// в трёх разных местах, а сообщение одно и то же.
    ///
    /// Заодно `response` принимается и объектом, и массивом: часть путей
    /// панели отвечает списком даже там, где пользователь заведомо один.
    pub fn parse_user(&self, response: &[u8]) -> Result<User, Error> {
        #[derive(Deserialize)]
        struct Body {
            id: i64,
            uuid: String,
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

        let envelope: serde_json::Value = serde_json::from_slice(response)
            .map_err(|error| Error::Unreadable(format!("это не JSON: {error}")))?;

        let Some(node) = envelope.get("response") else {
            return Err(match envelope.get("message").and_then(|m| m.as_str()) {
                Some(message) => Error::Rejected(message.to_owned()),
                None => Error::Malformed("в ответе нет пользователя"),
            });
        };

        // Список вместо объекта — не ошибка панели, а другой её путь. Пустой
        // список при этом значит ровно «такого нет», а не поломку.
        let node = match node {
            serde_json::Value::Array(items) => items.first().ok_or(Error::NotFound)?,
            other => other,
        };

        let body: Body = serde_json::from_value(node.clone())
            .map_err(|error| Error::Unreadable(format!("пользователь: {error}")))?;

        let expires_at =
            from_iso8601(&body.expire_at).ok_or(Error::Malformed("срок не разбирается"))?;

        Ok(User {
            id: body.id,
            uuid: body.uuid,
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
        let panel = Panel::new("https://panel.example.org", TOKEN);
        // Иначе каждый тест ниже начинался бы с тихого `return`, и весь файл
        // проходил бы вхолостую. Зелёный без единой проверки — худший исход.
        assert!(panel.is_some(), "клиент панели не собрался");
        panel
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
            r#"{{"response":{{"id":7,"uuid":"03ea8748-bd6e-4432-af37-74d45f3d397e",
                "shortUuid":"rTLwqLBoohWeKVAR","username":"tg_42",
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
        let parsed = panel.parse_user(&user_json("2026-01-01T00:00:00.000Z"));
        // Раньше здесь стоял тихий выход, и добавление обязательного поля в
        // разбор оставило тест зелёным при полностью сломанном разборе.
        assert!(parsed.is_ok(), "ответ панели не разобрался: {parsed:?}");
        let Ok(user) = parsed else { return };

        assert_eq!(user.id, 7);
        assert_eq!(user.uuid, "03ea8748-bd6e-4432-af37-74d45f3d397e");
        assert_eq!(user.short_uuid, "rTLwqLBoohWeKVAR");
        assert_eq!(user.telegram_id, Some(42));
        assert_eq!(user.expires_at, 1_767_225_600);
        assert!(user.is_active());
        assert!(user.subscription_url.ends_with("/api/sub/rTLwqLBoohWeKVAR"));
    }

    /// Часть путей панели отвечает списком даже там, где пользователь
    /// заведомо один. Разбор, знающий только объект, отвечал на это глухим
    /// «ответ панели не разбирается» — и перевыпуск падал у всех.
    #[test]
    fn a_user_wrapped_in_a_list_is_read_the_same_way() {
        let Some(panel) = panel() else { return };
        let object = user_json("2026-01-01T00:00:00.000Z");
        let listed = String::from_utf8_lossy(&object)
            .replacen(r#""response":{"#, r#""response":[{"#, 1)
            .replacen("}}", "}]}", 1)
            .into_bytes();

        let from_list = panel.parse_user(&listed);
        assert!(from_list.is_ok(), "список не разобрался: {from_list:?}");
        assert_eq!(from_list.ok(), panel.parse_user(&object).ok());
    }

    /// Пустой список — это «такого нет», а не поломка разбора. Разница видна
    /// только в сообщении, и именно по нему потом чинят.
    #[test]
    fn an_empty_list_means_the_user_is_absent() {
        let Some(panel) = panel() else { return };
        assert_eq!(
            panel.parse_user(br#"{"response":[]}"#),
            Err(Error::NotFound)
        );
    }

    /// Сообщение об ошибке разбора должно называть причину: без неё
    /// «не разбирается» одинаково звучит и на оборванный ответ, и на
    /// переименованное поле, а чинятся они по-разному.
    #[test]
    fn a_parsing_failure_says_what_exactly_went_wrong() {
        let Some(panel) = panel() else { return };

        let broken = panel
            .parse_user(b"{ not json at all")
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(broken.contains("это не JSON"), "{broken}");

        // Поле переименовано — ответ остаётся правильным JSON, и отличить
        // этот случай от предыдущего можно только по тексту.
        let renamed = String::from_utf8_lossy(&user_json("2026-01-01T00:00:00.000Z"))
            .replace("shortUuid", "short_uuid")
            .into_bytes();
        let missing = panel
            .parse_user(&renamed)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(missing.contains("shortUuid"), "{missing}");
    }

    /// Перевыпуск идёт по UUID и никуда больше: путь запроса собирается из
    /// него, и подстановка чужого значения увела бы запрос в другое место.
    #[test]
    fn revoking_goes_to_the_users_own_address() {
        let Some(panel) = panel() else { return };
        let request = panel.revoke("03ea8748-bd6e-4432-af37-74d45f3d397e");
        assert!(request.is_ok(), "{request:?}");
        let Ok(request) = request else { return };
        assert_eq!(
            request.url,
            "https://panel.example.org/api/users/03ea8748-bd6e-4432-af37-74d45f3d397e/actions/revoke"
        );
        assert_eq!(request.method, Method::Post);
    }

    /// UUID приходит из ответа панели, но проверяется всё равно: в путь
    /// запроса нельзя пускать ничего, что способно его изменить.
    #[test]
    fn a_uuid_that_could_bend_the_url_is_refused() {
        let Some(panel) = panel() else { return };
        for bad in [
            "",
            "../../users",
            "03ea8748/actions/delete",
            "03ea8748?x=1",
            "03ea8748 bd6e",
        ] {
            assert!(
                panel.revoke(bad).is_err(),
                "UUID {bad:?} принят, а не должен"
            );
        }
    }

    /// Настройки бота разрешают петлевой адрес панели, и клиент обязан
    /// разрешать его тоже. Пока это расходилось, бот отказывался стартовать
    /// с адресом, который сам же README и советует.
    #[test]
    fn the_panel_may_live_on_the_loopback_over_plain_http() {
        for good in [
            "http://127.0.0.1:3000",
            "http://localhost:3000",
            "http://[::1]:3000",
        ] {
            assert!(Panel::new(good, TOKEN).is_some(), "{good} отвергнут");
        }
        for bad in [
            "http://panel.example.org",
            "http://127.0.0.1.attacker.example",
            "http://localhost.attacker.example",
            "ftp://127.0.0.1",
        ] {
            assert!(Panel::new(bad, TOKEN).is_none(), "{bad} принят");
        }
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
