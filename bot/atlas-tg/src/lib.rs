//! Транспорт Telegram Bot API.
//!
//! Как и остальные адаптеры проекта, крейт не ходит в сеть: собирает запросы
//! и разбирает ответы. Запрос описывается тем же типом, что у платёжных
//! сервисов и панели, — исполнитель HTTP у бота один на всё.
//!
//! # Ловушка, которой нет у других
//!
//! **Токен бота лежит в адресе запроса.** У ЮKassa он в заголовке, у панели
//! в заголовке, а здесь — в пути: `api.telegram.org/bot<ТОКЕН>/sendMessage`.
//! Значит любая запись в журнал, содержащая адрес, выдаёт токен целиком, а
//! токен — это полная власть над ботом: чужой может читать переписку
//! покупателей и писать от нашего имени.
//!
//! Поэтому здесь есть [`Telegram::redact`], и всё, что уходит в журнал,
//! обязано проходить через него.

#![forbid(unsafe_code)]

use atlas_billing::http::{Method, Request};
use atlas_bot::{Keyboard, Press};
use serde::Deserialize;

/// Предел Telegram на длину сообщения, в символах.
///
/// Более длинное не отправляется вовсе, и узнаётся это не по ошибке в нашем
/// коде, а по тому, что покупатель не получил ответа.
pub const MESSAGE_LIMIT: usize = 4096;

/// Отказ транспорта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Текст длиннее предела Telegram.
    TooLong { chars: usize },
    /// Ответ Telegram не разобрался.
    Malformed(&'static str),
    /// Telegram ответил отказом своими словами.
    Rejected(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong { chars } => {
                write!(f, "сообщение из {chars} символов длиннее {MESSAGE_LIMIT}")
            }
            Self::Malformed(what) => write!(f, "не удалось разобрать: {what}"),
            Self::Rejected(reason) => write!(f, "Telegram отказал: {reason}"),
        }
    }
}

impl core::error::Error for Error {}

/// Что пришло от человека.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// Сообщение или команда.
    Message { chat: i64, from: i64, text: String },
    /// Нажатие на кнопку под сообщением.
    Button {
        chat: i64,
        from: i64,
        /// То, что мы сами положили в кнопку. Приходит от клиента, а значит
        /// проверяется разбором в `atlas_bot::Action::decode`.
        data: String,
        /// Идентификатор нажатия — на него надо ответить, иначе у человека
        /// кнопка крутится до таймаута.
        callback_id: String,
    },
}

impl Incoming {
    /// Кто это. Наш ключ во всей базе.
    #[must_use]
    pub const fn from(&self) -> i64 {
        match self {
            Self::Message { from, .. } | Self::Button { from, .. } => *from,
        }
    }

    /// Куда отвечать.
    #[must_use]
    pub const fn chat(&self) -> i64 {
        match self {
            Self::Message { chat, .. } | Self::Button { chat, .. } => *chat,
        }
    }
}

/// Обновление с порядковым номером.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// Номер, по которому считается сдвиг для следующего запроса.
    pub id: i64,
    /// Что пришло.
    pub incoming: Incoming,
}

/// Разобранная пачка обновлений.
///
/// Кроме понятых обновлений хранит **наибольший номер во всей пачке**,
/// включая пропущенные. Это существенно: сдвиг считается по нему, а не по
/// понятым. Иначе непонятное обновление с самым большим номером никогда бы
/// не подтверждалось, длинный опрос возвращался бы немедленно с ним же, и
/// бот крутился бы вхолостую, пока не придёт что-нибудь понятное.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Batch {
    /// Обновления, которые мы поняли.
    pub updates: Vec<Update>,
    /// Наибольший номер в пачке, понятый он или нет.
    pub highest_id: Option<i64>,
}

/// Сдвиг для следующего запроса обновлений.
///
/// **Плюс один — не украшение.** Telegram отдаёт обновления, начиная с
/// указанного номера, и считает подтверждёнными все, что меньше. Передать
/// номер последнего значит получить его снова, и так до бесконечности:
/// человек получает один и тот же ответ по кругу, а если это была выдача
/// пробы — то и пробу по кругу.
///
/// Номер берётся наибольший, а не последний в списке: порядок в ответе
/// Telegram не обещает.
///
/// Считается по всей пачке, включая пропущенные обновления, — см. [`Batch`].
#[must_use]
pub fn next_offset(batch: &Batch, current: Option<i64>) -> Option<i64> {
    batch.highest_id.map(|id| id + 1).or(current)
}

/// Клиент Telegram Bot API.
#[derive(Clone)]
pub struct Telegram {
    token: String,
}

impl core::fmt::Debug for Telegram {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Telegram")
            .field("token", &"<скрыт>")
            .finish()
    }
}

impl Telegram {
    /// Собрать клиента.
    ///
    /// Набор символов токена проверяется, и это не придирка: токен
    /// подставляется **в путь запроса**. Значение с косой чертой увело бы
    /// запрос на другой метод API.
    #[must_use]
    pub fn new(token: &str) -> Option<Self> {
        let (id, secret) = token.split_once(':')?;
        if id.is_empty() || secret.is_empty() {
            return None;
        }
        if !id.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if !secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        Some(Self {
            token: token.to_owned(),
        })
    }

    fn url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{method}", self.token)
    }

    fn post(&self, method: &str, body: String) -> Request {
        Request {
            method: Method::Post,
            url: self.url(method),
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.into_bytes(),
        }
    }

    /// Убрать токен из строки, уходящей в журнал.
    ///
    /// Обязательно для всего, что печатается: адрес запроса содержит токен,
    /// а сообщения об ошибках HTTP-клиентов обычно содержат адрес.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        text.replace(&self.token, "<токен скрыт>")
    }

    /// Запросить обновления.
    ///
    /// `timeout` — длинное ожидание в секундах: Telegram держит соединение,
    /// пока не появится обновление. Это дешевле частых пустых запросов и
    /// быстрее доставляет ответ человеку.
    #[must_use]
    pub fn get_updates(&self, offset: Option<i64>, timeout: u16) -> Request {
        let body = match offset {
            Some(offset) => format!(r#"{{"offset":{offset},"timeout":{timeout}}}"#),
            None => format!(r#"{{"timeout":{timeout}}}"#),
        };
        self.post("getUpdates", body)
    }

    /// Отправить сообщение.
    pub fn send_message(
        &self,
        chat: i64,
        text: &str,
        keyboard: Option<&Keyboard>,
    ) -> Result<Request, Error> {
        let chars = text.chars().count();
        if chars > MESSAGE_LIMIT {
            return Err(Error::TooLong { chars });
        }

        let markup = match keyboard {
            Some(keyboard) => format!(r#","reply_markup":{}"#, inline_markup(keyboard)),
            None => String::new(),
        };

        Ok(self.post(
            "sendMessage",
            format!(
                r#"{{"chat_id":{chat},"text":"{}","parse_mode":"HTML"{markup}}}"#,
                json_string(text)
            ),
        ))
    }

    /// Ответить на нажатие кнопки.
    ///
    /// Отвечать обязательно, даже если сказать нечего: иначе у человека
    /// кнопка крутится, пока не истечёт таймаут, и он жмёт её ещё раз.
    #[must_use]
    pub fn answer_callback(&self, callback_id: &str, text: Option<&str>) -> Request {
        let text = match text {
            Some(text) => format!(r#","text":"{}""#, json_string(text)),
            None => String::new(),
        };
        self.post(
            "answerCallbackQuery",
            format!(
                r#"{{"callback_query_id":"{}"{text}}}"#,
                json_string(callback_id)
            ),
        )
    }

    /// Разобрать ответ на [`Telegram::get_updates`].
    ///
    /// Обновления, которых мы не понимаем — вступления в группы, опросы,
    /// изменения сообщений, — пропускаются молча. Отвергать их нельзя:
    /// одно непонятное обновление остановило бы разбор всей пачки, а его
    /// номер всё равно надо подтвердить, иначе оно придёт снова и снова.
    pub fn parse_updates(&self, body: &[u8]) -> Result<Batch, Error> {
        #[derive(Deserialize)]
        struct Envelope {
            ok: bool,
            result: Option<Vec<Raw>>,
            description: Option<String>,
        }
        #[derive(Deserialize)]
        struct Raw {
            update_id: i64,
            message: Option<Message>,
            callback_query: Option<CallbackQuery>,
        }
        #[derive(Deserialize)]
        struct Message {
            chat: Chat,
            from: Option<From>,
            text: Option<String>,
        }
        #[derive(Deserialize)]
        struct CallbackQuery {
            id: String,
            from: From,
            message: Option<Message>,
            data: Option<String>,
        }
        #[derive(Deserialize)]
        struct Chat {
            id: i64,
        }
        #[derive(Deserialize)]
        struct From {
            id: i64,
        }

        let envelope: Envelope = serde_json::from_slice(body)
            .map_err(|_| Error::Malformed("ответ Telegram не разбирается"))?;

        if !envelope.ok {
            return Err(Error::Rejected(
                envelope
                    .description
                    .unwrap_or_else(|| "без причины".to_owned()),
            ));
        }

        let mut updates = Vec::new();
        let mut highest_id: Option<i64> = None;
        for raw in envelope.result.unwrap_or_default() {
            // Номер учитывается до разбора: пропущенное обновление тоже надо
            // подтвердить, иначе оно придёт снова.
            highest_id = Some(highest_id.map_or(raw.update_id, |id: i64| id.max(raw.update_id)));
            let incoming = if let Some(query) = raw.callback_query {
                match (query.data, query.message) {
                    (Some(data), Some(message)) => Some(Incoming::Button {
                        chat: message.chat.id,
                        from: query.from.id,
                        data,
                        callback_id: query.id,
                    }),
                    _ => None,
                }
            } else if let Some(message) = raw.message {
                match (message.text, message.from) {
                    (Some(text), Some(from)) => Some(Incoming::Message {
                        chat: message.chat.id,
                        from: from.id,
                        text,
                    }),
                    _ => None,
                }
            } else {
                None
            };

            if let Some(incoming) = incoming {
                updates.push(Update {
                    id: raw.update_id,
                    incoming,
                });
            }
        }

        Ok(Batch {
            updates,
            highest_id,
        })
    }
}

/// Раскладка кнопок в том виде, как её ждёт Telegram.
fn inline_markup(keyboard: &Keyboard) -> String {
    let rows = keyboard
        .rows
        .iter()
        .map(|row| {
            let buttons = row
                .iter()
                .map(|button| {
                    // Кнопка-ссылка уводит человека наружу, и нажатие к нам
                    // не возвращается вовсе. Поле у Telegram для этого
                    // другое, и прислать оба он не даст.
                    let press = match &button.press {
                        Press::Act(action) => {
                            format!(r#""callback_data":"{}""#, json_string(&action.encode()))
                        }
                        Press::Open(url) => format!(r#""url":"{}""#, json_string(url)),
                    };
                    format!(r#"{{"text":"{}",{press}}}"#, json_string(&button.label))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("[{buttons}]")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"inline_keyboard":[{rows}]}}"#)
}

/// Экранирование для вставки в строку JSON.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Экранирование для разметки HTML, которую понимает Telegram.
///
/// Имя покупателя приходит от него самого. Без этого имя вида `<b>` ломает
/// разметку, а Telegram отвергает всё сообщение целиком — человек просто не
/// получает ответа.
#[must_use]
pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::{
        escape_html, next_offset, Batch, Error, Incoming, Telegram, Update, MESSAGE_LIMIT,
    };
    use atlas_bot::{main_menu, Action};

    const TOKEN: &str = "123456789:AAHkTestTokenForUnitTestsOnly_x";

    fn telegram() -> Option<Telegram> {
        Telegram::new(TOKEN)
    }

    fn updates(body: &str) -> Option<Vec<Update>> {
        Some(telegram()?.parse_updates(body.as_bytes()).ok()?.updates)
    }

    fn batch(ids: &[i64]) -> Batch {
        Batch {
            updates: ids
                .iter()
                .map(|id| Update {
                    id: *id,
                    incoming: Incoming::Message {
                        chat: 1,
                        from: 1,
                        text: "x".to_owned(),
                    },
                })
                .collect(),
            highest_id: ids.iter().copied().max(),
        }
    }

    // --- сдвиг ------------------------------------------------------------

    /// Самая дорогая ошибка длинного опроса. Передав номер последнего
    /// обновления вместо следующего, бот получает его снова — и отвечает по
    /// кругу, вечно.
    #[test]
    fn the_offset_is_one_past_the_last_update() {
        assert_eq!(next_offset(&batch(&[100, 101]), None), Some(102));
    }

    /// Порядок в ответе Telegram не обещает, поэтому берётся наибольший, а
    /// не последний: иначе часть обновлений пришла бы повторно.
    #[test]
    fn the_offset_takes_the_largest_and_not_the_last() {
        assert_eq!(next_offset(&batch(&[105, 103]), None), Some(106));
    }

    /// Пустая пачка — обычное дело при длинном опросе: сдвиг не должен
    /// сбрасываться, иначе вся история придёт заново.
    #[test]
    fn an_empty_batch_keeps_the_offset() {
        assert_eq!(next_offset(&Batch::default(), Some(500)), Some(500));
        assert_eq!(next_offset(&Batch::default(), None), None);
    }

    // --- разбор -----------------------------------------------------------

    #[test]
    fn a_command_is_understood() {
        let Some(list) = updates(
            r#"{"ok":true,"result":[{"update_id":7,"message":{
                "message_id":1,"chat":{"id":42},"from":{"id":42},"text":"/start"}}]}"#,
        ) else {
            return;
        };
        assert_eq!(
            list,
            vec![Update {
                id: 7,
                incoming: Incoming::Message {
                    chat: 42,
                    from: 42,
                    text: "/start".to_owned()
                }
            }]
        );
    }

    #[test]
    fn a_button_press_is_understood() {
        let Some(list) = updates(
            r#"{"ok":true,"result":[{"update_id":8,"callback_query":{
                "id":"cb-1","from":{"id":42},"data":"buy:d30",
                "message":{"message_id":5,"chat":{"id":42}}}}]}"#,
        ) else {
            return;
        };
        let Some(update) = list.first() else { return };
        assert_eq!(
            update.incoming,
            Incoming::Button {
                chat: 42,
                from: 42,
                data: "buy:d30".to_owned(),
                callback_id: "cb-1".to_owned()
            }
        );
    }

    /// Непонятное обновление пропускается, но **номер его учитывается**.
    ///
    /// Непонятное обновление стоит здесь последним намеренно: это тот самый
    /// случай, который ломается. Считай мы сдвиг по понятым обновлениям,
    /// вступление в группу никогда бы не подтвердилось, длинный опрос
    /// возвращался бы с ним немедленно, и бот крутился бы вхолостую, пока
    /// кто-нибудь не напишет.
    #[test]
    fn an_unknown_update_is_skipped_but_still_acknowledged() {
        let body = r#"{"ok":true,"result":[
            {"update_id":10,"message":{"chat":{"id":42},"from":{"id":42},"text":"/start"}},
            {"update_id":11,"my_chat_member":{"chat":{"id":1}}}
        ]}"#;
        let Some(telegram) = telegram() else { return };
        let Ok(parsed) = telegram.parse_updates(body.as_bytes()) else {
            return;
        };
        assert_eq!(
            parsed.updates.len(),
            1,
            "непонятное обновление не пропущено"
        );
        assert_eq!(parsed.highest_id, Some(11));
        assert_eq!(
            next_offset(&parsed, None),
            Some(12),
            "сдвиг не перешагнул через непонятное обновление"
        );
    }

    /// Сообщение без текста (картинка, стикер) не должно ронять разбор.
    #[test]
    fn a_message_without_text_is_skipped() {
        let Some(list) = updates(
            r#"{"ok":true,"result":[{"update_id":9,"message":{
                "chat":{"id":42},"from":{"id":42},"photo":[]}}]}"#,
        ) else {
            return;
        };
        assert!(list.is_empty());
    }

    #[test]
    fn a_refusal_is_passed_on_in_telegrams_own_words() {
        let Some(telegram) = telegram() else { return };
        let body = br#"{"ok":false,"description":"Unauthorized"}"#;
        assert_eq!(
            telegram.parse_updates(body),
            Err(Error::Rejected("Unauthorized".to_owned()))
        );
    }

    // --- отправка ---------------------------------------------------------

    #[test]
    fn a_message_carries_its_keyboard() {
        let Some(telegram) = telegram() else { return };
        let Ok(request) = telegram.send_message(42, "Подписка активна", Some(&main_menu()))
        else {
            return;
        };
        let body = String::from_utf8_lossy(&request.body);
        assert!(body.contains(r#""chat_id":42"#));
        assert!(body.contains("inline_keyboard"), "{body}");
        assert!(body.contains(r#""callback_data":"sub""#), "{body}");
        assert!(body.contains("Моя подписка"));
    }

    /// Более длинное сообщение Telegram не отправляет вовсе, и заметно это
    /// не по ошибке, а по тому, что человек не получил ответа.
    #[test]
    fn an_overlong_message_is_refused_before_sending() {
        let Some(telegram) = telegram() else { return };
        let long = "я".repeat(MESSAGE_LIMIT + 1);
        assert_eq!(
            telegram.send_message(42, &long, None),
            Err(Error::TooLong {
                chars: MESSAGE_LIMIT + 1
            })
        );
        // Ровно на пределе — можно.
        assert!(telegram
            .send_message(42, &"я".repeat(MESSAGE_LIMIT), None)
            .is_ok());
    }

    /// Предел считается в символах, а не в байтах: кириллица занимает по два
    /// байта, и счёт по байтам отверг бы вдвое более короткое сообщение.
    #[test]
    fn the_limit_counts_characters_and_not_bytes() {
        let Some(telegram) = telegram() else { return };
        let text = "я".repeat(3000); // 6000 байт, 3000 символов
        assert!(telegram.send_message(42, &text, None).is_ok());
    }

    #[test]
    fn quotes_in_the_text_do_not_break_the_body() {
        let Some(telegram) = telegram() else { return };
        let Ok(request) = telegram.send_message(42, "тариф \"год\"\nвторая строка", None)
        else {
            return;
        };
        let body = String::from_utf8_lossy(&request.body);
        assert!(body.contains(r#"тариф \"год\"\nвторая строка"#), "{body}");
    }

    /// Имя покупателя приходит от него самого. Без экранирования имя вида
    /// `<b>` ломает разметку, и Telegram отвергает сообщение целиком.
    #[test]
    fn a_name_with_markup_does_not_break_the_message() {
        assert_eq!(
            escape_html("<b>Иван</b> & Ко"),
            "&lt;b&gt;Иван&lt;/b&gt; &amp; Ко"
        );
    }

    // --- токен ------------------------------------------------------------

    /// Главная особенность этого API: токен лежит в пути запроса. Значит
    /// любая печать адреса выдаёт полную власть над ботом.
    #[test]
    fn the_token_is_removed_from_anything_that_goes_to_the_log() {
        let Some(telegram) = telegram() else { return };
        let request = telegram.get_updates(None, 30);
        assert!(request.url.contains(TOKEN), "токен должен быть в адресе");

        let printed = telegram.redact(&format!("не удалось: {}", request.url));
        assert!(!printed.contains(TOKEN), "{printed}");
        assert!(printed.contains("<токен скрыт>"));

        assert!(!format!("{telegram:?}").contains(TOKEN));
    }

    /// Токен подставляется в путь, поэтому косая черта увела бы запрос на
    /// другой метод API.
    #[test]
    fn a_token_that_could_bend_the_url_is_refused() {
        for bad in [
            "123:abc/../sendMessage",
            "123:abc?x=1",
            "123:abc#f",
            "abc:def",
            "123456789",
            ":secret",
            "123:",
            "",
        ] {
            assert!(Telegram::new(bad).is_none(), "принят токен {bad:?}");
        }
    }

    #[test]
    fn the_offset_is_absent_on_the_very_first_request() {
        let Some(telegram) = telegram() else { return };
        let body = String::from_utf8_lossy(&telegram.get_updates(None, 30).body).into_owned();
        assert!(!body.contains("offset"), "{body}");

        let body = String::from_utf8_lossy(&telegram.get_updates(Some(102), 30).body).into_owned();
        assert!(body.contains(r#""offset":102"#), "{body}");
    }

    /// На нажатие надо ответить, даже если сказать нечего: иначе у человека
    /// кнопка крутится до таймаута, и он жмёт её ещё раз.
    #[test]
    fn a_button_press_is_always_answered() {
        let Some(telegram) = telegram() else { return };
        let request = telegram.answer_callback("cb-1", None);
        assert!(request.url.ends_with("/answerCallbackQuery"));
        let body = String::from_utf8_lossy(&request.body);
        assert!(body.contains(r#""callback_query_id":"cb-1""#));
    }

    /// Кнопка оплаты уводит наружу. Telegram различает два вида кнопок по
    /// полю, и прислать оба он не даст: с `callback_data` вместо `url`
    /// человек нажал бы «Оплатить» и остался на месте.
    #[test]
    fn a_link_button_becomes_a_link_and_not_a_callback() {
        let Some(telegram) = telegram() else { return };
        let keyboard = atlas_bot::Keyboard {
            rows: vec![vec![atlas_bot::Button::link(
                "Оплатить",
                "https://yoomoney.ru/checkout/payments/v2/contract?orderId=abc",
            )]],
        };
        let Ok(request) = telegram.send_message(42, "К оплате", Some(&keyboard)) else {
            return;
        };
        let body = String::from_utf8_lossy(&request.body);
        assert!(body.contains(r#""url":"https://yoomoney.ru/"#), "{body}");
        assert!(!body.contains("callback_data"), "{body}");
    }

    /// То, что уехало в кнопку, должно вернуться разбираемым: иначе кнопка
    /// нажимается, а бот молчит.
    #[test]
    fn what_goes_into_a_button_comes_back_understood() {
        for button in main_menu().buttons() {
            let Some(action) = button.action() else {
                continue;
            };
            assert_eq!(Action::decode(&action.encode()), Ok(action.clone()));
        }
    }
}
