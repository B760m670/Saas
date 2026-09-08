//! WATA.
//!
//! # Чем этот сервис отличается от остальных
//!
//! **Уведомления подписаны, и подпись мы не проверяем.** У WATA есть
//! `X-Signature` — RSA SHA512 по нетронутому телу, с публичным ключом по
//! отдельному адресу. Это лучше, чем у ЮKassa, где подписи нет вовсе.
//!
//! Тем не менее зачисление здесь опирается не на подпись, а на повторный
//! запрос состояния транзакции. Причин две.
//!
//! Первая: проверка RSA потребовала бы новой зависимости в крейте, который
//! сейчас обходится хешами. Криптографическая зависимость в денежном коде —
//! это не строчка в `Cargo.toml`, а обязательство следить за ней.
//!
//! Вторая, и главная: повторный запрос надёжнее подписи в любом случае.
//! Подпись доказывает, что тело пришло от WATA и не изменилось по дороге.
//! Ответ на наш собственный запрос доказывает то же самое **и** показывает
//! состояние на текущий момент, а не на момент отправки уведомления.
//! Уведомление может опоздать, повториться, прийти по отменённой позже
//! транзакции — ответ API про это знает, а подпись нет.
//!
//! Отсюда устройство модуля: [`Notice`] содержит **только** номер транзакции
//! и её заявленное состояние. Ни суммы, ни заказа оттуда не берут. Дальше
//! [`Wata::status_request`] и [`Wata::settle`] — и только они выдают
//! `PaymentEvent`.
//!
//! Поэтому [`Provider::callback`] здесь намеренно отвечает
//! [`Error::Unsupported`]: зачисления по уведомлению у этого сервиса нет.
//!
//! # Предоплатные уведомления надо выключить
//!
//! WATA умеет три вида уведомлений. У предоплатного ответ ждут **10 секунд**,
//! и не получив его, транзакцию отклоняют, не обращаясь в банк. Мы за эти
//! десять секунд успеть не обязаны: обработчик ходит в API за состоянием.
//!
//! Значит в личном кабинете предоплатные уведомления должны быть выключены.
//! У постоплатного ответа ждут минуту и повторяют попытки 32 часа — этого
//! хватает с запасом.

use serde::Deserialize;

use crate::event::{PaymentEvent, PaymentStatus};
use crate::http::{Callback, Checkout, Method, Request};
use crate::money::{Currency, Money};
use crate::order::{Order, OrderId};
use crate::provider::{Error, Provider};

/// Корень API.
const API: &str = "https://api.wata.pro/api/h2h";

/// Сколько живёт платёжная ссылка.
///
/// Совпадает со сроком жизни счёта у нас: ссылка не должна пережить заказ,
/// под который её выдали, иначе человек оплатит счёт, которого уже нет.
/// Меньше десяти минут WATA не принимает.
const LINK_LIFETIME_MINUTES: i64 = 20;

/// Состояние транзакции у WATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Создана; ждёт ответа на предоплатное уведомление.
    Created,
    /// В обработке, состояние выясняется у банка.
    Pending,
    /// Оплачена.
    Paid,
    /// Отклонена.
    Declined,
}

impl State {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "Created" => Some(Self::Created),
            "Pending" => Some(Self::Pending),
            "Paid" => Some(Self::Paid),
            "Declined" => Some(Self::Declined),
            _ => None,
        }
    }
}

/// Разобранное уведомление.
///
/// Содержит **только** номер транзакции и заявленное состояние. Ни суммы, ни
/// номера заказа здесь нет намеренно: эти данные пришли по открытому адресу,
/// и опираться на них — значит выдавать подписку тому, кто прислал нужный
/// JSON. Настоящее состояние берётся повторным запросом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// Номер транзакции в системе WATA.
    pub transaction: TransactionId,
    /// Что уведомление о ней говорит. Повод сходить и спросить, не более.
    pub claimed: State,
}

/// Номер транзакции у WATA.
///
/// Набор символов ограничен по той же причине, что и у номера заказа: он
/// приходит снаружи и подставляется **в адрес запроса**. Значение с косой
/// чертой или знаком вопроса увело бы запрос в другое место.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionId(String);

impl TransactionId {
    /// Наибольшая длина. UUID занимает 36 символов; запас на случай, если
    /// формат когда-нибудь сменят.
    pub const MAX_LEN: usize = 64;

    /// Проверить и принять номер.
    #[must_use]
    pub fn new(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > Self::MAX_LEN {
            return None;
        }
        if !value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return None;
        }
        Some(Self(value.to_owned()))
    }

    /// Номер как строка.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Приём оплаты через WATA.
#[derive(Clone)]
pub struct Wata {
    token: String,
    success_url: String,
    fail_url: String,
}

impl core::fmt::Debug for Wata {
    /// Токен в вывод не попадает: отладочная печать уезжает в журналы, а
    /// журналы читают и пересылают.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Wata")
            .field("token", &"<скрыт>")
            .field("success_url", &self.success_url)
            .field("fail_url", &self.fail_url)
            .finish()
    }
}

impl Wata {
    /// Собрать адаптер.
    ///
    /// `token` — доступ терминала из личного кабинета. Терминал у WATA — это
    /// точка приёма под конкретный вид деятельности, и ссылка создаётся для
    /// того терминала, чей токен указан в заголовке.
    ///
    /// Возвращает `None`, если что-то из обязательного пусто: пустой токен
    /// даёт запрос, который отвергают на той стороне, а разбирать это по
    /// журналам дороже, чем не дать собрать адаптер.
    #[must_use]
    pub fn new(token: &str, success_url: &str, fail_url: &str) -> Option<Self> {
        if token.is_empty() || success_url.is_empty() || fail_url.is_empty() {
            return None;
        }
        Some(Self {
            token: token.to_owned(),
            success_url: success_url.to_owned(),
            fail_url: fail_url.to_owned(),
        })
    }

    fn authorization(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// Запрос на создание платёжной ссылки.
    ///
    /// Способ оплаты не выбирается: на форме WATA покупателю показывают всё,
    /// что включено на терминале, — СБП, карты, T-Pay, SberPay. Навязанный
    /// способ отсекает тех, кто им не пользуется, а потерянная продажа стоит
    /// дороже разницы в комиссии.
    ///
    /// Ссылка одноразовая по умолчанию и живёт [`LINK_LIFETIME_MINUTES`]:
    /// столько же, сколько наш счёт.
    fn create(&self, order: &Order, now: i64) -> Request {
        let body = format!(
            concat!(
                r#"{{"amount":{amount},"#,
                r#""currency":"{currency}","#,
                r#""description":"{description}","#,
                r#""orderId":"{order}","#,
                r#""successRedirectUrl":"{success}","#,
                r#""failRedirectUrl":"{fail}","#,
                r#""expirationDateTime":"{expires}"}}"#
            ),
            amount = order.amount.to_decimal(),
            currency = order.amount.currency().code(),
            description = escape(&order.description),
            order = order.id.as_str(),
            success = escape(&self.success_url),
            fail = escape(&self.fail_url),
            expires = to_iso8601(now + LINK_LIFETIME_MINUTES * 60),
        );

        Request {
            method: Method::Post,
            url: format!("{API}/links"),
            headers: vec![
                ("Authorization".to_owned(), self.authorization()),
                ("Content-Type".to_owned(), "application/json".to_owned()),
            ],
            body: body.into_bytes(),
        }
    }

    /// Разобрать уведомление.
    ///
    /// Из тела берутся только номер транзакции и заявленное состояние. Всё
    /// остальное — сумма, заказ, комиссия, время — сознательно отбрасывается:
    /// эти данные прислал тот, кто нашёл адрес обработчика, а не WATA.
    ///
    /// Номер транзакции документация называет по-разному: в описании тела
    /// уведомления это `id`, а в описании запроса состояния сказано, что
    /// номер «отправляется мерчанту с webhook уведомлением в поле
    /// `transactionId`». Расхождение в их документации, а не у нас, поэтому
    /// принимаются оба поля: сначала `transactionId`, затем `id`.
    pub fn notice(&self, callback: &Callback) -> Result<Notice, Error> {
        #[derive(Deserialize)]
        struct Body<'a> {
            #[serde(rename = "transactionId")]
            transaction_id: Option<&'a str>,
            id: Option<&'a str>,
            #[serde(rename = "transactionStatus")]
            transaction_status: &'a str,
        }

        let body: Body<'_> = serde_json::from_slice(&callback.body)
            .map_err(|_| Error::Malformed("тело уведомления не разбирается"))?;

        let raw = body
            .transaction_id
            .or(body.id)
            .ok_or(Error::Malformed("в уведомлении нет номера транзакции"))?;

        let transaction =
            TransactionId::new(raw).ok_or(Error::Malformed("недопустимый номер транзакции"))?;

        let claimed = State::parse(body.transaction_status)
            .ok_or(Error::Malformed("незнакомое состояние транзакции"))?;

        Ok(Notice {
            transaction,
            claimed,
        })
    }

    /// Запрос за настоящим состоянием транзакции.
    ///
    /// Вот это и есть проверка подлинности: ответ приходит по TLS от WATA на
    /// запрос с нашим токеном. Подделать его, не имея токена, нельзя, а
    /// значит и подделать оплату — тоже.
    #[must_use]
    pub fn status_request(&self, transaction: &TransactionId) -> Request {
        Request {
            method: Method::Get,
            url: format!("{API}/transactions/{}", transaction.as_str()),
            headers: vec![("Authorization".to_owned(), self.authorization())],
            body: Vec::new(),
        }
    }

    /// Разобрать ответ о состоянии транзакции.
    ///
    /// Возвраты (`kind: "Refund"`) сюда не пускаются: у возврата свой
    /// жизненный цикл, и принять его за оплату — значит выдать подписку за
    /// возвращённые деньги.
    pub fn settle(&self, response: &[u8]) -> Result<PaymentEvent, Error> {
        #[derive(Deserialize)]
        struct Body {
            id: String,
            kind: Option<String>,
            status: String,
            amount: serde_json::Value,
            currency: String,
            #[serde(rename = "orderId")]
            order_id: Option<String>,
        }

        let body: Body = serde_json::from_slice(response)
            .map_err(|_| Error::Malformed("ответ о транзакции не разбирается"))?;

        if body.kind.as_deref() == Some("Refund") {
            return Err(Error::Malformed("это возврат, а не оплата"));
        }

        let status = match State::parse(&body.status) {
            Some(State::Paid) => PaymentStatus::Paid,
            Some(State::Declined) => PaymentStatus::Failed,
            Some(State::Created | State::Pending) => PaymentStatus::Pending,
            None => return Err(Error::Malformed("незнакомое состояние транзакции")),
        };

        let raw_order = body
            .order_id
            .ok_or(Error::Malformed("в ответе нет номера заказа"))?;
        let order =
            OrderId::new(&raw_order).ok_or(Error::Malformed("недопустимый номер заказа"))?;

        let currency =
            Currency::parse(&body.currency).ok_or(Error::Malformed("неизвестная валюта"))?;

        // Сумма приходит числом, а не строкой, — в отличие от ЮKassa. Число
        // с плавающей точкой в деньгах недопустимо: 1188.00 и 1187.9999
        // выглядят одинаково, а расходятся на копейку. Поэтому значение
        // берётся тем текстом, каким оно записано в JSON, и разбирается как
        // десятичная дробь.
        let decimal = match &body.amount {
            serde_json::Value::Number(number) => number.to_string(),
            serde_json::Value::String(text) => text.clone(),
            _ => return Err(Error::Malformed("сумма не число и не строка")),
        };
        let paid = Money::parse_decimal(&decimal, currency)
            .ok_or(Error::Malformed("сумма не разбирается"))?;

        Ok(PaymentEvent {
            order,
            status,
            paid: Some(paid),
            reference: body.id,
        })
    }
}

impl Provider for Wata {
    fn name(&self) -> &'static str {
        "wata"
    }

    /// Не поддерживается намеренно: см. [`Wata::checkout_at`].
    ///
    /// Ссылке нужен срок жизни, сроку — часы, а крейт часов не имеет и иметь
    /// не должен: именно поэтому он проверяется обычными тестами, а не
    /// запуском. Молча подставить трёхдневный срок по умолчанию хуже, чем
    /// отказать: ссылка пережила бы счёт, под который её выдали, и человек
    /// оплатил бы заказ, которого уже нет.
    fn checkout(&self, _order: &Order) -> Result<Checkout, Error> {
        Err(Error::Unsupported)
    }

    fn checkout_page(&self, response: &[u8]) -> Result<String, Error> {
        #[derive(Deserialize)]
        struct Body {
            url: Option<String>,
            status: Option<String>,
        }

        let body: Body = serde_json::from_slice(response)
            .map_err(|_| Error::Malformed("ответ на создание ссылки не разбирается"))?;

        let Some(url) = body.url else {
            return Err(match body.status {
                Some(status) => Error::Rejected(status),
                None => Error::Malformed("в ответе нет ссылки на оплату"),
            });
        };
        Ok(url)
    }

    /// У WATA зачисления по уведомлению не существует.
    ///
    /// Уведомление говорит только о том, что с транзакцией что-то произошло.
    /// Путь один: [`Wata::notice`], затем [`Wata::status_request`], затем
    /// [`Wata::settle`].
    fn callback(&self, _callback: &Callback) -> Result<PaymentEvent, Error> {
        Err(Error::Unsupported)
    }
}

impl Wata {
    /// Собрать запрос на создание ссылки к известному моменту времени.
    ///
    /// Отдельно от [`Provider::checkout`] потому, что сроку жизни ссылки
    /// нужны часы, а трейт их не передаёт. Городить часы внутри крейта нельзя:
    /// он намеренно не имеет ни ввода-вывода, ни времени, и именно поэтому
    /// проверяется обычными тестами.
    #[must_use]
    pub fn checkout_at(&self, order: &Order, now: i64) -> Request {
        self.create(order, now)
    }
}

/// Момент в формате, который принимает WATA: ISO 8601 в UTC.
fn to_iso8601(seconds: i64) -> String {
    // Тот же расчёт, что в `atlas_panel::time`, но повторять зависимость ради
    // одной функции незачем: календарь здесь считается от эпохи вперёд.
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);

    let (mut year, mut day) = (1970_i64, days);
    loop {
        let length = if is_leap(year) { 366 } else { 365 };
        if day < length {
            break;
        }
        day -= length;
        year += 1;
    }

    let lengths = [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    // Обход итератором, а не по индексу: индекс здесь заведомо в границах,
    // но доказывать это читателю дороже, чем не давать повода сомневаться.
    let mut month = 0;
    for length in lengths {
        if day < length {
            break;
        }
        day -= length;
        month += 1;
    }

    format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        month + 1,
        day + 1,
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60,
    )
}

const fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Экранирование для вставки в строку JSON.
///
/// Крохотная функция, но без неё кавычка в описании заказа разваливает тело
/// запроса, а перевод строки — ещё и меняет его смысл.
fn escape(value: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::{escape, State, TransactionId, Wata};
    use crate::event::PaymentStatus;
    use crate::http::{Callback, Method};
    use crate::money::{Currency, Money};
    use crate::order::{Order, OrderId, UserId};
    use crate::provider::{Error, Provider};

    /// 2026-09-08T10:00:00Z.
    ///
    /// Подписанная руками константа однажды уже разошлась с подписью — на
    /// двенадцать дней, и тест на сроке жизни ссылки это поймал. Проверяется
    /// она здесь же: первый тест ниже сверяет её обратный перевод.
    const NOW: i64 = 1_788_861_600;

    fn service() -> Option<Wata> {
        Wata::new(
            "test-terminal-token",
            "https://t.me/GloriaVPN_Bot",
            "https://t.me/GloriaVPN_Bot",
        )
    }

    fn order() -> Option<Order> {
        Some(Order {
            id: OrderId::new("u42-d30-7f")?,
            user: UserId(42),
            plan: "d30".to_owned(),
            amount: Money::from_minor(19_937, Currency::Rub),
            description: "Gloria VPN — 1 месяц".to_owned(),
        })
    }

    /// Сначала — что константа означает то, что о ней написано. Иначе
    /// остальные тесты проверяют не тот момент времени.
    #[test]
    fn the_moment_used_by_the_tests_is_the_one_written_above() {
        assert_eq!(super::to_iso8601(NOW), "2026-09-08T10:00:00Z");
    }

    /// Календарь здесь свой, написанный руками, — значит проверять его надо
    /// на високосных годах и границах месяцев, а не на одной дате.
    #[test]
    fn the_calendar_holds_on_the_awkward_dates() {
        for (seconds, want) in [
            (0_i64, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_735_689_599, "2024-12-31T23:59:59Z"),
            (1_735_689_600, "2025-01-01T00:00:00Z"),
            (1_788_861_600, "2026-09-08T10:00:00Z"),
        ] {
            assert_eq!(super::to_iso8601(seconds), want, "для {seconds}");
        }
    }

    #[test]
    fn a_payment_link_request_is_built_as_the_service_expects() {
        let (Some(service), Some(order)) = (service(), order()) else {
            return;
        };
        let request = service.checkout_at(&order, NOW);

        assert_eq!(request.method, Method::Post);
        assert_eq!(request.url, "https://api.wata.pro/api/h2h/links");

        let body = String::from_utf8_lossy(&request.body);
        assert!(body.contains(r#""amount":199.37"#), "сумма: {body}");
        assert!(body.contains(r#""currency":"RUB""#), "{body}");
        assert!(body.contains(r#""orderId":"u42-d30-7f""#), "{body}");

        // Способ оплаты не навязывается: его выбирает покупатель на форме
        // WATA из того, что включено на терминале.
        assert!(!body.contains("paymentMethod"), "способ навязан: {body}");
    }

    /// Токен уходит в заголовке, а не в адресе, и в отладочную печать не
    /// попадает: журналы читают и пересылают.
    #[test]
    fn the_token_travels_in_a_header_and_is_never_printed() {
        let (Some(service), Some(order)) = (service(), order()) else {
            return;
        };
        let request = service.checkout_at(&order, NOW);

        assert!(request.headers.iter().any(|(name, value)| {
            name == "Authorization" && value == "Bearer test-terminal-token"
        }));
        assert!(!request.url.contains("test-terminal-token"));
        assert!(!format!("{service:?}").contains("test-terminal-token"));
    }

    /// Ссылка живёт столько же, сколько наш счёт. Пережившая счёт ссылка —
    /// это оплата заказа, которого уже нет.
    #[test]
    fn the_link_expires_together_with_the_invoice() {
        let (Some(service), Some(order)) = (service(), order()) else {
            return;
        };
        let body = String::from_utf8_lossy(&service.checkout_at(&order, NOW).body).into_owned();
        assert!(
            body.contains(r#""expirationDateTime":"2026-09-08T10:20:00Z""#),
            "{body}"
        );
    }

    /// Через трейт ссылку не создать намеренно: сроку жизни нужны часы,
    /// которых у крейта нет. Молчаливый трёхдневный срок по умолчанию хуже
    /// отказа.
    #[test]
    fn the_trait_refuses_instead_of_guessing_the_expiry() {
        let (Some(service), Some(order)) = (service(), order()) else {
            return;
        };
        assert_eq!(service.checkout(&order), Err(Error::Unsupported));
    }

    #[test]
    fn the_payment_page_is_taken_from_the_answer() {
        let Some(service) = service() else { return };
        let response = br#"{"id":"8a5d1c1e-1111-2222-3333-444455556666",
            "amount":199.37,"currency":"RUB","status":"Opened",
            "url":"https://pay.wata.pro/link/8a5d1c1e","orderId":"u42-d30-7f"}"#;
        assert_eq!(
            service.checkout_page(response).ok().as_deref(),
            Some("https://pay.wata.pro/link/8a5d1c1e")
        );
    }

    /// Из уведомления берутся только номер транзакции и заявленное
    /// состояние. Ни суммы, ни заказа: их прислал тот, кто нашёл адрес.
    #[test]
    fn a_notice_carries_nothing_but_a_number_and_a_claim() {
        let Some(service) = service() else { return };
        let body = br#"{"transactionType":"SBP","kind":"Payment",
            "id":"0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff",
            "transactionStatus":"Paid","amount":100000.00,"currency":"RUB",
            "orderId":"u42-d30-7f","commission":400.00}"#;
        let notice = service.notice(&Callback::new(Vec::new(), body.to_vec()));
        assert!(notice.is_ok(), "{notice:?}");
        let Ok(notice) = notice else { return };

        assert_eq!(
            notice.transaction.as_str(),
            "0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff"
        );
        assert_eq!(notice.claimed, State::Paid);
    }

    /// Документация WATA называет номер транзакции то `id`, то
    /// `transactionId`. Расхождение у них, а принимать надо оба.
    #[test]
    fn both_names_of_the_transaction_number_are_accepted() {
        let Some(service) = service() else { return };
        let body = br#"{"transactionId":"0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff",
            "transactionStatus":"Paid"}"#;
        let notice = service.notice(&Callback::new(Vec::new(), body.to_vec()));
        assert!(notice.is_ok(), "{notice:?}");
    }

    /// Номер транзакции подставляется в адрес запроса. Значение, способное
    /// увести запрос в другое место, не принимается.
    #[test]
    fn a_number_that_could_bend_the_url_is_refused() {
        for bad in [
            "",
            "../../links",
            "0f2c7a90/actions/refund",
            "0f2c7a90?x=1",
            "0f2c7a90 90",
            "почти-uuid",
        ] {
            assert!(TransactionId::new(bad).is_none(), "принят {bad:?}");
        }
        assert!(TransactionId::new("0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff").is_some());
    }

    #[test]
    fn the_status_request_goes_to_the_transactions_own_address() {
        let Some(service) = service() else { return };
        let Some(id) = TransactionId::new("0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff") else {
            return;
        };
        let request = service.status_request(&id);
        assert_eq!(request.method, Method::Get);
        assert_eq!(
            request.url,
            "https://api.wata.pro/api/h2h/transactions/0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff"
        );
    }

    fn transaction(status: &str, amount: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff","type":"SBP",
                "kind":"Payment","amount":{amount},"currency":"RUB",
                "status":"{status}","orderId":"u42-d30-7f",
                "orderDescription":"Gloria VPN","totalCommission":0.80}}"#
        )
        .into_bytes()
    }

    #[test]
    fn a_paid_transaction_settles_the_order() {
        let Some(service) = service() else { return };
        let event = service.settle(&transaction("Paid", "199.37"));
        assert!(event.is_ok(), "{event:?}");
        let Ok(event) = event else { return };

        assert_eq!(event.status, PaymentStatus::Paid);
        assert_eq!(event.order.as_str(), "u42-d30-7f");
        assert_eq!(event.paid, Some(Money::from_minor(19_937, Currency::Rub)));
        assert_eq!(event.reference, "0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff");
    }

    #[test]
    fn a_declined_transaction_hands_out_nothing() {
        let Some(service) = service() else { return };
        let Ok(event) = service.settle(&transaction("Declined", "199.37")) else {
            return;
        };
        assert_eq!(event.status, PaymentStatus::Failed);
    }

    #[test]
    fn a_pending_transaction_is_not_a_payment_yet() {
        let Some(service) = service() else { return };
        for waiting in ["Created", "Pending"] {
            let Ok(event) = service.settle(&transaction(waiting, "199.37")) else {
                return;
            };
            assert_eq!(event.status, PaymentStatus::Pending, "{waiting}");
        }
    }

    /// Сумма у WATA приходит числом, а не строкой. Разбирать её через
    /// плавающую точку нельзя: 199.37 и 199.36999… выглядят одинаково, а
    /// расходятся на копейку — и расхождение это денежное.
    #[test]
    fn the_amount_survives_being_a_json_number() {
        let Some(service) = service() else { return };
        for (written, minor) in [("199.37", 19_937), ("1290.00", 129_000), ("10", 1_000)] {
            let event = service.settle(&transaction("Paid", written));
            assert!(event.is_ok(), "не разобралась сумма {written}: {event:?}");
            assert_eq!(
                event.ok().and_then(|event| event.paid),
                Some(Money::from_minor(minor, Currency::Rub)),
                "сумма {written}"
            );
        }
    }

    /// Возврат — не оплата. Принять его за оплату значит выдать подписку за
    /// деньги, которые уже вернули.
    #[test]
    fn a_refund_is_not_mistaken_for_a_payment() {
        let Some(service) = service() else { return };
        let body = br#"{"id":"0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff","kind":"Refund",
            "status":"Paid","amount":199.37,"currency":"RUB","orderId":"u42-d30-7f"}"#;
        assert!(service.settle(body).is_err());
    }

    /// Зачисления по уведомлению у этого сервиса не существует: уведомление
    /// сообщает только, что пора сходить и спросить.
    #[test]
    fn settling_straight_from_a_notice_is_impossible() {
        let Some(service) = service() else { return };
        let body = br#"{"id":"0f2c7a90-aaaa-bbbb-cccc-ddddeeeeffff",
            "transactionStatus":"Paid","amount":100000.00,"orderId":"u42-d30-7f"}"#;
        assert_eq!(
            service.callback(&Callback::new(Vec::new(), body.to_vec())),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn an_empty_token_or_address_does_not_build_a_service() {
        assert!(Wata::new("", "https://t.me/x", "https://t.me/x").is_none());
        assert!(Wata::new("token", "", "https://t.me/x").is_none());
        assert!(Wata::new("token", "https://t.me/x", "").is_none());
    }

    #[test]
    fn a_quote_in_the_description_does_not_break_the_body() {
        assert_eq!(escape(r#"Gloria "VPN""#), r#"Gloria \"VPN\""#);
        assert_eq!(escape("две\nстроки"), r"две\nстроки");
    }
}
