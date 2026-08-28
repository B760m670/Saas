//! ЮKassa.
//!
//! # Чем этот сервис отличается от остальных
//!
//! **Уведомления ЮKassa не подписаны.** Ни HMAC, ни какой-либо другой
//! подписи в них нет — это их устройство, а не наша недоработка. Подлинность
//! предлагается проверять двумя способами: по адресу отправителя и повторным
//! запросом к API за настоящим состоянием платежа.
//!
//! Из этого следует главное правило модуля: **уведомление — подсказка, а не
//! факт.** Оно сообщает только то, что с платежом что-то произошло и пора
//! сходить спросить. Никакой суммы и никакого зачисляемого состояния из него
//! не извлекается — [`Notice`] их попросту не содержит, и построить
//! `PaymentEvent` из уведомления нельзя физически.
//!
//! Зачисляет только [`YooKassa::settle`] — из ответа на наш собственный
//! запрос, ушедший по TLS с нашим ключом. Такой ответ подделать нельзя, не
//! имея ключа, а адрес отправителя остаётся вторым рубежом, а не первым.
//!
//! Поэтому [`Provider::callback`] здесь намеренно отвечает
//! [`Error::Unsupported`]: зачисления по уведомлению у этого сервиса не
//! существует.

use base64::Engine;
use serde::Deserialize;

use crate::event::{PaymentEvent, PaymentStatus};
use crate::http::{Callback, Checkout, Method, Request};
use crate::money::{Currency, Money};
use crate::order::{Order, OrderId};
use crate::provider::{Error, Provider};

/// Адрес API.
const API: &str = "https://api.yookassa.ru/v3/payments";

/// Сети, из которых ЮKassa шлёт уведомления.
///
/// Второй рубеж, а не первый: настоящую проверку делает повторный запрос к
/// API. Но отсечь по адресу дёшево, и это убирает весь шум от тех, кто
/// просто перебирает чужие адреса в поисках открытого обработчика.
pub const TRUSTED_V4: [(&str, u8); 6] = [
    ("185.71.76.0", 27),
    ("185.71.77.0", 27),
    ("77.75.153.0", 25),
    ("77.75.156.11", 32),
    ("77.75.156.35", 32),
    ("77.75.154.128", 25),
];

/// Событие, о котором сообщает уведомление.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Платёж прошёл.
    Succeeded,
    /// Платёж ждёт подтверждения списания.
    WaitingForCapture,
    /// Платёж отменён.
    Canceled,
    /// Возврат прошёл.
    RefundSucceeded,
}

/// Разобранное уведомление.
///
/// Содержит **только** идентификатор платежа и название события. Ни суммы,
/// ни состояния, по которому можно было бы выдать подписку, здесь нет — и
/// это не упущение, а суть: данные пришли от кого угодно, и доверять им
/// нечего. Дальше положено сходить в API за настоящим состоянием.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// Что произошло.
    pub event: Event,
    /// Идентификатор платежа у ЮKassa.
    pub payment_id: PaymentId,
}

/// Идентификатор платежа у ЮKassa.
///
/// Набор символов ограничен по той же причине, что и у номера заказа: этот
/// идентификатор приходит снаружи и подставляется в адрес запроса. Значение
/// с косой чертой или знаком вопроса увело бы запрос не туда.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentId(String);

impl PaymentId {
    /// Наибольшая длина.
    pub const MAX_LEN: usize = 64;

    /// Проверить и принять идентификатор.
    #[must_use]
    pub fn new(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > Self::MAX_LEN {
            return None;
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
        Some(Self(value.to_owned()))
    }

    /// Идентификатор как строка.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Приём оплаты через ЮKassa.
pub struct YooKassa {
    shop_id: String,
    secret_key: String,
    return_url: String,
}

impl core::fmt::Debug for YooKassa {
    /// Ключ в вывод не попадает. Отладочная печать уезжает в журналы, а
    /// журналы читают и пересылают.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("YooKassa")
            .field("shop_id", &self.shop_id)
            .field("secret_key", &"<скрыт>")
            .field("return_url", &self.return_url)
            .finish()
    }
}

impl YooKassa {
    /// Собрать адаптер.
    ///
    /// Возвращает `None`, если что-то из обязательного пусто: пустой ключ
    /// даёт запрос, который отвергается уже на стороне сервиса, и разбирать
    /// это по журналам дороже, чем не дать собрать адаптер.
    #[must_use]
    pub fn new(shop_id: &str, secret_key: &str, return_url: &str) -> Option<Self> {
        if shop_id.is_empty() || secret_key.is_empty() || return_url.is_empty() {
            return None;
        }
        Some(Self {
            shop_id: shop_id.to_owned(),
            secret_key: secret_key.to_owned(),
            return_url: return_url.to_owned(),
        })
    }

    /// Заголовок авторизации: обычный HTTP Basic из пары «магазин : ключ».
    fn authorization(&self) -> String {
        let pair = format!("{}:{}", self.shop_id, self.secret_key);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(pair)
        )
    }

    /// Запрос на создание платежа.
    ///
    /// `Idempotence-Key` — номер нашего заказа. Заголовок обязателен у
    /// ЮKassa, и смысл у него ровно тот, что нужен: повтор запроса с тем же
    /// ключом не создаёт второй платёж, а возвращает первый. Сеть моргнула,
    /// мы отправили заново — покупатель не получит два счёта.
    fn create(&self, order: &Order) -> Request {
        let body = format!(
            concat!(
                r#"{{"amount":{{"value":"{amount}","currency":"{currency}"}},"#,
                r#""capture":true,"#,
                r#""confirmation":{{"type":"redirect","return_url":"{back}"}},"#,
                r#""payment_method_data":{{"type":"sbp"}},"#,
                r#""description":"{description}","#,
                r#""metadata":{{"order_id":"{order}"}}}}"#
            ),
            amount = order.amount.to_decimal(),
            currency = order.amount.currency().code(),
            back = escape(&self.return_url),
            description = escape(&order.description),
            order = order.id.as_str(),
        );

        Request {
            method: Method::Post,
            url: API.to_owned(),
            headers: vec![
                ("Authorization".to_owned(), self.authorization()),
                ("Idempotence-Key".to_owned(), order.id.as_str().to_owned()),
                ("Content-Type".to_owned(), "application/json".to_owned()),
            ],
            body: body.into_bytes(),
        }
    }

    /// Разобрать уведомление.
    ///
    /// Из тела берутся только событие и идентификатор платежа. Всё
    /// остальное — сумма, состояние, время — сознательно отбрасывается:
    /// эти данные пришли не от ЮKassa, а от того, кто прислал запрос.
    pub fn notice(&self, callback: &Callback) -> Result<Notice, Error> {
        #[derive(Deserialize)]
        struct Body<'a> {
            #[serde(rename = "type")]
            kind: &'a str,
            event: &'a str,
            object: Object<'a>,
        }
        #[derive(Deserialize)]
        struct Object<'a> {
            id: &'a str,
        }

        let body: Body<'_> = serde_json::from_slice(&callback.body)
            .map_err(|_| Error::Malformed("тело уведомления не разбирается"))?;

        if body.kind != "notification" {
            return Err(Error::Malformed("это не уведомление"));
        }

        let event = match body.event {
            "payment.succeeded" => Event::Succeeded,
            "payment.waiting_for_capture" => Event::WaitingForCapture,
            "payment.canceled" => Event::Canceled,
            "refund.succeeded" => Event::RefundSucceeded,
            _ => return Err(Error::Malformed("незнакомое событие")),
        };

        let payment_id =
            PaymentId::new(body.object.id).ok_or(Error::Malformed("недопустимый номер платежа"))?;

        Ok(Notice { event, payment_id })
    }

    /// Запрос за настоящим состоянием платежа.
    ///
    /// Вот это и есть проверка подлинности: ответ приходит по TLS от ЮKassa
    /// на запрос, подписанный нашим ключом. Подделать его, не имея ключа,
    /// нельзя, а значит и подделать оплату — тоже.
    #[must_use]
    pub fn status_request(&self, payment: &PaymentId) -> Request {
        Request {
            method: Method::Get,
            url: format!("{API}/{}", payment.as_str()),
            headers: vec![("Authorization".to_owned(), self.authorization())],
            body: Vec::new(),
        }
    }

    /// Разобрать ответ на [`YooKassa::status_request`] — единственный путь к
    /// зачислению.
    pub fn settle(&self, response: &[u8]) -> Result<PaymentEvent, Error> {
        #[derive(Deserialize)]
        struct Body {
            id: String,
            status: String,
            amount: Amount,
            metadata: Option<Metadata>,
        }
        #[derive(Deserialize)]
        struct Amount {
            value: String,
            currency: String,
        }
        #[derive(Deserialize)]
        struct Metadata {
            order_id: Option<String>,
        }

        let body: Body = serde_json::from_slice(response)
            .map_err(|_| Error::Malformed("ответ о платеже не разбирается"))?;

        let status = match body.status.as_str() {
            "succeeded" => PaymentStatus::Paid,
            "canceled" => PaymentStatus::Failed,
            "pending" | "waiting_for_capture" => PaymentStatus::Pending,
            _ => return Err(Error::Malformed("незнакомое состояние платежа")),
        };

        let currency =
            Currency::parse(&body.amount.currency).ok_or(Error::Malformed("неизвестная валюта"))?;
        let amount = Money::parse_decimal(&body.amount.value, currency)
            .ok_or(Error::Malformed("сумма не разбирается"))?;

        // Номер заказа мы клали в metadata сами при создании платежа. Если
        // его нет — платёж не наш либо создан мимо этого кода, и молча
        // угадывать заказ по сумме нельзя.
        let order = body
            .metadata
            .and_then(|m| m.order_id)
            .and_then(|id| OrderId::new(&id))
            .ok_or(Error::Malformed("в платеже нет номера заказа"))?;

        Ok(PaymentEvent {
            order,
            status,
            paid: Some(amount),
            reference: body.id,
        })
    }

    /// Пришло ли уведомление из сети ЮKassa.
    ///
    /// Второй рубеж. Отдельно от [`YooKassa::settle`] намеренно: соблазн
    /// зачислить «раз уж адрес правильный» надо исключить, поэтому проверка
    /// адреса ничего не возвращает, кроме `bool`.
    #[must_use]
    pub fn is_trusted_source(ip: core::net::Ipv4Addr) -> bool {
        let value = u32::from(ip);
        TRUSTED_V4.iter().any(|(network, bits)| {
            let Ok(base) = network.parse::<core::net::Ipv4Addr>() else {
                return false;
            };
            let mask = if *bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(*bits))
            };
            (u32::from(base) & mask) == (value & mask)
        })
    }
}

impl Provider for YooKassa {
    fn name(&self) -> &'static str {
        "yookassa"
    }

    fn checkout(&self, order: &Order) -> Result<Checkout, Error> {
        Ok(Checkout::Request(self.create(order)))
    }

    fn checkout_page(&self, response: &[u8]) -> Result<String, Error> {
        #[derive(Deserialize)]
        struct Body {
            confirmation: Option<Confirmation>,
            description: Option<String>,
        }
        #[derive(Deserialize)]
        struct Confirmation {
            confirmation_url: Option<String>,
        }

        let body: Body = serde_json::from_slice(response)
            .map_err(|_| Error::Malformed("ответ на создание платежа не разбирается"))?;

        let Some(url) = body.confirmation.and_then(|c| c.confirmation_url) else {
            // ЮKassa кладёт причину отказа в `description`. Передать её
            // дальше полезнее, чем «что-то пошло не так».
            return Err(match body.description {
                Some(reason) => Error::Rejected(reason),
                None => Error::Malformed("в ответе нет ссылки на оплату"),
            });
        };
        Ok(url)
    }

    /// У ЮKassa зачисления по уведомлению не существует.
    ///
    /// Уведомление не подписано, поэтому «разобрать уведомление и выдать
    /// подписку» — это выдать подписку любому, кто нашёл адрес обработчика.
    /// Путь один: [`YooKassa::notice`], затем [`YooKassa::status_request`],
    /// затем [`YooKassa::settle`].
    fn callback(&self, _callback: &Callback) -> Result<PaymentEvent, Error> {
        Err(Error::Unsupported)
    }
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
    use super::{escape, Event, PaymentId, YooKassa};
    use crate::event::{PaymentEvent, PaymentStatus};
    use crate::http::{Callback, Checkout, Method};
    use crate::money::{Currency, Money};
    use crate::order::{order_id, Order, UserId};
    use crate::provider::{Error, Provider};

    fn service() -> Option<YooKassa> {
        YooKassa::new("123456", "test_secret_key", "https://t.me/GloriaVPN_Bot")
    }

    fn order() -> Option<Order> {
        Some(Order {
            id: order_id("u42-d30-7f"),
            user: UserId(42),
            plan: "d30".to_owned(),
            amount: Money::from_minor(19_937, Currency::Rub),
            description: "Gloria VPN, 30 дней".to_owned(),
        })
    }

    fn header<'a>(request: &'a crate::http::Request, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn a_payment_request_is_built_as_the_service_expects() {
        let (Some(service), Some(order)) = (service(), order()) else {
            return;
        };
        let Ok(Checkout::Request(request)) = service.checkout(&order) else {
            return;
        };

        assert_eq!(request.method, Method::Post);
        assert_eq!(request.url, "https://api.yookassa.ru/v3/payments");

        let body = String::from_utf8_lossy(&request.body);
        assert!(body.contains(r#""value":"199.37""#), "сумма: {body}");
        assert!(body.contains(r#""currency":"RUB""#));
        assert!(body.contains(r#""type":"sbp""#), "способ оплаты: {body}");
        assert!(body.contains(r#""order_id":"u42-d30-7f""#));
        assert!(body.contains(r#""capture":true"#));
    }

    /// Заголовок повторяемости обязателен у ЮKassa, и его значение должно
    /// быть привязано к заказу: тогда повтор запроса после сетевого сбоя
    /// вернёт тот же платёж, а не создаст второй счёт тому же человеку.
    #[test]
    fn the_idempotence_key_is_the_order_number() {
        let (Some(service), Some(order)) = (service(), order()) else {
            return;
        };
        let Ok(Checkout::Request(request)) = service.checkout(&order) else {
            return;
        };
        assert_eq!(header(&request, "Idempotence-Key"), Some("u42-d30-7f"));
    }

    #[test]
    fn authorization_is_basic_from_shop_and_key() {
        let (Some(service), Some(order)) = (service(), order()) else {
            return;
        };
        let Ok(Checkout::Request(request)) = service.checkout(&order) else {
            return;
        };
        // base64("123456:test_secret_key")
        assert_eq!(
            header(&request, "Authorization"),
            Some("Basic MTIzNDU2OnRlc3Rfc2VjcmV0X2tleQ==")
        );
    }

    /// Ключ не должен попадать в журналы через отладочную печать.
    #[test]
    fn the_secret_key_never_shows_up_in_debug_output() {
        let Some(service) = service() else { return };
        let printed = format!("{service:?}");
        assert!(!printed.contains("test_secret_key"), "{printed}");
        assert!(printed.contains("скрыт"));
    }

    #[test]
    fn the_payment_page_is_taken_from_the_response() {
        let Some(service) = service() else { return };
        let response = br#"{"id":"2c5c5ae6-0001","status":"pending",
            "confirmation":{"type":"redirect","confirmation_url":"https://yoomoney.ru/checkout/x"}}"#;
        assert_eq!(
            service.checkout_page(response),
            Ok("https://yoomoney.ru/checkout/x".to_owned())
        );
    }

    /// Отказ сервиса передаётся его же словами: «что-то пошло не так»
    /// в поддержке разобрать нельзя.
    #[test]
    fn a_refusal_is_passed_on_in_the_services_own_words() {
        let Some(service) = service() else { return };
        let response = br#"{"type":"error","description":"Idempotence key duplicated"}"#;
        assert_eq!(
            service.checkout_page(response),
            Err(Error::Rejected("Idempotence key duplicated".to_owned()))
        );
    }

    // --- уведомления -------------------------------------------------------

    fn notification(event: &str, id: &str) -> Callback {
        Callback::new(
            Vec::new(),
            format!(
                r#"{{"type":"notification","event":"{event}",
                    "object":{{"id":"{id}","status":"succeeded",
                    "amount":{{"value":"100000.00","currency":"RUB"}}}}}}"#
            )
            .into_bytes(),
        )
    }

    #[test]
    fn a_notification_yields_only_the_event_and_the_payment_number() {
        let Some(service) = service() else { return };
        let parsed = service.notice(&notification("payment.succeeded", "2c5c5ae6-0001"));
        assert!(parsed.is_ok(), "уведомление не разобралось: {parsed:?}");
        let Ok(notice) = parsed else { return };
        assert_eq!(notice.event, Event::Succeeded);
        assert_eq!(notice.payment_id.as_str(), "2c5c5ae6-0001");
    }

    /// Главная проверка модуля. В теле уведомления стоит сумма в сто тысяч
    /// и состояние «оплачено», но выдать по ним подписку нельзя: у сервиса
    /// нет пути от уведомления к зачислению.
    #[test]
    fn a_notification_can_never_settle_an_order_by_itself() {
        let Some(service) = service() else { return };
        assert_eq!(
            service.callback(&notification("payment.succeeded", "2c5c5ae6-0001")),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn a_notification_with_a_tampered_payment_number_is_refused() {
        let Some(service) = service() else { return };
        for bad in [
            "../refunds/1",
            "2c5c/../x",
            "id?query=1",
            "id&x=1",
            "плат1",
            "",
        ] {
            assert!(
                service
                    .notice(&notification("payment.succeeded", bad))
                    .is_err(),
                "принят номер платежа {bad:?}"
            );
        }
    }

    #[test]
    fn a_body_that_is_not_a_notification_is_refused() {
        let Some(service) = service() else { return };
        let body = Callback::new(Vec::new(), br#"{"type":"object","event":"x"}"#.to_vec());
        assert!(service.notice(&body).is_err());
        assert!(service
            .notice(&Callback::new(Vec::new(), b"not json".to_vec()))
            .is_err());
    }

    // --- зачисление --------------------------------------------------------

    fn payment(status: &str, value: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"2c5c5ae6-0001","status":"{status}","paid":true,
                "amount":{{"value":"{value}","currency":"RUB"}},
                "metadata":{{"order_id":"u42-d30-7f"}}}}"#
        )
        .into_bytes()
    }

    /// Разобрать ответ о платеже, провалив тест с внятным сообщением, если
    /// разобрать не вышло. Иначе каждая проверка ниже начиналась бы с трёх
    /// строк обвязки, за которыми теряется то, что она проверяет.
    fn settled(service: &YooKassa, response: &[u8]) -> Option<PaymentEvent> {
        let parsed = service.settle(response);
        assert!(parsed.is_ok(), "ответ не разобрался: {parsed:?}");
        parsed.ok()
    }

    #[test]
    fn a_succeeded_payment_settles_the_order() {
        let Some(service) = service() else { return };
        let Some(event) = settled(&service, &payment("succeeded", "199.37")) else {
            return;
        };
        assert_eq!(event.status, PaymentStatus::Paid);
        assert_eq!(event.order.as_str(), "u42-d30-7f");
        assert_eq!(event.paid, Some(Money::from_minor(19_937, Currency::Rub)));
        assert!(event.settles(Money::from_minor(19_937, Currency::Rub)));
    }

    #[test]
    fn an_unfinished_payment_does_not_settle() {
        let Some(service) = service() else { return };
        for status in ["pending", "waiting_for_capture"] {
            let Some(event) = settled(&service, &payment(status, "199.37")) else {
                return;
            };
            assert_eq!(event.status, PaymentStatus::Pending);
            assert!(!event.settles(Money::from_minor(19_937, Currency::Rub)));
        }
    }

    #[test]
    fn a_canceled_payment_does_not_settle() {
        let Some(service) = service() else { return };
        let Some(event) = settled(&service, &payment("canceled", "199.37")) else {
            return;
        };
        assert_eq!(event.status, PaymentStatus::Failed);
        assert!(!event.settles(Money::from_minor(19_937, Currency::Rub)));
    }

    /// Недоплата не выдаёт подписку. Проверка живёт в `PaymentEvent`, но
    /// закрепляется и здесь: это то место, где потеря денег незаметна.
    #[test]
    fn an_underpayment_does_not_settle() {
        let Some(service) = service() else { return };
        let Some(event) = settled(&service, &payment("succeeded", "100.00")) else {
            return;
        };
        assert!(!event.settles(Money::from_minor(19_937, Currency::Rub)));
    }

    /// Платёж без номера заказа не зачисляется: угадывать заказ по сумме
    /// нельзя, а молчаливое «похоже, это он» — способ выдать подписку не тому.
    #[test]
    fn a_payment_without_our_order_number_is_refused() {
        let Some(service) = service() else { return };
        let response = br#"{"id":"x-1","status":"succeeded",
            "amount":{"value":"199.37","currency":"RUB"}}"#;
        assert!(service.settle(response).is_err());
    }

    // --- сеть отправителя --------------------------------------------------

    #[test]
    fn notifications_from_the_services_networks_are_recognised() {
        for ip in [
            "185.71.76.1",
            "185.71.77.30",
            "77.75.153.100",
            "77.75.156.11",
            "77.75.156.35",
            "77.75.154.200",
        ] {
            let Ok(parsed) = ip.parse() else { continue };
            assert!(YooKassa::is_trusted_source(parsed), "{ip} не опознан");
        }
    }

    #[test]
    fn notifications_from_anywhere_else_are_not() {
        for ip in [
            "185.71.76.32",  // за границей /27
            "77.75.156.12",  // соседний с одиночным адресом
            "77.75.154.127", // на единицу ниже /25
            "8.8.8.8",
        ] {
            let Ok(parsed) = ip.parse() else { continue };
            assert!(
                !YooKassa::is_trusted_source(parsed),
                "{ip} опознан ошибочно"
            );
        }
    }

    // --- мелочи, которые ломают тело запроса -------------------------------

    #[test]
    fn quotes_in_the_description_do_not_break_the_body() {
        assert_eq!(escape(r#"тариф "год""#), r#"тариф \"год\""#);
        assert_eq!(escape("две\nстроки"), "две\\nстроки");
        assert_eq!(escape("обратный\\слеш"), "обратный\\\\слеш");
    }

    #[test]
    fn an_empty_credential_does_not_build_a_service() {
        assert!(YooKassa::new("", "key", "https://x").is_none());
        assert!(YooKassa::new("123", "", "https://x").is_none());
        assert!(YooKassa::new("123", "key", "").is_none());
    }

    #[test]
    fn ordinary_payment_numbers_are_accepted() {
        assert!(PaymentId::new("2c5c5ae6-000f-5000-8000-1d2f4c0d3a1e").is_some());
        assert!(PaymentId::new(&"a".repeat(65)).is_none());
    }
}
