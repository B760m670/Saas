//! Freekassa.
//!
//! # Чем этот сервис отличается от остальных
//!
//! **Уведомлению здесь верят.** У ЮKassa подписи нет вовсе, у WATA она есть,
//! но мы её не проверяем — оба сервиса перезапрашивают состояние платежа по
//! своему API. Freekassa устроена иначе: уведомление подписано **секретным
//! словом 2**, и подпись покрывает и сумму, и номер заказа. Значит по
//! проверенному уведомлению можно зачислять — подделать его, не зная
//! секрета, нельзя, а сумма и заказ в нём заверены той же подписью.
//!
//! Поэтому это первый и пока единственный адаптер, у которого
//! [`Provider::callback`] возвращает настоящий [`PaymentEvent`], а не
//! отказ. Ради этого случая метод и задумывался.
//!
//! # Где здесь легко ошибиться
//!
//! Подпись считается по строке, собранной из **сырых** полей уведомления —
//! ровно как они пришли, без разбора и пересборки. `AMOUNT` приходит строкой
//! «198.63»; если её разобрать в сумму и собрать обратно, «198.6» и «198.60»
//! разойдутся, и подпись перестанет сходиться. Поэтому порядок строгий:
//! сначала проверяем подпись по сырым строкам, и только потом, когда она
//! сошлась, разбираем сумму и номер заказа.
//!
//! Секрет для формы (слово 1) и секрет для уведомления (слово 2) — **разные**.
//! Перепутать их — значит либо получить форму, которую Freekassa отвергает,
//! либо принимать уведомления, которые не проверяются. Первое заметно сразу,
//! второе — worst case: бесплатные подписки всем, кто угадал формат.
//!
//! # Что должен сделать вызывающий
//!
//! Два действия сверх разбора, и оба вне этого крейта — здесь их описать
//! негде, а забыть дорого:
//!
//! - На проверенное уведомление ответить телом **`YES`** (см. [`OK_REPLY`]).
//!   Не получив его, Freekassa считает уведомление недоставленным и шлёт
//!   снова — а человек ждёт подписку.
//! - До разбора отсечь чужие адреса по [`TRUSTED_V4`]. Это второй рубеж, не
//!   первый: настоящая защита — подпись. Но отсев по адресу убирает весь шум
//!   от тех, кто просто перебирает открытые обработчики.

use crate::event::{PaymentEvent, PaymentStatus};
use crate::http::{Callback, Checkout};
use crate::money::{Currency, Money};
use crate::order::{Order, OrderId};
use crate::provider::{Error, Provider};
use crate::signature::Scheme;

/// Адрес формы оплаты.
const SCI: &str = "https://pay.fk.money/";

/// Что ответить Freekassa на принятое уведомление.
///
/// Ровно это тело, без переводов строки и пробелов. Любой другой ответ
/// Freekassa считает провалом доставки и повторяет уведомление.
pub const OK_REPLY: &str = "YES";

/// Адреса, с которых Freekassa шлёт уведомления.
///
/// Второй рубеж проверки, а не первый: подлинность доказывает подпись.
/// Но отсечь по адресу дёшево, и это снимает шум от переборщиков открытых
/// обработчиков.
pub const TRUSTED_V4: [&str; 4] = [
    "168.119.157.136",
    "168.119.60.227",
    "178.154.197.79",
    "51.250.54.238",
];

/// Клиент Freekassa.
///
/// Хранит номер магазина и два секрета. `Debug` для них не выводит ничего:
/// секрет в логе — это чужие подписки.
#[derive(Clone)]
pub struct Freekassa {
    merchant: String,
    /// Секрет для подписи формы оплаты (слово 1).
    form_secret: String,
    /// Секрет для проверки уведомления (слово 2).
    notice_secret: String,
}

impl core::fmt::Debug for Freekassa {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Freekassa")
            .field("merchant", &self.merchant)
            .field("form_secret", &"<секрет>")
            .field("notice_secret", &"<секрет>")
            .finish()
    }
}

impl Freekassa {
    /// Собрать клиента.
    ///
    /// Номер магазина обязан быть числом: он подставляется и в адрес формы,
    /// и в строку подписи, и значение с двоеточием сдвинуло бы границы полей
    /// в подписи — ровно то, от чего бережётся [`OrderId`]. Секреты не
    /// проверяются: их набор символов задаёт Freekassa, а пустой секрет
    /// сделал бы подпись бессмысленной, поэтому и он отвергается.
    #[must_use]
    pub fn new(merchant: &str, form_secret: &str, notice_secret: &str) -> Option<Self> {
        if merchant.is_empty() || !merchant.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if form_secret.is_empty() || notice_secret.is_empty() {
            return None;
        }
        Some(Self {
            merchant: merchant.to_owned(),
            form_secret: form_secret.to_owned(),
            notice_secret: notice_secret.to_owned(),
        })
    }

    /// Строка, по которой подписывается уведомление: `магазин:сумма:секрет:заказ`.
    fn notice_message(&self, amount: &str, order: &str) -> String {
        format!("{}:{amount}:{}:{order}", self.merchant, self.notice_secret)
    }
}

impl Provider for Freekassa {
    fn name(&self) -> &'static str {
        "freekassa"
    }

    fn checkout(&self, order: &Order) -> Result<Checkout, Error> {
        // Только рубли: подпись формы включает валюту, и слать не-рубль,
        // не договорившись о его записи, значит получить отказ формы.
        if order.amount.currency() != Currency::Rub {
            return Err(Error::Unsupported);
        }

        // Сумма считается **один раз** и в таком виде уходит и в адрес, и в
        // подпись. Freekassa вернёт её же в уведомлении, и там она войдёт в
        // проверку подписи — записи обязаны совпасть до знака.
        let amount = order.amount.to_decimal();
        let currency = order.amount.currency().code();
        let order_id = order.id.as_str();

        // Подпись формы: магазин, сумма, секрет формы, валюта, заказ.
        let message = format!(
            "{}:{amount}:{}:{currency}:{order_id}",
            self.merchant, self.form_secret
        );
        let sign = Scheme::Md5.sign(message.as_bytes());

        // Все значения безопасны для URL без кодирования: сумма — цифры и
        // точка, валюта и подпись — латиница и цифры, номер заказа charset
        // ограничен [`OrderId`]. Кодировать нечего, а лишнее кодирование
        // сломало бы подпись на стороне Freekassa.
        let url = format!(
            "{SCI}?m={merchant}&oa={amount}&currency={currency}&o={order_id}&s={sign}",
            merchant = self.merchant
        );
        Ok(Checkout::Page(url))
    }

    fn callback(&self, callback: &Callback) -> Result<PaymentEvent, Error> {
        let params = parse_form(&callback.body);

        let field = |name: &str| {
            params
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };

        let (Some(merchant), Some(amount), Some(order), Some(sign)) = (
            field("MERCHANT_ID"),
            field("AMOUNT"),
            field("MERCHANT_ORDER_ID"),
            field("SIGN"),
        ) else {
            return Err(Error::Malformed("в уведомлении не хватает полей"));
        };

        // Чужой магазин — не наше уведомление. Проверяется до подписи: незачем
        // считать хеш для того, что и так адресовано не нам.
        if merchant != self.merchant {
            return Err(Error::BadSignature);
        }

        // Подпись — по сырым строкам, до всякого разбора. Разобрать и собрать
        // обратно значит изменить запись суммы и не сойтись с Freekassa.
        if !Scheme::Md5.verify(self.notice_message(amount, order).as_bytes(), sign) {
            return Err(Error::BadSignature);
        }

        // Подпись сошлась — теперь строкам можно верить и разбирать их.
        let Some(order) = OrderId::new(order) else {
            return Err(Error::Malformed("номер заказа с недопустимым символом"));
        };
        let Some(paid) = Money::parse_decimal(amount, Currency::Rub) else {
            return Err(Error::Malformed("сумму не разобрать"));
        };

        // Уведомление Freekassa приходит только по успешной оплате: отказы
        // до обработчика не доходят. Поэтому состояние — всегда `Paid`.
        // Номер операции кладём в reference для разбора спорных случаев.
        let reference = field("intid").unwrap_or("").to_owned();

        Ok(PaymentEvent {
            order,
            status: PaymentStatus::Paid,
            paid: Some(paid),
            reference,
        })
    }
}

/// Разобрать тело `application/x-www-form-urlencoded` в пары.
///
/// Свой разбор, а не зависимость: формат простой, а лишний ящик в денежном
/// крейте — это ещё одна вещь, за которой надо следить. `+` — пробел,
/// `%XX` — байт; всё прочее как есть.
fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    body.split(|&b| b == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.iter().position(|&b| b == b'=') {
            Some(i) => {
                let (key, rest) = pair.split_at(i);
                // rest начинается с «=»: пропускаем его, не индексируя.
                let value = rest.split_first().map_or(&b""[..], |(_, tail)| tail);
                (percent_decode(key), percent_decode(value))
            }
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

/// Раскодировать один кусок `x-www-form-urlencoded`.
///
/// Без индексов по срезу: разбор идёт итератором, а `%XX` собирается из двух
/// следующих байтов через `next`. Так clippy спокоен, а главное — выхода за
/// границу здесь быть не может по устройству, а не по внимательности.
fn percent_decode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len());
    let mut bytes = input.iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => out.push(b' '),
            b'%' => {
                // Копию — чтобы при неполной или негодной паре вернуть «%» и
                // разбирать дальше с того же места, ничего не потеряв.
                let mut lookahead = bytes.clone();
                let hi = lookahead.next().and_then(|b| (b as char).to_digit(16));
                let lo = lookahead.next().and_then(|b| (b as char).to_digit(16));
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    bytes = lookahead;
                } else {
                    out.push(b'%');
                }
            }
            byte => out.push(byte),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{parse_form, Freekassa, OK_REPLY};
    use crate::http::{Callback, Checkout};
    use crate::money::{Currency, Money};
    use crate::order::{Order, OrderId, UserId};
    use crate::provider::{Error, Provider};
    use crate::signature::Scheme;

    const MERCHANT: &str = "7012";
    const FORM_SECRET: &str = "form-secret-1";
    const NOTICE_SECRET: &str = "notice-secret-2";

    fn service() -> Freekassa {
        match Freekassa::new(MERCHANT, FORM_SECRET, NOTICE_SECRET) {
            Some(service) => service,
            None => unreachable!("клиент обязан собраться"),
        }
    }

    fn order(amount_minor: u64) -> Order {
        Order {
            id: match OrderId::new("u42-d30-123") {
                Some(id) => id,
                None => unreachable!(),
            },
            user: UserId(42),
            plan: "d30".to_owned(),
            amount: Money::from_minor(amount_minor, Currency::Rub),
            description: "Подписка на месяц".to_owned(),
        }
    }

    /// Как Freekassa подпишет настоящее уведомление на эту сумму и заказ.
    fn notice_sign(amount: &str, order: &str) -> String {
        Scheme::Md5.sign(format!("{MERCHANT}:{amount}:{NOTICE_SECRET}:{order}").as_bytes())
    }

    fn notice(amount: &str, order: &str, sign: &str) -> Callback {
        let body = format!(
            "MERCHANT_ID={MERCHANT}&AMOUNT={amount}&intid=987654&MERCHANT_ORDER_ID={order}&SIGN={sign}"
        );
        Callback::new(Vec::new(), body.into_bytes())
    }

    /// Форма оплаты собирается на нужный адрес, с суммой и подписью, и подпись
    /// считается от той же строки суммы, что уходит в `oa`. Разъедься они —
    /// Freekassa отвергнет форму.
    #[test]
    fn a_checkout_form_is_signed_over_the_amount_it_shows() {
        let Ok(Checkout::Page(url)) = service().checkout(&order(19_863)) else {
            unreachable!("Freekassa отдаёт готовую ссылку");
        };

        assert!(url.starts_with("https://pay.fk.money/?"), "{url}");
        assert!(url.contains("m=7012"), "{url}");
        assert!(url.contains("oa=198.63"), "{url}");
        assert!(url.contains("o=u42-d30-123"), "{url}");

        let expected =
            Scheme::Md5.sign(format!("{MERCHANT}:198.63:{FORM_SECRET}:RUB:u42-d30-123").as_bytes());
        assert!(url.contains(&format!("s={expected}")), "{url}");
    }

    /// Главное в модуле: по проверенному уведомлению рождается событие оплаты
    /// на ту сумму, что заверена подписью.
    #[test]
    fn a_signed_notice_settles_the_order() {
        let sign = notice_sign("198.63", "u42-d30-123");
        let Ok(event) = service().callback(&notice("198.63", "u42-d30-123", &sign)) else {
            unreachable!("проверенное уведомление обязано разобраться");
        };

        assert_eq!(event.order.as_str(), "u42-d30-123");
        assert!(event.settles(Money::from_minor(19_863, Currency::Rub)));
        assert_eq!(event.reference, "987654");
    }

    /// Худший случай: подделка без секрета. Один изменённый знак суммы — и
    /// подпись, снятая с прежней суммы, больше не подходит.
    #[test]
    fn a_tampered_amount_is_refused() {
        // Подпись честная для 198.63, а в поле AMOUNT — 1.00.
        let sign = notice_sign("198.63", "u42-d30-123");
        assert_eq!(
            service().callback(&notice("1.00", "u42-d30-123", &sign)),
            Err(Error::BadSignature)
        );
    }

    /// Тем же прикрыт и подменённый заказ: подпись заверяет и его.
    #[test]
    fn a_swapped_order_is_refused() {
        let sign = notice_sign("198.63", "u42-d30-123");
        assert_eq!(
            service().callback(&notice("198.63", "u99-d365-1", &sign)),
            Err(Error::BadSignature)
        );
    }

    /// Уведомление без подписи не проходит через пустое сравнение.
    #[test]
    fn a_notice_without_a_signature_is_refused() {
        assert_eq!(
            service().callback(&notice("198.63", "u42-d30-123", "")),
            Err(Error::BadSignature)
        );
    }

    /// Чужой магазин отсекается до подписи.
    #[test]
    fn a_notice_for_another_merchant_is_refused() {
        let body = "MERCHANT_ID=9999&AMOUNT=198.63&MERCHANT_ORDER_ID=u42-d30-123&SIGN=whatever";
        assert_eq!(
            service().callback(&Callback::new(Vec::new(), body.as_bytes().to_vec())),
            Err(Error::BadSignature)
        );
    }

    /// Секреты формы и уведомления нельзя путать: подпись, снятая секретом
    /// формы, уведомление не проходит.
    #[test]
    fn the_form_secret_does_not_verify_a_notice() {
        let wrong =
            Scheme::Md5.sign(format!("{MERCHANT}:198.63:{FORM_SECRET}:u42-d30-123").as_bytes());
        assert_eq!(
            service().callback(&notice("198.63", "u42-d30-123", &wrong)),
            Err(Error::BadSignature)
        );
    }

    /// Верная подпись, но номер заказа с разделителем — отвергается на
    /// разборе, уже после проверки подписи. Сами такой номер мы не создаём,
    /// но верить ему всё равно нельзя.
    #[test]
    fn a_valid_signature_over_a_dirty_order_is_still_refused() {
        let dirty = "u42:d30";
        let sign = notice_sign("198.63", dirty);
        assert_eq!(
            service().callback(&notice("198.63", dirty, &sign)),
            Err(Error::Malformed("номер заказа с недопустимым символом"))
        );
    }

    /// Разные секреты в конструкторе не перепутаны местами: подпись
    /// уведомления считается именно словом 2.
    #[test]
    fn the_notice_uses_the_second_secret() {
        let sign = notice_sign("198.63", "u42-d30-123");
        assert!(service()
            .callback(&notice("198.63", "u42-d30-123", &sign))
            .is_ok());
    }

    /// Пустой магазин или секрет — не клиент.
    #[test]
    fn a_service_without_credentials_is_not_built() {
        assert!(Freekassa::new("", FORM_SECRET, NOTICE_SECRET).is_none());
        assert!(Freekassa::new("abc", FORM_SECRET, NOTICE_SECRET).is_none());
        assert!(Freekassa::new(MERCHANT, "", NOTICE_SECRET).is_none());
        assert!(Freekassa::new(MERCHANT, FORM_SECRET, "").is_none());
    }

    /// Ответ Freekassa обязан быть ровно «YES».
    #[test]
    fn the_ok_reply_is_exactly_yes() {
        assert_eq!(OK_REPLY, "YES");
    }

    #[test]
    fn form_parsing_splits_pairs_and_decodes() {
        let parsed = parse_form(b"a=1&b=two+words&c=%2B7");
        let pairs: Vec<(&str, &str)> = parsed
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(pairs, vec![("a", "1"), ("b", "two words"), ("c", "+7")]);
    }

    /// Секрет не должен утечь в журнал через Debug.
    #[test]
    fn debug_hides_the_secrets() {
        let shown = format!("{:?}", service());
        assert!(!shown.contains(FORM_SECRET), "{shown}");
        assert!(!shown.contains(NOTICE_SECRET), "{shown}");
        assert!(shown.contains("7012"), "{shown}");
    }
}
