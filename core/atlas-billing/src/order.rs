//! Заказ: что человек покупает и за сколько.

use serde::{Deserialize, Serialize};

use crate::money::Money;

/// Покупатель. Численно совпадает с идентификатором пользователя Telegram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserId(pub i64);

/// Номер заказа — то, по чему платёж находит свой заказ на возврате.
///
/// Набор символов ограничен намеренно. Номер попадает в строку запроса и в
/// строку, по которой считается подпись, а разделителем в этой строке у
/// разных сервисов служит то двоеточие, то `:`-склейка полей подряд. Номер,
/// в который можно вписать разделитель, позволяет сдвинуть границы полей и
/// подписать одной подписью два разных набора данных — сумму в том числе.
/// Поэтому разделители в номер попасть не могут в принципе.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct OrderId(String);

impl OrderId {
    /// Наибольшая длина. Сервисы обрезают длинные номера молча, а обрезанный
    /// номер не находит свой заказ.
    pub const MAX_LEN: usize = 64;

    /// Проверить и принять номер заказа.
    ///
    /// Допускаются латинские буквы, цифры, `-` и `_`.
    #[must_use]
    pub fn new(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > Self::MAX_LEN {
            return None;
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
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

impl<'de> Deserialize<'de> for OrderId {
    /// Проверка charset действует и на разборе: номер приходит обратно из
    /// уведомления, то есть снаружи, и доверять ему нельзя ровно так же.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(&raw).ok_or_else(|| serde::de::Error::custom("недопустимый номер заказа"))
    }
}

/// Номер заказа из заведомо допустимого литерала — для тестов других модулей,
/// которым поле `OrderId` не видно.
#[cfg(test)]
pub(crate) fn order_id(value: &str) -> OrderId {
    match OrderId::new(value) {
        Some(id) => id,
        None => unreachable!("тестовый номер заказа обязан быть допустимым"),
    }
}

/// Тариф — то, что выбирают в боте.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// Внутреннее имя тарифа, например `month` или `year`.
    pub id: String,
    /// Как тариф называется для покупателя.
    pub title: String,
    /// Срок подписки в днях.
    pub days: u32,
    /// Сколько устройств разрешено одновременно.
    pub devices: u8,
    /// Цена.
    pub price: Money,
}

/// Дней в месяце для пересчёта цены. Календарь здесь не нужен: число
/// используется только для витрины, а не для отсчёта срока подписки.
const DAYS_IN_MONTH: u128 = 30;

impl Plan {
    /// Цена в пересчёте на месяц — то, что показывается под кнопкой.
    #[must_use]
    pub fn monthly_price(&self) -> Option<Money> {
        let days = u128::from(self.days);
        if days == 0 {
            return None;
        }
        let minor = u128::from(self.price.minor())
            .checked_mul(DAYS_IN_MONTH)?
            .checked_div(days)?;
        u64::try_from(minor)
            .ok()
            .map(|minor| Money::from_minor(minor, self.price.currency()))
    }

    /// Выгода против помесячной оплаты того же срока, в целых процентах.
    ///
    /// Округление до ближайшего. Разница между показанным и настоящим
    /// значением не превышает половины процентного пункта, и это то, что
    /// нужно проверять при каждой правке цен: витрина, обещающая больше,
    /// чем даёт, — это претензия от покупателя, а не косметика.
    #[must_use]
    pub fn discount_percent(&self, monthly_base: Money) -> Option<u32> {
        if monthly_base.currency() != self.price.currency() {
            return None;
        }
        // Во что обошёлся бы тот же срок помесячно.
        let full = u128::from(monthly_base.minor())
            .checked_mul(u128::from(self.days))?
            .checked_div(DAYS_IN_MONTH)?;
        let price = u128::from(self.price.minor());
        if full == 0 || price >= full {
            return Some(0);
        }
        let saved = full - price;
        // saved / full в процентах с округлением до ближайшего целого.
        let percent = saved
            .checked_mul(200)?
            .checked_add(full)?
            .checked_div(full.checked_mul(2)?)?;
        u32::try_from(percent).ok()
    }
}

/// Выставленный заказ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// Номер, по которому платёж вернётся к заказу.
    pub id: OrderId,
    /// Кто платит.
    pub user: UserId,
    /// Имя тарифа (`Plan::id`).
    pub plan: String,
    /// Сумма к оплате.
    pub amount: Money,
    /// Назначение платежа — его видит покупатель на странице оплаты.
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::{OrderId, Plan};
    use crate::money::{Currency, Money};

    /// Витрина Gloria VPN. Цены и показываемая выгода — как в
    /// `docs/14-bot.md`, раздел 2.
    const SHOWCASE: [(u32, u64, u32); 4] = [
        // дней, цена в рублях, показываемая выгода в процентах
        (30, 199, 0),
        (90, 499, 16),
        (180, 790, 34),
        (365, 1290, 46),
    ];

    fn plan(days: u32, rubles: u64) -> Option<Plan> {
        Some(Plan {
            id: format!("d{days}"),
            title: format!("{days} дней"),
            days,
            devices: 4,
            price: Money::from_major(rubles, Currency::Rub)?,
        })
    }

    /// Главная проверка витрины: обещанная выгода не должна расходиться с
    /// настоящей больше, чем на округление. Правка цены, которая сделает
    /// надпись неправдой, обязана ронять сборку — иначе расхождение первым
    /// заметит покупатель.
    #[test]
    fn advertised_discounts_stay_truthful() {
        let Some(base) = Money::from_major(199, Currency::Rub) else {
            return;
        };
        let mut checked = 0;
        for (days, rubles, advertised) in SHOWCASE {
            let Some(plan) = plan(days, rubles) else {
                continue;
            };
            let Some(actual) = plan.discount_percent(base) else {
                continue;
            };
            assert!(
                actual.abs_diff(advertised) <= 1,
                "{days} дней: показываем −{advertised}%, на деле −{actual}%"
            );
            checked += 1;
        }
        // Иначе тест зеленел бы, пропустив всю витрину молча.
        assert_eq!(
            checked,
            SHOWCASE.len(),
            "часть тарифов осталась непроверенной"
        );
    }

    #[test]
    fn a_monthly_plan_has_no_discount_against_itself() {
        let Some(base) = Money::from_major(199, Currency::Rub) else {
            return;
        };
        let Some(month) = plan(30, 199) else { return };
        assert_eq!(month.discount_percent(base), Some(0));
        assert_eq!(month.monthly_price(), Some(base));
    }

    #[test]
    fn the_year_costs_about_a_hundred_and_six_a_month() {
        let Some(year) = plan(365, 1290) else { return };
        assert_eq!(
            year.monthly_price(),
            Some(Money::from_minor(10_602, Currency::Rub))
        );
    }

    /// Тариф дороже помесячного не должен показывать отрицательную выгоду.
    #[test]
    fn a_plan_with_no_saving_shows_zero() {
        let Some(base) = Money::from_major(199, Currency::Rub) else {
            return;
        };
        let Some(overpriced) = plan(90, 700) else {
            return;
        };
        assert_eq!(overpriced.discount_percent(base), Some(0));
    }

    #[test]
    fn a_plan_priced_in_another_currency_has_no_comparable_discount() {
        let Some(base) = Money::from_major(199, Currency::Rub) else {
            return;
        };
        let mut plan = match plan(90, 499) {
            Some(plan) => plan,
            None => return,
        };
        plan.price = Money::from_minor(5_000_000, Currency::Usdt);
        assert_eq!(plan.discount_percent(base), None);
    }

    #[test]
    fn ordinary_order_numbers_are_accepted() {
        for value in ["1", "a1b2", "order-42", "u1000_m3", &"a".repeat(64)] {
            assert!(OrderId::new(value).is_some(), "отвергнут номер {value:?}");
        }
    }

    /// Ровно те символы, которыми можно сдвинуть границы полей в строке
    /// подписи или вылезти из параметра в URL.
    #[test]
    fn separators_never_reach_the_order_number() {
        for value in [
            "order:42",
            "order|42",
            "order 42",
            "order&42",
            "order=42",
            "order/42",
            "order#42",
            "order\n42",
            "order%3A42",
            "заказ42",
        ] {
            assert!(OrderId::new(value).is_none(), "принят номер {value:?}");
        }
    }

    #[test]
    fn empty_and_overlong_numbers_are_rejected() {
        assert!(OrderId::new("").is_none());
        assert!(OrderId::new(&"a".repeat(65)).is_none());
    }

    /// Номер приходит обратно снаружи — проверка обязана работать и на разборе.
    #[test]
    fn deserialization_applies_the_same_rule() {
        assert!(serde_json::from_str::<OrderId>(r#""order-42""#).is_ok());
        assert!(serde_json::from_str::<OrderId>(r#""order:42""#).is_err());
    }
}
