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
    use super::OrderId;

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
