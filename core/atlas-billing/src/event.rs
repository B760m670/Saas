//! Событие оплаты — то единственное, на чём висит выдача подписки.
//!
//! Ни бот, ни выдача ключей не знают, через какой сервис пришли деньги. Они
//! знают только это событие. Смена платёжного сервиса поэтому не задевает
//! ничего, кроме одного адаптера.

use serde::{Deserialize, Serialize};

use crate::money::Money;
use crate::order::OrderId;

/// Чем кончился платёж.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentStatus {
    /// Счёт выставлен, денег пока нет.
    Pending,
    /// Деньги получены. Только это состояние выдаёт подписку.
    Paid,
    /// Отказ, отмена или истёкший срок счёта.
    Failed,
    /// Деньги вернули покупателю после того, как платёж прошёл.
    ///
    /// Отдельно от `Failed`, потому что реакция другая: подписка уже выдана
    /// и её надо отозвать.
    Refunded,
}

/// Разобранное и проверенное уведомление сервиса.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentEvent {
    /// Заказ, к которому относится платёж.
    pub order: OrderId,
    /// Состояние платежа.
    pub status: PaymentStatus,
    /// Сколько на самом деле заплатили.
    ///
    /// Отдельно от суммы заказа намеренно: сервисы иногда зачисляют меньше
    /// выставленного — округление, комиссия на стороне плательщика, частичная
    /// оплата. Сверять обязан вызывающий, и сверять он должен именно это
    /// поле, а не то, что сам же выставил.
    pub paid: Option<Money>,
    /// Номер платежа на стороне сервиса — для разбора спорных случаев.
    pub reference: String,
}

impl PaymentEvent {
    /// Оплачен ли заказ на нужную сумму.
    ///
    /// Ровно две причины выдать подписку: состояние `Paid` и сумма не меньше
    /// выставленной. Проверять только состояние недостаточно — иначе счёт на
    /// 2880 ₽ закрывается платежом на рубль.
    #[must_use]
    pub fn settles(&self, expected: Money) -> bool {
        if self.status != PaymentStatus::Paid {
            return false;
        }
        match self.paid {
            Some(paid) => {
                paid.currency() == expected.currency() && paid.minor() >= expected.minor()
            }
            // Сумму не прислали — сверить нечем, решение принимает человек.
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PaymentEvent, PaymentStatus};
    use crate::money::{Currency, Money};
    use crate::order::order_id;

    fn event(status: PaymentStatus, paid: Option<Money>) -> PaymentEvent {
        PaymentEvent {
            order: order_id("order-1"),
            status,
            paid,
            reference: "ref".to_owned(),
        }
    }

    fn rub(minor: u64) -> Money {
        Money::from_minor(minor, Currency::Rub)
    }

    #[test]
    fn a_full_payment_settles() {
        assert!(event(PaymentStatus::Paid, Some(rub(29_900))).settles(rub(29_900)));
    }

    #[test]
    fn an_overpayment_settles_too() {
        assert!(event(PaymentStatus::Paid, Some(rub(30_000))).settles(rub(29_900)));
    }

    /// Главный случай: состояние верное, а денег меньше.
    #[test]
    fn a_short_payment_does_not_settle() {
        assert!(!event(PaymentStatus::Paid, Some(rub(100))).settles(rub(29_900)));
    }

    #[test]
    fn a_payment_in_another_currency_does_not_settle() {
        let paid = Money::from_minor(29_900, Currency::Usdt);
        assert!(!event(PaymentStatus::Paid, Some(paid)).settles(rub(29_900)));
    }

    #[test]
    fn a_missing_amount_does_not_settle() {
        assert!(!event(PaymentStatus::Paid, None).settles(rub(29_900)));
    }

    #[test]
    fn only_paid_settles() {
        for status in [
            PaymentStatus::Pending,
            PaymentStatus::Failed,
            PaymentStatus::Refunded,
        ] {
            assert!(!event(status, Some(rub(29_900))).settles(rub(29_900)));
        }
    }
}
