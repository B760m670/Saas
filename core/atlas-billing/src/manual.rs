//! Приём оплаты вручную.
//!
//! Никуда не подключается и ничего не требует: боту показывают реквизиты,
//! человек платит, владелец подтверждает кнопкой. Подписка выдаётся тем же
//! путём, что и при любом другом сервисе, — через [`PaymentEvent`].
//!
//! Смысл не в удобстве, а в очерёдности. Договориться с платёжным сервисом —
//! дело недель, и всё это время неизвестно главное: покупают ли вообще.
//! С этим провайдером бот работает сегодня, а сервис подключается потом
//! заменой одной строки, потому что весь остальной код о деньгах знает
//! только `PaymentEvent`.

use crate::event::{PaymentEvent, PaymentStatus};
use crate::http::{Callback, Checkout};
use crate::money::Money;
use crate::order::Order;
use crate::provider::{Error, Provider};

/// Оплата вне бота с подтверждением владельцем.
#[derive(Debug, Clone)]
pub struct Manual {
    template: String,
}

impl Manual {
    /// Подстановка суммы в шаблон.
    pub const AMOUNT: &'static str = "{amount}";
    /// Подстановка номера заказа в шаблон.
    pub const ORDER: &'static str = "{order}";

    /// Задать текст, который увидит покупатель.
    ///
    /// В шаблоне подставляются [`Manual::AMOUNT`] и [`Manual::ORDER`].
    /// Номер заказа стоит оставить: без него платёж на общий счёт не с чем
    /// сопоставить, и подтверждать придётся по времени и сумме — на паре
    /// покупателей это работает, на двадцати уже нет.
    #[must_use]
    pub fn new(template: impl Into<String>) -> Self {
        Self {
            template: template.into(),
        }
    }

    /// Подтвердить, что деньги получены.
    ///
    /// Вызывать только по действию владельца бота. Проверки здесь нет и быть
    /// не может — сумму подтверждает человек, глядя в банковское приложение.
    /// Если этот вызов окажется доступен покупателю, он выпишет себе подписку
    /// сам, и никакая другая часть кода этому не помешает.
    #[must_use]
    pub fn confirm(&self, order: &Order, received: Money) -> PaymentEvent {
        PaymentEvent {
            order: order.id.clone(),
            status: PaymentStatus::Paid,
            paid: Some(received),
            reference: "manual".to_owned(),
        }
    }

    /// Отметить заказ несостоявшимся.
    #[must_use]
    pub fn decline(&self, order: &Order) -> PaymentEvent {
        PaymentEvent {
            order: order.id.clone(),
            status: PaymentStatus::Failed,
            paid: None,
            reference: "manual".to_owned(),
        }
    }
}

impl Provider for Manual {
    fn name(&self) -> &'static str {
        "manual"
    }

    fn checkout(&self, order: &Order) -> Result<Checkout, Error> {
        let text = self
            .template
            .replace(Self::AMOUNT, &order.amount.to_decimal())
            .replace(Self::ORDER, order.id.as_str());
        Ok(Checkout::Offline(text))
    }

    /// Уведомлять некому: платёж подтверждает человек.
    fn callback(&self, _callback: &Callback) -> Result<PaymentEvent, Error> {
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::Manual;
    use crate::event::PaymentStatus;
    use crate::http::{Callback, Checkout};
    use crate::money::{Currency, Money};
    use crate::order::{order_id, Order, UserId};
    use crate::provider::{Error, Provider};

    fn order() -> Order {
        Order {
            id: order_id("u77-month-1"),
            user: UserId(77),
            plan: "month".to_owned(),
            amount: Money::from_minor(29_900, Currency::Rub),
            description: "Подписка на месяц".to_owned(),
        }
    }

    #[test]
    fn the_template_gets_the_amount_and_the_order_number() {
        let manual = Manual::new("Переведите {amount} ₽ и укажите в комментарии {order}");
        let checkout = manual.checkout(&order());
        assert_eq!(
            checkout,
            Ok(Checkout::Offline(
                "Переведите 299.00 ₽ и укажите в комментарии u77-month-1".to_owned()
            ))
        );
    }

    #[test]
    fn confirmation_settles_the_order() {
        let manual = Manual::new("{amount}");
        let order = order();
        let event = manual.confirm(&order, order.amount);
        assert_eq!(event.status, PaymentStatus::Paid);
        assert_eq!(event.order, order.id);
        assert!(event.settles(order.amount));
    }

    /// Подтверждение на меньшую сумму не закрывает заказ: сверку делает
    /// `settles`, а не тот факт, что владелец нажал кнопку.
    #[test]
    fn confirming_a_smaller_amount_does_not_settle() {
        let manual = Manual::new("{amount}");
        let order = order();
        let event = manual.confirm(&order, Money::from_minor(100, Currency::Rub));
        assert!(!event.settles(order.amount));
    }

    #[test]
    fn declining_does_not_settle() {
        let manual = Manual::new("{amount}");
        let order = order();
        assert!(!manual.decline(&order).settles(order.amount));
    }

    #[test]
    fn there_is_no_webhook_to_forge() {
        let manual = Manual::new("{amount}");
        let callback = Callback::new(Vec::new(), br#"{"status":"paid"}"#.to_vec());
        assert_eq!(manual.callback(&callback), Err(Error::Unsupported));
    }
}
