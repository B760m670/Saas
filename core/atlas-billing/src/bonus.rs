//! Бонусы за приглашённых: начисление и скидка.
//!
//! Один бонус — один рубль скидки. Начисляются они пригласившему, когда
//! приведённый им человек оплатил подписку, и тратятся при следующей
//! покупке.
//!
//! Здесь только правила: сколько начислить и сколько разрешено списать.
//! Ни базы, ни времени, ни знания о том, кто кого привёл, — всё это выше.
//!
//! # Почему скидка не может покрыть счёт целиком
//!
//! Платёж узнаётся по сумме перевода, и другого способа у нас нет (см.
//! [`crate::invoice`]). Счёт, закрытый бонусами полностью, не оставляет
//! перевода — опознавать нечего, подтверждать нечего. Поэтому есть потолок:
//! списать можно не больше половины цены.
//!
//! Потолок заодно ограничивает и убыток: сколько бы друзей человек ни
//! привёл, с каждой его покупки приходит хотя бы половина цены.
//!
//! # Почему начисление — десятая часть, а не пятая
//!
//! Дело не в скупости, а в том, что начисленное должно быть тратимым.
//! Потолок разрешает списать 99 ₽ с месячной подписки. При пятой части
//! трое приведённых дают 120 бонусов в месяц — и двадцать один из них
//! ежемесячно ложится мёртвым грузом, потому что списать их некуда.
//!
//! Обещание, которое невозможно исполнить, хуже меньшего обещания. При
//! десятой части начисление догоняет потолок только на шестом приведённом.

use crate::money::{Currency, Money};

/// Какая часть платежа возвращается пригласившему, в сотых долях.
///
/// Десятая часть. Число здесь, а не в боте: это денежное правило, и второго
/// места, где оно живёт, быть не должно.
const EARN_PERCENT: u64 = 10;

/// Какую часть цены разрешено закрыть бонусами, в сотых долях.
const SPEND_PERCENT: u64 = 50;

/// Сколько бонусов приносит оплата.
///
/// `None` — за эту оплату бонусов нет.
///
/// Так отвечают платежи не в рублях: бонус измеряется в рублях, и начислить
/// его за USDT можно только по какому-то курсу. Курса в денежном ядре нет и
/// быть не должно — выдуманный здесь, он тихо расходился бы с настоящим.
///
/// Округление **вверх**: 10 % от 199 ₽ — это 19,90, а человек получает 20.
/// Та же линия, что и у выгоды тарифов и у хвоста счёта: расхождение всегда
/// в пользу покупателя.
#[must_use]
pub fn earned(paid: Money) -> Option<u64> {
    if paid.currency() != Currency::Rub {
        return None;
    }

    let scale = 10u64.pow(Currency::Rub.exponent());
    // Делим на сто (доля) и на scale (копейки в рубль) одним делением с
    // округлением вверх: два округления подряд дали бы лишний рубль.
    let numerator = paid.minor().checked_mul(EARN_PERCENT)?;
    let denominator = 100u64.checked_mul(scale)?;

    Some(numerator.div_ceil(denominator))
}

/// Сколько бонусов разрешено списать с этой цены.
///
/// Округление **вниз**: половина от 199 ₽ — это 99 ₽, а не 100. Перебор
/// здесь нарушал бы собственное правило «не больше половины».
#[must_use]
pub fn cap(price: Money) -> u64 {
    if price.currency() != Currency::Rub {
        return 0;
    }

    let scale = 10u64.pow(Currency::Rub.exponent());
    price.minor().saturating_mul(SPEND_PERCENT) / (100 * scale)
}

/// Во что обойдётся покупка с учётом бонусов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Сколько перевести деньгами.
    pub to_pay: Money,
    /// Сколько бонусов при этом спишется.
    pub spent: u64,
}

/// Применить бонусы к цене.
///
/// Списывается столько, сколько есть, но не больше потолка. Остаток к
/// переводу — всегда хотя бы половина цены, и этого с запасом хватает
/// [`crate::invoice::allocate`], которому нужна сумма больше одного хвоста.
#[must_use]
pub fn apply(price: Money, balance: u64) -> Applied {
    let spent = balance.min(cap(price));
    let scale = 10u64.pow(price.currency().exponent());
    let off = spent.saturating_mul(scale);

    Applied {
        to_pay: Money::from_minor(price.minor().saturating_sub(off), price.currency()),
        spent,
    }
}

#[cfg(test)]
mod tests {
    use super::{apply, cap, earned, Applied};
    use crate::invoice::{allocate, TakenAmounts};
    use crate::money::{Currency, Money};

    fn rub(major: u64) -> Money {
        Money::from_major(major, Currency::Rub).expect("рубли")
    }

    /// Начисление считается от того, что человек заплатил, и округляется в
    /// его пользу.
    #[test]
    fn a_payment_earns_a_tenth_rounded_up() {
        assert_eq!(earned(rub(199)), Some(20), "19,90 обязаны стать двадцатью");
        assert_eq!(earned(rub(499)), Some(50));
        assert_eq!(earned(rub(790)), Some(79));
        assert_eq!(earned(rub(1290)), Some(129));
    }

    /// Хвост счёта уменьшает уплаченное на копейки, и начисление считается
    /// от него же. Округление вверх не даёт копейкам съесть бонус.
    #[test]
    fn the_kopeck_tail_does_not_eat_a_bonus() {
        // 198,01 — самый дальний хвост месячной подписки.
        assert_eq!(earned(Money::from_minor(19_801, Currency::Rub)), Some(20));
    }

    /// Мелочь тоже что-то приносит: ноль за оплату выглядел бы поломкой.
    #[test]
    fn even_a_small_payment_earns_something() {
        assert_eq!(earned(Money::from_minor(1, Currency::Rub)), Some(1));
        assert_eq!(earned(rub(0)), Some(0));
    }

    /// Бонус измеряется в рублях, и курса в денежном ядре нет.
    #[test]
    fn a_payment_in_another_currency_earns_nothing() {
        assert_eq!(earned(Money::from_minor(2_550_000, Currency::Usdt)), None);
        assert_eq!(cap(Money::from_minor(2_550_000, Currency::Usdt)), 0);
    }

    /// Половина — и ни копейкой больше.
    #[test]
    fn the_cap_is_half_rounded_down() {
        assert_eq!(cap(rub(199)), 99, "99,5 обязаны стать девяноста девятью");
        assert_eq!(cap(rub(499)), 249);
        assert_eq!(cap(rub(790)), 395);
        assert_eq!(cap(rub(1290)), 645);
    }

    /// Обычный случай: бонусов меньше потолка, списываются все.
    #[test]
    fn a_small_balance_is_spent_whole() {
        assert_eq!(
            apply(rub(199), 40),
            Applied {
                to_pay: rub(159),
                spent: 40
            }
        );
    }

    /// Большой счёт упирается в потолок, а не закрывает покупку целиком.
    #[test]
    fn a_large_balance_stops_at_the_cap() {
        assert_eq!(
            apply(rub(199), 5_000),
            Applied {
                to_pay: rub(100),
                spent: 99
            }
        );
    }

    /// Пустой счёт ничего не меняет.
    #[test]
    fn an_empty_balance_changes_nothing() {
        assert_eq!(
            apply(rub(199), 0),
            Applied {
                to_pay: rub(199),
                spent: 0
            }
        );
    }

    /// Главное свойство: после скидки счёт всё ещё можно выставить.
    ///
    /// Платёж узнаётся по сумме перевода. Счёт, закрытый бонусами целиком,
    /// не оставил бы перевода — и опознавать было бы нечего. Проверяется на
    /// всех тарифах и на заведомо огромном счёте бонусов.
    #[test]
    fn a_discounted_order_can_still_be_invoiced() {
        for major in [199, 499, 790, 1290] {
            let price = rub(major);
            let applied = apply(price, u64::MAX);

            assert!(
                applied.to_pay.minor() * 2 >= price.minor(),
                "с {major} ₽ списали больше половины"
            );
            assert!(
                allocate(applied.to_pay, &TakenAmounts::new()).is_ok(),
                "счёт со скидкой не выставляется при цене {major} ₽"
            );
        }
    }

    /// Списанное и оплаченное вместе дают цену: рубли не теряются и не
    /// появляются из ниоткуда.
    #[test]
    fn nothing_is_lost_between_money_and_bonuses() {
        for balance in [0, 1, 40, 99, 100, 1_000] {
            let price = rub(199);
            let applied = apply(price, balance);
            assert_eq!(
                applied.to_pay.minor() + applied.spent * 100,
                price.minor(),
                "баланс {balance} рассыпал цену"
            );
        }
    }
}
