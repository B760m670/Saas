//! Счёт на уникальную сумму.
//!
//! # Зачем
//!
//! Главная трудность приёма денег — не «получить», а понять, **чей** это
//! платёж. Обычно её решают доступом к счёту: банк присылает уведомление с
//! номером заказа. У счёта физического лица такого доступа нет ни у одного
//! банка, и не появится.
//!
//! Выдумка обходит задачу целиком: счёт выставляется на сумму, которая среди
//! открытых счетов встречается ровно один раз. Пришло 198,63 — значит
//! заплатил тот, кому мы назвали 198,63. Ни назначения платежа, ни API, ни
//! доверия к тому, что покупатель что-то правильно впишет.
//!
//! Тот же приём работает и в блокчейне, где у USDT шесть знаков после
//! запятой, а значит и запас на порядки больше.
//!
//! # Два правила, которые здесь важнее остального
//!
//! **Хвост вычитается, а не прибавляется.** Кнопка обещает 199 ₽ — значит
//! больше 199 ₽ мы взять не имеем права. Счёт на 199,37 брал бы на 37 копеек
//! больше обещанного; счёт на 198,63 берёт меньше. Это та же линия, что и с
//! округлением выгоды вниз: покупатель получает чуть больше обещанного и
//! никогда меньше.
//!
//! **Круглая сумма не выдаётся никогда.** Человек, платящий по памяти,
//! отправит ровно 199 ₽. Если бы круглая сумма была кому-то назначена, такой
//! платёж зачислился бы **чужому** заказу. Поэтому круглая сумма не
//! принадлежит никому, и платёж на неё уходит в ручной разбор — туда, где
//! человек разберётся, чей он.

use std::collections::BTreeSet;

use crate::money::Money;

/// Суммы открытых счетов, в минорных единицах.
///
/// Отдельный тип, а не голое множество чисел: он читается на месте
/// использования и не даёт случайно передать сюда что-нибудь другое,
/// измеряемое в тех же копейках.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TakenAmounts(BTreeSet<u64>);

impl TakenAmounts {
    /// Ни одного открытого счёта.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Отметить сумму занятой.
    pub fn insert(&mut self, minor: u64) {
        self.0.insert(minor);
    }

    /// Занята ли сумма.
    #[must_use]
    pub fn contains(&self, minor: u64) -> bool {
        self.0.contains(&minor)
    }

    /// Сколько счетов открыто.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Нет ли открытых счетов.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<u64> for TakenAmounts {
    fn from_iter<I: IntoIterator<Item = u64>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Почему счёт не удалось выставить.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Все хвосты для этой цены заняты.
    ///
    /// Значит одновременно открыто столько счетов, сколько хвостов бывает.
    /// Для рубля это 99 — при жизни счёта в 20 минут соответствует примерно
    /// семи тысячам оплат в сутки на один тариф.
    NoFreeAmount,
    /// Цена меньше самого хвоста — вычитать не из чего.
    PriceTooSmall,
}

/// Наибольший хвост для валюты: все знаки после запятой, кроме нулевого.
fn max_tail(price: Money) -> u64 {
    10u64.pow(price.currency().exponent()).saturating_sub(1)
}

/// Подобрать сумму счёта, не совпадающую ни с одним открытым счётом.
///
/// Возвращает сумму **строго меньше** объявленной цены и **никогда не
/// круглую**. Из свободных берётся ближайшая к цене: покупатель платит
/// настолько близко к обещанному, насколько позволяет занятость.
pub fn allocate(price: Money, taken: &TakenAmounts) -> Result<Money, Error> {
    let ceiling = max_tail(price);
    if price.minor() <= ceiling {
        return Err(Error::PriceTooSmall);
    }

    // Хвост начинается с единицы: ноль дал бы круглую сумму, а она не
    // принадлежит никому намеренно.
    for tail in 1..=ceiling {
        let candidate = price.minor().saturating_sub(tail);
        if !taken.contains(candidate) {
            return Ok(Money::from_minor(candidate, price.currency()));
        }
    }

    Err(Error::NoFreeAmount)
}

/// Найти счёт по пришедшей сумме.
///
/// Возвращает `None`, если такой суммы среди открытых счетов нет, — в том
/// числе для круглой суммы. Такой платёж не теряется: он уходит в ручной
/// разбор, где человек решит, чей он.
#[must_use]
pub fn matches(paid: Money, taken: &TakenAmounts) -> bool {
    taken.contains(paid.minor())
}

#[cfg(test)]
mod tests {
    use super::{allocate, matches, Error, TakenAmounts};
    use crate::money::{Currency, Money};

    fn rub(minor: u64) -> Money {
        Money::from_minor(minor, Currency::Rub)
    }

    fn price() -> Money {
        rub(19_900) // 199,00 ₽
    }

    #[test]
    fn the_first_invoice_is_as_close_to_the_price_as_possible() {
        let Ok(amount) = allocate(price(), &TakenAmounts::new()) else {
            return;
        };
        assert_eq!(amount, rub(19_899)); // 198,99 ₽
    }

    /// Кнопка обещает 199 ₽ — значит больше 199 ₽ брать нельзя.
    #[test]
    fn an_invoice_never_asks_for_more_than_the_advertised_price() {
        let mut taken = TakenAmounts::new();
        for _ in 0..99 {
            let Ok(amount) = allocate(price(), &taken) else {
                break;
            };
            assert!(
                amount.minor() < price().minor(),
                "счёт на {} при цене {}",
                amount.to_decimal(),
                price().to_decimal()
            );
            taken.insert(amount.minor());
        }
        assert_eq!(taken.len(), 99, "выдано меньше счетов, чем есть хвостов");
    }

    /// Самая важная проверка модуля. Человек, платящий по памяти, отправит
    /// ровно 199 ₽. Если бы круглая сумма кому-то принадлежала, его платёж
    /// зачислился бы чужому заказу.
    #[test]
    fn the_round_amount_is_never_given_to_anyone() {
        let mut taken = TakenAmounts::new();
        while let Ok(amount) = allocate(price(), &taken) {
            assert_ne!(amount.minor(), price().minor(), "выдана круглая сумма");
            taken.insert(amount.minor());
        }
        assert!(
            !matches(price(), &taken),
            "круглый платёж нашёл себе чужой заказ"
        );
    }

    #[test]
    fn two_invoices_never_share_an_amount() {
        let mut taken = TakenAmounts::new();
        let mut issued = Vec::new();
        while let Ok(amount) = allocate(price(), &taken) {
            assert!(
                !issued.contains(&amount.minor()),
                "сумма {} выдана дважды",
                amount.to_decimal()
            );
            issued.push(amount.minor());
            taken.insert(amount.minor());
        }
        assert_eq!(issued.len(), 99);
    }

    #[test]
    fn a_freed_amount_is_handed_out_again() {
        let mut taken: TakenAmounts = (19_801..=19_899).collect();
        assert_eq!(allocate(price(), &taken), Err(Error::NoFreeAmount));

        // Счёт истёк — сумма вернулась в оборот.
        let mut freed = TakenAmounts::new();
        for minor in 19_801..=19_899 {
            if minor != 19_850 {
                freed.insert(minor);
            }
        }
        taken = freed;
        assert_eq!(allocate(price(), &taken), Ok(rub(19_850)));
    }

    #[test]
    fn running_out_of_tails_is_reported_and_not_guessed() {
        let taken: TakenAmounts = (19_801..=19_899).collect();
        assert_eq!(allocate(price(), &taken), Err(Error::NoFreeAmount));
    }

    /// У USDT шесть знаков после запятой, поэтому запас на порядки больше —
    /// в криптоканале об исчерпании можно не думать.
    #[test]
    fn the_crypto_rail_has_far_more_room() {
        let price = Money::from_minor(2_551_037, Currency::Usdt);
        let Ok(amount) = allocate(price, &TakenAmounts::new()) else {
            return;
        };
        assert_eq!(amount, Money::from_minor(2_551_036, Currency::Usdt));

        // Хвостов ровно на шесть знаков.
        let taken: TakenAmounts = (price.minor() - 999_999..price.minor()).collect();
        assert_eq!(allocate(price, &taken), Err(Error::NoFreeAmount));
    }

    /// Цена меньше хвоста означала бы счёт на ноль или на отрицательное.
    #[test]
    fn a_price_smaller_than_the_tail_is_refused() {
        assert_eq!(
            allocate(rub(50), &TakenAmounts::new()),
            Err(Error::PriceTooSmall)
        );
        assert_eq!(
            allocate(rub(99), &TakenAmounts::new()),
            Err(Error::PriceTooSmall)
        );
        assert!(allocate(rub(100), &TakenAmounts::new()).is_ok());
    }

    #[test]
    fn a_payment_finds_its_invoice_only_by_exact_amount() {
        let taken: TakenAmounts = [19_899, 49_898].into_iter().collect();
        assert!(matches(rub(19_899), &taken));
        assert!(
            !matches(rub(19_898), &taken),
            "соседняя сумма не должна подходить"
        );
        assert!(
            !matches(rub(19_900), &taken),
            "круглая сумма не должна подходить"
        );
    }

    /// Разные тарифы не мешают друг другу: их хвосты лежат вокруг разных цен.
    #[test]
    fn different_plans_do_not_collide() {
        let mut taken = TakenAmounts::new();
        let mut issued = 0;
        for price in [rub(19_900), rub(49_900), rub(79_000), rub(129_000)] {
            for _ in 0..99 {
                let Ok(amount) = allocate(price, &taken) else {
                    break;
                };
                taken.insert(amount.minor());
                issued += 1;
            }
        }
        assert_eq!(issued, 396, "не хватило сумм там, где их должно хватать");
        assert_eq!(taken.len(), 396, "часть сумм совпала между тарифами");
    }
}
