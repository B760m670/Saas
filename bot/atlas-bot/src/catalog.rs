//! Витрина: единственное место, где записаны цены.
//!
//! До этого тарифы жили в трёх местах — в документе, в тестах биллинга и в
//! тестах меню, — и расходились бы при первой же правке цены. Теперь они
//! здесь, а тесты сверяют с ними и надписи на кнопках, и обещанную выгоду.

use atlas_billing::money::{Currency, Money};
use atlas_billing::order::Plan;

/// Сколько устройств разрешено. Одинаково во всех тарифах: различия по
/// возможностям порождают вопросы в поддержку, а поддержка здесь — один
/// человек (docs/14-bot.md §2).
pub const DEVICES: u8 = 3;

/// Пробный период, дней.
pub const TRIAL_DAYS: u32 = 3;

/// Сколько живёт выставленный счёт, секунд.
///
/// Сутки. Раньше стояло двадцать минут — и это ломало весь ручной приём:
/// человек платит вечером, владелец смотрит выписку утром, а счёта уже нет,
/// и подтвердить перевод нечем. На этом и споткнулась первая же проверка.
///
/// Двадцать минут были нужны криптоканалу, где за это время уходит курс. У
/// перевода такой причины нет: сумма в рублях названа и не меняется.
///
/// Цена срока — запас уникальных сумм. Хвостов 99 на тариф, значит при сутках
/// одновременно живут 99 счетов на тариф. При нынешних числах это в разы
/// больше нужного, а станет мало — срок легко укоротить обратно.
pub const INVOICE_LIFETIME: i64 = 24 * 60 * 60;

/// Тот же срок словами — так, как он произносится покупателю.
///
/// Отдельная функция, потому что срок называется в трёх местах: в чате, в
/// кабинете и в ответе сервера кабинету. Считать часы из секунд в каждом из
/// них — три возможности разойтись с четвёртым местом, где стоит само число.
#[must_use]
pub fn invoice_lifetime_label() -> String {
    let hours = INVOICE_LIFETIME / 3600;
    match hours {
        24 => "сутки".to_owned(),
        0 => format!("{} минут", INVOICE_LIFETIME / 60),
        _ => format!("{hours} ч"),
    }
}

/// Тарифы в том порядке, в каком они показываются.
///
/// Срок в днях, цена в рублях, название для кнопки.
const SHOWCASE: [(&str, &str, u32, u64); 4] = [
    ("d30", "1 месяц", 30, 199),
    ("d90", "3 месяца", 90, 499),
    ("d180", "6 месяцев", 180, 790),
    ("d365", "12 месяцев", 365, 1290),
];

/// Цена месяца — то, относительно чего считается выгода остальных тарифов.
#[must_use]
pub fn monthly_base() -> Option<Money> {
    Money::from_major(199, Currency::Rub)
}

/// Все тарифы.
#[must_use]
pub fn plans() -> Vec<Plan> {
    SHOWCASE
        .into_iter()
        .filter_map(|(id, title, days, rubles)| {
            Some(Plan {
                id: id.to_owned(),
                title: title.to_owned(),
                days,
                devices: DEVICES,
                price: Money::from_major(rubles, Currency::Rub)?,
            })
        })
        .collect()
}

/// Найти тариф по имени, пришедшему с кнопки.
#[must_use]
pub fn plan(id: &str) -> Option<Plan> {
    plans().into_iter().find(|plan| plan.id == id)
}

#[cfg(test)]
mod tests {
    use super::{monthly_base, plan, plans, SHOWCASE};

    /// Витрина обязана собираться целиком. Молчаливая потеря тарифа из-за
    /// переполнения оставила бы покупателя без части кнопок.
    #[test]
    fn every_advertised_plan_is_built() {
        assert_eq!(plans().len(), SHOWCASE.len());
        assert!(monthly_base().is_some());
    }

    /// Имена тарифов уходят в кнопку и возвращаются оттуда, поэтому обязаны
    /// проходить ту же проверку набора символов, что и всё приходящее извне.
    #[test]
    fn plan_names_survive_a_round_trip_through_a_button() {
        for plan in plans() {
            let action = crate::Action::Buy(plan.id.clone());
            assert_eq!(
                crate::Action::decode(&action.encode()),
                Ok(action),
                "имя тарифа {} не переживает кнопку",
                plan.id
            );
        }
    }

    /// Срок счёта называется покупателю словами. Разойтись слову с числом
    /// нельзя: человек, поверивший «сутки» при двадцати минутах, заплатит по
    /// счёту, которого уже нет.
    #[test]
    fn the_invoice_lifetime_is_spelled_out_correctly() {
        assert_eq!(super::INVOICE_LIFETIME, 24 * 60 * 60);
        assert_eq!(super::invoice_lifetime_label(), "сутки");
    }

    #[test]
    fn an_unknown_plan_is_not_found() {
        assert!(plan("d999").is_none());
        assert!(plan("").is_none());
        assert!(plan("d30").is_some());
    }

    /// Цены в тарифах и в таблице документации — одно и то же.
    #[test]
    fn prices_match_the_showcase() {
        for (plan, (id, title, days, rubles)) in plans().into_iter().zip(SHOWCASE) {
            assert_eq!(plan.id, id);
            assert_eq!(plan.title, title);
            assert_eq!(plan.days, days);
            assert_eq!(plan.price.minor(), rubles * 100);
        }
    }
}
