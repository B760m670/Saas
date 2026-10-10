//! Витрина: единственное место, где записаны цены.
//!
//! До этого тарифы жили в трёх местах — в документе, в тестах биллинга и в
//! тестах меню, — и расходились бы при первой же правке цены. Теперь они
//! здесь, а тесты сверяют с ними и надписи на кнопках, и обещанную выгоду.

use atlas_billing::money::{Currency, Money};
use atlas_billing::order::Plan;

/// Сколько устройств в подписке.
///
/// Тариф один, и все различия — только в сроке. Отдельный «семейный»
/// тариф и гости были (миграция 0012) и убраны: на старте каждый платит
/// за свою подписку сам.
pub const PLAN_DEVICES: u8 = 2;

/// Сколько устройств было у всех до октября 2026.
///
/// Остаётся у тех, кто заплатил тогда, — до конца оплаченного срока: при
/// следующей покупке человек получает [`PLAN_DEVICES`].
pub const DEVICES: u8 = 3;

/// Устройств на пробе — как в подписке: проба показывает то, что продаётся.
pub const TRIAL_DEVICES: u8 = PLAN_DEVICES;

/// Потолок трафика у прежней пробы (до октября 2026: 14 дней и 5 ГБ).
///
/// Новым пробам потолка нет. Константа осталась для тех, чья проба выдана
/// по старым правилам и ещё идёт: панель держит у них 5 ГБ, и бот с
/// кабинетом показывают остаток «из 5 ГБ», пока проба не кончится.
pub const TRIAL_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Сколько длится проба: двое суток, трафик без ограничения.
///
/// Раньше было 14 дней и 5 ГБ. Две недели — слишком долго: человек
/// забывал, что пользуется пробой, и решение «продлевать ли» откладывалось
/// до самого отключения. А потолок в гигабайтах показывал не тот продукт,
/// который продаётся: человек экономил трафик вместо того, чтобы
/// пользоваться. Двое суток без ограничений — это настоящая подписка,
/// и решение принимается, пока впечатление свежее.
///
/// Напоминают о конце пробы обычные напоминания (`due_reminders`): за
/// сутки до конца — это как раз конец первого дня — и за три часа.
pub const TRIAL_DAYS: u32 = 2;

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
/// Имя, название срока, срок в днях, цена в рублях.
const SHOWCASE: [(&str, &str, u32, u64); 4] = [
    ("d30", "1 месяц", 30, 199),
    ("d90", "3 месяца", 90, 549),
    ("d180", "6 месяцев", 180, 999),
    ("d365", "12 месяцев", 365, 1790),
];

/// Сколько стоит опция «Без рекламы», рублей. Одна цена на любой срок:
/// к сроку при покупке и к уже идущей подписке до её конца — одинаково.
///
/// Опция — добавка, а не отдельный тариф.
pub const ADBLOCK_PRICE: u64 = 50;

/// Цена месяца — то, относительно чего считается выгода длинных сроков.
#[must_use]
pub fn monthly_base() -> Option<Money> {
    Money::from_major(199, Currency::Rub)
}

/// Все тарифы без опции.
#[must_use]
pub fn plans() -> Vec<Plan> {
    build(&SHOWCASE)
}

/// Те же сроки с опцией «Без рекламы»: имя `<срок>-ad`, к цене —
/// [`ADBLOCK_PRICE`], на любой срок одинаково.
#[must_use]
pub fn adblock_plans() -> Vec<Plan> {
    plans()
        .into_iter()
        .filter_map(|plan| {
            let extra = Money::from_major(ADBLOCK_PRICE, Currency::Rub)?;
            let price = Money::from_minor(
                plan.price.minor().checked_add(extra.minor())?,
                Currency::Rub,
            );
            Some(Plan {
                id: format!("{}-ad", plan.id),
                price,
                ..plan
            })
        })
        .collect()
}

/// Добавка «Без рекламы» к идущей подписке — до её конца, за
/// [`ADBLOCK_PRICE`], сколько бы ни оставалось. `None` — подписка не идёт
/// или опция (`adblock_until`) уже до её конца.
///
/// В `days` — сколько дней покрывает добавка; срок подписки она не
/// продлевает (это видит база по имени, `ADBLOCK_REST`).
#[must_use]
pub fn adblock_rest(expires_at: Option<i64>, adblock_until: Option<i64>, now: i64) -> Option<Plan> {
    let expires_at = expires_at?;
    if adblock_until.is_some_and(|until| until >= expires_at) {
        return None;
    }
    let left = expires_at.checked_sub(now)?;
    if left <= 0 {
        return None;
    }
    let days = u64::try_from(left.checked_add(86_399)? / 86_400).ok()?;
    Some(Plan {
        id: atlas_billing::order::ADBLOCK_REST.to_owned(),
        title: "Без рекламы до конца подписки".to_owned(),
        days: u32::try_from(days).ok()?,
        devices: PLAN_DEVICES,
        price: Money::from_major(ADBLOCK_PRICE, Currency::Rub)?,
    })
}

fn build(showcase: &[(&str, &str, u32, u64)]) -> Vec<Plan> {
    showcase
        .iter()
        .copied()
        .filter_map(|(id, title, days, rubles)| {
            Some(Plan {
                id: id.to_owned(),
                title: title.to_owned(),
                days,
                devices: PLAN_DEVICES,
                price: Money::from_major(rubles, Currency::Rub)?,
            })
        })
        .collect()
}

/// Найти тариф по имени, пришедшему с кнопки.
#[must_use]
pub fn plan(id: &str) -> Option<Plan> {
    plans()
        .into_iter()
        .chain(adblock_plans())
        .find(|plan| plan.id == id)
}

#[cfg(test)]
mod tests {
    use super::{adblock_plans, adblock_rest, monthly_base, plan, plans, PLAN_DEVICES, SHOWCASE};

    /// Тарифы с опцией узнаются базой по имени — и только они; цена — та
    /// же плюс 50 ₽ на любой срок.
    #[test]
    fn adblock_plans_are_the_same_terms_plus_fifty() {
        let with: Vec<(String, u32, u64)> = adblock_plans()
            .iter()
            .map(|p| (p.id.clone(), p.days, p.price.minor() / 100))
            .collect();
        assert_eq!(
            with,
            vec![
                ("d30-ad".to_owned(), 30, 249),
                ("d90-ad".to_owned(), 90, 599),
                ("d180-ad".to_owned(), 180, 1049),
                ("d365-ad".to_owned(), 365, 1840),
            ]
        );
        for p in adblock_plans() {
            assert!(atlas_billing::order::is_adblock_plan(&p.id), "{}", p.id);
            assert!(plan(&p.id).is_some(), "{}", p.id);
            let action = crate::Action::Buy(p.id.clone());
            assert_eq!(crate::Action::decode(&action.encode()), Ok(action));
        }
        for p in plans() {
            assert!(!atlas_billing::order::is_adblock_plan(&p.id), "{}", p.id);
        }
    }

    /// Добавка к идущей подписке — 50 ₽ сколько бы ни оставалось; без
    /// подписки или при опции до её конца её нет.
    #[test]
    fn adblock_for_the_rest_of_a_subscription_costs_fifty() {
        const NOW: i64 = 1_760_000_000;
        let price = |days: i64| {
            adblock_rest(Some(NOW + days * 86_400), None, NOW).map(|p| p.price.minor() / 100)
        };
        assert_eq!(price(1), Some(50));
        assert_eq!(price(365), Some(50));
        assert_eq!(adblock_rest(Some(NOW - 1), None, NOW), None);
        assert_eq!(adblock_rest(None, None, NOW), None);
        let end = NOW + 9 * 86_400;
        assert_eq!(adblock_rest(Some(end), Some(end), NOW), None);
        assert!(adblock_rest(Some(end), Some(end - 86_400), NOW).is_some());
        let rest = adblock_rest(Some(NOW + 3600), None, NOW);
        assert_eq!(rest.as_ref().map(|p| p.days), Some(1));
        assert!(rest.is_some_and(|p| atlas_billing::order::is_adblock_plan(&p.id)));
    }

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
            assert_eq!(plan.devices, PLAN_DEVICES);
            assert_eq!(plan.price.minor(), rubles * 100);
        }
    }

    /// Прежние кнопки «Семьи» (`f30` …) в старых сообщениях больше не
    /// продают ничего: тарифа нет.
    #[test]
    fn the_family_plans_are_gone() {
        for id in ["f30", "f90", "f180", "f365"] {
            assert!(plan(id).is_none(), "{id}");
        }
    }
}
