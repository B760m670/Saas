//! Витрина: единственное место, где записаны цены.
//!
//! До этого тарифы жили в трёх местах — в документе, в тестах биллинга и в
//! тестах меню, — и расходились бы при первой же правке цены. Теперь они
//! здесь, а тесты сверяют с ними и надписи на кнопках, и обещанную выгоду.

use atlas_billing::money::{Currency, Money};
use atlas_billing::order::Plan;

/// Сколько устройств было у всех до тарифов «Личный» и «Семья».
///
/// Остаётся у тех, кто заплатил до их появления, — до конца оплаченного
/// срока: при следующей покупке человек переходит на выбранный тариф.
pub const DEVICES: u8 = 3;

/// Устройств на пробе — как у «Личного»: проба показывает тот тариф, на
/// который человек скорее всего перейдёт.
pub const TRIAL_DEVICES: u8 = 2;

/// Тариф: сколько устройств у владельца и скольким близким он может дать
/// свою подписку.
///
/// Цена от тарифа зависит, срок — нет: сроки одни и те же у обоих.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Для себя: 2 устройства и один гость.
    Personal,
    /// Для семьи: 3 устройства у владельца и четыре гостя.
    Family,
}

impl Tier {
    /// Оба тарифа в порядке показа.
    pub const ALL: [Self; 2] = [Self::Personal, Self::Family];

    /// Имя, под которым тариф лежит в базе (`users.tier`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Family => "family",
        }
    }

    /// Обратно из базы. Незнакомое — `None`, а не «Личный по умолчанию»:
    /// молча подставленный тариф — это чужие устройства и чужие гости.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "personal" => Some(Self::Personal),
            "family" => Some(Self::Family),
            _ => None,
        }
    }

    /// Название для человека.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Personal => "Личный",
            Self::Family => "Семья",
        }
    }

    /// Устройств у владельца.
    #[must_use]
    pub const fn devices(self) -> u8 {
        match self {
            Self::Personal => 2,
            Self::Family => 3,
        }
    }

    /// Скольким близким владелец может дать подписку.
    ///
    /// Совпадает с `atlas_store::guest_slots` — там то же правило нужно
    /// базе, когда покупка «Личного» оставляет лишних гостей. Разойтись им
    /// не даёт тест в `gloria`.
    #[must_use]
    pub const fn guests(self) -> u8 {
        match self {
            Self::Personal => 1,
            Self::Family => 4,
        }
    }

    /// Цена месяца — то, от чего считается выгода длинных сроков.
    #[must_use]
    pub fn monthly_base(self) -> Option<Money> {
        let rubles = match self {
            Self::Personal => 199,
            Self::Family => 299,
        };
        Money::from_major(rubles, Currency::Rub)
    }

    /// Тариф по имени тарифа-срока: `d30` — «Личный», `f30` — «Семья».
    #[must_use]
    pub fn of_plan(plan_id: &str) -> Option<Self> {
        SHOWCASE
            .iter()
            .find(|(id, ..)| *id == plan_id)
            .map(|(_, tier, ..)| *tier)
    }
}

/// Устройств у гостя — того, кому владелец дал свою подписку.
pub const GUEST_DEVICES: u8 = 1;

/// Трафика у гостя в месяц. Безлимит — у владельца, который платит; гость
/// пользуется его подпиской, и подписка не должна превращаться в бесплатный
/// безлимит на пятерых.
pub const GUEST_BYTES: u64 = 30 * 1024 * 1024 * 1024;

/// Сколько трафика даётся на пробу.
///
/// Проба мерится гигабайтами, а не днями, и это не мелочь.
///
/// Календарные три дня сгорали сами: человек нажал `/start`, отвлёкся, через
/// трое суток проба кончилась — а он так и не увидел, работает у него VPN
/// или нет. Гигабайты кончаются **от использования**, то есть ровно тогда,
/// когда он это узнал. В этот момент и покупают.
///
/// Вторая причина — дыра. Три дня без потолка это до трёхсот гигабайт
/// бесплатно на аккаунт, а завести аккаунт дешевле, чем стоит такой трафик.
///
/// Пять — потому что этого хватает попробовать всё (час-полтора видео или
/// неделя переписки и лент), но не хватает жить на пробе.
pub const TRIAL_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Сколько дней даётся на то, чтобы пробу потратить.
///
/// Это не срок подписки: настоящий предел у пробы — трафик. Дата нужна
/// затем, чтобы заброшенная проба не висела в панели вечно, и поэтому она
/// заметно длиннее, чем нужно живому человеку.
pub const TRIAL_DAYS: u32 = 14;

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
/// Имя, тариф, название срока, срок в днях, цена в рублях. Имя «Личного»
/// начинается с `d`, «Семьи» — с `f`: по имени тариф узнаёт и база
/// (`settle`), и старые кнопки `d30` в переписке продолжают работать.
const SHOWCASE: [(&str, Tier, &str, u32, u64); 8] = [
    ("d30", Tier::Personal, "1 месяц", 30, 199),
    ("d90", Tier::Personal, "3 месяца", 90, 549),
    ("d180", Tier::Personal, "6 месяцев", 180, 999),
    ("d365", Tier::Personal, "12 месяцев", 365, 1790),
    ("f30", Tier::Family, "1 месяц", 30, 299),
    ("f90", Tier::Family, "3 месяца", 90, 829),
    ("f180", Tier::Family, "6 месяцев", 180, 1499),
    ("f365", Tier::Family, "12 месяцев", 365, 2690),
];

/// Цена месяца «Личного» — то, относительно чего считается выгода.
#[must_use]
pub fn monthly_base() -> Option<Money> {
    Tier::Personal.monthly_base()
}

/// Все тарифы.
#[must_use]
pub fn plans() -> Vec<Plan> {
    SHOWCASE
        .into_iter()
        .filter_map(|(id, tier, title, days, rubles)| {
            Some(Plan {
                id: id.to_owned(),
                title: title.to_owned(),
                days,
                devices: tier.devices(),
                price: Money::from_major(rubles, Currency::Rub)?,
            })
        })
        .collect()
}

/// Сроки одного тарифа.
#[must_use]
pub fn plans_of(tier: Tier) -> Vec<Plan> {
    plans()
        .into_iter()
        .filter(|plan| Tier::of_plan(&plan.id) == Some(tier))
        .collect()
}

/// Найти тариф по имени, пришедшему с кнопки.
#[must_use]
pub fn plan(id: &str) -> Option<Plan> {
    plans().into_iter().find(|plan| plan.id == id)
}

#[cfg(test)]
mod tests {
    use super::{monthly_base, plan, plans, plans_of, Tier, SHOWCASE};

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
        for (plan, (id, tier, title, days, rubles)) in plans().into_iter().zip(SHOWCASE) {
            assert_eq!(plan.id, id);
            assert_eq!(plan.title, title);
            assert_eq!(plan.days, days);
            assert_eq!(plan.devices, tier.devices());
            assert_eq!(plan.price.minor(), rubles * 100);
        }
    }

    /// Оба тарифа продают одни и те же сроки: разница — в устройствах и
    /// гостях, а не в том, на сколько можно купить.
    #[test]
    fn both_tiers_offer_the_same_terms() {
        let days = |tier| plans_of(tier).iter().map(|p| p.days).collect::<Vec<_>>();
        assert_eq!(days(Tier::Personal), days(Tier::Family));
        assert_eq!(days(Tier::Personal), vec![30, 90, 180, 365]);
    }

    /// Тариф узнаётся по имени срока, и имя в базе читается обратно.
    #[test]
    fn a_tier_is_recognised_by_its_plan_and_its_name() {
        assert_eq!(Tier::of_plan("d30"), Some(Tier::Personal));
        assert_eq!(Tier::of_plan("f365"), Some(Tier::Family));
        assert_eq!(Tier::of_plan("x30"), None);
        for tier in Tier::ALL {
            assert_eq!(Tier::parse(tier.as_str()), Some(tier));
        }
        assert_eq!(Tier::parse("premium"), None);
    }

    /// Имя «Семьи» обязано начинаться с `f`, «Личного» — с `d`: по первой
    /// букве тариф определяет база при зачислении (`atlas_store::settle`).
    #[test]
    fn the_first_letter_of_a_plan_names_its_tier() {
        for (id, tier, ..) in SHOWCASE {
            let letter = match tier {
                Tier::Personal => 'd',
                Tier::Family => 'f',
            };
            assert!(id.starts_with(letter), "{id}");
        }
    }

    /// «Семья» дороже и даёт больше — иначе её незачем покупать.
    #[test]
    fn the_family_gives_more_than_the_personal() {
        assert!(Tier::Family.devices() > Tier::Personal.devices());
        assert!(Tier::Family.guests() > Tier::Personal.guests());
        let base = |tier: Tier| tier.monthly_base().map(|m| m.minor());
        assert!(base(Tier::Family) > base(Tier::Personal));
    }
}
