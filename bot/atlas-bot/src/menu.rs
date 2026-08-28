//! Экраны, кнопки и то, что кнопка присылает обратно.
//!
//! Меню плоское: ни одного пункта, ведущего в подменю ради подменю. На
//! телефоне вложенность — это тупик, из которого половина не возвращается
//! (docs/14-bot.md §7).
//!
//! Модуль намеренно ничего не знает ни о Telegram, ни о сети: он строит
//! описания кнопок и разбирает то, что приходит с них обратно. Поэтому его
//! можно проверить целиком, не поднимая ни бота, ни базу.

use atlas_billing::{Money, Plan};

/// Предел Telegram на `callback_data` — 64 байта.
///
/// Кнопка с более длинным полем не отправляется вовсе, и узнаётся это не по
/// ошибке, а по тому, что у части покупателей меню просто пустое.
pub const CALLBACK_LIMIT: usize = 64;

/// Устройство, под которое показывается инструкция подключения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    Iphone,
    Android,
    Desktop,
}

impl Device {
    const fn code(self) -> &'static str {
        match self {
            Self::Iphone => "ios",
            Self::Android => "android",
            Self::Desktop => "pc",
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::Iphone => "iPhone",
            Self::Android => "Android",
            Self::Desktop => "Компьютер",
        }
    }

    fn parse(code: &str) -> Option<Self> {
        match code {
            "ios" => Some(Self::Iphone),
            "android" => Some(Self::Android),
            "pc" => Some(Self::Desktop),
            _ => None,
        }
    }

    /// Все устройства в том порядке, в каком они показываются.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Iphone, Self::Android, Self::Desktop]
    }
}

/// Что человек попросил, нажав кнопку.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Экран «Моя подписка».
    Subscription,
    /// Список тарифов.
    Plans,
    /// Выбран тариф с таким именем.
    Buy(String),
    /// Выбор устройства.
    Connect,
    /// Инструкция под конкретное устройство.
    ConnectTo(Device),
    /// Помощь.
    Help,
    /// Назад в главное меню.
    Home,
}

/// Почему нажатие нельзя принять.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unknown {
    /// Такого действия у нас нет.
    NoSuchAction,
    /// Имя тарифа содержит недопустимые символы.
    ///
    /// Поле приходит обратно от клиента, а не из нашей памяти. Обычный
    /// клиент вернёт ровно то, что мы послали, но полагаться на это нельзя:
    /// имя тарифа идёт дальше — в номер заказа и в запрос к базе.
    BadPlanName,
}

impl Action {
    /// Строка, которая уедет в кнопку и вернётся с нажатием.
    #[must_use]
    pub fn encode(&self) -> String {
        match self {
            Self::Subscription => "sub".to_owned(),
            Self::Plans => "plans".to_owned(),
            Self::Buy(plan) => format!("buy:{plan}"),
            Self::Connect => "conn".to_owned(),
            Self::ConnectTo(device) => format!("dev:{}", device.code()),
            Self::Help => "help".to_owned(),
            Self::Home => "home".to_owned(),
        }
    }

    /// Разобрать то, что пришло с нажатием.
    pub fn decode(data: &str) -> Result<Self, Unknown> {
        if let Some(plan) = data.strip_prefix("buy:") {
            if plan.is_empty()
                || plan.len() > 32
                || !plan.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(Unknown::BadPlanName);
            }
            return Ok(Self::Buy(plan.to_owned()));
        }

        if let Some(code) = data.strip_prefix("dev:") {
            return Device::parse(code)
                .map(Self::ConnectTo)
                .ok_or(Unknown::NoSuchAction);
        }

        match data {
            "sub" => Ok(Self::Subscription),
            "plans" => Ok(Self::Plans),
            "conn" => Ok(Self::Connect),
            "help" => Ok(Self::Help),
            "home" => Ok(Self::Home),
            _ => Err(Unknown::NoSuchAction),
        }
    }
}

/// Кнопка: что написано и что произойдёт.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    pub label: String,
    pub action: Action,
}

impl Button {
    fn new(label: impl Into<String>, action: Action) -> Self {
        Self {
            label: label.into(),
            action,
        }
    }
}

/// Раскладка кнопок: строки сверху вниз, в строке — слева направо.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyboard {
    pub rows: Vec<Vec<Button>>,
}

impl Keyboard {
    /// Все кнопки подряд, без разбиения на строки.
    pub fn buttons(&self) -> impl Iterator<Item = &Button> {
        self.rows.iter().flatten()
    }
}

/// Главное меню. По кнопке в строке: на узком экране две в ряд слипаются,
/// и промахнуться мимо нужной легче, чем кажется.
#[must_use]
pub fn main_menu() -> Keyboard {
    Keyboard {
        rows: vec![
            vec![Button::new("Моя подписка", Action::Subscription)],
            vec![Button::new("Продлить", Action::Plans)],
            vec![Button::new("Подключить", Action::Connect)],
            vec![Button::new("Помощь", Action::Help)],
        ],
    }
}

/// Выбор устройства.
///
/// Три ветки, и каждая ведёт к **одному** клиенту, а не к списку из шести.
/// Список — это выбор, а выбор в этом месте делают неправильно и потом
/// пишут в поддержку.
#[must_use]
pub fn connect_menu() -> Keyboard {
    let mut rows: Vec<Vec<Button>> = Device::all()
        .into_iter()
        .map(|device| vec![Button::new(device.title(), Action::ConnectTo(device))])
        .collect();
    rows.push(vec![Button::new("Назад", Action::Home)]);
    Keyboard { rows }
}

/// Кнопки тарифов.
///
/// Надпись собирается из самого тарифа, а не пишется руками: `1290 ₽` и
/// `−46 %` вычисляются из цены и срока. Иначе правка цены оставляет на
/// кнопке прежнюю выгоду, и расхождение первым замечает покупатель.
#[must_use]
pub fn plans_menu(plans: &[Plan], monthly_base: Money) -> Keyboard {
    let mut rows: Vec<Vec<Button>> = plans
        .iter()
        .map(|plan| {
            vec![Button::new(
                plan_label(plan, monthly_base),
                Action::Buy(plan.id.clone()),
            )]
        })
        .collect();
    rows.push(vec![Button::new("Назад", Action::Home)]);
    Keyboard { rows }
}

/// Надпись на кнопке тарифа: `12 месяцев — 1290 ₽ (−46 %)`.
#[must_use]
pub fn plan_label(plan: &Plan, monthly_base: Money) -> String {
    let price = price_label(plan.price);
    match plan.discount_percent(monthly_base) {
        Some(percent) if percent > 0 => format!("{} — {price} (−{percent} %)", plan.title),
        _ => format!("{} — {price}", plan.title),
    }
}

/// Цена для показа: `199 ₽`, но `199,50 ₽`, если копейки не нулевые.
///
/// Ровные `199.00` на кнопке выглядят как выгрузка из бухгалтерии. При этом
/// молча отбрасывать ненулевые копейки нельзя: надпись перестанет совпадать
/// с суммой к оплате, и первым это заметит покупатель.
#[must_use]
pub fn price_label(amount: Money) -> String {
    let decimal = amount.to_decimal();
    let whole = match decimal.split_once('.') {
        Some((whole, fraction)) if fraction.bytes().all(|b| b == b'0') => whole,
        // Разделитель дробной части в русском тексте — запятая.
        _ => return format!("{} {}", decimal.replace('.', ","), symbol(amount)),
    };
    format!("{whole} {}", symbol(amount))
}

fn symbol(amount: Money) -> &'static str {
    match amount.currency() {
        atlas_billing::Currency::Rub => "₽",
        atlas_billing::Currency::Usdt => "USDT",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        connect_menu, main_menu, plan_label, plans_menu, price_label, Action, Device, Keyboard,
        Unknown, CALLBACK_LIMIT,
    };
    use atlas_billing::{Currency, Money, Plan};

    fn plan(id: &str, title: &str, days: u32, rubles: u64) -> Option<Plan> {
        Some(Plan {
            id: id.to_owned(),
            title: title.to_owned(),
            days,
            devices: 4,
            price: Money::from_major(rubles, Currency::Rub)?,
        })
    }

    fn showcase() -> Vec<Plan> {
        crate::catalog::plans()
    }

    fn base() -> Option<Money> {
        crate::catalog::monthly_base()
    }

    fn every_keyboard() -> Vec<Keyboard> {
        let Some(base) = base() else {
            return Vec::new();
        };
        vec![main_menu(), connect_menu(), plans_menu(&showcase(), base)]
    }

    /// Кнопка с полем длиннее 64 байт не уходит к покупателю вовсе, и
    /// заметно это не по ошибке, а по пустому меню.
    #[test]
    fn no_button_exceeds_the_telegram_limit() {
        let mut checked = 0;
        for keyboard in every_keyboard() {
            for button in keyboard.buttons() {
                let data = button.action.encode();
                assert!(
                    data.len() <= CALLBACK_LIMIT,
                    "кнопка {:?} несёт {} байт",
                    button.label,
                    data.len()
                );
                assert!(!button.label.is_empty(), "кнопка без надписи");
                checked += 1;
            }
        }
        assert!(checked >= 11, "проверено всего {checked} кнопок");
    }

    /// Нажатие возвращается тем же, чем ушло. Ломается это молча: кнопка
    /// есть, нажимается, и ничего не происходит.
    #[test]
    fn every_button_survives_the_round_trip() {
        for keyboard in every_keyboard() {
            for button in keyboard.buttons() {
                assert_eq!(
                    Action::decode(&button.action.encode()),
                    Ok(button.action.clone()),
                    "не разобралось: {:?}",
                    button.label
                );
            }
        }
    }

    #[test]
    fn an_unknown_action_is_refused() {
        for data in ["", "sub2", "нажали", "dev:blackberry", "buy"] {
            assert_eq!(
                Action::decode(data),
                Err(Unknown::NoSuchAction),
                "принято {data:?}"
            );
        }
    }

    /// Имя тарифа приходит обратно от клиента и идёт дальше — в номер
    /// заказа и в запрос к базе. Обычный клиент вернёт наше, изменённый —
    /// что угодно.
    #[test]
    fn a_tampered_plan_name_is_refused() {
        for data in [
            "buy:",
            "buy:d30;drop",
            "buy:d30 or 1=1",
            "buy:тариф",
            "buy:d30:extra",
            &format!("buy:{}", "d".repeat(33)),
        ] {
            assert_eq!(
                Action::decode(data),
                Err(Unknown::BadPlanName),
                "принято имя тарифа из {data:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_plan_name_passes() {
        assert_eq!(
            Action::decode("buy:d365"),
            Ok(Action::Buy("d365".to_owned()))
        );
    }

    /// Главная проверка витрины: то, что написано на кнопке, обязано
    /// совпадать с тем, что записано в docs/14-bot.md §2.
    #[test]
    fn the_buttons_say_what_the_tariffs_say() {
        let Some(base) = base() else { return };
        let expected = [
            "1 месяц — 199 ₽",
            "3 месяца — 499 ₽ (−16 %)",
            "6 месяцев — 790 ₽ (−33 %)",
            "12 месяцев — 1290 ₽ (−46 %)",
        ];

        let plans = showcase();
        assert_eq!(plans.len(), expected.len(), "витрина собралась не целиком");

        for (plan, want) in plans.iter().zip(expected) {
            assert_eq!(plan_label(plan, base), want);
        }
    }

    /// Месячный тариф сравнивается сам с собой, и приписывать ему «−0 %»
    /// значит выглядеть глупо на самой заметной кнопке.
    #[test]
    fn the_monthly_plan_carries_no_discount_tail() {
        let Some(base) = base() else { return };
        let Some(month) = plan("d30", "1 месяц", 30, 199) else {
            return;
        };
        let label = plan_label(&month, base);
        assert!(!label.contains('%'), "на кнопке лишняя выгода: {label}");
    }

    /// Ровные суммы показываются без копеек, неровные — с ними. Второе
    /// важнее: надпись, разошедшаяся с суммой к оплате, — это спор.
    #[test]
    fn kopecks_are_shown_only_when_there_are_any() {
        assert_eq!(
            price_label(Money::from_minor(19_900, Currency::Rub)),
            "199 ₽"
        );
        assert_eq!(
            price_label(Money::from_minor(19_950, Currency::Rub)),
            "199,50 ₽"
        );
        assert_eq!(price_label(Money::from_minor(1, Currency::Rub)), "0,01 ₽");
    }

    /// Из любого подменю должен быть выход, иначе человек упирается в
    /// тупик и жмёт «стоп».
    #[test]
    fn every_submenu_leads_home() {
        let Some(base) = base() else { return };
        for keyboard in [connect_menu(), plans_menu(&showcase(), base)] {
            assert!(
                keyboard.buttons().any(|b| b.action == Action::Home),
                "из подменю некуда вернуться"
            );
        }
    }

    /// Главное меню плоское: из него никуда «назад» не ведёт, потому что
    /// оно и есть верх.
    #[test]
    fn the_main_menu_has_no_way_back() {
        assert!(!main_menu().buttons().any(|b| b.action == Action::Home));
    }

    #[test]
    fn every_device_has_its_own_button() {
        let menu = connect_menu();
        for device in Device::all() {
            assert!(
                menu.buttons()
                    .any(|b| b.action == Action::ConnectTo(device)),
                "нет кнопки для {device:?}"
            );
        }
    }
}
