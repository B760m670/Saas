//! Что бот отвечает и что при этом делает.
//!
//! Модуль чистый: он получает состояние покупателя и то, что тот нажал, и
//! возвращает ответ вместе с намерением. Ни базы, ни сети, ни времени изнутри
//! — поэтому весь разговор с покупателем проверяется обычными тестами, а не
//! перепиской с живым ботом.
//!
//! Разделение намеренное. Побочные действия — выдать пробу, выставить счёт —
//! возвращаются описанием, а исполняет их вызывающий. Иначе проверить «что
//! именно бот собирался сделать» можно было бы только по последствиям.

use atlas_billing::subscription;

use crate::catalog;
use crate::menu::{connect_menu, main_menu, plans_menu, Action, Device, Keyboard};

/// Что бот собирается сделать помимо ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Ничего, только ответить.
    None,
    /// Выдать пробный период.
    GrantTrial,
    /// Выставить счёт по тарифу.
    OpenOrder { plan: String },
}

/// Ответ покупателю.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// Текст сообщения.
    pub text: String,
    /// Кнопки под ним.
    pub keyboard: Option<Keyboard>,
}

/// Состояние покупателя на момент ответа.
#[derive(Debug, Clone, Copy)]
pub struct View<'a> {
    /// До какого момента действует подписка.
    pub expires_at: Option<i64>,
    /// Выдавалась ли проба.
    pub trial_used: bool,
    /// Ссылка на подписку, если она уже выдана.
    pub subscription_url: Option<&'a str>,
    /// Текущий момент.
    pub now: i64,
}

impl View<'_> {
    fn is_active(&self) -> bool {
        subscription::is_active(self.expires_at, self.now)
    }

    /// Сколько дней ещё можно пользоваться — с округлением **вверх**.
    ///
    /// Вниз округлять нельзя с обоих концов. Через десять минут после выдачи
    /// трёх пробных дней остаётся 2 дня 23 часа, и floor показал бы
    /// «осталось 2 дня» — покупатель читает это как обман и идёт в
    /// поддержку. А за полчаса до конца floor показал бы «осталось 0 дней»
    /// при работающем VPN.
    ///
    /// Вверх верно на обоих концах: 2 дня 23 часа — это и есть «ещё три дня
    /// можно пользоваться», а полчаса — «сегодня ещё работает».
    fn days_left(&self) -> i64 {
        self.expires_at.map_or(0, |end| {
            // `i64::div_ceil` пока нестабилен, поэтому вручную. Насыщение —
            // на случай нелепой даты окончания из базы: переполнение здесь
            // дало бы отрицательное число дней вместо большого.
            let left = end.saturating_sub(self.now).max(0);
            left.saturating_add(86_399) / 86_400
        })
    }
}

/// Склонение существительного при числе.
#[must_use]
pub fn plural(
    count: i64,
    one: &'static str,
    few: &'static str,
    many: &'static str,
) -> &'static str {
    let hundreds = count.abs() % 100;
    let tens = hundreds % 10;
    if (11..=19).contains(&hundreds) {
        return many;
    }
    match tens {
        1 => one,
        2..=4 => few,
        _ => many,
    }
}

/// Ответ на текстовое сообщение.
#[must_use]
pub fn on_message(text: &str, view: &View<'_>) -> (Reply, Effect) {
    // Команда может прийти с именем бота: `/start@GloriaVPN_Bot`. В группах
    // Telegram дописывает его сам, и без отсечения команда не узнаётся.
    let command = text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .split('@')
        .next()
        .unwrap_or("");

    match command {
        "/start" if !view.trial_used => (
            Reply {
                text: format!(
                    "Подписка на {} {} уже включена — платить пока не нужно.\n\n\
                     Нажмите «Подключить», и я покажу, что делать дальше.",
                    catalog::TRIAL_DAYS,
                    plural(i64::from(catalog::TRIAL_DAYS), "день", "дня", "дней")
                ),
                keyboard: Some(main_menu()),
            },
            Effect::GrantTrial,
        ),
        "/start" | "/menu" | "/help" => (subscription_screen(view), Effect::None),
        _ => (
            Reply {
                text: "Не понял. Вот что я умею:".to_owned(),
                keyboard: Some(main_menu()),
            },
            Effect::None,
        ),
    }
}

/// Ответ на нажатие кнопки.
#[must_use]
pub fn on_action(action: &Action, view: &View<'_>) -> (Reply, Effect) {
    match action {
        Action::Subscription | Action::Home => (subscription_screen(view), Effect::None),
        Action::Plans => (plans_screen(), Effect::None),
        Action::Connect => (connect_screen(view), Effect::None),
        Action::ConnectTo(device) => (device_screen(*device, view), Effect::None),
        Action::Help => (help_screen(), Effect::None),
        Action::Buy(plan) => buy(plan),
    }
}

fn subscription_screen(view: &View<'_>) -> Reply {
    let head = if view.is_active() {
        let days = view.days_left();
        format!(
            "Подписка активна: осталось {days} {}.",
            plural(days, "день", "дня", "дней")
        )
    } else if view.expires_at.is_some() {
        "Подписка закончилась. Продлите, чтобы продолжить.".to_owned()
    } else {
        "Подписки пока нет.".to_owned()
    };

    // Ссылка показывается всегда, а не только при действующей подписке:
    // человек, у которого она уже вставлена в приложение, не должен искать
    // её заново (docs/14-bot.md §7).
    let link = match view.subscription_url {
        Some(url) => format!("\n\nВаша ссылка — одна на все устройства:\n<code>{url}</code>"),
        None => String::new(),
    };

    Reply {
        text: format!("{head}{link}"),
        keyboard: Some(main_menu()),
    }
}

fn plans_screen() -> Reply {
    Reply {
        text: "Срок складывается с текущим: если подписка ещё действует, \
               оплаченные дни добавятся к оставшимся."
            .to_owned(),
        keyboard: catalog::monthly_base().map(|base| plans_menu(&catalog::plans(), base)),
    }
}

fn connect_screen(view: &View<'_>) -> Reply {
    let text = match view.subscription_url {
        Some(url) => format!("Выберите устройство. Ссылка одна на все:\n<code>{url}</code>"),
        None => "Выберите устройство.".to_owned(),
    };
    Reply {
        text,
        keyboard: Some(connect_menu()),
    }
}

fn device_screen(device: Device, view: &View<'_>) -> Reply {
    let (app, store) = match device {
        Device::Iphone => ("Streisand", "App Store"),
        Device::Android => ("Happ", "Google Play"),
        Device::Desktop => ("Hiddify", "hiddify.com"),
    };

    let link = match view.subscription_url {
        Some(url) => format!("\n\n3. Вставьте ссылку:\n<code>{url}</code>"),
        None => "\n\n3. Ссылка появится здесь после оплаты или пробного периода.".to_owned(),
    };

    Reply {
        text: format!(
            "1. Установите {app} — он есть в {store}.\n\n\
             2. Откройте приложение и выберите добавление подписки по ссылке.{link}\n\n\
             Дальше приложение само заберёт ключи и будет обновлять их при смене сервера.",
        ),
        keyboard: Some(connect_menu()),
    }
}

fn help_screen() -> Reply {
    Reply {
        text: "Напишите @GloriaVPNSupport — отвечает человек.\n\n\
               Частое: во время региональных ограничений мобильного интернета \
               не работает ни один VPN, включая наш, — ограничение стоит в сети \
               оператора. Дома по Wi-Fi и на проводном всё продолжает работать."
            .to_owned(),
        keyboard: Some(main_menu()),
    }
}

fn buy(plan_id: &str) -> (Reply, Effect) {
    // Имя тарифа пришло с кнопки, то есть от клиента. Оно уже прошло проверку
    // набора символов при разборе, но существование тарифа — отдельный
    // вопрос: цены меняются, а старая кнопка у человека в переписке остаётся.
    let Some(plan) = catalog::plan(plan_id) else {
        return (
            Reply {
                text: "Этого тарифа больше нет. Вот те, что есть:".to_owned(),
                keyboard: catalog::monthly_base().map(|base| plans_menu(&catalog::plans(), base)),
            },
            Effect::None,
        );
    };

    (
        Reply {
            text: format!("Выставляю счёт: {}.", plan.title),
            keyboard: None,
        },
        Effect::OpenOrder {
            plan: plan.id.clone(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{on_action, on_message, plural, Effect, View};
    use crate::menu::{Action, Device};

    const NOW: i64 = 1_760_000_000;
    const DAY: i64 = 86_400;
    const LINK: &str = "https://panel.example.org/api/sub/rTLwqLBoohWeKVAR";

    fn newcomer() -> View<'static> {
        View {
            expires_at: None,
            trial_used: false,
            subscription_url: None,
            now: NOW,
        }
    }

    fn active() -> View<'static> {
        View {
            expires_at: Some(NOW + 10 * DAY),
            trial_used: true,
            subscription_url: Some(LINK),
            now: NOW,
        }
    }

    fn expired() -> View<'static> {
        View {
            expires_at: Some(NOW - DAY),
            trial_used: true,
            subscription_url: Some(LINK),
            now: NOW,
        }
    }

    /// Проба включается при первом `/start` — не по кнопке и не по запросу:
    /// каждый лишний шаг между «зашёл» и «работает» теряет часть людей
    /// (docs/14-bot.md §4).
    #[test]
    fn the_first_start_turns_the_trial_on_without_asking() {
        let (reply, effect) = on_message("/start", &newcomer());
        assert_eq!(effect, Effect::GrantTrial);
        assert!(reply.text.contains("3 дня"), "{}", reply.text);
    }

    #[test]
    fn a_second_start_does_not_grant_anything() {
        let (_, effect) = on_message("/start", &active());
        assert_eq!(effect, Effect::None);
    }

    /// В группах Telegram дописывает к команде имя бота, и без отсечения
    /// `/start@GloriaVPN_Bot` не узнавался бы вовсе.
    #[test]
    fn a_command_addressed_to_the_bot_is_still_a_command() {
        let (_, effect) = on_message("/start@GloriaVPN_Bot", &newcomer());
        assert_eq!(effect, Effect::GrantTrial);
    }

    #[test]
    fn anything_else_shows_the_menu_instead_of_silence() {
        let (reply, effect) = on_message("привет", &active());
        assert_eq!(effect, Effect::None);
        assert!(reply.keyboard.is_some(), "человек остался без кнопок");
    }

    #[test]
    fn an_active_subscription_reports_the_days_left() {
        let (reply, _) = on_action(&Action::Subscription, &active());
        assert!(reply.text.contains("10 дней"), "{}", reply.text);
    }

    #[test]
    fn an_expired_subscription_says_so_plainly() {
        let (reply, _) = on_action(&Action::Subscription, &expired());
        assert!(reply.text.contains("закончилась"), "{}", reply.text);
    }

    /// Ссылка показывается всегда, а не только при действующей подписке:
    /// человек, у которого она уже вставлена в приложение, не должен искать
    /// её заново.
    #[test]
    fn the_link_is_shown_even_when_the_subscription_has_ended() {
        let (reply, _) = on_action(&Action::Subscription, &expired());
        assert!(reply.text.contains(LINK), "{}", reply.text);
    }

    #[test]
    fn a_newcomer_without_a_link_is_not_shown_an_empty_one() {
        let (reply, _) = on_action(&Action::Subscription, &newcomer());
        assert!(!reply.text.contains("<code>"), "{}", reply.text);
    }

    #[test]
    fn choosing_a_plan_asks_for_an_invoice() {
        let (_, effect) = on_action(&Action::Buy("d365".to_owned()), &active());
        assert_eq!(
            effect,
            Effect::OpenOrder {
                plan: "d365".to_owned()
            }
        );
    }

    /// Цены меняются, а старая кнопка остаётся у человека в переписке. Нажав
    /// её через полгода, он должен получить список нынешних тарифов, а не
    /// счёт по исчезнувшей цене.
    #[test]
    fn a_button_from_an_old_price_list_does_not_bill_anyone() {
        let (reply, effect) = on_action(&Action::Buy("d999".to_owned()), &active());
        assert_eq!(effect, Effect::None);
        assert!(reply.keyboard.is_some(), "не показаны нынешние тарифы");
    }

    /// Каждый экран обязан оставлять человеку кнопки. Экран без них — тупик,
    /// из которого выход только через перезапуск бота.
    #[test]
    fn no_screen_leaves_the_person_without_buttons() {
        let views = [newcomer(), active(), expired()];
        let actions = [
            Action::Subscription,
            Action::Plans,
            Action::Connect,
            Action::ConnectTo(Device::Iphone),
            Action::ConnectTo(Device::Android),
            Action::ConnectTo(Device::Desktop),
            Action::Help,
            Action::Home,
        ];

        let mut checked = 0;
        for view in &views {
            for action in &actions {
                let (reply, _) = on_action(action, view);
                assert!(
                    reply.keyboard.is_some(),
                    "экран {action:?} оставил человека без кнопок"
                );
                assert!(!reply.text.is_empty(), "экран {action:?} без текста");
                checked += 1;
            }
        }
        assert_eq!(checked, views.len() * actions.len());
    }

    /// Инструкция подключения обязана называть одно конкретное приложение,
    /// а не список из шести: список — это выбор, а выбор в этом месте люди
    /// делают неправильно и потом пишут в поддержку.
    #[test]
    fn each_device_gets_one_named_application() {
        for (device, app) in [
            (Device::Iphone, "Streisand"),
            (Device::Android, "Happ"),
            (Device::Desktop, "Hiddify"),
        ] {
            let (reply, _) = on_action(&Action::ConnectTo(device), &active());
            assert!(reply.text.contains(app), "{device:?}: {}", reply.text);
            assert!(reply.text.contains(LINK), "{device:?}: нет ссылки");
        }
    }

    /// Обещание из docs/17-payments.md, которое покупатель должен увидеть
    /// до покупки, а не после.
    #[test]
    fn help_admits_that_no_vpn_survives_regional_restrictions() {
        let (reply, _) = on_action(&Action::Help, &active());
        assert!(reply.text.contains("ни один VPN"), "{}", reply.text);
    }

    #[test]
    fn russian_plurals_are_right() {
        for (n, want) in [
            (1, "день"),
            (2, "дня"),
            (5, "дней"),
            (11, "дней"),
            (21, "день"),
            (22, "дня"),
            (101, "день"),
            (111, "дней"),
            (0, "дней"),
        ] {
            assert_eq!(plural(n, "день", "дня", "дней"), want, "число {n}");
        }
    }

    /// Полтора суток — это «осталось 2 дня»: пользоваться можно ещё и
    /// сегодня, и завтра.
    #[test]
    fn the_days_left_are_rounded_up() {
        let view = View {
            expires_at: Some(NOW + DAY + DAY / 2),
            trial_used: true,
            subscription_url: None,
            now: NOW,
        };
        let (reply, _) = on_action(&Action::Subscription, &view);
        assert!(reply.text.contains("2 дня"), "{}", reply.text);
    }

    /// Случай с боевого запуска: `/start` выдал три пробных дня, человек
    /// через десять минут нажал «Моя подписка» и прочёл «осталось 2 дня».
    /// Обещание и показания разошлись на глазах у покупателя.
    #[test]
    fn a_trial_checked_minutes_later_still_shows_all_its_days() {
        let granted_at = NOW;
        let view = View {
            expires_at: Some(granted_at + 3 * DAY),
            trial_used: true,
            subscription_url: None,
            now: granted_at + 10 * 60,
        };
        let (reply, _) = on_action(&Action::Subscription, &view);
        assert!(reply.text.contains("3 дня"), "{}", reply.text);
    }

    /// Обратный конец: подписка ещё действует, значит счётчик не вправе
    /// показывать ноль. «Осталось 0 дней» при работающем VPN — обращение в
    /// поддержку на ровном месте.
    #[test]
    fn the_last_half_hour_is_still_a_day() {
        let view = View {
            expires_at: Some(NOW + 1800),
            trial_used: true,
            subscription_url: None,
            now: NOW,
        };
        assert!(view.is_active());
        let (reply, _) = on_action(&Action::Subscription, &view);
        assert!(reply.text.contains("1 день"), "{}", reply.text);
    }
}
