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

use atlas_billing::{subscription, Currency, Money};

use crate::catalog;
use crate::menu::{
    connect_menu, main_menu, plans_menu, price_label, Action, Button, Device, Keyboard,
};

/// Что бот собирается сделать помимо ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Ничего, только ответить.
    None,
    /// Выдать пробный период.
    GrantTrial,
    /// Выставить счёт по тарифу.
    OpenOrder { plan: String },
    /// Человек говорит, что перевёл, и называет отправленную сумму.
    ///
    /// Сумма здесь — **его слова**, а не наш счёт: весь смысл в том, что он
    /// мог отправить не то, что мы выставили. Проверяет её владелец по
    /// выписке, зачисляется она только его командой.
    ClaimPaid { minor: u64 },
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
    /// Адрес кабинета. Есть — кнопки ведут в него, а не в переписку.
    pub app_url: Option<&'a str>,
    /// Сколько трафика осталось у пробы, байт. `None` — потолка нет.
    ///
    /// У пробы предел не в днях, а в гигабайтах, и показывать ей дни
    /// значит врать: трафик кончится раньше срока, VPN отключится, а экран
    /// будет обещать ещё неделю. Ровно та же ложь, что была с датой,
    /// поправленной в панели руками.
    pub trial_left: Option<u64>,
    /// Текущий момент.
    pub now: i64,
}

impl View<'_> {
    fn is_active(&self) -> bool {
        subscription::is_active(self.expires_at, self.now)
    }

    /// Сколько дней ещё можно пользоваться.
    ///
    /// Само правило — в `atlas_billing::subscription`: то же число
    /// показывает мини-приложение, и считаться оно обязано одинаково.
    fn days_left(&self) -> i64 {
        subscription::days_left(self.expires_at, self.now)
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

    // `/start d30` — приход из мини-приложения по кнопке тарифа. Счёт
    // выставляет бот, а не страница: сумма у каждого счёта своя, по ней
    // платёж потом и узнаётся, и придумывать её на клиенте нельзя.
    //
    // Имя тарифа пришло снаружи и здесь не проверяется: этим занимается
    // `buy`, и выдуманное имя получит список нынешних тарифов.
    if command == "/start" {
        if let Some(plan) = text.split_whitespace().nth(1) {
            if catalog::plan(plan).is_some() {
                return buy(plan);
            }
        }
    }

    match command {
        "/start" if !view.trial_used => (
            Reply {
                text: format!(
                    "{} на пробу уже включены — платить пока не нужно.\n\n\
                     Нажмите «Подключить», и я покажу, что делать дальше.",
                    gigabytes(catalog::TRIAL_BYTES)
                ),
                keyboard: Some(main_menu(view.app_url)),
            },
            Effect::GrantTrial,
        ),
        "/start" | "/menu" => (subscription_screen(view), Effect::None),

        // Эти двое объявлены в подсказке Telegram (см. `announce` в
        // `gloria`), поэтому обязаны делать ровно то, что там написано.
        // Раньше `/help` показывал экран подписки: команда есть, а помощи
        // по ней нет — худший вид обещания.
        "/connect" => (connect_screen(view), Effect::None),
        "/help" => (help_screen(view), Effect::None),
        _ => (
            Reply {
                text: "Не понял. Вот что я умею:".to_owned(),
                keyboard: Some(main_menu(view.app_url)),
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
        Action::Help => (help_screen(view), Effect::None),
        Action::Buy(plan) => buy(plan),

        Action::Paid(minor) => (paid_screen(*minor), Effect::None),
        Action::SentOther => (other_amount_screen(view), Effect::None),

        // Доступа это не даёт: проверить перевод может только тот, у кого
        // перед глазами выписка. Обещать срок не будем — обещание, которое
        // некому исполнить ночью, хуже честного «проверю».
        Action::Sent(minor) => (
            Reply {
                text: "Спасибо. Найду перевод и включу подписку — \
                       придёт сообщение."
                    .to_owned(),
                keyboard: None,
            },
            Effect::ClaimPaid { minor: *minor },
        ),
    }
}

/// Байты словами: «4,3 ГБ».
///
/// Один знак после запятой, и не из скупости: «4,28 ГБ» человек всё равно
/// читает как «около четырёх», а лишние цифры выглядят точностью, которой
/// у счётчика трафика нет.
///
/// Гигабайт здесь двоичный — тот же, каким его считает панель. Иначе наши
/// пять гигабайт не сошлись бы с её пятью.
#[must_use]
pub fn gigabytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;

    let whole = bytes / GIB;
    let tenths = (bytes % GIB) * 10 / GIB;
    if tenths == 0 {
        format!("{whole} ГБ")
    } else {
        format!("{whole},{tenths} ГБ")
    }
}

/// Что человек мог отправить, если выставлено `minor` копеек.
///
/// Две: сама сумма и следующая сотня. Первая — для тех, кто ввёл названное,
/// вторая — для округливших вверх «по-хорошему».
///
/// Целых рублей здесь нет намеренно, хотя 198,62 округляют и до 199. На
/// экране у человека стоит 198,62, а 199 — это цена тарифа, которую надо
/// вспомнить; отправивший именно её впишет её руками. Кнопка, которой
/// пользуется меньшинство, стоит внимания всех остальных.
///
/// Порядок от точного к грубому, повторы убраны: у счёта на ровные 200 обе
/// совпали бы, и человек увидел бы одну кнопку дважды.
fn claim_options(minor: u64) -> Vec<u64> {
    let mut options = vec![minor, round_up(minor, 10_000)];
    options.dedup();
    options
}

/// Округлить вверх до кратного `step`.
fn round_up(minor: u64, step: u64) -> u64 {
    match minor % step {
        0 => minor,
        tail => minor.saturating_add(step - tail),
    }
}

/// Экран «сколько вы отправили».
///
/// # Зачем вообще спрашивать
///
/// Платёж опознаётся по сумме: 198,62 назвали ровно одному. Это работает,
/// пока человек вводит названное, — а он вправе отправить 199 или 200,
/// и тогда его перевод не совпадает ни с одним счётом.
///
/// Знает отправленное только он сам. Банк сообщает владельцу сумму и не
/// сообщает, кто её отправил; мы знаем, кто нажал, и не знаем сколько.
/// Вопрос сводит эти две половины вместе, и стоит он один тап.
///
/// Кнопки, а не ввод числа: набранное руками пришлось бы разбирать,
/// переспрашивать и ловить «двести рублей» словами.
fn paid_screen(minor: u64) -> Reply {
    // Рубли здесь заданы прямо: кнопка «Я оплатил» стоит только под счётом
    // на перевод, а перевод у нас рублёвый. Появится счёт в другой валюте —
    // валюту придётся везти в самой кнопке.
    let money = |minor| Money::from_minor(minor, Currency::Rub);

    let rows = claim_options(minor)
        .into_iter()
        .map(|option| {
            let label = if option == minor {
                format!("{} — как в счёте", price_label(money(option)))
            } else {
                price_label(money(option))
            };
            vec![Button::new(label, Action::Sent(option))]
        })
        .collect();

    let mut rows: Vec<Vec<Button>> = rows;

    // Четвёртая кнопка — для сумм, которых нет среди готовых: 250, 500,
    // ошибочные 190. Без неё такой человек упирался бы в «напишите в
    // поддержку», то есть в ту самую переписку вручную, ради ухода от
    // которой всё и заведено.
    rows.push(vec![Button::new(
        "Отправил другую сумму",
        Action::SentOther,
    )]);

    Reply {
        text: "Какую сумму вы отправили?\n\n\
               Банк сообщает мне только сумму перевода, не имя отправителя. \
               По ней я и нахожу, чей платёж, — поэтому важно, \
               что вы отправили, а не что было в счёте.\n\n\
               По ней я и нахожу, чей платёж, — поэтому важно, \
               что вы отправили, а не что было в счёте."
            .to_owned(),
        keyboard: Some(Keyboard { rows }),
    }
}

/// Экран «напишите сумму сами».
///
/// Ввод числа, а не список: перечислить всё, что человек мог отправить,
/// нельзя, и попытка кончилась бы экраном из двадцати кнопок.
///
/// Отвечать он будет обычным сообщением, и никакой памяти о том, что мы
/// его спросили, у бота нет. Её роль играет открытый счёт: число от
/// человека, у которого счёта нет, — это просто число, и оно получает
/// меню, как получало раньше.
fn other_amount_screen(view: &View<'_>) -> Reply {
    Reply {
        text: "Напишите сумму сообщением — числом, как в банке.\n\n\
               Например: <code>250</code> или <code>250,50</code>.\n\n\
               Словами не разберу: ошибиться в сумме перевода нельзя, \
               а угадывать я не буду."
            .to_owned(),
        // Меню, хотя ответа мы ждём текстом. Экран без кнопок — тупик:
        // передумавшему остаётся только перезапускать бота.
        keyboard: Some(main_menu(view.app_url)),
    }
}

fn subscription_screen(view: &View<'_>) -> Reply {
    // У пробы своя мера. Пока она идёт, дни не называются вовсе: человек
    // упрётся в гигабайты гораздо раньше, чем в дату, и число дней ввело бы
    // его в заблуждение ровно в тот момент, когда VPN перестал работать.
    let head = if let Some(left) = view.trial_left.filter(|_| view.is_active()) {
        if left == 0 {
            "Пробные гигабайты закончились.\n\n\
             Дальше — подписка: трафик без ограничений."
                .to_owned()
        } else {
            format!(
                "Пробный доступ: осталось {} из {}.",
                gigabytes(left),
                gigabytes(catalog::TRIAL_BYTES)
            )
        }
    } else if view.is_active() {
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

    // Ссылка нужна в переписке ровно до тех пор, пока её негде показать
    // иначе. Есть кабинет — она живёт там, вместе с кнопкой «скопировать» и
    // переходом прямо в приложение. Дублировать её в чат значит завести
    // второе место для одного и того же; второе всегда отстаёт от первого.
    let link = match (view.app_url, view.subscription_url) {
        (None, Some(url)) => {
            format!("\n\nВаша ссылка — одна на все устройства:\n<code>{url}</code>")
        }
        _ => String::new(),
    };

    Reply {
        text: format!("{head}{link}"),
        keyboard: Some(main_menu(view.app_url)),
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
    // Есть кабинет — настройка живёт там: мастер по шагам, кнопка перехода
    // прямо в приложение и ссылка рядом. Повторять это переписке нечем.
    if let Some(base) = view.app_url {
        return Reply {
            text: "Настройка занимает минуту: выберите устройство, \
                   установите приложение и подтвердите."
                .to_owned(),
            keyboard: Some(Keyboard {
                rows: vec![vec![Button::app("Настроить", base, "setup")]],
            }),
        };
    }

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
    // Приложение одно и то же на всех устройствах — Happ; различается только
    // место, откуда его берут. INCY назван вторым и без объяснений: это
    // запасной вариант на случай, если первый не встал, а не второй пункт
    // выбора. Выбор в этом месте люди делают неправильно и пишут в поддержку.
    let store = match device {
        Device::Iphone => "App Store",
        Device::Android => "Google Play",
        Device::Desktop => "happ.su",
    };

    let link = match view.subscription_url {
        Some(url) => format!("\n\n3. Вставьте ссылку:\n<code>{url}</code>"),
        None => "\n\n3. Ссылка появится здесь после оплаты или пробного периода.".to_owned(),
    };

    Reply {
        text: format!(
            "1. Установите Happ — он есть в {store}.\n\n\
             2. Откройте приложение и выберите добавление подписки по ссылке.{link}\n\n\
             Дальше приложение само заберёт ключи и будет обновлять их при смене сервера.\n\n\
             Если Happ не подошёл, то же самое умеет INCY.",
        ),
        keyboard: Some(connect_menu()),
    }
}

fn help_screen(view: &View<'_>) -> Reply {
    Reply {
        text: "Напишите @GloriaVPNSupport_Bot — отвечает человек.\n\n\
               Частое: во время региональных ограничений мобильного интернета \
               не работает ни один VPN, включая наш, — ограничение стоит в сети \
               оператора. Дома по Wi-Fi и на проводном всё продолжает работать."
            .to_owned(),
        keyboard: Some(main_menu(view.app_url)),
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
    use super::{
        claim_options, on_action, on_message, other_amount_screen, paid_screen, plural, Effect,
        View,
    };
    use crate::menu::{Action, Device};

    const NOW: i64 = 1_760_000_000;
    const DAY: i64 = 86_400;
    const LINK: &str = "https://panel.example.org/api/sub/rTLwqLBoohWeKVAR";

    fn newcomer() -> View<'static> {
        View {
            expires_at: None,
            trial_used: false,
            subscription_url: None,
            app_url: None,
            trial_left: None,
            now: NOW,
        }
    }

    fn active() -> View<'static> {
        View {
            expires_at: Some(NOW + 10 * DAY),
            trial_used: true,
            subscription_url: Some(LINK),
            app_url: None,
            trial_left: None,
            now: NOW,
        }
    }

    fn expired() -> View<'static> {
        View {
            expires_at: Some(NOW - DAY),
            trial_used: true,
            subscription_url: Some(LINK),
            app_url: None,
            trial_left: None,
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
        // Проба называется гигабайтами, а не днями: её предел — трафик.
        assert!(reply.text.contains("5 ГБ"), "{}", reply.text);
    }

    #[test]
    fn a_second_start_does_not_grant_anything() {
        let (_, effect) = on_message("/start", &active());
        assert_eq!(effect, Effect::None);
    }

    /// Кнопка тарифа в мини-приложении уводит сюда: `/start d30`. Без этой
    /// ветки человек попадал бы на обычный экран подписки и не понимал, куда
    /// делся выбранный им тариф.
    #[test]
    fn a_plan_in_the_start_payload_opens_an_invoice() {
        let (reply, effect) = on_message("/start d30", &active());
        assert_eq!(
            effect,
            Effect::OpenOrder {
                plan: "d30".to_owned()
            }
        );
        // Сумму подставляет вызывающий: она у каждого счёта своя и считается
        // вне этого модуля. Здесь проверяется другое — что человек попал на
        // выбранный тариф, а не на общий экран со списком.
        assert!(reply.text.contains("1 месяц"), "{}", reply.text);
    }

    /// Приход по такой ссылке — не первый `/start`: пробу он выдавать не
    /// должен, иначе ссылка на оплату раздавала бы бесплатные дни.
    #[test]
    fn a_plan_link_does_not_hand_out_a_trial() {
        let (_, effect) = on_message("/start d30", &newcomer());
        assert_ne!(effect, Effect::GrantTrial);
    }

    /// Имя тарифа приходит снаружи. Выдуманное не должно ни выставлять счёт,
    /// ни ронять бота — только показывать нынешний список.
    #[test]
    fn a_made_up_plan_in_the_payload_shows_the_price_list() {
        let (reply, effect) = on_message("/start d9999", &active());
        assert_eq!(effect, Effect::None);
        assert!(reply.keyboard.is_some(), "не показаны тарифы");
    }

    /// Реферальная ссылка тоже приходит как `/start ref_123`. Тарифом она не
    /// является и обязана вести себя как обычный `/start`.
    #[test]
    fn a_referral_payload_still_behaves_like_a_plain_start() {
        let (_, effect) = on_message("/start ref_777", &newcomer());
        assert_eq!(effect, Effect::GrantTrial);
    }

    /// В группах Telegram дописывает к команде имя бота, и без отсечения
    /// `/start@GloriaVPN_Bot` не узнавался бы вовсе.
    #[test]
    fn a_command_addressed_to_the_bot_is_still_a_command() {
        let (_, effect) = on_message("/start@GloriaVPN_Bot", &newcomer());
        assert_eq!(effect, Effect::GrantTrial);
    }

    /// Команды объявлены в подсказке Telegram, значит обязаны делать ровно
    /// то, что там написано. `/help` показывал экран подписки — команда
    /// есть, а помощи по ней нет.
    #[test]
    fn every_announced_command_leads_where_it_promises() {
        // Сравниваем с кнопкой, а не с текстом: текст экрана меняется, а
        // требование остаётся прежним — команда и кнопка ведут в одно место.
        let (by_command, _) = on_message("/help", &active());
        let (by_button, _) = on_action(&Action::Help, &active());
        assert_eq!(by_command.text, by_button.text, "/help ведёт не в помощь");

        let (by_command, _) = on_message("/connect", &active());
        let (by_button, _) = on_action(&Action::Connect, &active());
        assert_eq!(
            by_command.text, by_button.text,
            "/connect ведёт не в подключение"
        );

        // И ни один из них не должен оказаться экраном подписки — с этого
        // всё и началось: `/help` показывал именно его.
        let (menu, _) = on_message("/menu", &active());
        assert_ne!(by_command.text, menu.text);
    }

    /// И с именем бота — в группах Telegram дописывает его сам.
    #[test]
    fn the_new_commands_survive_the_bot_name_too() {
        let (with_name, _) = on_message("/help@GloriaVPN_Bot", &active());
        let (plain, _) = on_message("/help", &active());
        assert_eq!(with_name.text, plain.text);
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

    /// «Я оплатил» никого не подключает: подписку включает подтверждение
    /// владельца, увидевшего поступление. Если бы нажатие само что-то
    /// продлевало, доступ раздавался бы по одному нажатию.
    #[test]
    fn saying_you_paid_does_not_grant_anything() {
        let (_, asked) = on_action(&Action::Paid(19_899), &expired());
        assert_eq!(asked, Effect::None, "вопрос о сумме что-то сделал");

        let (reply, effect) = on_action(&Action::Sent(20_000), &expired());
        assert_eq!(effect, Effect::ClaimPaid { minor: 20_000 });
        assert!(
            !reply.text.is_empty(),
            "нажатие осталось без ответа — человек решит, что кнопка не работает"
        );
    }

    /// Названная сумма — **слова покупателя**, и до владельца она обязана
    /// доехать нетронутой. Подставить вместо неё наш счёт значило бы
    /// отправить его искать в выписке то, чего там нет.
    #[test]
    fn the_named_sum_is_the_one_the_person_pressed() {
        for minor in [19_899_u64, 19_900, 20_000] {
            let (_, effect) = on_action(&Action::Sent(minor), &expired());
            assert_eq!(effect, Effect::ClaimPaid { minor });
        }
    }

    /// Вопрос «сколько вы отправили» обязан предлагать то, чем люди
    /// ошибаются: сам счёт и следующую сотню. Остальное пишется руками.
    #[test]
    fn the_question_offers_the_ways_people_round() {
        assert_eq!(claim_options(19_899), vec![19_899, 20_000]);
        assert_eq!(claim_options(49_863), vec![49_863, 50_000]);
        assert_eq!(claim_options(128_937), vec![128_937, 130_000]);

        // Ровный счёт округлять некуда — одна кнопка вместо двух одинаковых.
        assert_eq!(claim_options(20_000), vec![20_000]);
    }

    /// Экран без кнопок — тупик: человек уже перевёл деньги и сказать об
    /// этом ему нечем.
    #[test]
    fn the_question_always_has_buttons() {
        for minor in [19_899_u64, 19_900, 20_000, 129_000] {
            let reply = paid_screen(minor);
            let buttons = reply.keyboard.map_or(0, |keys| keys.buttons().count());

            // Готовые суммы плюс «другая»: у ровного счёта готовая одна, и
            // выход всё равно обязан быть.
            assert!(buttons >= 2, "у счёта на {minor} копеек нет ответов");
        }

        assert!(
            other_amount_screen(&expired()).keyboard.is_some(),
            "передумавшему некуда деться"
        );
    }

    /// То же правило обязано работать на **каждом** тарифе, а не только на
    /// месячном, на котором его придумывали.
    ///
    /// Проверка идёт по настоящей витрине и по всем хвостам, какие бывает:
    /// счёт — это цена минус 1..99 копеек. Для каждого должно получиться
    /// ровно два варианта — сам счёт и следующая сотня, — и вторая обязана
    /// совпасть у всех хвостов одного тарифа. Иначе двое, отправившие по
    /// 200 ₽, увидели бы разные круглые суммы.
    #[test]
    fn every_plan_offers_its_own_round_sum() {
        for plan in crate::catalog::plans() {
            let price = plan.price.minor();
            let expected_round = super::round_up(price, 10_000);

            for tail in 1..=99 {
                let invoice = price - tail;
                assert_eq!(
                    claim_options(invoice),
                    vec![invoice, expected_round],
                    "тариф {} на {price} копеек, счёт {invoice}",
                    plan.id
                );
            }
        }
    }

    /// У пробы предел в гигабайтах, и показывать ей дни — врать: трафик
    /// кончится раньше срока, VPN отключится, а экран будет обещать неделю.
    #[test]
    fn a_trial_is_measured_in_gigabytes_not_days() {
        let mut view = active();
        view.trial_left = Some(3 * 1024 * 1024 * 1024 + 1024 * 1024 * 1024 / 2);

        let text = on_action(&Action::Subscription, &view).0.text;
        assert!(text.contains("3,5 ГБ"), "не показан остаток: {text}");
        assert!(text.contains("5 ГБ"), "не названо, из скольких: {text}");
        // Именно «дней», а не «дн»: подстрока «дн» есть в слове «одна»,
        // которое стоит в строке про ссылку. Проверка на неё срабатывала
        // на ровном месте.
        assert!(
            !["день", "дня", "дней"]
                .iter()
                .any(|word| text.contains(word)),
            "у пробы названы дни: {text}"
        );

        // Кончились — говорим прямо, а не «осталось 0».
        view.trial_left = Some(0);
        let text = on_action(&Action::Subscription, &view).0.text;
        assert!(text.contains("закончились"), "{text}");

        // У оплаченной подписки предел прежний — дни.
        view.trial_left = None;
        let text = on_action(&Action::Subscription, &view).0.text;
        assert!(text.contains("дн"), "у подписки пропали дни: {text}");
    }

    /// Округление вниз до десятых, и без «5,0 ГБ» у ровного числа.
    #[test]
    fn gigabytes_read_like_people_write_them() {
        use super::gigabytes;
        const GIB: u64 = 1024 * 1024 * 1024;

        assert_eq!(gigabytes(5 * GIB), "5 ГБ");
        assert_eq!(gigabytes(0), "0 ГБ");
        assert_eq!(gigabytes(GIB / 2), "0,5 ГБ");
        assert_eq!(gigabytes(3 * GIB + GIB / 4), "3,2 ГБ");
        // Ни байта не показываем больше, чем есть: 4,99 — это «4,9».
        assert_eq!(gigabytes(5 * GIB - 1), "4,9 ГБ");
    }

    /// Любая сумма обязана быть выразимой. Готовых три, и человек, отправивший
    /// 250, упирался бы без этого в переписку вручную.
    #[test]
    fn any_amount_at_all_can_be_named() {
        let (reply, effect) = on_action(&Action::SentOther, &expired());
        assert_eq!(effect, Effect::None, "вопрос о сумме что-то сделал");
        assert!(
            reply.text.contains("250"),
            "не показан пример того, что писать"
        );

        // То, что человек напишет, разбирается тем же крейтом.
        assert_eq!(crate::menu::parse_typed_amount("250"), Some(25_000));
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

    /// Инструкция подключения обязана называть одно приложение и одно место,
    /// откуда его брать. Список — это выбор, а выбор в этом месте люди
    /// делают неправильно и потом пишут в поддержку.
    #[test]
    fn each_device_gets_one_named_application_and_one_place() {
        for (device, store) in [
            (Device::Iphone, "App Store"),
            (Device::Android, "Google Play"),
            (Device::Desktop, "happ.su"),
        ] {
            let (reply, _) = on_action(&Action::ConnectTo(device), &active());
            assert!(reply.text.contains("Happ"), "{device:?}: {}", reply.text);
            assert!(reply.text.contains(store), "{device:?}: {}", reply.text);
            assert!(reply.text.contains(LINK), "{device:?}: нет ссылки");
        }
    }

    /// Клиентов ровно два, и оба должны быть теми, что мы поддерживаем.
    /// Названия брошенных приложений в подсказке — это обращения в поддержку
    /// от людей, которые их поставили и не смогли подключиться.
    #[test]
    fn no_abandoned_client_is_recommended() {
        for device in [Device::Iphone, Device::Android, Device::Desktop] {
            let (reply, _) = on_action(&Action::ConnectTo(device), &active());
            for dropped in ["Streisand", "Hiddify", "v2rayTun", "Shadowrocket"] {
                assert!(
                    !reply.text.contains(dropped),
                    "{device:?} советует {dropped}: {}",
                    reply.text
                );
            }
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
            app_url: None,
            trial_left: None,
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
            app_url: None,
            trial_left: None,
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
            app_url: None,
            trial_left: None,
            now: NOW,
        };
        assert!(view.is_active());
        let (reply, _) = on_action(&Action::Subscription, &view);
        assert!(reply.text.contains("1 день"), "{}", reply.text);
    }
}
