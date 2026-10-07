//! Бот Gloria VPN.
//!
//! Здесь только соединение проводов: логика разговора живёт в `atlas-bot`,
//! деньги в `atlas-billing`, хранилище в `atlas-store`, панель в
//! `atlas-panel`, а разбор обновлений в `atlas-tg`. Всё это проверено
//! тестами по отдельности; этот файл намеренно оставлен настолько глупым,
//! насколько получилось, потому что проверить его можно только запуском.
//!
//! Порядок работы простой: спросить обновления, на каждое ответить, повторить.

#![forbid(unsafe_code)]

mod admin;
mod api;
mod config;
mod family;
mod http;
mod support;

use std::process::ExitCode;

use atlas_billing::{
    bonus, invoice, Checkout, Money, Order, OrderId, Provider, UserId, Wata, YooKassa,
};
use atlas_bot::{catalog, flow, Action, Button, Keyboard, Unknown};
use atlas_panel::{NewUser, Panel};
use atlas_store::{Accepted, Reminder, Settled, Store, Subscriber, Trial};
use atlas_tg::{next_offset, Command, Incoming, Scope, Telegram};

use config::Config;

/// Сколько секунд Telegram держит соединение, ожидая обновлений.
const LONG_POLL: u16 = 30;

/// Пауза после сбоя связи, чтобы не колотиться в упавшую службу.
const RETRY_PAUSE: std::time::Duration = std::time::Duration::from_secs(5);

fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Настройки: {error}");
            eprintln!("См. bot/README.md — там перечислено, что нужно задать.");
            return ExitCode::FAILURE;
        }
    };

    let Some(telegram) = Telegram::new(&config.bot_token) else {
        eprintln!("Настройки: токен бота имеет недопустимый вид");
        return ExitCode::FAILURE;
    };

    let Some(panel) = Panel::new(&config.panel_url, &config.panel_token) else {
        eprintln!("Настройки: адрес или токен панели негодны");
        return ExitCode::FAILURE;
    };

    let mut store = match Store::connect(&config.database_url) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("База: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Ключи ЮKassa проверяются при запуске, а не при первом счёте: узнать о
    // негодном ключе в момент, когда человек уже нажал «оплатить», — значит
    // узнать об этом от него.
    let yookassa = match (&config.yookassa_shop_id, &config.yookassa_secret) {
        (Some(shop), Some(secret)) => {
            let back = config.bot_username.as_ref().map_or_else(
                || "https://t.me".to_owned(),
                |name| format!("https://t.me/{name}"),
            );
            let Some(service) = YooKassa::new(shop, secret, &back) else {
                eprintln!("Настройки: ключи ЮKassa негодны");
                return ExitCode::FAILURE;
            };
            Some(service)
        }
        _ => None,
    };

    // Freekassa проверяется при запуске по той же причине: неполные или
    // негодные реквизиты не должны всплыть в момент, когда человек нажал
    // «оплатить». `config.freekassa()` собирает клиента, только если все три
    // реквизита на месте и годны.
    let freekassa = if config.freekassa_merchant.is_some() {
        let Some(service) = config.freekassa() else {
            eprintln!("Настройки: реквизиты Freekassa неполны или негодны");
            return ExitCode::FAILURE;
        };
        Some(service)
    } else {
        None
    };

    // WATA отдаёт СБП, карты, T-Pay и SberPay одной ссылкой, поэтому если
    // её токен задан, счёт открывает она. ЮKassa остаётся запасной.
    let wata = match &config.wata_token {
        Some(token) => {
            let back = config.bot_username.as_ref().map_or_else(
                || "https://t.me".to_owned(),
                |name| format!("https://t.me/{name}"),
            );
            let Some(service) = Wata::new(token, &back, &back) else {
                eprintln!("Настройки: токен WATA негоден");
                return ExitCode::FAILURE;
            };
            Some(service)
        }
        None => None,
    };

    // Мини-приложение поднимается до основного цикла: не занятый адрес —
    // это настройка, и знать о ней надо при запуске, а не при первом
    // человеке, открывшем кабинет.
    if let Err(error) = api::spawn(&config) {
        eprintln!("Мини-приложение: {error}");
        return ExitCode::FAILURE;
    }

    // Поддержка — отдельный бот со своим токеном. Не поднялся — об этом
    // сказано в журнале, и на остальное это не влияет: обращения тогда идут
    // туда, куда указывает кнопка в кабинете.
    support::spawn(&config);

    announce(&config, &telegram);

    println!("Бот запущен. {config:?}");
    let deps = Deps {
        config: &config,
        telegram: &telegram,
        panel: &panel,
        yookassa: yookassa.as_ref(),
        wata: wata.as_ref(),
        freekassa: freekassa.as_ref(),
    };
    run(&deps, &mut store);
    ExitCode::SUCCESS
}

/// Всё, с чем бот разговаривает наружу.
///
/// Собрано в один узел не ради красоты: эти четверо ходят вместе по всей
/// цепочке ответа, и по отдельности превращают каждую подпись в простыню.
struct Deps<'a> {
    config: &'a Config,
    telegram: &'a Telegram,
    panel: &'a Panel,
    /// Отсутствует, пока приём оплаты картой не подключён.
    yookassa: Option<&'a YooKassa>,
    /// Отсутствует, пока не подключена WATA. Если есть — счёт открывает она.
    wata: Option<&'a Wata>,
    /// Отсутствует, пока не подключена Freekassa.
    freekassa: Option<&'a atlas_billing::Freekassa>,
}

/// Основной цикл. Из него не выходят: любая ошибка — повод подождать и
/// попробовать снова, а не остановиться.
fn run(deps: &Deps<'_>, store: &mut Store) {
    let telegram = deps.telegram;
    let mut offset: Option<i64> = None;

    loop {
        let request = telegram.get_updates(offset, LONG_POLL);
        let response = match http::send(&request) {
            Ok(response) => response,
            Err(error) => {
                // Обязательно через redact: адрес запроса содержит токен.
                eprintln!(
                    "Telegram недоступен: {}",
                    telegram.redact(&error.to_string())
                );
                std::thread::sleep(RETRY_PAUSE);
                continue;
            }
        };

        let batch = match telegram.parse_updates(&response.body) {
            Ok(batch) => batch,
            Err(error) => {
                eprintln!("Ответ Telegram: {}", telegram.redact(&error.to_string()));
                std::thread::sleep(RETRY_PAUSE);
                continue;
            }
        };

        for update in &batch.updates {
            if let Err(error) = handle(deps, store, &update.incoming) {
                eprintln!("Обновление {}: {}", update.id, telegram.redact(&error));
            }
        }

        // Сдвиг двигается даже когда обработка не удалась. Иначе одно
        // упрямое обновление приходило бы вечно и загораживало остальные:
        // человек, чей запрос не удалось выполнить, напишет снова, а
        // застрявший бот не поможет никому.
        offset = next_offset(&batch, offset);

        sync_panel(deps.config, deps.panel, store);
        remind(deps, store);
    }
}

/// Рассказать Telegram о себе: команды в подсказке и кнопка «Меню».
///
/// Делается при каждом запуске, а не однажды руками в BotFather. Настройка,
/// живущая только на чужом сервере, восстанавливается по памяти — и не
/// восстанавливается; та же причина, по которой правила ответов панели
/// лежат в репозитории.
///
/// Ни один отказ здесь не останавливает бота. Подсказка — украшение; без
/// неё он работает ровно так же, а падение при запуске из-за недоступного
/// Telegram означало бы, что бот не поднимется, пока тот не ответит.
fn announce(config: &Config, telegram: &Telegram) {
    // Покупателю — три команды. Больше в подсказке вредно: список читают
    // целиком, и каждая лишняя строка уменьшает шанс, что прочтут нужную.
    let public = [
        Command::new("start", "подписка и меню"),
        Command::new("connect", "как подключить устройство"),
        Command::new("help", "поддержка"),
    ];

    let tell = |what: &str, request| match http::send(&request) {
        Ok(response) if response.is_ok() => {}
        Ok(response) => eprintln!(
            "{what}: панель Telegram отказала, код {}: {}",
            response.status,
            excerpt(&response.body)
        ),
        Err(error) => eprintln!("{what}: {}", telegram.redact(&error.to_string())),
    };

    tell(
        "Команды",
        telegram.set_my_commands(&public, Scope::Everyone),
    );

    // Владельцу — те же плюс свои. Отдельной областью, чтобы админские не
    // висели в подсказке у покупателей: это не дыра (бот всё равно
    // проверяет, кто пишет), но приглашение нажать на то, что откажет.
    if !config.admins.is_empty() {
        let mut owner: Vec<Command> = public.to_vec();
        owner.extend([
            Command::new("pending", "открытые счета"),
            Command::new("ok", "подтвердить оплату по сумме"),
            Command::new("revoke", "перевыпустить ссылку человеку"),
            Command::new("admin", "админка"),
        ]);

        for admin in &config.admins {
            tell(
                "Команды владельца",
                telegram.set_my_commands(&owner, Scope::Chat(*admin)),
            );
        }
    }

    // Кнопка «Меню» ведёт в кабинет. Без адреса её не ставим вовсе: по
    // умолчанию Telegram показывает там список команд, и это лучше, чем
    // кнопка, ведущая в никуда.
    if let Some(url) = &config.miniapp_url {
        tell("Кнопка меню", telegram.set_menu_button("Открыть VPN", url));
    }
}

/// Сколько напоминаний отправляем за круг.
///
/// Предел нужен по той же причине, что и у очереди панели: после долгого
/// простоя накопившееся не должно превратиться в сотню запросов подряд,
/// пока обновления Telegram не читаются.
const REMIND_PER_ROUND: i64 = 20;

/// Напомнить тем, у кого срок подходит или уже вышел.
///
/// Переключателя у этого нет и не будет. Напоминаний три за весь срок, и
/// каждое — о собственной подписке человека, а не рассылка. «Не сообщайте
/// мне, что подписка кончается» осознанно не выбирают, зато выключить
/// случайно и остаться без предупреждения легко. Общий выключатель у
/// человека и так есть: отключить звук боту или заблокировать его.
///
/// Отметка ставится **после** отправки. Не дошло — следующий круг
/// попробует снова; обратный порядок терял бы напоминание молча.
fn remind(deps: &Deps<'_>, store: &mut Store) {
    let due = match store.due_reminders(unix_now(), REMIND_PER_ROUND) {
        Ok(due) => due,
        Err(error) => {
            eprintln!("Напоминания: {error}");
            return;
        }
    };

    // Одна кнопка на все три сообщения: с кабинетом она ведёт прямо к
    // тарифам, без него — открывает их же перепиской.
    let renew = match &deps.config.miniapp_url {
        Some(base) => Keyboard {
            rows: vec![vec![Button::app("Оплата", base, "plans")]],
        },
        None => Keyboard {
            rows: vec![vec![Button::new("Оплата", Action::Plans)]],
        },
    };

    for item in due {
        let Some(text) = reminder_text(&item) else {
            // Вид из базы, которого мы не знаем. Молча пропускаем: гадать,
            // что написать человеку, хуже, чем не написать ничего.
            eprintln!("Напоминание {} неизвестного вида", item.kind);
            continue;
        };

        tell_with(deps.telegram, item.telegram_id, &text, Some(&renew));

        if let Err(error) = store.mark_reminded(item.telegram_id, &item.kind, item.expires_at) {
            eprintln!("Отметка напоминания для {}: {error}", item.telegram_id);
        }
    }
}

/// Что написать человеку. `None` — вид напоминания нам неизвестен.
///
/// Ни даты, ни счёта в уме. «Истекает завтра» человек понимает сразу;
/// «истекает 30.09.2026, меньше чем через сутки» — это два способа сказать
/// одно и то же, и второй лишний: какое сегодня число, он знает.
///
/// Что делать, говорит кнопка «Оплата» под сообщением. Словом в тексте
/// кабинет не открыть: ссылка из сообщения уводит в браузер, а кабинету
/// нужен запуск внутри Telegram — иначе не будет подписи, по которой мы
/// узнаём, кто пришёл.
///
/// У `same_day` вместо «сегодня» — дата и время: ночью напоминание уходит
/// накануне вечером, и «сегодня» было бы неправдой. У пробы своя пара
/// текстов: «подписка» человеку, который ещё не платил, звучит как счёт.
fn reminder_text(item: &Reminder) -> Option<String> {
    let at = moscow_time(item.expires_at);
    Some(match (item.kind.as_str(), item.trial) {
        ("day_before", true) => format!(
            "⏳ Пробный доступ закончится {at} (МСК).\n\n\
             Продлите доступ, чтобы оставаться на связи."
        ),
        ("day_before", false) => "⚠️ Подписка истекает завтра.\n\n\
                                  Продлите сейчас — и останетесь под защитой без перерыва."
            .to_owned(),

        ("same_day", true) => format!(
            "🚨 Пробный доступ заканчивается {at} (МСК).\n\n\
             Продлите сейчас, и VPN не отключится."
        ),
        ("same_day", false) => format!(
            "🚨 Подписка истекает {at} (МСК).\n\n\
             Продлите, и доступ не прервётся."
        ),

        // Здесь дата уместна: относительной оговорки рядом нет, и она
        // единственное, от чего человек может оттолкнуться.
        ("after_3d", _) => format!("Подписка закончилась {}.", day_month_year(item.expires_at)),

        _ => return None,
    })
}

/// Момент по Москве: `09.10.2026 в 14:05`. Москва — потому что часового
/// пояса человека мы не знаем, а покупатели в основном живут по ней.
fn moscow_time(seconds: i64) -> String {
    const MSK: i64 = 3 * 60 * 60;
    let local = seconds.saturating_add(MSK);
    let of_day = local.rem_euclid(24 * 60 * 60);
    format!(
        "{} в {:02}:{:02}",
        day_month_year(local),
        of_day / 3600,
        of_day % 3600 / 60
    )
}

/// Сколько человек за один круг увозим в панель.
///
/// Ограничение нужно на случай, когда панель была недоступна долго и очередь
/// накопилась: без него первый удачный круг превратился бы в сотни запросов
/// подряд, а обновления Telegram в это время не читались бы вовсе. Остаток
/// разберётся на следующих кругах — круг идёт не реже раза в полминуты.
const SYNC_PER_ROUND: i64 = 20;

/// Отвезти в панель даты окончания, которые она ещё не подтвердила.
///
/// Это единственное место, где наша дата попадает в панель, — и оплата, и
/// первая выдача проходят через него. Прямого вызова после оплаты нет
/// намеренно: он теряется при обрыве связи ровно в тот момент, когда деньги
/// уже взяты. Очередь при обрыве просто остаётся непустой.
///
/// Гасить просроченных не нужно: панель меняет статусы сама по той дате,
/// которая у неё записана.
///
/// Кроме случая, когда включён бесплатный доступ (`GLORIA_FREE_SQUADS`).
/// Тогда гасит бот: просроченному оставляет одни бесплатные отряды и далёкую
/// дату в панели, чтобы та его не погасила. Что именно везти — решает
/// [`panel_plan`].
fn sync_panel(config: &Config, panel: &Panel, store: &mut Store) {
    let with_free = config.free_enabled();
    let work = match store.panel_work(SYNC_PER_ROUND, unix_now(), with_free) {
        Ok(work) => work,
        Err(error) => {
            eprintln!("Очередь панели: {error}");
            return;
        }
    };

    for item in work {
        let plan = panel_plan(config, &item);
        let spec = atlas_panel::PlanSpec {
            expires_at: plan.expires_at,
            traffic_limit: plan.traffic,
            traffic_reset: plan.reset,
            devices: plan.devices,
            squads: &plan.squads,
        };
        let request = match panel.set_plan(item.panel_id, &spec) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("Панель для {}: {error}", item.telegram_id);
                continue;
            }
        };
        let response = match http::send(&request) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("Панель для {}: {error}", item.telegram_id);
                continue;
            }
        };

        // «Такого нет» — не отказ, а расхождение: пользователя удалили в
        // панели руками или панель переставили. Наш номер указывает в
        // пустоту, и повторять этот запрос до скончания века бессмысленно.
        // Забываем связь — при первом же обращении человека бот заведёт его
        // заново, с тем же оплаченным сроком.
        if response.status == 404 {
            eprintln!(
                "Панель потеряла {}: заводим заново при следующем обращении",
                item.telegram_id
            );
            if let Err(error) = store.forget_panel_link(item.telegram_id) {
                eprintln!("Сброс связи с панелью для {}: {error}", item.telegram_id);
            }
            continue;
        }

        if !response.is_ok() {
            eprintln!(
                "Панель для {} отказала, код {}: {}",
                item.telegram_id,
                response.status,
                excerpt(&response.body)
            );
            continue;
        }

        // Отметка ставится только после ответа панели. Ставить её заранее
        // значило бы считать потерянный запрос выполненным.
        let marked = if item.lapsed {
            println!(
                "Подписка {} закончилась: оставлен бесплатный доступ",
                item.telegram_id
            );
            store.mark_panel_free(item.telegram_id, item.expires_at, FREE_UNTIL)
        } else {
            store.mark_panel_synced(item.telegram_id, item.expires_at, &item.kind)
        };
        if let Err(error) = marked {
            eprintln!("Отметка о панели для {}: {error}", item.telegram_id);
        }
    }
}

/// Дата, которую панель видит у человека на бесплатном доступе.
///
/// Далёкая, чтобы панель его не гасила: гасит теперь бот — отрядами. Наша
/// настоящая дата остаётся у нас, в панель она не едет.
///
/// 31.12.2099. Конкретное число неважно, важно, что до него никто не
/// доживёт и что оно больше [`FREE_MARK`].
const FREE_UNTIL: i64 = 4_102_358_400;

/// Даты панели не раньше этой — метка бесплатного доступа, а не срок.
///
/// 01.01.2099. Сверка с панелью принимает ручные правки срока за истину —
/// и далёкую дату бесплатного доступа приняла бы так же, подарив человеку
/// подписку до конца века. Всё, что не раньше этой даты, сверка за правку не
/// считает.
const FREE_MARK: i64 = 4_070_908_800;

/// Что везти в панель об одном человеке.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Plan {
    expires_at: i64,
    traffic: u64,
    reset: atlas_panel::TrafficReset,
    devices: u8,
    squads: Vec<String>,
}

/// Решить, что везти. Чистая функция: здесь всё, что стоит проверять тестом.
///
/// Вид человека (`PanelWork::kind`) считает база, по нашей дате и тарифу:
///
/// | Вид | Срок | Трафик | Устройства | Отряды |
/// |---|---|---|---|---|
/// | `personal`, `family` | наш | безлимит | по тарифу | платные + бесплатные |
/// | `guest` | владельца | 30 ГБ, каждый месяц заново | 1 | платные + бесплатные |
/// | `paid` | наш | безлимит | 3 у платившего до тарифов, 2 у пробы | платные + бесплатные |
/// | `free` | 2099 | без потолка | 2 | только бесплатные |
///
/// У `free` потолка нет намеренно: проба, израсходованная до дна, иначе
/// отрезала бы человека и от бесплатного сервера, а он открывает только
/// Telegram и кабинет.
fn panel_plan(config: &Config, item: &atlas_store::PanelWork) -> Plan {
    use atlas_panel::TrafficReset;

    if item.lapsed {
        return Plan {
            expires_at: FREE_UNTIL,
            traffic: 0,
            reset: TrafficReset::Never,
            devices: catalog::TRIAL_DEVICES,
            squads: config.free_squads.clone(),
        };
    }

    let (traffic, reset, devices) = match item.kind.as_str() {
        "guest" => (
            catalog::GUEST_BYTES,
            TrafficReset::Monthly,
            catalog::GUEST_DEVICES,
        ),
        kind => match catalog::Tier::parse(kind) {
            Some(tier) => (0, TrafficReset::Never, tier.devices()),
            // Платил до тарифов — прежние три устройства до конца срока;
            // проба — как «Личный».
            None if item.has_paid => (0, TrafficReset::Never, catalog::DEVICES),
            // Проба — как «Личный» и тоже без потолка трафика.
            None => (0, TrafficReset::Never, catalog::TRIAL_DEVICES),
        },
    };

    Plan {
        expires_at: item.expires_at,
        traffic,
        reset,
        devices,
        squads: config.paid_squads(),
    }
}

/// Насколько дата панели должна разойтись с нашей, чтобы считать это
/// правкой, а не разным округлением.
///
/// Мы храним секунды, панель — строку ISO с миллисекундами, и обратный
/// перевод может отличаться на доли секунды. Без допуска такое отличие
/// выглядело бы как вечная правка: мы приняли бы её, записали, на следующем
/// круге снова увидели расхождение — и так без конца.
const PANEL_DRIFT: i64 = 60;

/// Что панель говорит о человеке сверх того, что знаем мы.
enum Verdict {
    /// Расхождений нет — записывать нечего.
    Same,
    /// Пользователя в панели больше нет: удалили руками или переставили её.
    Lost,
    /// Панель знает о нём другое.
    Differs {
        panel_id: i64,
        subscription_url: String,
        expires_at: i64,
    },
}

/// Сходить в панель и посмотреть, что там на самом деле.
///
/// В базу не ходит и её замка не держит: запрос по сети под общим замком
/// останавливал бы всех остальных на время похода.
///
/// Сверяемся только когда **своих** неувезённых изменений нет, то есть
/// `expires_at` совпадает с `panel_expires_at`. Если они разошлись, работа
/// уже стоит в очереди, и решает она: оплата важнее ручной правки. Условия
/// взаимоисключающие, поэтому очередь и сверка не тянут одну дату в разные
/// стороны.
fn panel_verdict(panel: &Panel, subscriber: &Subscriber, now: i64) -> Verdict {
    if !worth_asking(subscriber, now) {
        return Verdict::Same;
    }

    let telegram_id = subscriber.telegram_id;

    let Ok(request) = panel.find(telegram_id) else {
        return Verdict::Same;
    };
    let Ok(response) = http::send(&request) else {
        // Панель недоступна — это не повод портить разговор. Покажем то,
        // что знаем сами, и сверимся при следующем обращении.
        return Verdict::Same;
    };

    if response.status == 404 {
        return Verdict::Lost;
    }

    if !response.is_ok() {
        eprintln!(
            "Сверка с панелью для {telegram_id}: код {}",
            response.status
        );
        return Verdict::Same;
    }

    let user = match panel.parse_user(&response.body) {
        Ok(user) => user,
        Err(error) => {
            eprintln!("Сверка с панелью для {telegram_id}: {error}");
            return Verdict::Same;
        }
    };

    decide(subscriber, &user)
}

/// Стоит ли вообще спрашивать панель об этом человеке.
///
/// Вынесено отдельно, потому что это правило и есть защита от драки за одну
/// дату между очередью и сверкой.
fn worth_asking(subscriber: &Subscriber, now: i64) -> bool {
    // Не заведён в панели — сверять не с чем.
    if subscriber.panel_id.is_none() {
        return false;
    }

    // Своё несогласованное изменение — очередь довезёт его сама, и решает
    // она: оплата важнее ручной правки.
    if subscriber.expires_at == subscriber.panel_expires_at {
        return true;
    }

    // Даты разошлись, но очередь эту работу не возьмёт: прошедший срок
    // панель не примет, а пустого у неё и не спросишь. Ждать нечего, и без
    // этой оговорки такой человек не согласовался бы никогда — очередь его
    // пропускает, а сверка не бралась бы. Ровно в этот тупик мы и попали.
    subscriber
        .expires_at
        .is_none_or(|expires_at| expires_at <= now)
}

/// Чем ответ панели отличается от того, что записано у нас.
///
/// Чистая функция: ни сети, ни базы. Здесь живёт всё, что стоит проверять
/// тестом, — остальное вокруг только возит байты.
fn decide(subscriber: &Subscriber, user: &atlas_panel::User) -> Verdict {
    let known = subscriber.panel_expires_at.unwrap_or(0);
    // Далёкая дата бесплатного доступа — не правка срока, а метка: её
    // поставил сам бот. Принять её значило бы подарить подписку до 2099 года.
    let same_date = (user.expires_at - known).abs() < PANEL_DRIFT || user.expires_at >= FREE_MARK;
    let same_link = subscriber.subscription_url.as_deref() == Some(user.subscription_url.as_str())
        && subscriber.panel_id == Some(user.id);

    if same_date && same_link {
        return Verdict::Same;
    }

    Verdict::Differs {
        panel_id: user.id,
        subscription_url: user.subscription_url.clone(),
        expires_at: user.expires_at,
    }
}

/// Записать то, что сказала панель. По сети не ходит.
fn apply_verdict(store: &mut Store, subscriber: &mut Subscriber, verdict: Verdict) {
    let telegram_id = subscriber.telegram_id;

    match verdict {
        Verdict::Same => {}

        // Пользователя удалили в панели руками. Забываем связь: при
        // следующем обращении бот заведёт его заново с тем же сроком.
        Verdict::Lost => {
            eprintln!("Панель потеряла {telegram_id}: заводим заново");
            if let Err(error) = store.forget_panel_link(telegram_id) {
                eprintln!("Сброс связи с панелью для {telegram_id}: {error}");
                return;
            }
            subscriber.panel_id = None;
            subscriber.subscription_url = None;
            subscriber.panel_expires_at = None;
        }

        Verdict::Differs {
            panel_id,
            subscription_url,
            expires_at,
        } => {
            // Ссылка сменилась — значит пользователя в панели пересоздали.
            // Наш прежний адрес указывает в пустоту, и человек добавил бы в
            // приложение подписку, которой нет.
            if subscriber.subscription_url.as_deref() != Some(subscription_url.as_str())
                || subscriber.panel_id != Some(panel_id)
            {
                eprintln!("Ссылка на подписку {telegram_id} сменилась в панели: запоминаем новую");
                match store.link_to_panel(telegram_id, panel_id, &subscription_url) {
                    Ok(()) => {
                        subscriber.panel_id = Some(panel_id);
                        subscriber.subscription_url = Some(subscription_url);
                    }
                    Err(error) => eprintln!("Запись ссылки для {telegram_id}: {error}"),
                }
            }

            let known = subscriber.panel_expires_at.unwrap_or(0);
            if (expires_at - known).abs() < PANEL_DRIFT || expires_at >= FREE_MARK {
                return;
            }

            eprintln!(
                "Срок {telegram_id} правили в панели: было {}, стало {} — принимаем",
                day_month_year(known),
                day_month_year(expires_at)
            );

            if let Err(error) = store.adopt_from_panel(telegram_id, expires_at) {
                eprintln!("Приём даты из панели для {telegram_id}: {error}");
                return;
            }

            subscriber.expires_at = Some(expires_at);
            subscriber.panel_expires_at = Some(expires_at);
        }
    }
}

/// Сверить запись человека с панелью и принять то, что там поправили руками.
///
/// Очередь (`sync_panel`) возит даты **в одну сторону**: от нас к панели.
/// Пока никто не трогает панель руками, этого хватает. Стоит владельцу
/// продлить кого-нибудь прямо в панели — и мы об этом не узнаём никак:
/// кабинет показывает «истекла» человеку, у которого VPN работает.
///
/// Цена — один запрос к панели на обращение человека. При нынешних числах
/// это незаметно; когда станет заметно, сверку надо будет двигать в фоновый
/// круг с отметкой «когда проверяли в последний раз».
fn reconcile(panel: &Panel, store: &mut Store, subscriber: &mut Subscriber, now: i64) {
    let verdict = panel_verdict(panel, subscriber, now);
    apply_verdict(store, subscriber, verdict);
}

/// То же для мини-приложения, где база живёт под общим замком.
///
/// Замок берётся дважды и ни разу не держится на время похода в панель:
/// иначе один медленный ответ панели останавливал бы всех остальных.
pub fn reconcile_for(
    panel: &Panel,
    store: &std::sync::Mutex<Store>,
    telegram_id: i64,
    now: i64,
) -> Result<Subscriber, String> {
    let mut subscriber = {
        let mut guard = store.lock().map_err(|_| "замок базы испорчен".to_owned())?;
        guard
            .ensure_subscriber(telegram_id)
            .map_err(|error| format!("база: {error}"))?
    };

    let verdict = panel_verdict(panel, &subscriber, now);

    if !matches!(verdict, Verdict::Same) {
        let mut guard = store.lock().map_err(|_| "замок базы испорчен".to_owned())?;
        apply_verdict(&mut guard, &mut subscriber, verdict);
    }

    Ok(subscriber)
}

/// Ответить на одно обновление.
fn handle(deps: &Deps<'_>, store: &mut Store, incoming: &Incoming) -> Result<(), String> {
    let (config, telegram, panel) = (deps.config, deps.telegram, deps.panel);
    let telegram_id = incoming.from();
    let now = unix_now();

    // На нажатие отвечаем сразу, не дожидаясь остального: иначе у человека
    // кнопка крутится, пока мы ходим в базу и панель.
    if let Incoming::Button { callback_id, .. } = incoming {
        let _ = http::send(&telegram.answer_callback(callback_id, None));
    }

    // Админские команды идут в обход обычного разговора: они не про
    // подписку, а про чужие платежи, и показывать их всем нельзя.
    if let Incoming::Message { text, .. } = incoming {
        if config.is_admin(telegram_id) && is_command(text, "/admin") {
            return open_admin(config, telegram, incoming.chat());
        }
        if config.is_admin(telegram_id) {
            if let Some(answer) = admin(telegram, panel, store, text, now)? {
                let request = telegram
                    .send_message(incoming.chat(), &answer, None)
                    .map_err(|error| format!("сообщение: {error}"))?;
                http::send(&request).map_err(|error| format!("отправка: {error}"))?;
                return Ok(());
            }
        }
    }

    // Число сообщением — ответ на «напишите сумму сами». Памяти о том, что
    // мы спросили, у бота нет: её роль играет открытый счёт. Нет счёта —
    // это просто число, и оно пойдёт дальше обычным путём, в меню.
    //
    // Проверка стоит до захода в базу за покупателем, но обходится дёшево:
    // разбор чистый, и в базу мы идём только если он что-то нашёл.
    if let Incoming::Message { text, .. } = incoming {
        if let Some(minor) = atlas_bot::menu::parse_typed_amount(text) {
            if claim_typed(deps, store, telegram_id, minor, now)? {
                return Ok(());
            }
        }
    }

    let mut subscriber = store
        .ensure_subscriber(telegram_id)
        .map_err(|error| format!("база: {error}"))?;

    // Пришёл по чьей-то ссылке — запоминаем, кто привёл. Запись идёт сразу
    // после того, как человек заведён, и только один раз: решает это
    // хранилище, а здесь — лишь разбор ссылки.
    //
    // Бонусов приглашение пока не приносит и принесёт, только когда этот
    // человек заплатит и владелец платёж подтвердит.
    if let Incoming::Message { text, .. } = incoming {
        if let Some(inviter) = flow::parse_invite(text) {
            match store.remember_invite(telegram_id, inviter) {
                Ok(true) => println!("Приглашение: {telegram_id} от {inviter}"),
                Ok(false) => {}
                // Разговор не прерываем: человек пришёл пользоваться VPN, а
                // не оформлять приглашение.
                Err(error) => eprintln!("Приглашение для {telegram_id}: {error}"),
            }
        }
    }

    // Пришёл по семейному приглашению. Принимаем до сверки: сверка смотрит
    // на срок в памяти, и новый срок гостя должна видеть уже она, иначе
    // приняла бы прежнюю дату панели за ручную правку.
    let family = match incoming {
        Incoming::Message { text, .. } => atlas_bot::parse_family_invite(text)
            .map(|code| join_family(deps, store, &mut subscriber, &code, now)),
        Incoming::Button { .. } => None,
    };

    // Сначала сверка, потом всё остальное: срок могли поправить в панели
    // руками, и без этого человек увидел бы «истекла» при работающем VPN.
    reconcile(panel, store, &mut subscriber, now);

    // Подписка есть, а ссылки нет — значит панель отказала в тот раз, когда
    // мы заводили человека. Само это не исправится: проба выдаётся один раз,
    // и ветка с созданием в панели больше не отработает никогда. Чиним при
    // следующем же обращении, иначе оплативший останется без ссылки навсегда.
    if subscriber.subscription_url.is_none() {
        if let Some(expires_at) = subscriber.expires_at {
            match ensure_panel_user(config, panel, store, telegram_id, expires_at) {
                Ok(url) => subscriber.subscription_url = Some(url),
                // Разговор не прерываем. Меню без ссылки — плохо, молчащий
                // бот — хуже: человек не поймёт, сломалось у него или у нас.
                Err(error) => eprintln!("Панель для {telegram_id}: {error}"),
            }
        }
    }

    // Ответ на приглашение — вместо обычного приветствия: человек пришёл
    // именно за этим, и «добро пожаловать» с кнопкой пробы его бы запутало.
    if let Some(text) = family {
        let menu = atlas_bot::main_menu(config.miniapp_url.as_deref());
        let request = telegram
            .send_message(incoming.chat(), &text, Some(&menu))
            .map_err(|error| format!("сообщение: {error}"))?;
        http::send(&request).map_err(|error| format!("отправка: {error}"))?;
        return Ok(());
    }

    let view = flow::View {
        expires_at: subscriber.expires_at,
        on_trial: subscriber.trial_granted_at.is_some()
            && !subscriber.has_paid
            && subscriber.owner_id.is_none(),
        trial_used: subscriber.trial_granted_at.is_some(),
        subscription_url: subscriber.subscription_url.as_deref(),
        app_url: config.miniapp_url.as_deref(),
        trial_left: trial_left(panel, &subscriber),
        now,
    };

    let (reply, effect) = match incoming {
        Incoming::Message { text, .. } => flow::on_message(text, &view),
        Incoming::Button { data, .. } => match Action::decode(data) {
            Ok(action) => flow::on_action(&action, &view),
            // Нажатие, которого мы не понимаем, — либо старая кнопка, либо
            // изменённый клиент. И то и другое лечится показом меню.
            Err(Unknown::NoSuchAction | Unknown::BadPlanName | Unknown::BadAmount) => {
                flow::on_message("", &view)
            }
        },
    };

    let extra = apply(deps, store, telegram_id, &effect, now)?;

    let (text, keyboard) = match extra {
        Some(extra) => (
            format!("{}\n\n{}", reply.text, extra.text),
            extra.keyboard.or(reply.keyboard),
        ),
        None => (reply.text, reply.keyboard),
    };

    let request = telegram
        .send_message(incoming.chat(), &text, keyboard.as_ref())
        .map_err(|error| format!("сообщение: {error}"))?;

    let response = http::send(&request).map_err(|error| format!("отправка: {error}"))?;
    if !response.is_ok() {
        return Err(format!(
            "Telegram отверг сообщение, код {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        ));
    }
    Ok(())
}

/// Принять семейное приглашение и сказать, чем кончилось.
///
/// Ошибка базы не прерывает разговор: человек получит понятный отказ, а мы —
/// строку в журнале.
fn join_family(
    deps: &Deps<'_>,
    store: &mut Store,
    subscriber: &mut Subscriber,
    code: &str,
    now: i64,
) -> String {
    let guest_id = subscriber.telegram_id;
    let accepted = match store.accept_invite(guest_id, code, now) {
        Ok(accepted) => accepted,
        Err(error) => {
            eprintln!("Семейное приглашение для {guest_id}: {error}");
            return "Не получилось принять приглашение. Попробуйте ещё раз чуть позже.".to_owned();
        }
    };

    match accepted {
        Accepted::Joined {
            owner_id,
            expires_at,
        } => {
            println!("Семья: {guest_id} стал гостем {owner_id}");
            subscriber.expires_at = Some(expires_at);
            subscriber.owner_id = Some(owner_id);

            // Владельцу — весточка: место занято, и он должен знать кем.
            let text = format!(
                "👋 Ваше приглашение принято: к подписке подключился {guest_id}. \
                 Отключить гостя можно в кабинете, во вкладке «Друзья»."
            );
            if let Ok(request) = deps.telegram.send_message(owner_id, &text, None) {
                let _ = http::send(&request);
            }

            format!(
                "🎉 Готово: вам открыт VPN по семейной подписке до {}.\n\n\
                 У вас своя ссылка: 1 устройство и {} ГБ в месяц. \
                 Подключиться — кнопкой ниже.",
                day_month_year(expires_at),
                catalog::GUEST_BYTES / (1024 * 1024 * 1024)
            )
        }
        Accepted::Invalid => {
            "Приглашение не найдено, уже использовано или устарело — попросите новое.".to_owned()
        }
        Accepted::OwnInvite => {
            "Это ваше собственное приглашение — перешлите его тому, кого хотите подключить."
                .to_owned()
        }
        Accepted::OwnerInactive => {
            "Подписка того, кто вас пригласил, сейчас не даёт гостей. Попросите его продлить её."
                .to_owned()
        }
        Accepted::NoSlots => "Все места в этой подписке уже заняты.".to_owned(),
        Accepted::HasOwnSubscription => {
            "У вас уже есть своя оплаченная подписка, без ограничения трафика, — \
             приглашение вам не нужно."
                .to_owned()
        }
        Accepted::AlreadyGuest => {
            "Вы уже подключены к чьей-то подписке. Чтобы перейти к другой, попросите \
             нынешнего владельца отключить вас."
                .to_owned()
        }
        Accepted::HasGuests => {
            "К вашей подписке подключены гости, поэтому стать гостем самому нельзя.".to_owned()
        }
    }
}

/// Открыть страницу оплаты и вернуть её адрес.
///
/// Заказ уже лежит в базе к этому моменту, и это важно: страница может не
/// открыться, а деньги человек может перевести и вручную. Терять открытый
/// счёт из-за недоступности сервиса нельзя — человек его уже видел.
fn order_for(
    order_id: &str,
    telegram_id: i64,
    plan: &atlas_billing::Plan,
    amount: Money,
) -> Result<Order, String> {
    let Some(id) = OrderId::new(order_id) else {
        return Err("номер заказа не годится для платёжного сервиса".to_owned());
    };

    Ok(Order {
        id,
        user: UserId(telegram_id),
        plan: plan.id.clone(),
        amount,
        // Это видит покупатель в своём банке. «Оплата 199,37» без имени
        // читается как списание неизвестно за что и заканчивается спором.
        description: format!("Gloria VPN — {}", plan.title),
    })
}

/// Отправить запрос на создание оплаты и вернуть тело ответа.
fn ask_for_page(request: &atlas_billing::Request) -> Result<Vec<u8>, String> {
    let response = http::send(request).map_err(|error| format!("связь: {error}"))?;
    if !response.is_ok() {
        return Err(format!(
            "код {}: {}",
            response.status,
            excerpt(&response.body)
        ));
    }
    Ok(response.body)
}

fn checkout(
    service: &YooKassa,
    order_id: &str,
    telegram_id: i64,
    plan: &atlas_billing::Plan,
    amount: Money,
) -> Result<String, String> {
    let order = order_for(order_id, telegram_id, plan, amount)?;

    let Checkout::Request(request) = service
        .checkout(&order)
        .map_err(|error| format!("запрос не собрался: {error}"))?
    else {
        return Err("сервис не предложил запроса".to_owned());
    };

    service
        .checkout_page(&ask_for_page(&request)?)
        .map_err(|error| format!("ответ: {error}"))
}

/// То же через WATA.
///
/// Отдельная функция, а не ветка внутри общей: у WATA ссылке нужен срок
/// жизни, а сроку — часы, которых у платёжного крейта нет намеренно. Часы
/// живут здесь, и это единственное отличие.
fn checkout_wata(
    service: &Wata,
    order_id: &str,
    telegram_id: i64,
    plan: &atlas_billing::Plan,
    amount: Money,
    now: i64,
) -> Result<String, String> {
    let order = order_for(order_id, telegram_id, plan, amount)?;
    let request = service.checkout_at(&order, now);

    service
        .checkout_page(&ask_for_page(&request)?)
        .map_err(|error| format!("ответ: {error}"))
}

/// То же через Freekassa.
///
/// Два пути. С ключом API (его требует Freekassa) — запрос на создание
/// заказа и ссылка из ответа. Без ключа — старая форма SCI, которая
/// собирается на месте без похода в сеть.
///
/// В заказ API уходят почта вида `id@telegram.org` — так Freekassa не
/// просит покупателя вводить почту — и публичный IP сервера: бот за Caddy
/// видит только `127.0.0.1`, а его Freekassa отвергает.
fn checkout_freekassa(
    service: &atlas_billing::Freekassa,
    server_ip: Option<&str>,
    order_id: &str,
    telegram_id: i64,
    plan: &atlas_billing::Plan,
    amount: Money,
    fee_bp: u32,
) -> Result<String, String> {
    // В Freekassa уходит цена без комиссии: Freekassa прибавит её сама, и
    // покупатель заплатит ровно цену из меню. Обратный пересчёт — в
    // уведомлении (`freekassa_gross`).
    let order = order_for(
        order_id,
        telegram_id,
        plan,
        freekassa_charge(amount, fee_bp),
    )?;

    if service.uses_api() {
        let Some(ip) = server_ip else {
            return Err("для API Freekassa не задан GLORIA_SERVER_IP".to_owned());
        };
        let email = format!("{telegram_id}@telegram.org");
        let request = service
            .create_order(
                &order,
                &atlas_billing::freekassa::ApiOrder {
                    nonce: next_nonce(),
                    email: &email,
                    ip,
                    method: atlas_billing::freekassa::METHOD_SBP,
                },
            )
            .map_err(|error| format!("заказ не собрался: {error}"))?;
        return service
            .checkout_page(&ask_for_page(&request)?)
            .map_err(|error| format!("ответ: {error}"));
    }

    match service
        .checkout(&order)
        .map_err(|error| format!("форма не собралась: {error}"))?
    {
        Checkout::Page(url) => Ok(url),
        _ => Err("Freekassa не отдала ссылку".to_owned()),
    }
}

/// Сколько заплатит покупатель по СБП вместе с комиссией Freekassa.
///
/// Округление до копейки — к ближайшей, как у Freekassa: 199 ₽ при 6%
/// дают ровно 210,94 ₽, это сверено с настоящим заказом.
fn with_fee(amount: Money, fee_bp: u32) -> Money {
    let total = (u128::from(amount.minor()) * u128::from(10_000 + fee_bp) + 5_000) / 10_000;
    Money::from_minor(u64::try_from(total).unwrap_or(u64::MAX), amount.currency())
}

/// Сколько отправить в Freekassa, чтобы с её комиссией вышла ровно цена.
///
/// Freekassa прибавляет свою ставку к сумме заказа, и покупатель платил
/// больше, чем видел в меню. Теперь комиссию несёт сервис: в заказ уходит
/// наименьшая сумма, которая с наценкой даёт не меньше цены. Для всех цен
/// витрины наценка даёт цену ровно (199 ₽ → 187,74 ₽ → 199,00 ₽). У редких
/// сумм (после бонусов) копейка «перепрыгивается» — тогда выходит на
/// копейку больше: меньше нельзя, оплата не покрыла бы счёт.
///
/// Способ оплаты в заказе — СБП (`METHOD_SBP`), поэтому ставка одна:
/// `GLORIA_FREEKASSA_FEE`.
fn freekassa_charge(amount: Money, fee_bp: u32) -> Money {
    let price = amount.minor();
    let rate = u128::from(10_000 + fee_bp);
    let mut net = u64::try_from(u128::from(price) * 10_000 / rate).unwrap_or(price);
    let at = |minor: u64| with_fee(Money::from_minor(minor, amount.currency()), fee_bp).minor();
    while net > 0 && at(net - 1) >= price {
        net -= 1;
    }
    while net < price && at(net) < price {
        net += 1;
    }
    Money::from_minor(net, amount.currency())
}

/// Сумма в уведомлении Freekassa — обратно в то, что заплатил покупатель.
///
/// Freekassa сообщает сумму заказа, то есть цену без комиссии, а оплата
/// сверяется с ценой (`settle`). По построению `freekassa_charge` наценка
/// возвращает не меньше цены. Заказ, открытый до перехода на эту схему (в
/// Freekassa ушла полная цена), зачтётся тоже — покупатель тогда и правда
/// заплатил больше.
fn freekassa_gross(paid: Money, fee_bp: u32) -> Money {
    with_fee(paid, fee_bp)
}

/// Строка о комиссии, которую покупатель видит до оплаты.
const FEE_NOTE: &str = "Комиссия платёжной системы уже включена — к оплате ровно эта сумма.";

/// Номер запроса к API Freekassa.
///
/// Freekassa требует, чтобы он рос от запроса к запросу. Берём миллисекунды
/// с эпохи — после перезапуска они заведомо больше прежних, — а внутри
/// процесса не даём повториться: два счёта в одну миллисекунду (бот и
/// кабинет работают в разных потоках) получат разные номера.
fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);

    let mut previous = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(previous.saturating_add(1));
        match LAST.compare_exchange_weak(previous, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(seen) => previous = seen,
        }
    }
}

/// Что намерение дописывает к ответу.
struct Extra {
    /// Текст под ответом экрана.
    text: String,
    /// Кнопки взамен тех, что предложил экран. Нужны счёту: кнопка оплаты
    /// уводит на страницу сервиса, и построить её экран не может — ссылки
    /// на тот момент ещё не существует.
    keyboard: Option<Keyboard>,
}

impl From<String> for Extra {
    fn from(text: String) -> Self {
        Self {
            text,
            keyboard: None,
        }
    }
}

/// Выполнить намерение и вернуть то, что надо дописать к ответу.
fn apply(
    deps: &Deps<'_>,
    store: &mut Store,
    telegram_id: i64,
    effect: &flow::Effect,
    now: i64,
) -> Result<Option<Extra>, String> {
    let (config, telegram) = (deps.config, deps.telegram);
    match effect {
        flow::Effect::None => Ok(None),

        flow::Effect::GrantTrial => {
            let Trial::Granted { expires_at } = store
                .grant_trial(telegram_id, catalog::TRIAL_DAYS, now)
                .map_err(|error| format!("выдача пробы: {error}"))?
            else {
                // Проба уже выдавалась. Молча: человек об этом знает.
                return Ok(None);
            };

            let url = ensure_panel_user(config, deps.panel, store, telegram_id, expires_at)?;
            Ok(Some(
                format!("Ваша ссылка — одна на все устройства:\n<code>{url}</code>").into(),
            ))
        }

        flow::Effect::OpenOrder { plan } => {
            let Some(plan) = catalog::plan(plan) else {
                return Ok(None);
            };

            // Сначала возвращаем бонусы с истёкших счетов: человек мог
            // передумать вчера, и его же бонусы должны быть при нём сегодня.
            store
                .reclaim_expired_bonuses(telegram_id, now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("возврат бонусов: {error}"))?;

            let balance = store
                .bonus_balance(telegram_id)
                .map_err(|error| format!("бонусы: {error}"))?;

            // Скидка считается до подбора суммы, а не после: подбирается
            // уникальный хвост уже к той сумме, которую человек переведёт.
            // Наоборот — и опознавать пришлось бы не то, что пришло.
            let discounted = bonus::apply(plan.price, balance);

            let taken = store
                .taken_amounts(now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("занятые суммы: {error}"))?;

            // Уникальный копеечный хвост нужен только переводу: платёж там
            // опознаётся по сумме. Перевод выключен — платёжный сервис
            // опознаёт заказ по номеру, и счёт выставляется ровной ценой.
            let amount = if config.accepts_transfers() {
                invoice::allocate(discounted.to_pay, &taken)
                    .map_err(|_| "сейчас слишком много открытых счетов, попробуйте через минуту")?
            } else {
                discounted.to_pay
            };

            // Номер заказа: кто, что и когда. Набор символов проверяется
            // и здесь, и в базе — он уходит в подпись платёжного сервиса.
            let order_id = format!("u{telegram_id}-{}-{now}", plan.id);
            let opened = store
                .open_order(
                    &order_id,
                    telegram_id,
                    &plan.id,
                    plan.days,
                    amount,
                    discounted.spent,
                    now,
                )
                .map_err(|error| format!("счёт: {error}"))?;

            // Бонусов не хватило — значит их потратил счёт, открытый секунду
            // назад с другого устройства. Счёт не выставлен вовсе; говорим
            // об этом и не выставляем втихую по полной цене: человек ждёт
            // скидку и заплатит, не глядя на сумму.
            if !opened {
                return Err(
                    "бонусы уже заняты другим счётом — откройте его или подождите, \
                     пока он истечёт"
                        .to_owned(),
                );
            }

            // Владелец узнаёт о счёте сразу, а не когда вспомнит про
            // /pending. Счёт живёт двадцать минут: человек, заплативший и
            // ждущий, за это время успевает решить, что его обманули.
            notify_admins(
                config,
                telegram,
                &format!(
                    "Счёт <b>{}</b> · {} · от {telegram_id}{}\n  \
                     подтвердить: <code>/ok {}</code>",
                    atlas_bot::menu::price_label(amount),
                    plan.title,
                    // Скидка называется владельцу: иначе сумма, не похожая ни
                    // на один тариф, выглядит как ошибка, а не как бонусы.
                    if discounted.spent > 0 {
                        format!("\n  со скидкой {} за приглашённых", discounted.spent)
                    } else {
                        String::new()
                    },
                    amount.to_decimal(),
                ),
            );

            // Сначала пробуем открыть страницу оплаты. Не вышло — счёт
            // остаётся в базе и подтверждается вручную: терять уже открытый
            // заказ из-за недоступности сервиса нельзя, человек его видел.
            //
            // Порядок: Freekassa, затем WATA, затем ЮKassa. Freekassa первой,
            // потому что её подключают под СБП без процессинга; WATA даёт СБП
            // и карты одной ссылкой; ЮKassa запасная. Задан не один — берём
            // тот, что выше.
            let page = if let Some(service) = deps.freekassa {
                Some(checkout_freekassa(
                    service,
                    config.server_ip.as_deref(),
                    &order_id,
                    telegram_id,
                    &plan,
                    amount,
                    config.freekassa_fee_bp,
                ))
            } else if let Some(service) = deps.wata {
                Some(checkout_wata(
                    service,
                    &order_id,
                    telegram_id,
                    &plan,
                    amount,
                    now,
                ))
            } else {
                deps.yookassa
                    .map(|service| checkout(service, &order_id, telegram_id, &plan, amount))
            };

            if let Some(opened) = page {
                match opened {
                    Ok(page) => {
                        return Ok(Some(Extra {
                            text: format!(
                                "К оплате: <b>{}</b>{}{}\n\nСчёт действует 20 минут.",
                                atlas_bot::menu::price_label(amount),
                                // Комиссию Freekassa платит покупатель — он
                                // обязан увидеть её до оплаты, а не на
                                // странице банка.
                                if deps.freekassa.is_some() {
                                    format!("\n\n{FEE_NOTE}")
                                } else {
                                    String::new()
                                },
                                // Та же оговорка, что и на ручном пути: счёт
                                // меньше витринной цены без объяснения
                                // выглядит ошибкой, а не подарком.
                                if discounted.spent > 0 {
                                    format!("\nСписано бонусов: {}", discounted.spent)
                                } else {
                                    String::new()
                                }
                            ),
                            keyboard: Some(Keyboard {
                                rows: vec![vec![Button::link("Оплатить", page)]],
                            }),
                        }));
                    }
                    Err(error) => {
                        eprintln!("Оплата для {telegram_id}: {error}");
                        notify_admins(
                            config,
                            telegram,
                            &format!("Не открылась оплата по счёту {order_id}: {error}"),
                        );
                    }
                }
            }

            // Перевод — запасной способ, и его можно выключить
            // (GLORIA_MANUAL_TRANSFER). Тогда на этом месте — не ручной счёт, а
            // путь к человеку: иначе выключенный способ всё равно показался бы,
            // когда карта недоступна.
            if config.accepts_transfers() {
                Ok(Some(transfer_invoice(config, amount, discounted.spent)))
            } else {
                Ok(Some(Extra {
                    text: "Оплата сейчас недоступна — напишите в поддержку, \
                           и подписку выдадут вручную."
                        .to_owned(),
                    keyboard: None,
                }))
            }
        }

        flow::Effect::ClaimPaid { minor } => {
            // Программа о зачислении не знает: банк ей не сообщает. Знает
            // владелец счёта — и вся кнопка в том, чтобы он узнал сейчас, а
            // не когда сам заглянет в /pending.
            let sent = Money::from_minor(*minor, atlas_billing::Currency::Rub);
            let found = store
                .mark_claimed(telegram_id, sent, now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("база: {error}"))?;

            notify_admins(
                config,
                telegram,
                &claim_text(telegram_id, found.as_ref(), sent),
            );
            Ok(None)
        }
    }
}

/// Админские команды. `None` означает «это не админская команда».
///
/// Подтверждение вручную — то, чем рублёвый канал живёт, пока не одобрен
/// процессинг: банк не сообщает программе о зачислении, знает о нём только
/// владелец счёта.
/// Это команда `name` — с упоминанием бота или без (`/admin@gloria_bot`).
fn is_command(text: &str, name: &str) -> bool {
    text.split_whitespace()
        .next()
        .and_then(|word| word.split('@').next())
        == Some(name)
}

/// Адрес админки: тот же сайт, что у кабинета, папка `admin/`.
///
/// Параметры и якорь кабинета отбрасываются: они про кабинет, и админке
/// достались бы чужими.
fn admin_url(miniapp_url: &str) -> String {
    let base = miniapp_url
        .split(['?', '#'])
        .next()
        .unwrap_or(miniapp_url)
        .trim_end_matches('/');
    format!("{base}/admin/")
}

/// Ответить владельцу кнопкой, открывающей админку.
///
/// Кнопкой мини-приложения, а не ссылкой: только так страница получает
/// подпись Telegram, по которой сервер узнаёт владельца. Ссылка открылась бы
/// браузером, без подписи, и сервер справедливо отказал бы.
fn open_admin(config: &Config, telegram: &Telegram, chat: i64) -> Result<(), String> {
    let (text, keyboard) = match &config.miniapp_url {
        Some(url) => (
            "⚙️ Админка",
            Some(Keyboard {
                rows: vec![vec![Button::app("Открыть админку", &admin_url(url), "")]],
            }),
        ),
        None => (
            "Админке нужен адрес кабинета: задайте GLORIA_MINIAPP_URL.",
            None,
        ),
    };
    let request = telegram
        .send_message(chat, text, keyboard.as_ref())
        .map_err(|error| format!("сообщение: {error}"))?;
    http::send(&request).map_err(|error| format!("отправка: {error}"))?;
    Ok(())
}

fn admin(
    telegram: &Telegram,
    panel: &Panel,
    store: &mut Store,
    text: &str,
    now: i64,
) -> Result<Option<String>, String> {
    let mut parts = text.split_whitespace();
    let command = parts.next().unwrap_or("").split('@').next().unwrap_or("");

    match command {
        "/pending" => {
            let pending = store
                .pending_orders(now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("база: {error}"))?;

            if pending.is_empty() {
                return Ok(Some("Открытых счетов нет.".to_owned()));
            }

            let mut answer = String::from("Ожидают оплаты:\n");
            for order in pending {
                // Названная покупателем сумма — то, что ищется в выписке,
                // и она же идёт в готовую команду. Наша стоит рядом только
                // затем, чтобы владелец видел расхождение, а не гадал,
                // почему числа разные.
                let (search, note) = match order.claimed {
                    Some(sent) if sent != order.amount => (
                        sent,
                        format!(
                            " ✔ говорит: <b>{}</b> (счёт {})",
                            atlas_bot::menu::price_label(sent),
                            atlas_bot::menu::price_label(order.amount),
                        ),
                    ),
                    Some(sent) => (sent, " ✔ говорит, что отправил".to_owned()),
                    None => (order.amount, String::new()),
                };

                answer.push_str(&format!(
                    "\n<b>{}</b> · {} · {}{note}\n  \
                     подтвердить: <code>/ok {} {}</code>",
                    atlas_bot::menu::price_label(search),
                    order.plan,
                    order.telegram_id,
                    search.to_decimal(),
                    order.telegram_id,
                ));
            }
            Ok(Some(answer))
        }

        "/revoke" => {
            let Some(who) = parts.next().and_then(|w| w.parse::<i64>().ok()) else {
                return Ok(Some(
                    "Укажите номер: <code>/revoke</code> <i>номер</i>".to_owned(),
                ));
            };

            let url = reissue(panel, store, who)?;

            // Человека извещаем: его старая ссылка только что умерла, и без
            // предупреждения он увидит лишь то, что VPN перестал работать.
            tell(
                telegram,
                who,
                &format!(
                    "Ссылка на подписку перевыпущена — старая больше не работает.\n\n\
                     Новая:\n<code>{url}</code>\n\n\
                     Добавьте её в приложение заново."
                ),
            );

            Ok(Some(format!("Перевыпущено для {who}.")))
        }

        // Числа в подсказках намеренно заменены на «сумма» и «номер».
        // Пример вида «/ok 198.99» выглядит как настоящая сумма и является
        // ею: первый счёт по месячному тарифу получает ровно этот хвост,
        // `allocate` берёт ближайший свободный. Скопированный из подсказки
        // пример закрывает чужой живой счёт — так и вышло на первом же
        // настоящем подтверждении.
        "/ok" => {
            let Some(sum) = parts.next() else {
                return Ok(Some(
                    "Укажите сумму — ту, что пришла в банк:\n\n\
                     <code>/ok</code> <i>сумма</i>\n\
                     <code>/ok</code> <i>сумма номер</i> — если сумма не сошлась\n\n\
                     Готовые команды с настоящими числами есть в /pending: \
                     нажатие по ним копирует строку целиком."
                        .to_owned(),
                ));
            };
            let Some(amount) =
                atlas_billing::Money::parse_decimal(sum, atlas_billing::Currency::Rub)
            else {
                return Ok(Some(
                    "Сумма не разобралась. Ожидается число: <code>/ok</code> <i>сумма</i>"
                        .to_owned(),
                ));
            };

            // Второй, необязательный довод — номер человека. Обычно он не
            // нужен: сумма уникальна среди открытых счетов, по ней счёт и
            // находится. Нужен он тогда, когда сумма не сошлась: человек
            // округлил 198,63 до 200 или отправил 199 по памяти. Деньги
            // пришли, совпадения нет, и без этого выхода зачислить их нечем.
            let who = parts.next();
            if let Some(who) = who {
                let Some(who) = who.parse::<i64>().ok() else {
                    return Ok(Some(
                        "Номер не разобрался. Ожидается число: \
                         <code>/ok</code> <i>сумма номер</i>"
                            .to_owned(),
                    ));
                };

                // Сначала тот счёт, по которому этот человек назвал ровно
                // эту сумму. Иначе — самый свежий из его открытых.
                //
                // Порядок неслучаен. Счетов у человека может быть два: нажал
                // тариф, передумал, нажал другой. «Самый свежий» тогда не тот,
                // о котором идёт речь, и годовая оплата закрыла бы месячный
                // счёт — с продлением на месяц.
                let claimed = store
                    .orders_claiming(amount, now, catalog::INVOICE_LIFETIME)
                    .map_err(|error| format!("база: {error}"))?
                    .into_iter()
                    .find(|(_, buyer, _)| *buyer == who)
                    .map(|(order_id, _, invoiced)| (order_id, invoiced));

                let found = match claimed {
                    Some(found) => Some(found),
                    None => store
                        .pending_order_of(who, now, catalog::INVOICE_LIFETIME)
                        .map_err(|error| format!("база: {error}"))?,
                };

                let Some((order_id, invoiced)) = found else {
                    return Ok(Some(format!("У {who} нет открытого счёта.")));
                };

                return settle_order(telegram, store, &order_id, who, invoiced, amount, now)
                    .map(Some);
            }

            let found = store
                .order_by_amount(amount, now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("база: {error}"))?;
            if let Some((order_id, buyer)) = found {
                return settle_order(telegram, store, &order_id, buyer, amount, amount, now)
                    .map(Some);
            }

            // Счёта на такую сумму нет — но кто-то мог сказать, что отправил
            // именно её. По сумме счёта находится тот, кто ввёл названное;
            // округливший 198,97 до 199 по 198,97 не найдётся никогда, он
            // этих денег не отправлял. Зато он сказал, сколько отправил, и в
            // выписке лежит это самое число.
            //
            // Поэтому владельцу довольно того, что он видит в банке: номер
            // покупателя набирать не нужно, пока сказавший один.
            let claiming = store
                .orders_claiming(amount, now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("база: {error}"))?;

            match claiming.as_slice() {
                [] => Ok(Some(format!(
                    "Открытого счёта на {} нет, и столько никто не говорил, \
                     что отправил.\n\nПосмотрите /pending — там видно, кто ждёт \
                     и сколько назвал.",
                    atlas_bot::menu::price_label(amount)
                ))),

                [(order_id, buyer, invoiced)] => {
                    settle_order(telegram, store, order_id, *buyer, *invoiced, amount, now)
                        .map(Some)
                }

                // Сказавших несколько — решает человек. Взять первого молча
                // значило бы продлить подписку не тому, у кого лежат деньги,
                // а второй остался бы и без подписки, и без своих денег.
                several => {
                    let mut answer = format!(
                        "Столько сказали, что отправили, {} человек. \
                         Уточните, кому зачислить:\n",
                        several.len()
                    );
                    for (_, buyer, invoiced) in several {
                        answer.push_str(&format!(
                            "\n{buyer} · счёт был на {}\n  <code>/ok {} {buyer}</code>",
                            atlas_bot::menu::price_label(*invoiced),
                            amount.to_decimal(),
                        ));
                    }
                    Ok(Some(answer))
                }
            }
        }

        _ => Ok(None),
    }
}

/// Принять сумму, написанную сообщением.
///
/// Возвращает `false`, если счёта нет: тогда это было не про оплату, и
/// разговор идёт дальше обычным путём. Молчать в ответ нельзя — человек,
/// написавший «200» просто так, должен получить меню, а не тишину.
fn claim_typed(
    deps: &Deps<'_>,
    store: &mut Store,
    telegram_id: i64,
    minor: u64,
    now: i64,
) -> Result<bool, String> {
    let sent = Money::from_minor(minor, atlas_billing::Currency::Rub);
    let found = store
        .mark_claimed(telegram_id, sent, now, catalog::INVOICE_LIFETIME)
        .map_err(|error| format!("база: {error}"))?;

    if found.is_none() {
        return Ok(false);
    }

    notify_admins(
        deps.config,
        deps.telegram,
        &claim_text(telegram_id, found.as_ref(), sent),
    );

    tell(
        deps.telegram,
        telegram_id,
        &format!(
            "Записал: <b>{}</b>. Найду перевод и включу подписку — \
             придёт сообщение.",
            atlas_bot::menu::price_label(sent)
        ),
    );

    Ok(true)
}

/// Что получает владелец, когда покупатель говорит «я оплатил».
///
/// `sent` — сумма, которую назвал сам покупатель. Именно она ищется в
/// выписке и именно она стоит в готовой команде: наш счёт владельцу здесь
/// не нужен, он его уже видел при выставлении.
///
/// Команда даётся готовой, а не приглашением её вспомнить: подтверждение —
/// то единственное, что владелец делает руками, и делает он это с телефона.
///
/// Счёта может и не быть: истёк или кнопка нажата из старого сообщения.
/// Владельцу это всё равно сообщается — деньги-то могли прийти, — но
/// подтверждать тогда нечего, и готовой команды нет.
fn claim_text(telegram_id: i64, order: Option<&(String, Money)>, sent: Money) -> String {
    let label = atlas_bot::menu::price_label(sent);

    let Some((order_id, invoiced)) = order else {
        return format!(
            "{telegram_id} говорит, что отправил <b>{label}</b>, \
             но открытого счёта у него нет. \
             Если перевод был — попросите выставить счёт заново."
        );
    };

    // Расхождение называется вслух. Иначе владелец, помнящий счёт на 198,62,
    // ищет в выписке 198,62 и не находит ничего: человек отправил 200.
    let mismatch = if *invoiced == sent {
        String::new()
    } else {
        format!(
            "\nСчёт был на {} — округлил.",
            atlas_bot::menu::price_label(*invoiced)
        )
    };

    format!(
        "Ищите в выписке <b>{label}</b> · от {telegram_id} · \
         счёт <code>{order_id}</code>{mismatch}\n  \
         подтвердить: <code>/ok {} {telegram_id}</code>",
        sent.to_decimal(),
    )
}

/// Закрыть счёт полученной суммой и рассказать об этом обеим сторонам.
///
/// `invoiced` — сумма, которую мы назвали, `paid` — та, что пришла. Обычно
/// это одно и то же число; расходятся они только на запасном пути, когда
/// счёт найден по номеру человека, а не по сумме. Обе нужны: зачисляется
/// пришедшая, а в отказе «меньше выставленной» надо назвать выставленную —
/// иначе владельцу нечего сравнивать.
fn settle_order(
    telegram: &Telegram,
    store: &mut Store,
    order_id: &str,
    buyer: i64,
    invoiced: Money,
    paid: Money,
    now: i64,
) -> Result<String, String> {
    // Номер платежа собирается из суммы и времени: повторное
    // подтверждение того же счёта упрётся в UNIQUE и не продлит
    // подписку дважды.
    let reference = format!("{}-{order_id}", paid.minor());
    let settled = store
        .settle(order_id, "manual", &reference, paid, "{}", now)
        .map_err(|error| format!("зачисление: {error}"))?;

    // Покупателя извещаем сами. Он заплатил и ждёт; тишина после
    // платежа читается как «деньги пропали», и следующим сообщением
    // будет обращение в поддержку.
    if let Settled::Extended { expires_at } = settled {
        let text = format!(
            "Оплата получена. Подписка продлена до {}.\n\n\
             Ничего перенастраивать не нужно — ключ прежний, \
             приложение подхватит новый срок само.",
            day_month_year(expires_at)
        );
        tell(telegram, buyer, &text);

        // Пригласившему — сообщение о начислении. Молча пополнять счёт
        // нельзя: человек узнал бы о бонусах, только заглянув в кабинет, а
        // заглядывать туда без повода незачем. Сообщение и есть повод
        // рассказать про ссылку ещё кому-то.
        if let Err(error) = thank_the_inviter(telegram, store, buyer, paid) {
            // Зачисление уже состоялось и от этого не зависит.
            eprintln!("Бонусы пригласившему {buyer}: {error}");
        }
    }

    Ok(match settled {
        // Ответ называет закрытый счёт, а не просто «зачислено». Владелец
        // подтверждает по числу из выписки, и число это может совпасть с
        // чужим — со старым счётом того же тарифа, например. Тогда ошибка
        // видна сразу, а не всплывает в учёте через месяц.
        Settled::Extended { expires_at } => format!(
            "Зачислено <b>{}</b> · от {buyer} · счёт <code>{order_id}</code>\n\
             Подписка до {}.",
            atlas_bot::menu::price_label(paid),
            day_month_year(expires_at)
        ),
        Settled::AlreadyCounted => "Этот платёж уже был учтён.".to_owned(),
        Settled::OrderAlreadyPaid => "Счёт уже закрыт другим платежом.".to_owned(),
        Settled::Underpaid => format!(
            "Пришло {}, а выставлено {} — не зачислено.",
            atlas_bot::menu::price_label(paid),
            atlas_bot::menu::price_label(invoiced),
        ),
        Settled::NoSuchOrder => "Такого заказа нет.".to_owned(),
    })
}

/// Сказать пригласившему, что ему начислены бонусы.
///
/// Начисляет их само зачисление, в одной транзакции с продлением подписки;
/// здесь — только письмо. Поэтому неудача письма ничего не отменяет: бонусы
/// уже на счету, и человек увидит их в кабинете.
fn thank_the_inviter(
    telegram: &Telegram,
    store: &mut Store,
    buyer: i64,
    paid: Money,
) -> Result<(), String> {
    let Some(inviter) = store
        .inviter_of(buyer)
        .map_err(|error| format!("база: {error}"))?
    else {
        return Ok(());
    };

    let Some(earned) = bonus::earned(paid).filter(|earned| *earned > 0) else {
        return Ok(());
    };

    let balance = store
        .bonus_balance(inviter)
        .map_err(|error| format!("база: {error}"))?;

    // Номера покупателя в сообщении нет намеренно. Пригласивший знает, кого
    // звал; называть, кто именно и сколько заплатил, значит рассказывать
    // одному человеку о покупках другого.
    tell(
        telegram,
        inviter,
        &format!(
            "Ваш друг оплатил подписку — начислено {earned} \
             {}.\n\nВсего у вас {balance} {} — их можно списать при следующей \
             оплате, до половины суммы.",
            atlas_bot::flow::plural(
                i64::try_from(earned).unwrap_or(i64::MAX),
                "бонус",
                "бонуса",
                "бонусов"
            ),
            atlas_bot::flow::plural(
                i64::try_from(balance).unwrap_or(i64::MAX),
                "бонус",
                "бонуса",
                "бонусов"
            ),
        ),
    );
    Ok(())
}

/// Перевыпустить ссылку на подписку.
///
/// Старая перестаёт работать сразу и навсегда. Это единственный ответ на
/// утечку: адрес подписки сам по себе пропуск, отозвать его иначе нечем.
///
/// Возвращает новую ссылку. Панель отвечает обновлённым пользователем, из
/// него же берётся и новый адрес — собирать его самим нельзя, он строится
/// из нового `shortUuid`, которого мы не выдумываем.
pub fn reissue(panel: &Panel, store: &mut Store, telegram_id: i64) -> Result<String, String> {
    // Перевыпуск идёт по UUID, а хранится у нас числовой номер. Спрашиваем
    // панель по имени: оно выводится из номера Telegram и не меняется.
    let request = panel
        .find(telegram_id)
        .map_err(|error| format!("панель: {error}"))?;
    let found = http::send(&request).map_err(|error| format!("панель: {error}"))?;
    if !found.is_ok() {
        return Err(format!(
            "панель не нашла пользователя, код {}: {}",
            found.status,
            excerpt(&found.body)
        ));
    }
    // Шаг называется в сообщении: поиск и сам перевыпуск разбираются одним и
    // тем же кодом, и без пометки непонятно, какой из двух ответов подвёл.
    let user = panel
        .parse_user(&found.body)
        .map_err(|error| format!("поиск в панели: {error}"))?;

    let request = panel
        .revoke(&user.action_key())
        .map_err(|error| format!("панель: {error}"))?;
    let response = http::send(&request).map_err(|error| format!("панель: {error}"))?;
    if !response.is_ok() {
        return Err(format!(
            "панель отказала в перевыпуске, код {}: {}",
            response.status,
            excerpt(&response.body)
        ));
    }

    let user = panel
        .parse_user(&response.body)
        .map_err(|error| format!("ответ на перевыпуск: {error}"))?;

    // Записываем только после ответа панели: иначе при обрыве связи у нас
    // осталась бы ссылка, которой не существует, а у человека — рабочая
    // старая, которую мы считали бы отозванной.
    store
        .link_to_panel(telegram_id, user.id, &user.subscription_url)
        .map_err(|error| format!("база: {error}"))?;

    Ok(user.subscription_url)
}

/// Выставить счёт из кабинета и вернуть его описание страницей.
///
/// То же самое, что делает кнопка тарифа в чате, но без ухода в переписку:
/// человек остаётся в кабинете, видит сумму и нажимает «Оплатить» там же.
///
/// Сумма считается **здесь**, а не на странице. Она уникальна среди открытых
/// счетов, и по ней потом опознаётся платёж; придуманная клиентом совпала бы
/// с чужой или не совпала ни с чем.
///
/// Замок базы берётся дважды и не держится на время похода в Telegram:
/// извещение владельца идёт по сети, и ждать его всем остальным незачем.
pub(crate) fn open_order_for(
    shared: &api::Shared,
    telegram_id: i64,
    plan_id: &str,
    now: i64,
) -> Result<String, String> {
    let Some(plan) = catalog::plan(plan_id) else {
        return Err(format!("тарифа {plan_id} нет в витрине"));
    };

    let (order_id, amount, spent) = {
        let mut store = shared
            .store
            .lock()
            .map_err(|_| "замок базы испорчен".to_owned())?;

        // Бонусы применяются и здесь — тем же порядком, что и в боте. Иначе
        // одно и то же действие даёт разную цену, смотря откуда нажали.
        store
            .reclaim_expired_bonuses(telegram_id, now, catalog::INVOICE_LIFETIME)
            .map_err(|error| format!("возврат бонусов: {error}"))?;
        let balance = store
            .bonus_balance(telegram_id)
            .map_err(|error| format!("бонусы: {error}"))?;
        let discounted = bonus::apply(plan.price, balance);

        let taken = store
            .taken_amounts(now, catalog::INVOICE_LIFETIME)
            .map_err(|error| format!("занятые суммы: {error}"))?;

        // Копеечный хвост — только ради перевода (см. путь из чата).
        let amount = if shared.pay_link.is_some() {
            invoice::allocate(discounted.to_pay, &taken)
                .map_err(|_| "сейчас слишком много открытых счетов".to_owned())?
        } else {
            discounted.to_pay
        };

        let order_id = format!("u{telegram_id}-{}-{now}", plan.id);
        let opened = store
            .open_order(
                &order_id,
                telegram_id,
                &plan.id,
                plan.days,
                amount,
                discounted.spent,
                now,
            )
            .map_err(|error| format!("счёт: {error}"))?;

        if !opened {
            return Err("бонусы уже заняты другим счётом".to_owned());
        }

        (order_id, amount, discounted.spent)
    };

    // Владельца о счёте здесь **не** уведомляем. Раньше уведомление уходило
    // в момент открытия счёта — то есть до того, как человек выбрал способ.
    // Выбрал он карту или закрыл экран — а владелец уже получил «ждите
    // перевод», которого не будет. Теперь уведомление шлёт `announce_transfer`
    // по выбору «Перевод»: подтверждать вручную надо только перевод, у
    // Freekassa зачисление приходит само.
    let _ = spent;

    let pay = match &shared.pay_link {
        Some(url) => format!(r#""payUrl":"{}","#, atlas_tg::escape_json(url)),
        None => String::new(),
    };

    // Ссылка Freekassa — второй способ оплаты. Тот же заказ и та же сумма:
    // Freekassa опознаёт платёж по номеру заказа, а не по сумме, так что
    // уникальный хвост ей не мешает и один счёт годится обоим способам.
    // Кабинет по наличию этой ссылки и решает, показывать ли выбор.
    let freekassa = shared
        .freekassa
        .as_ref()
        .and_then(|service| {
            checkout_freekassa(
                service,
                shared.server_ip.as_deref(),
                &order_id,
                telegram_id,
                &plan,
                amount,
                shared.freekassa_fee_bp,
            )
            .map_err(|error| eprintln!("Freekassa для счёта {order_id}: {error}"))
            .ok()
        })
        .map(|url| {
            format!(
                r#""freekassaUrl":"{}","feeNote":"{}","#,
                atlas_tg::escape_json(&url),
                atlas_tg::escape_json(FEE_NOTE),
            )
        })
        .unwrap_or_default();

    // `minor` — то же число в копейках. Из него кабинет строит варианты
    // «сколько вы отправили», ровно как их строит чат: считать их на
    // сервере и везти списком значило бы завести второе место, где живёт
    // одно правило округления.
    Ok(format!(
        r#"{{"amount":"{}","minor":{},"label":"{}","bonusSpent":{spent},{pay}{freekassa}"life":"{}","orderId":"{order_id}"}}"#,
        amount.to_decimal(),
        amount.minor(),
        atlas_bot::menu::price_label(amount),
        atlas_tg::escape_json(&catalog::invoice_lifetime_label()),
    ))
}

/// Уведомить владельца, что человек выбрал оплату **переводом**.
///
/// Шлётся по выбору «Перевод по СБП» в кабинете, а не при открытии счёта:
/// перевод подтверждается вручную, и владельцу надо знать сумму, чтобы
/// поймать её в выписке. У Freekassa зачисление автоматическое, и такого
/// уведомления там нет вовсе.
///
/// Счёт берётся из базы по номеру и **только** если принадлежит этому
/// человеку: номер приходит от клиента, и подставить чужой нельзя.
pub(crate) fn announce_transfer(
    shared: &api::Shared,
    telegram_id: i64,
    order_id: &str,
) -> Result<(), String> {
    let notice = {
        let mut store = shared
            .store
            .lock()
            .map_err(|_| "замок базы испорчен".to_owned())?;
        store
            .transfer_notice(order_id, telegram_id)
            .map_err(|error| format!("база: {error}"))?
    };

    // Нет счёта — молчим. Либо номер чужой, либо счёт уже закрыт: ни то ни
    // другое не повод беспокоить владельца.
    let Some((amount, plan_id, spent)) = notice else {
        return Ok(());
    };

    let title = catalog::plan(&plan_id).map_or(plan_id, |plan| plan.title);

    if let Some(telegram) = &shared.telegram {
        for admin in &shared.admins {
            tell(
                telegram,
                *admin,
                &format!(
                    "Счёт <b>{}</b> · {title} · от {telegram_id} (перевод){}\n  \
                     подтвердить: <code>/ok {}</code>",
                    atlas_bot::menu::price_label(amount),
                    if spent > 0 {
                        format!("\n  со скидкой {spent} за приглашённых")
                    } else {
                        String::new()
                    },
                    amount.to_decimal(),
                ),
            );
        }
    }
    Ok(())
}

/// То же, что кнопка «Я оплатил» в чате, но нажатая в кабинете.
///
/// Оплата теперь начинается в кабинете, и возвращать человека в переписку
/// ради одной кнопки незачем: сказать «перевёл» он должен там же, где платил.
pub(crate) fn claim_paid_for(
    shared: &api::Shared,
    telegram_id: i64,
    sent: Money,
    now: i64,
) -> Result<(), String> {
    let found = {
        let mut store = shared
            .store
            .lock()
            .map_err(|_| "замок базы испорчен".to_owned())?;
        store
            .mark_claimed(telegram_id, sent, now, catalog::INVOICE_LIFETIME)
            .map_err(|error| format!("база: {error}"))?
    };

    let text = claim_text(telegram_id, found.as_ref(), sent);
    if let Some(telegram) = &shared.telegram {
        for admin in &shared.admins {
            tell(telegram, *admin, &text);
        }
    }

    Ok(())
}

/// То же, что [`reissue`], но под общим замком базы — для мини-приложения.
///
/// Замок держится только на записи результата, а не на походе в панель:
/// иначе один медленный ответ панели останавливал бы всех остальных.
pub fn reissue_for(
    panel: &Panel,
    store: &std::sync::Mutex<Store>,
    telegram_id: i64,
) -> Result<(), String> {
    let mut guard = store.lock().map_err(|_| "замок базы испорчен".to_owned())?;
    reissue(panel, &mut guard, telegram_id).map(|_| ())
}

/// Сколько трафика осталось у пробы. `None` — предела нет или он неизвестен.
///
/// Спрашивается у панели, а не считается у нас: байты живут там, и второго
/// места, где они считаются, быть не должно.
///
/// Спрашиваем **только про пробу**. У заплатившего трафик не ограничен, и
/// лишний поход в панель на каждое его сообщение ничего бы не дал.
///
/// Панель не ответила — возвращаем `None`, и человек увидит дни. Это хуже
/// точного числа и гораздо лучше молчания: разговор не прерывается из-за
/// того, что не удалось узнать остаток.
fn trial_left(panel: &Panel, subscriber: &Subscriber) -> Option<u64> {
    // У гостя потолок свой, месячный, — пробным он не назван и в боте не
    // показывается как проба.
    if subscriber.has_paid || subscriber.owner_id.is_some() || subscriber.expires_at.is_none() {
        return None;
    }

    let request = panel.find(subscriber.telegram_id).ok()?;
    let response = http::send(&request).ok()?;
    if !response.is_ok() {
        return None;
    }

    panel.parse_user(&response.body).ok()?.traffic_left()
}

/// Завести человека в панели, если его там ещё нет, и запомнить ссылку.
fn ensure_panel_user(
    config: &Config,
    panel: &Panel,
    store: &mut Store,
    telegram_id: i64,
    expires_at: i64,
) -> Result<String, String> {
    let request = panel
        .create(&NewUser {
            telegram_id,
            expires_at,
            squads: config.paid_squads(),
            // Проба — как «Личный»; тариф, если он есть, очередь отвезёт
            // следом вместе с отрядами.
            device_limit: catalog::TRIAL_DEVICES,
            // Без потолка: и у подписки, и у пробы (двое суток безлимита).
            traffic_limit: 0,
        })
        .map_err(|error| format!("панель: {error}"))?;

    let response = http::send(&request).map_err(|error| format!("панель: {error}"))?;

    // Человек мог остаться в панели от прошлого раза — например, если наша
    // база пересоздавалась. Тогда создание не проходит, и надо просто найти
    // его по имени: оно выводится из номера Telegram и не меняется.
    let body = if response.is_ok() {
        response.body
    } else {
        // Ответ на неудачное создание запоминаем до второй попытки: именно
        // он объясняет причину. Код от поиска не объясняет ничего — 404 там
        // означает обычное «такого пользователя нет», то есть в точности то,
        // ради чего мы и создавали.
        let refused_with = response.status;
        let refusal = excerpt(&response.body);

        let request = panel
            .find(telegram_id)
            .map_err(|error| format!("панель: {error}"))?;
        let found = http::send(&request).map_err(|error| format!("панель: {error}"))?;
        if !found.is_ok() {
            return Err(format!(
                "панель не завела ({refused_with}) и не нашла ({}) пользователя; \
                 адрес {}; ответ на создание: {refusal}",
                found.status, request.url
            ));
        }
        found.body
    };

    let user = panel
        .parse_user(&body)
        .map_err(|error| format!("панель: {error}"))?;

    store
        .link_to_panel(telegram_id, user.id, &user.subscription_url)
        .map_err(|error| format!("база: {error}"))?;

    Ok(user.subscription_url)
}

/// Что показать покупателю, когда страницу оплаты открыть не удалось или
/// платёжный сервис не подключён вовсе.
///
/// Перевод по ссылке, а не по номеру телефона: ссылка — это то же, что
/// стоит за QR-кодом в банковском приложении, и номер получателя она
/// плательщику не показывает. Имя получателя банк плательщика всё же
/// покажет — этим управляет он, а не мы.
///
/// Сумму человек вводит сам, и это не недоделка: по ней, скопеечной и
/// уникальной среди открытых счетов, владелец находит платёж в выписке.
/// Ссылка с зашитой суммой сломала бы поиск, а не упростила его.
fn transfer_invoice(config: &Config, amount: atlas_billing::Money, bonus: u64) -> Extra {
    let sum = atlas_bot::menu::price_label(amount);

    // Скидку называем прямо. Счёт на 139 ₽ там, где на витрине 199 ₽, без
    // объяснения выглядит не подарком, а ошибкой — и человек скорее
    // переспросит, чем заплатит.
    let discount = if bonus > 0 {
        format!(
            "\n\nСписано {bonus} {} за приглашённых — цена уменьшена на эту сумму.",
            atlas_bot::flow::plural(
                i64::try_from(bonus).unwrap_or(i64::MAX),
                "бонус",
                "бонуса",
                "бонусов"
            )
        )
    } else {
        String::new()
    };

    let Some(link) = &config.pay_link else {
        return format!(
            "К оплате: <b>{sum}</b>{discount}\n\n\
             Приём оплаты ещё настраивается — напишите @GloriaVPNSupport_Bot, \
             и подписку выдадут вручную."
        )
        .into();
    };

    // Кнопка называется так же, как у счёта от платёжного сервиса. Разными
    // словами мы описывали бы покупателю разницу, которая касается только
    // нас: он в обоих случаях делает одно — платит за подписку. А то, что
    // откроется банковское приложение, сказано следующей же строкой, и
    // неожиданностью это не станет.
    Extra {
        text: format!(
            "К оплате: <b>{sum}</b>{discount}\n\n\
             Нажмите «Оплатить» — откроется ваше банковское приложение. \
             Введите сумму <b>{sum}</b>: она должна совпасть до копейки, по ней \
             я нахожу ваш платёж.\n\n\
             Счёт действует {}. После перевода нажмите «Я оплатил».",
            catalog::invoice_lifetime_label()
        ),
        // Вторая кнопка есть только здесь, на ручном пути. У счёта от
        // платёжного сервиса она была бы лишней и вредной: там о зачислении
        // сообщает сам сервис, и нажимать человеку нечего.
        //
        // Толку от неё ровно столько, сколько от звонка в дверь: подписку она
        // не включает и включать не может — банк программе о переводе не
        // сообщает. Она сокращает ожидание, потому что владелец узнаёт о
        // переводе сразу, а не когда сам заглянет в /pending.
        keyboard: Some(Keyboard {
            rows: vec![
                vec![Button::link("Оплатить", link.clone())],
                vec![Button::new("Я оплатил", Action::Paid(amount.minor()))],
            ],
        }),
    }
}

/// Текущий момент в секундах эпохи.
///
/// Часы одни на весь бот: то же число уходит в базу, в расчёт сроков и в
/// проверку подписи мини-приложения.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Сказать что-то одному человеку, не прерывая начатого.
///
/// Отказ Telegram здесь не должен ломать то, ради чего всё делалось:
/// подписка уже продлена, деньги уже зачислены. Не дошло — строка в
/// журнал, а не откат.
fn tell(telegram: &Telegram, chat_id: i64, text: &str) {
    tell_with(telegram, chat_id, text, None);
}

/// То же, но с кнопками под сообщением.
fn tell_with(telegram: &Telegram, chat_id: i64, text: &str, keyboard: Option<&Keyboard>) {
    match telegram.send_message(chat_id, text, keyboard) {
        Ok(request) => {
            if let Err(error) = http::send(&request) {
                eprintln!(
                    "Сообщение для {chat_id}: {}",
                    telegram.redact(&error.to_string())
                );
            }
        }
        Err(error) => eprintln!("Сообщение для {chat_id}: {error}"),
    }
}

/// Сказать то же самое всем владельцам.
fn notify_admins(config: &Config, telegram: &Telegram, text: &str) {
    for admin in &config.admins {
        tell(telegram, *admin, text);
    }
}

/// Дата в том виде, в каком её читает человек: `31.08.2026`.
fn day_month_year(seconds: i64) -> String {
    api::day_month_year(seconds)
}

/// Начало ответа панели — для журнала.
///
/// Панель объясняет отказ в теле, а не в коде: `500` с `A018 Failed to create
/// user` чаще всего означает несуществующий UUID отряда. Печатать одно число
/// значит выбросить объяснение и искать его потом руками.
///
/// Обрезаем по символам, а не по байтам: тело приходит извне, разрез посреди
/// многобайтового символа испортил бы строку.
fn excerpt(body: &[u8]) -> String {
    const LIMIT: usize = 300;

    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    match text.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod reconcile_tests {
    use super::{decide, worth_asking, Verdict, FREE_MARK, FREE_UNTIL, PANEL_DRIFT};
    use atlas_store::Subscriber;

    const DAY: i64 = 86_400;
    const NOW: i64 = 1_788_861_600;

    /// Человек, у которого наша дата и дата панели сошлись.
    fn settled() -> Subscriber {
        Subscriber {
            telegram_id: 42,
            expires_at: Some(NOW),
            panel_expires_at: Some(NOW),
            trial_granted_at: Some(NOW - 3 * DAY),
            panel_id: Some(7),
            subscription_url: Some("https://panel.example.org/api/sub/AbCdE".to_owned()),
            has_paid: false,
            tier: None,
            owner_id: None,
        }
    }

    fn in_panel(expires_at: i64) -> atlas_panel::User {
        atlas_panel::User {
            id: 7,
            uuid: String::new(),
            short_uuid: "AbCdE".to_owned(),
            username: "tg_42".to_owned(),
            telegram_id: Some(42),
            status: "ACTIVE".to_owned(),
            expires_at,
            subscription_url: "https://panel.example.org/api/sub/AbCdE".to_owned(),
            used_traffic: 0,
            traffic_limit: 0,
        }
    }

    /// Ради чего всё это: срок продлили руками в панели. Без приёма этой
    /// правки кабинет говорит «истекла» человеку, у которого VPN работает.
    #[test]
    fn a_date_changed_by_hand_in_the_panel_is_adopted() {
        let verdict = decide(&settled(), &in_panel(NOW + 22 * DAY));
        assert!(
            matches!(verdict, Verdict::Differs { expires_at, .. } if expires_at == NOW + 22 * DAY),
            "правка в панели не замечена"
        );
    }

    /// Своё неувезённое изменение важнее: за него заплатили. Пока очередь не
    /// доехала, панель не спрашиваем вовсе — иначе двое тянули бы одну дату
    /// в разные стороны и она качалась бы между двумя значениями.
    #[test]
    fn our_own_pending_change_wins_and_the_panel_is_not_asked() {
        let mut subscriber = settled();
        subscriber.expires_at = Some(NOW + 30 * DAY);
        assert!(!worth_asking(&subscriber, NOW));
    }

    /// Тупик, в который мы попали. Наша дата в прошлом, панель такую не
    /// примет и отвечает `400`; очередь эту строку теперь не берёт. Если бы
    /// сверка тоже за неё не бралась, человек не согласовался бы никогда —
    /// кабинет вечно показывал бы «Истекла» при работающем VPN.
    #[test]
    fn a_past_date_the_queue_cannot_deliver_is_reconciled_instead() {
        let mut subscriber = settled();
        subscriber.expires_at = Some(NOW - DAY);
        subscriber.panel_expires_at = Some(NOW + 22 * DAY);
        assert!(worth_asking(&subscriber, NOW));
    }

    /// А будущая дата, ещё не увезённая, по-прежнему держит сверку: за неё
    /// заплатили, и решать должна очередь.
    #[test]
    fn a_future_pending_date_still_belongs_to_the_queue() {
        let mut subscriber = settled();
        subscriber.expires_at = Some(NOW + 30 * DAY);
        subscriber.panel_expires_at = Some(NOW);
        assert!(!worth_asking(&subscriber, NOW));
    }

    /// Не заведён в панели — спрашивать не о чем.
    #[test]
    fn somebody_absent_from_the_panel_is_not_asked_about() {
        let mut subscriber = settled();
        subscriber.panel_id = None;
        assert!(!worth_asking(&subscriber, NOW));
    }

    #[test]
    fn a_settled_subscriber_is_worth_asking_about() {
        assert!(worth_asking(&settled(), NOW));
    }

    /// Далёкую дату бесплатного доступа поставил сам бот. Принять её за
    /// ручное продление значило бы подарить человеку подписку до 2099 года —
    /// в том числе если отметка о бесплатном доступе не успела записаться.
    #[test]
    fn the_free_plan_date_is_never_taken_for_a_renewal() {
        let mut subscriber = settled();
        subscriber.expires_at = Some(NOW - DAY);
        subscriber.panel_expires_at = Some(NOW - DAY);
        for panel_date in [FREE_MARK, FREE_UNTIL, FREE_UNTIL + DAY] {
            assert!(
                matches!(decide(&subscriber, &in_panel(panel_date)), Verdict::Same),
                "дата {panel_date} принята за продление"
            );
        }
    }

    /// А настоящее ручное продление бесплатного человека по-прежнему
    /// принимается: владелец продлил в панели — очередь вернёт платное.
    #[test]
    fn a_real_renewal_of_a_free_person_is_still_adopted() {
        let mut subscriber = settled();
        subscriber.expires_at = Some(NOW - DAY);
        subscriber.panel_expires_at = Some(FREE_UNTIL);
        let verdict = decide(&subscriber, &in_panel(NOW + 30 * DAY));
        assert!(
            matches!(verdict, Verdict::Differs { expires_at, .. } if expires_at == NOW + 30 * DAY),
            "ручное продление не замечено"
        );
    }

    /// Совпало — записывать нечего.
    #[test]
    fn the_same_date_and_link_mean_no_work() {
        assert!(matches!(decide(&settled(), &in_panel(NOW)), Verdict::Same));
    }

    /// Мы храним секунды, панель — строку с миллисекундами. Без допуска
    /// обратный перевод дал бы вечную «правку»: приняли, записали, на
    /// следующем круге снова увидели расхождение — и так без конца.
    #[test]
    fn a_difference_smaller_than_the_drift_is_not_a_change() {
        for shift in [-(PANEL_DRIFT - 1), -1, 0, 1, PANEL_DRIFT - 1] {
            assert!(
                matches!(decide(&settled(), &in_panel(NOW + shift)), Verdict::Same),
                "сдвиг {shift} принят за правку"
            );
        }
    }

    /// А ровно на допуске — уже правка: граница должна быть где-то, и лучше
    /// ей быть проверенной.
    #[test]
    fn a_difference_at_the_drift_is_a_change() {
        for shift in [-PANEL_DRIFT, PANEL_DRIFT] {
            assert!(
                matches!(
                    decide(&settled(), &in_panel(NOW + shift)),
                    Verdict::Differs { .. }
                ),
                "сдвиг {shift} не принят за правку"
            );
        }
    }

    /// Пользователя пересоздали в панели: дата та же, а ссылка новая. Наш
    /// прежний адрес указывает в пустоту, и человек добавил бы в приложение
    /// подписку, которой нет.
    #[test]
    fn a_new_subscription_link_is_noticed_even_when_the_date_matches() {
        let mut user = in_panel(NOW);
        user.subscription_url = "https://panel.example.org/api/sub/ZZZZZ".to_owned();

        let verdict = decide(&settled(), &user);
        assert!(
            matches!(
                verdict,
                Verdict::Differs { ref subscription_url, .. }
                    if subscription_url.ends_with("ZZZZZ")
            ),
            "смена ссылки не замечена"
        );
    }

    /// И то же самое, когда сменился внутренний номер: продление уходило бы
    /// не тому.
    #[test]
    fn a_new_panel_number_is_noticed_too() {
        let mut user = in_panel(NOW);
        user.id = 9;

        let verdict = decide(&settled(), &user);
        assert!(
            matches!(verdict, Verdict::Differs { panel_id, .. } if panel_id == 9),
            "смена номера не замечена"
        );
    }

    /// Панель ни разу не подтверждала дату: сравнивать не с чем, и всё, что
    /// она скажет, — правка. Иначе первый же такой человек остался бы с
    /// нулём вместо срока.
    #[test]
    fn a_date_never_confirmed_by_the_panel_counts_as_a_change() {
        let mut subscriber = settled();
        subscriber.expires_at = None;
        subscriber.panel_expires_at = None;

        assert!(worth_asking(&subscriber, NOW));
        assert!(matches!(
            decide(&subscriber, &in_panel(NOW)),
            Verdict::Differs { .. }
        ));
    }
}

#[cfg(test)]
mod excerpt_tests {
    use super::excerpt;

    #[test]
    fn a_short_answer_is_shown_whole() {
        let body = br#"{"message":"Failed to create user","errorCode":"A018"}"#;
        assert_eq!(
            excerpt(body),
            r#"{"message":"Failed to create user","errorCode":"A018"}"#
        );
    }

    #[test]
    fn an_empty_answer_does_not_become_noise() {
        assert_eq!(excerpt(b""), "");
        assert_eq!(excerpt(b"  \n "), "");
    }

    /// Тело приходит извне: разрез посреди многобайтового символа выдал бы
    /// в журнал испорченную строку, а то и панику при делении по байтам.
    #[test]
    fn a_long_answer_is_cut_on_a_character_boundary() {
        let body = "щ".repeat(500);
        let cut = excerpt(body.as_bytes());
        assert!(cut.ends_with('…'));
        assert_eq!(cut.chars().count(), 301);
    }

    /// Панель может ответить и не текстом — например, страницей ошибки от
    /// промежуточного сервера. Журнал от этого не должен ломаться.
    #[test]
    fn bytes_that_are_not_text_do_not_break_anything() {
        assert_ne!(excerpt(&[0xff, 0xfe, 0x00, 0x41]).len(), 0);
    }
}

#[cfg(test)]
mod reminder_tests {
    use super::{moscow_time, reminder_text};
    use atlas_store::Reminder;

    /// 2 ноября 2026 года, 11:05 UTC — 14:05 по Москве.
    const AT: i64 = 1_793_577_600 + 11 * 3600 + 5 * 60;

    #[test]
    fn time_is_shown_by_moscow() {
        assert_eq!(moscow_time(AT), "02.11.2026 в 14:05");
        // 22:30 UTC — уже следующий день по Москве.
        assert_eq!(
            moscow_time(1_793_577_600 + 22 * 3600 + 1800),
            "03.11.2026 в 01:30"
        );
    }

    /// Проба называет дату и время окончания и просит продлить.
    #[test]
    fn a_trial_reminder_names_the_moment() {
        for kind in ["day_before", "same_day"] {
            let item = Reminder {
                telegram_id: 1,
                kind: kind.to_owned(),
                expires_at: AT,
                trial: true,
            };
            let Some(text) = reminder_text(&item) else {
                return;
            };
            assert!(text.contains("Пробный доступ"), "{text}");
            assert!(text.contains("02.11.2026 в 14:05"), "{text}");
        }
    }

    /// «Сегодня» в последнем напоминании нет: ночью оно уходит накануне.
    #[test]
    fn the_last_reminder_does_not_say_today() {
        let item = Reminder {
            telegram_id: 1,
            kind: "same_day".to_owned(),
            expires_at: AT,
            trial: false,
        };
        let text = reminder_text(&item).unwrap_or_default();
        assert!(!text.contains("сегодня"), "{text}");
        assert!(text.contains("14:05"), "{text}");
    }
}

#[cfg(test)]
mod fee_tests {
    use super::{freekassa_charge, freekassa_gross, with_fee};
    use atlas_billing::{Currency, Money};

    fn rub(minor: u64) -> Money {
        Money::from_minor(minor, Currency::Rub)
    }

    /// Все цены витрины: в Freekassa уходит цена без комиссии, а покупатель
    /// с её наценкой платит ровно цену из меню.
    #[test]
    fn the_buyer_pays_exactly_the_menu_price() {
        for (price, sent) in [
            (19_900, 18_774),
            (54_900, 51_792),
            (99_900, 94_245),
            (179_000, 168_868),
            (29_900, 28_208),
            (82_900, 78_208),
            (149_900, 141_415),
            (269_000, 253_774),
        ] {
            let charge = freekassa_charge(rub(price), 600);
            assert_eq!(charge.minor(), sent, "{price}");
            assert_eq!(with_fee(charge, 600).minor(), price, "{price}");
            assert_eq!(freekassa_gross(charge, 600).minor(), price, "{price}");
        }
    }

    /// Любая сумма (после бонусов, с хвостом счёта): уведомление всегда
    /// покрывает счёт, а переплата — не больше копейки.
    #[test]
    fn no_amount_is_overcharged_or_underpaid() {
        for price in (100..400_000).step_by(37) {
            for fee in [0, 350, 600, 650] {
                let charge = freekassa_charge(rub(price), fee);
                let total = with_fee(charge, fee).minor();
                assert!(
                    total >= price && total - price <= 1,
                    "{price} при {fee}: {total}"
                );
                assert_eq!(
                    freekassa_gross(charge, fee).minor(),
                    total,
                    "{price} при {fee}"
                );
            }
        }
    }

    /// Счёт, открытый до перехода: в Freekassa ушла полная цена — он тоже
    /// зачитывается.
    #[test]
    fn an_order_opened_before_the_switch_still_settles() {
        assert!(freekassa_gross(rub(19_900), 600).minor() >= 19_900);
    }

    /// Итог с комиссией сверен с настоящим заказом Freekassa: 199 ₽ при 6%
    /// у покупателя стали 210,94 ₽.
    #[test]
    fn the_fee_total_matches_freekassa() {
        let price = Money::from_minor(19_900, Currency::Rub);
        assert_eq!(with_fee(price, 600).minor(), 21_094);
        assert_eq!(with_fee(price, 0).minor(), 19_900);
    }
}

#[cfg(test)]
mod plan_tests {
    use super::{panel_plan, Plan, FREE_MARK, FREE_UNTIL};
    use crate::config::{Config, FREE_SQUADS};
    use atlas_bot::catalog;
    use atlas_panel::TrafficReset;
    use atlas_store::PanelWork;
    use std::collections::HashMap;

    const NOW: i64 = 1_788_861_600;
    const PAID: &str = "b6f5d810-8ef3-4be9-9012-3456789abcde";
    const FREE: &str = "0a0b0c0d-0000-4000-8000-000000000001";

    fn config() -> Option<Config> {
        let vars: HashMap<String, String> = [
            ("GLORIA_BOT_TOKEN", "123456:AAHkTestToken"),
            ("GLORIA_PANEL_URL", "https://panel.example.org"),
            ("GLORIA_PANEL_TOKEN", "panel-token"),
            ("GLORIA_DATABASE_URL", "postgres://gloria@localhost/gloria"),
            ("GLORIA_SQUADS", PAID),
            (FREE_SQUADS, FREE),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let config = Config::from_map(&vars);
        assert!(config.is_ok(), "настройки не собрались");
        config.ok()
    }

    fn work(kind: &str, has_paid: bool) -> PanelWork {
        PanelWork {
            telegram_id: 42,
            panel_id: 7,
            expires_at: NOW,
            has_paid,
            lapsed: kind == "free",
            kind: kind.to_owned(),
        }
    }

    fn both() -> Vec<String> {
        vec![PAID.to_owned(), FREE.to_owned()]
    }

    #[test]
    fn the_far_date_is_past_the_mark() {
        const { assert!(FREE_UNTIL > FREE_MARK) };
    }

    #[test]
    fn a_tier_gets_its_devices_and_no_traffic_cap() {
        let Some(config) = config() else { return };
        for (kind, devices) in [("personal", 2), ("family", 3)] {
            assert_eq!(
                panel_plan(&config, &work(kind, true)),
                Plan {
                    expires_at: NOW,
                    traffic: 0,
                    reset: TrafficReset::Never,
                    devices,
                    squads: both(),
                },
                "{kind}"
            );
        }
    }

    /// Гость — 30 ГБ, каждый месяц заново, одно устройство. Безлимит
    /// остаётся у владельца, который платит.
    #[test]
    fn a_guest_gets_thirty_gigabytes_a_month_on_one_device() {
        let Some(config) = config() else { return };
        assert_eq!(
            panel_plan(&config, &work("guest", false)),
            Plan {
                expires_at: NOW,
                traffic: 30 * 1024 * 1024 * 1024,
                reset: TrafficReset::Monthly,
                devices: 1,
                squads: both(),
            }
        );
    }

    /// Платил до тарифов — прежние три устройства; проба — два, без потолка.
    #[test]
    fn the_old_payers_keep_three_devices_and_the_trial_gets_two() {
        let Some(config) = config() else { return };
        let old = panel_plan(&config, &work("paid", true));
        assert_eq!((old.devices, old.traffic), (catalog::DEVICES, 0));
        let trial = panel_plan(&config, &work("paid", false));
        assert_eq!((trial.devices, trial.traffic), (catalog::TRIAL_DEVICES, 0));
    }

    /// Кончилась — одни бесплатные отряды, далёкая дата и никакого потолка.
    #[test]
    fn a_lapsed_subscription_keeps_only_the_free_squads() {
        let Some(config) = config() else { return };
        let plan = panel_plan(&config, &work("free", false));
        assert_eq!(plan.expires_at, FREE_UNTIL);
        assert_eq!(plan.traffic, 0);
        assert_eq!(plan.squads, vec![FREE.to_owned()]);
    }

    /// Места для гостей записаны дважды: витрине — в `catalog`, базе — в
    /// `atlas_store`. Разойдись они, кабинет обещал бы одно, а база
    /// пускала бы другое.
    #[test]
    fn the_shop_and_the_database_agree_on_guest_slots() {
        for tier in catalog::Tier::ALL {
            assert_eq!(
                i64::from(tier.guests()),
                atlas_store::guest_slots(Some(tier.as_str())),
                "{}",
                tier.as_str()
            );
        }
        assert_eq!(atlas_store::guest_slots(None), 0);
    }
}

#[cfg(test)]
mod admin_url_tests {
    use super::{admin_url, is_command};

    #[test]
    fn the_admin_lives_next_to_the_cabinet() {
        for (cabinet, admin) in [
            ("https://gloria.example", "https://gloria.example/admin/"),
            ("https://gloria.example/", "https://gloria.example/admin/"),
            (
                "https://gloria.example/?v=3",
                "https://gloria.example/admin/",
            ),
            (
                "https://gloria.example/#home",
                "https://gloria.example/admin/",
            ),
        ] {
            assert_eq!(admin_url(cabinet), admin, "{cabinet}");
        }
    }

    #[test]
    fn the_command_is_recognised_with_and_without_the_bot_name() {
        assert!(is_command("/admin", "/admin"));
        assert!(is_command("/admin@gloria_bot", "/admin"));
        assert!(is_command("  /admin  ", "/admin"));
        assert!(!is_command("/administrator", "/admin"));
        assert!(!is_command("admin", "/admin"));
    }
}
