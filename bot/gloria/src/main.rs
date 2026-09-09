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

mod api;
mod config;
mod http;

use std::process::ExitCode;

use atlas_billing::{invoice, Checkout, Money, Order, OrderId, Provider, UserId, Wata, YooKassa};
use atlas_bot::{catalog, flow, Action, Button, Keyboard, Unknown};
use atlas_panel::{NewUser, Panel};
use atlas_store::{Settled, Store, Subscriber, Trial};
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

    announce(&config, &telegram);

    println!("Бот запущен. {config:?}");
    let deps = Deps {
        config: &config,
        telegram: &telegram,
        panel: &panel,
        yookassa: yookassa.as_ref(),
        wata: wata.as_ref(),
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

        sync_panel(deps.panel, store);
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
fn sync_panel(panel: &Panel, store: &mut Store) {
    let work = match store.panel_work(SYNC_PER_ROUND, unix_now()) {
        Ok(work) => work,
        Err(error) => {
            eprintln!("Очередь панели: {error}");
            return;
        }
    };

    for item in work {
        let request = panel.set_expiry(item.panel_id, item.expires_at);
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
        if let Err(error) = store.mark_panel_synced(item.telegram_id, item.expires_at) {
            eprintln!("Отметка о панели для {}: {error}", item.telegram_id);
        }
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
    let same_date = (user.expires_at - known).abs() < PANEL_DRIFT;
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
            if (expires_at - known).abs() < PANEL_DRIFT {
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

    let mut subscriber = store
        .ensure_subscriber(telegram_id)
        .map_err(|error| format!("база: {error}"))?;

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

    let view = flow::View {
        expires_at: subscriber.expires_at,
        trial_used: subscriber.trial_granted_at.is_some(),
        subscription_url: subscriber.subscription_url.as_deref(),
        app_url: config.miniapp_url.as_deref(),
        now,
    };

    let (reply, effect) = match incoming {
        Incoming::Message { text, .. } => flow::on_message(text, &view),
        Incoming::Button { data, .. } => match Action::decode(data) {
            Ok(action) => flow::on_action(&action, &view),
            // Нажатие, которого мы не понимаем, — либо старая кнопка, либо
            // изменённый клиент. И то и другое лечится показом меню.
            Err(Unknown::NoSuchAction | Unknown::BadPlanName) => flow::on_message("", &view),
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

            let taken = store
                .taken_amounts(now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("занятые суммы: {error}"))?;

            let amount = invoice::allocate(plan.price, &taken)
                .map_err(|_| "сейчас слишком много открытых счетов, попробуйте через минуту")?;

            // Номер заказа: кто, что и когда. Набор символов проверяется
            // и здесь, и в базе — он уходит в подпись платёжного сервиса.
            let order_id = format!("u{telegram_id}-{}-{now}", plan.id);
            store
                .open_order(&order_id, telegram_id, &plan.id, plan.days, amount, now)
                .map_err(|error| format!("счёт: {error}"))?;

            // Владелец узнаёт о счёте сразу, а не когда вспомнит про
            // /pending. Счёт живёт двадцать минут: человек, заплативший и
            // ждущий, за это время успевает решить, что его обманули.
            notify_admins(
                config,
                telegram,
                &format!(
                    "Счёт <b>{}</b> · {} · от {telegram_id}\n  подтвердить: /ok {}",
                    atlas_bot::menu::price_label(amount),
                    plan.title,
                    amount.to_decimal(),
                ),
            );

            // Сначала пробуем открыть страницу оплаты. Не вышло — счёт
            // остаётся в базе и подтверждается вручную: терять уже открытый
            // заказ из-за недоступности сервиса нельзя, человек его видел.
            // Порядок неслучаен: WATA первая, потому что даёт СБП вместе с
            // картами одной ссылкой. Обе заданы — берём её.
            let page = if let Some(service) = deps.wata {
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
                                "К оплате: <b>{}</b>\n\nСчёт действует 20 минут.",
                                atlas_bot::menu::price_label(amount)
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

            Ok(Some(transfer_invoice(config, amount)))
        }
    }
}

/// Админские команды. `None` означает «это не админская команда».
///
/// Подтверждение вручную — то, чем рублёвый канал живёт, пока не одобрен
/// процессинг: банк не сообщает программе о зачислении, знает о нём только
/// владелец счёта.
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
                answer.push_str(&format!(
                    "\n<code>{}</code> · {} · {}\n  подтвердить: /ok {}",
                    atlas_bot::menu::price_label(order.amount),
                    order.plan,
                    order.telegram_id,
                    order.amount.to_decimal(),
                ));
            }
            Ok(Some(answer))
        }

        "/revoke" => {
            let Some(who) = parts.next().and_then(|w| w.parse::<i64>().ok()) else {
                return Ok(Some("Укажите номер: /revoke 123456789".to_owned()));
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

        "/ok" => {
            let Some(sum) = parts.next() else {
                return Ok(Some("Укажите сумму: /ok 198.99".to_owned()));
            };
            let Some(amount) =
                atlas_billing::Money::parse_decimal(sum, atlas_billing::Currency::Rub)
            else {
                return Ok(Some("Сумма не разобралась. Пример: /ok 198.99".to_owned()));
            };

            let found = store
                .order_by_amount(amount, now, catalog::INVOICE_LIFETIME)
                .map_err(|error| format!("база: {error}"))?;
            let Some((order_id, buyer)) = found else {
                return Ok(Some(
                    "Открытого счёта на такую сумму нет. Проверьте /pending.".to_owned(),
                ));
            };

            // Номер платежа собирается из суммы и времени: повторное
            // подтверждение того же счёта упрётся в UNIQUE и не продлит
            // подписку дважды.
            let reference = format!("{}-{order_id}", amount.minor());
            let settled = store
                .settle(&order_id, "manual", &reference, amount, "{}", now)
                .map_err(|error| format!("зачисление: {error}"))?;

            // Покупателя извещаем сами. Он заплатил и ждёт; тишина после
            // платежа читается как «деньги пропали», и следующим сообщением
            // будет обращение в поддержку.
            if let Settled::Extended { expires_at } = settled {
                let text = format!(
                    "Оплата получена. Подписка продлена до {}.\n\n                     Ничего перенастраивать не нужно — ключ прежний,                      приложение подхватит новый срок само.",
                    day_month_year(expires_at)
                );
                tell(telegram, buyer, &text);
            }

            Ok(Some(match settled {
                Settled::Extended { expires_at } => {
                    format!("Зачислено. Подписка до {}.", day_month_year(expires_at))
                }
                Settled::AlreadyCounted => "Этот платёж уже был учтён.".to_owned(),
                Settled::OrderAlreadyPaid => "Счёт уже закрыт другим платежом.".to_owned(),
                Settled::Underpaid => "Сумма меньше выставленной — не зачислено.".to_owned(),
                Settled::NoSuchOrder => "Такого заказа нет.".to_owned(),
            }))
        }

        _ => Ok(None),
    }
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

    let (order_id, amount) = {
        let mut store = shared
            .store
            .lock()
            .map_err(|_| "замок базы испорчен".to_owned())?;

        let taken = store
            .taken_amounts(now, catalog::INVOICE_LIFETIME)
            .map_err(|error| format!("занятые суммы: {error}"))?;

        let amount = invoice::allocate(plan.price, &taken)
            .map_err(|_| "сейчас слишком много открытых счетов".to_owned())?;

        let order_id = format!("u{telegram_id}-{}-{now}", plan.id);
        store
            .open_order(&order_id, telegram_id, &plan.id, plan.days, amount, now)
            .map_err(|error| format!("счёт: {error}"))?;

        (order_id, amount)
    };

    // Владелец узнаёт о счёте сразу. Подтверждает оплату он, и счёт живёт
    // двадцать минут: человек, заплативший и ждущий, за это время успевает
    // решить, что его обманули.
    if let Some(telegram) = &shared.telegram {
        for admin in &shared.admins {
            tell(
                telegram,
                *admin,
                &format!(
                    "Счёт <b>{}</b> · {} · от {telegram_id} (из кабинета)\n  подтвердить: /ok {}",
                    atlas_bot::menu::price_label(amount),
                    plan.title,
                    amount.to_decimal(),
                ),
            );
        }
    }

    let pay = match &shared.pay_link {
        Some(url) => format!(r#""payUrl":"{}","#, atlas_tg::escape_json(url)),
        None => String::new(),
    };

    Ok(format!(
        r#"{{"amount":"{}","label":"{}",{pay}"minutes":{},"orderId":"{order_id}"}}"#,
        amount.to_decimal(),
        atlas_bot::menu::price_label(amount),
        catalog::INVOICE_LIFETIME / 60,
    ))
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
            squads: config.squads.clone(),
            device_limit: catalog::DEVICES,
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
fn transfer_invoice(config: &Config, amount: atlas_billing::Money) -> Extra {
    let sum = atlas_bot::menu::price_label(amount);

    let Some(link) = &config.pay_link else {
        return format!(
            "К оплате: <b>{sum}</b>\n\n\
             Приём оплаты ещё настраивается — напишите @GloriaVPNSupport, \
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
            "К оплате: <b>{sum}</b>\n\n\
             Нажмите «Оплатить» — откроется ваше банковское приложение. \
             Введите сумму <b>{sum}</b>: она должна совпасть до копейки, по ней \
             я нахожу ваш платёж.\n\n\
             Счёт действует 20 минут. Подписка включится после проверки перевода."
        ),
        keyboard: Some(Keyboard {
            rows: vec![vec![Button::link("Оплатить", link.clone())]],
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
    match telegram.send_message(chat_id, text, None) {
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
    use super::{decide, worth_asking, Verdict, PANEL_DRIFT};
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
        assert!(!excerpt(&[0xff, 0xfe, 0x00, 0x41]).is_empty());
    }
}
