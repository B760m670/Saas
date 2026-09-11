//! Бот поддержки.
//!
//! Отдельный бот со своим токеном, но в том же процессе и на той же базе —
//! и это главное в нём. Обращение доходит до владельца не голым текстом, а
//! вместе с тем, что мы про человека знаем: подписка, открытые счета,
//! последняя оплата. Половина вопросов после этого отпадает, не будучи
//! заданной.
//!
//! # Как ответ находит адресата
//!
//! Владелец отвечает **свайпом** по пересланному обращению. Telegram при
//! этом сообщает номер процитированного сообщения; кто за ним стоит, лежит
//! в `support_messages`.
//!
//! Набирать номер человека руками не нужно. Такой способ тоже есть —
//! `/w <номер> текст`, — но он запасной: он держится на внимательности, а
//! ошибка в одной цифре отправляет ответ чужому вместе со всем, что в нём
//! написано.
//!
//! # Чего здесь намеренно нет
//!
//! Пересылки сообщений средствами Telegram (`forwardMessage`). Она показала
//! бы владельцу имя и фотографию отправителя — то есть то, чего мы про
//! покупателя не храним и хранить не обещали. Уходит только текст и номер.

use atlas_bot::support::Topic;
use atlas_bot::{Button, Keyboard};
use atlas_store::Store;
use atlas_tg::{next_offset, Incoming, Telegram};

use crate::config::Config;
use crate::{day_month_year, http};

/// Сколько тема считается свежей — час.
///
/// Выбравший тему и написавший через полчаса пишет, скорее всего, о ней.
/// Через неделю — вряд ли, и подпись «о чём речь» ввела бы владельца в
/// заблуждение вернее, чем её отсутствие.
const TOPIC_FRESH_FOR: i64 = 60 * 60;

/// Длинное ожидание обновлений, секунд.
const POLL_TIMEOUT: u16 = 30;

/// Сколько ждать после сбоя, прежде чем спрашивать снова.
///
/// Без паузы упавшая сеть превращается в поток запросов, и Telegram
/// перестаёт отвечать уже по своей воле.
const RETRY_PAUSE: std::time::Duration = std::time::Duration::from_secs(5);

/// Поднять бота поддержки в отдельном потоке.
///
/// Без токена не поднимается вовсе и об этом не жалуется: поддержка
/// необязательна, а бот без неё остаётся полезным.
pub fn spawn(config: &Config) -> Option<std::thread::JoinHandle<()>> {
    let token = config.support_token.clone()?;
    let Some(telegram) = Telegram::new(&token) else {
        eprintln!("Поддержка: токен негоден, бот не поднят");
        return None;
    };

    // Своё подключение к базе: основной цикл держит своё и в это время
    // может стоять на длинном опросе до полминуты. Одно на двоих означало
    // бы ожидание на каждом обращении.
    let store = match Store::connect(&config.database_url) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("Поддержка: база недоступна, бот не поднят: {error}");
            return None;
        }
    };

    let admins = config.admins.clone();
    if admins.is_empty() {
        eprintln!("Поддержка: некому отвечать (GLORIA_ADMINS пуст), бот не поднят");
        return None;
    }

    println!("Бот поддержки запущен");
    Some(std::thread::spawn(move || {
        let mut store = store;
        let mut offset = None;
        loop {
            match poll(&telegram, &mut store, &admins, offset) {
                Ok(next) => offset = next.or(offset),
                Err(error) => {
                    eprintln!("Поддержка: {}", telegram.redact(&error));
                    std::thread::sleep(RETRY_PAUSE);
                }
            }
        }
    }))
}

/// Один заход за обновлениями.
fn poll(
    telegram: &Telegram,
    store: &mut Store,
    admins: &[i64],
    offset: Option<i64>,
) -> Result<Option<i64>, String> {
    let request = telegram.get_updates(offset, POLL_TIMEOUT);
    let response = http::send(&request).map_err(|error| format!("опрос: {error}"))?;
    let batch = telegram
        .parse_updates(&response.body)
        .map_err(|error| format!("разбор: {error}"))?;

    for update in &batch.updates {
        if let Err(error) = handle(telegram, store, admins, &update.incoming) {
            // Разговор с одним человеком не должен останавливать остальных.
            eprintln!("Поддержка, обращение: {}", telegram.redact(&error));
        }
    }

    Ok(next_offset(&batch, offset))
}

/// Разобрать одно обращение или ответ.
fn handle(
    telegram: &Telegram,
    store: &mut Store,
    admins: &[i64],
    incoming: &Incoming,
) -> Result<(), String> {
    let who = incoming.from();
    let now = crate::unix_now();

    match incoming {
        Incoming::Button {
            data, callback_id, ..
        } => {
            // На нажатие отвечаем сразу: иначе у человека кнопка крутится,
            // пока мы ходим в базу.
            let _ = http::send(&telegram.answer_callback(callback_id, None));

            // «Не помогло» не меняет тему и не повторяет ответ: тема нужна
            // владельцу как подпись «о чём речь», а подменять её на «Другое»
            // значит терять ровно то, ради чего её и выбирали.
            if data == "ask" {
                send(
                    telegram,
                    incoming.chat(),
                    "Напишите, что случилось, — передам вместе с тем, \
                     что знаю о вашей подписке.",
                    None,
                );
                return Ok(());
            }

            let Some(topic) = data.strip_prefix("t:").and_then(Topic::parse) else {
                return greet(telegram, incoming.chat());
            };

            // Тему запоминаем: написанное следом дойдёт до владельца с
            // подписью, о чём речь.
            store
                .ensure_subscriber(who)
                .map_err(|error| format!("база: {error}"))?;
            store
                .set_support_topic(who, topic.code(), now)
                .map_err(|error| format!("база: {error}"))?;

            let keyboard = Keyboard {
                rows: vec![vec![Button::data("Не помогло, напишу", "ask")]],
            };
            send(telegram, incoming.chat(), topic.answer(), Some(&keyboard));
            Ok(())
        }

        Incoming::Message { text, chat, .. } => {
            let command = text.split_whitespace().next().unwrap_or("");

            if command == "/start" || command == "/help" {
                return greet(telegram, *chat);
            }

            // Владелец отвечает **явно**: свайпом по обращению или командой
            // `/w`. Всё остальное от него — обычное обращение.
            //
            // Раньше сюда уходил любой его текст, и у этого было два
            // следствия. Он не мог проверить бота, написав ему как
            // покупатель: вместо обращения получал подсказку про свайп. И не
            // мог обратиться в собственную поддержку, если бы понадобилось.
            //
            // Признак ответа — не «кто пишет», а «как»: процитированное
            // сообщение либо команда. Оба видны в самом сообщении, гадать не
            // приходится.
            let replying = match incoming {
                Incoming::Message { reply_to, .. } => reply_to.is_some(),
                Incoming::Button { .. } => false,
            } || command == "/w";

            if admins.contains(&who) && replying {
                return answer_from_owner(telegram, store, incoming, text, *chat);
            }

            from_buyer(telegram, store, admins, who, text, *chat, now)
        }
    }
}

/// Приветствие с выбором темы.
fn greet(telegram: &Telegram, chat: i64) -> Result<(), String> {
    let keyboard = Keyboard {
        rows: Topic::all()
            .into_iter()
            .map(|topic| vec![Button::data(topic.title(), format!("t:{}", topic.code()))])
            .collect(),
    };

    send(
        telegram,
        chat,
        "Чем помочь?\n\n\
         Выберите, что случилось, — на частое отвечу сразу. \
         Или просто напишите сообщением, я передам.",
        Some(&keyboard),
    );
    Ok(())
}

/// Обращение от покупателя: переслать владельцу вместе с тем, что о нём известно.
fn from_buyer(
    telegram: &Telegram,
    store: &mut Store,
    admins: &[i64],
    who: i64,
    text: &str,
    chat: i64,
    now: i64,
) -> Result<(), String> {
    let subscriber = store
        .ensure_subscriber(who)
        .map_err(|error| format!("база: {error}"))?;

    let topic = store
        .support_topic(who, now, TOPIC_FRESH_FOR)
        .map_err(|error| format!("база: {error}"))?
        .and_then(|code| Topic::parse(&code));

    let context = context_of(store, &subscriber, now);
    let head = match topic {
        Some(topic) => format!("🆘 <b>{}</b>", topic.title()),
        None => "🆘 <b>Обращение</b>".to_owned(),
    };

    // В блоке для копирования — только то, что можно отправить как есть.
    //
    // Раньше туда входило и слово «текст» как подсказка, что писать дальше.
    // Нажатие копирует блок целиком, поэтому подсказка уезжала в буфер,
    // вставлялась вместе с командой и уходила покупателю первым словом
    // ответа: «текст Уже работаем над проблемой». Заполнитель вынесен
    // наружу — копируется команда с номером, остальное дописывается.
    let message = format!(
        "{head}\nот <code>{who}</code>\n{context}\n\
         — — —\n{}\n\
         — — —\n\
         Ответить: свайпом по этому сообщению \
         или <code>/w {who}</code> и дальше сам ответ",
        atlas_tg::escape_html(text)
    );

    // Номер отправленного сообщения запоминается у каждого владельца свой:
    // номера уникальны внутри чата, и свайп в одном чате не должен
    // указывать на сообщение в другом.
    for admin in admins {
        let Ok(request) = telegram.send_message(*admin, &message, None) else {
            continue;
        };
        let Ok(response) = http::send(&request) else {
            continue;
        };
        if let Some(id) = Telegram::sent_message_id(&response.body) {
            store
                .remember_support_message(*admin, id, who)
                .map_err(|error| format!("база: {error}"))?;
        }
    }

    send(
        telegram,
        chat,
        "Передал. Отвечу сюда же — обычно в течение часа.",
        None,
    );
    Ok(())
}

/// Ответ владельца: свайпом или командой `/w`.
fn answer_from_owner(
    telegram: &Telegram,
    store: &mut Store,
    incoming: &Incoming,
    text: &str,
    chat: i64,
) -> Result<(), String> {
    // Свайп — основной путь. Ошибиться в нём нечем: получателя называет не
    // владелец, а то, на что он ответил.
    let quoted = match incoming {
        Incoming::Message { reply_to, .. } => *reply_to,
        Incoming::Button { .. } => None,
    };

    if let Some(quoted) = quoted {
        let found = store
            .support_recipient(chat, quoted)
            .map_err(|error| format!("база: {error}"))?;

        return match found {
            Some(buyer) => deliver(telegram, chat, buyer, text),
            // Ответ на постороннее сообщение. Придумывать получателя нельзя:
            // письмо ушло бы чужому.
            None => {
                send(
                    telegram,
                    chat,
                    "Это сообщение не из поддержки — кому отвечать, непонятно.\n\n\
                     Ответьте свайпом по обращению: номер в нём уже есть, \
                     и адресат определится сам.",
                    None,
                );
                Ok(())
            }
        };
    }

    // Запасной путь: номер набран руками. Разбор — в `atlas_bot::support`,
    // под тестами: от него зависит, кому уйдёт ответ, и однажды он уже
    // подвёл молча.
    if text.starts_with("/w") {
        return match atlas_bot::support::parse_reply(text) {
            Some((buyer, body)) => deliver(telegram, chat, buyer, body),
            None => {
                send(
                    telegram,
                    chat,
                    // Примера с выдуманным номером здесь нет намеренно: он
                    // выглядит готовым к отправке, а уходит в никуда.
                    "Не разобрал: после <code>/w</code> нужен номер человека, \
                     а следом — сам ответ.\n\n\
                     Номер есть в обращении, и проще ответить свайпом по нему.",
                    None,
                );
                Ok(())
            }
        };
    }

    send(
        telegram,
        chat,
        "Чтобы ответить, свайпните по обращению — так адресат определится сам.\n\n\
         Запасной путь: <code>/w</code>, номер человека и текст ответа.",
        None,
    );
    Ok(())
}

/// Доставить ответ покупателю и подтвердить владельцу.
fn deliver(telegram: &Telegram, admin_chat: i64, buyer: i64, text: &str) -> Result<(), String> {
    let body = format!("Поддержка:\n\n{}", atlas_tg::escape_html(text));

    let request = telegram
        .send_message(buyer, &body, None)
        .map_err(|error| format!("ответ: {error}"))?;

    match http::send(&request) {
        Ok(response) if response.is_ok() => {
            send(telegram, admin_chat, &format!("Отправлено {buyer}."), None);
        }
        // Не дошло — говорим об этом. Молчание владелец прочтёт как «дошло»,
        // и человек останется без ответа, а владелец об этом не узнает.
        Ok(response) => {
            send(
                telegram,
                admin_chat,
                &format!(
                    "Не дошло до {buyer}: Telegram ответил {}. \
                     Скорее всего, человек заблокировал бота.",
                    response.status
                ),
                None,
            );
        }
        Err(error) => {
            send(
                telegram,
                admin_chat,
                &format!(
                    "Не дошло до {buyer}: {}",
                    telegram.redact(&error.to_string())
                ),
                None,
            );
        }
    }
    Ok(())
}

/// Что мы знаем о человеке — то, с чего владелец начал бы расспрос.
fn context_of(store: &mut Store, subscriber: &atlas_store::Subscriber, now: i64) -> String {
    let mut lines = Vec::new();

    lines.push(match subscriber.expires_at {
        Some(expires_at) if expires_at > now => format!(
            "Подписка: {} до {}",
            if subscriber.has_paid {
                "оплачена"
            } else {
                "проба"
            },
            day_month_year(expires_at)
        ),
        Some(expires_at) => format!("Подписка: закончилась {}", day_month_year(expires_at)),
        None => "Подписки не было ни разу".to_owned(),
    });

    // Открытый счёт — первое, о чём спросит написавший «оплатил, но не
    // продлилось». Пусть он уже будет перед глазами.
    if let Ok(Some((order_id, amount))) = store.pending_order_of(
        subscriber.telegram_id,
        now,
        atlas_bot::catalog::INVOICE_LIFETIME,
    ) {
        lines.push(format!(
            "Открытый счёт: {} · <code>{order_id}</code>",
            atlas_bot::menu::price_label(amount)
        ));
    }

    lines.join("\n")
}

/// Отправить, не роняя разговор из-за неудачи.
fn send(telegram: &Telegram, chat: i64, text: &str, keyboard: Option<&Keyboard>) {
    match telegram.send_message(chat, text, keyboard) {
        Ok(request) => {
            if let Err(error) = http::send(&request) {
                eprintln!(
                    "Поддержка, сообщение для {chat}: {}",
                    telegram.redact(&error.to_string())
                );
            }
        }
        Err(error) => eprintln!("Поддержка, сообщение для {chat}: {error}"),
    }
}
