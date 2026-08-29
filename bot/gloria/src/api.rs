//! HTTP для мини-приложения.
//!
//! Отдаёт состояние подписки той странице, что открывается в Telegram.
//! Слушает **только петлю**: наружу его выставляет Caddy на том же домене,
//! где лежит сама страница. Отсюда два следствия — нет ни TLS, ни CORS:
//! запрос приходит с того же адреса, откуда пришла страница.
//!
//! Кто спрашивает, определяется не по номеру в запросе, а по подписи
//! Telegram (`X-Init-Data`). Номер, присланный клиентом, — это не
//! удостоверение: подставить чужой может кто угодно, и тогда чужая ссылка
//! на подписку отдавалась бы по первому желанию. Проверка подписи живёт в
//! `atlas_telegram::init_data` и покрыта отдельными тестами.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use atlas_billing::subscription;
use atlas_bot::catalog;
use atlas_store::Store;
use atlas_telegram::{self as telegram_init};

use crate::config::Config;

/// Сколько ждать запроса и отправки. Без срока одно зависшее соединение
/// заняло бы поток навсегда, а таких соединений может быть много.
const TIMEOUT: Duration = Duration::from_secs(15);

/// Предел на заголовки. Больше этого — не наш клиент, а попытка занять
/// память: заголовки читаются целиком, до пустой строки.
const MAX_HEADERS: usize = 16 * 1024;

/// Сколько живёт строка `initData`, прежде чем мы перестанем ей верить.
///
/// Telegram выдаёт её при открытии приложения и не обновляет, пока оно
/// открыто. Слишком короткий срок выбрасывал бы человека посреди работы;
/// слишком длинный — оставлял бы годной строку, подсмотренную в чужом
/// журнале. Сутки — то, что рекомендует сам Telegram.
const INIT_DATA_MAX_AGE: i64 = 24 * 60 * 60;

/// Схемы приложений, в которые умеем отдавать подписку.
///
/// Список закрытый: он же не даёт превратить перенаправление в открытое.
/// Ведёт оно всегда на нашу схему и на ссылку из нашей базы — что бы ни
/// пришло в запросе.
const SCHEMES: [(&str, &str); 2] = [("happ", "happ://add/"), ("incy", "incy://add/")];

/// Поднять сервер в отдельном потоке.
///
/// Возвращает ошибку, только если не удалось занять адрес: это настройка,
/// и знать о ней надо при запуске, а не при первом запросе.
pub fn spawn(config: &Config) -> Result<(), String> {
    let listener = TcpListener::bind(&config.api_addr)
        .map_err(|error| format!("не занять адрес {}: {error}", config.api_addr))?;

    // Своё подключение к базе, отдельное от основного цикла: цикл держит
    // своё и в это время может стоять на длинном опросе Telegram до
    // полминуты. Одно на двоих означало бы ожидание на каждом запросе.
    let store = Store::connect(&config.database_url)
        .map_err(|error| format!("база для мини-приложения: {error}"))?;

    let shared = Shared {
        store: Arc::new(Mutex::new(store)),
        bot_token: config.bot_token.clone(),
        bot_username: config.bot_username.clone(),
    };

    println!("Мини-приложение слушает {}", config.api_addr);

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let shared = shared.clone();

            // Поток на соединение. Дорого было бы при тысячах запросов в
            // секунду; у нас их десятки в минуту, а взамен один медленный
            // клиент не задерживает остальных.
            std::thread::spawn(move || {
                if let Err(error) = serve(&shared, stream) {
                    eprintln!("Мини-приложение: {error}");
                }
            });
        }
    });

    Ok(())
}

#[derive(Clone)]
struct Shared {
    store: Arc<Mutex<Store>>,
    bot_token: String,
    bot_username: Option<String>,
}

/// Ответить на одно соединение.
fn serve(shared: &Shared, mut stream: TcpStream) -> Result<(), String> {
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();

    let request = match read_request(&stream) {
        Ok(request) => request,
        // Ответить на неразобранное всё равно нечем: клиент либо не наш,
        // либо оборвался. Строка в журнал — и закрываем.
        Err(why) => return send(&mut stream, 400, r#"{"error":"плохой запрос"}"#).map_err(|_| why),
    };

    if request.method != "GET" {
        return send(&mut stream, 405, r#"{"error":"не тот способ"}"#);
    }

    // Переход в клиент. Отдельно от `/api/me` и без подписи Telegram: сюда
    // приходят не запросом со страницы, а нажатием по ссылке, и заголовков
    // при таком переходе нет. Удостоверением служит сам хвост ссылки — кто
    // его знает, тот уже имеет доступ к подписке.
    if let Some(rest) = request.path.strip_prefix("/api/open/") {
        return open_in_app(shared, &mut stream, rest);
    }

    // Остальные пути ждут своей очереди — до тех пор честнее отвечать «нет»,
    // чем делать вид.
    if request.path != "/api/me" {
        return send(&mut stream, 404, r#"{"error":"нет такого пути"}"#);
    }

    let Some(raw) = request.init_data.as_deref() else {
        return send(&mut stream, 401, r#"{"error":"нет подписи Telegram"}"#);
    };

    let now = crate::unix_now();
    let Ok(verified) = telegram_init::verify(raw, &shared.bot_token, now, INIT_DATA_MAX_AGE) else {
        // Отказ без подробностей: разница между «подпись не сошлась» и
        // «строка просрочена» полезна только тому, кто подбирает.
        return send(&mut stream, 401, r#"{"error":"подпись не принята"}"#);
    };

    let body = match state_of(shared, verified.user_id(), now) {
        Ok(body) => body,
        Err(error) => {
            eprintln!("Мини-приложение для {}: {error}", verified.user_id());
            return send(&mut stream, 500, r#"{"error":"внутренняя ошибка"}"#);
        }
    };

    send(&mut stream, 200, &body)
}

/// Перенаправить в клиент.
///
/// WebView мини-приложения не отдаёт системе переход на чужую схему вообще
/// никак: ни из скрипта, ни по ссылке с `href`. Встроенный браузер Telegram
/// — отдаёт, поэтому страница уводит нажатие туда через `openLink`.
///
/// А `openLink` умеет только `http` и `https`. Отсюда этот путь: он и есть
/// то звено, которое превращает наш обычный адрес в `happ://…` уже после
/// выхода из мини-приложения.
fn open_in_app(shared: &Shared, stream: &mut TcpStream, rest: &str) -> Result<(), String> {
    let mut parts = rest.splitn(2, '/');
    let (Some(app), Some(tail)) = (parts.next(), parts.next()) else {
        return send(stream, 404, r#"{"error":"нет такого пути"}"#);
    };

    let Some((_, scheme)) = SCHEMES.iter().find(|(name, _)| *name == app) else {
        return send(stream, 404, r#"{"error":"неизвестное приложение"}"#);
    };

    // Хвост попадает в запрос к базе и в заголовок ответа. Набор символов
    // тот же, что у идентификатора подписки в панели; всё остальное — не
    // наш адрес, а попытка подставить чужой.
    if tail.is_empty()
        || tail.len() > 64
        || !tail
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return send(stream, 404, r#"{"error":"негодный ключ"}"#);
    }

    let found = {
        let mut store = shared
            .store
            .lock()
            .map_err(|_| "замок базы испорчен".to_owned())?;
        store
            .subscription_url_ending_with(tail)
            .map_err(|error| format!("база: {error}"))?
    };

    let Some(url) = found else {
        return send(stream, 404, r#"{"error":"нет такой подписки"}"#);
    };

    redirect(stream, &format!("{scheme}{url}"))
}

/// Собрать состояние покупателя.
fn state_of(shared: &Shared, telegram_id: i64, now: i64) -> Result<String, String> {
    let subscriber = {
        let mut store = shared
            .store
            .lock()
            .map_err(|_| "замок базы испорчен".to_owned())?;
        store
            .ensure_subscriber(telegram_id)
            .map_err(|error| format!("база: {error}"))?
    };

    let expires_at = subscriber.expires_at;
    let active = subscription::is_active(expires_at, now);

    // Три состояния, а не два: «проба» и «оплачено» выглядят одинаково по
    // сроку, но говорить человеку «активна» про пробу — значит однажды
    // удивить его окончанием, которого он не ждал.
    let status = if !active {
        "expired"
    } else if subscriber.trial_granted_at.is_some() && !subscriber.has_paid {
        "trial"
    } else {
        "active"
    };

    // Реферальная ссылка строится из имени бота. Нет имени — нет и ссылки:
    // выдуманная вела бы в никуда, а человек бы её разослал.
    let referral_link = shared
        .bot_username
        .as_ref()
        .map(|name| format!("https://t.me/{name}?start=ref_{telegram_id}"));

    Ok(serde_json::json!({
        "status": status,
        "daysLeft": subscription::days_left(expires_at, now),
        "expiresAt": expires_at.map(day_month_year),
        // Сколько устройств занято, знает панель, а не мы. Присылать ноль
        // значило бы показать «0 из 4» тому, у кого их два.
        "devices": serde_json::Value::Null,
        "deviceLimit": catalog::DEVICES,
        "userId": telegram_id,
        "subscriptionUrl": subscriber.subscription_url,
        "referral": {
            "link": referral_link,
            // Начислений пока нет, и нули здесь — правда, а не заглушка.
            "invited": 0,
            "paying": 0,
            "bonusDays": 0,
        },
        "settings": { "notify": true },
    })
    .to_string())
}

/// Дата в том виде, в каком её читает человек: `31.08.2026`.
pub fn day_month_year(seconds: i64) -> String {
    // ISO уже умеет считать календарь, и второй такой счётчик нам не нужен:
    // «2026-08-31T00:00:00.000Z» → «31.08.2026».
    let iso = atlas_panel::to_iso8601(seconds);
    let mut parts = iso.split('T').next().unwrap_or_default().split('-');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(y), Some(m), Some(d)) => format!("{d}.{m}.{y}"),
        _ => iso,
    }
}

/// Разобранный запрос — ровно то немногое, что нам нужно.
struct Request {
    method: String,
    path: String,
    init_data: Option<String>,
}

/// Прочитать строку запроса и заголовки.
///
/// Тело не читается: единственный наш путь — `GET`. Это же означает, что
/// соединение не переиспользуется, и после ответа мы его закрываем.
fn read_request(stream: &TcpStream) -> Result<Request, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?).take(
        u64::try_from(MAX_HEADERS).map_err(|_| "предел заголовков не помещается".to_owned())?,
    );

    let mut start = String::new();
    reader
        .read_line(&mut start)
        .map_err(|error| format!("строка запроса: {error}"))?;

    let mut words = start.split_whitespace();
    let (Some(method), Some(target)) = (words.next(), words.next()) else {
        return Err("строка запроса не разобралась".to_owned());
    };

    // Отрезаем всё после «?»: у нас нет путей с параметрами, а сравнивать
    // путь вместе с ними значило бы промахиваться мимо своего же адреса.
    let path = target.split('?').next().unwrap_or(target).to_owned();

    let mut init_data = None;
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| format!("заголовок: {error}"))?;
        if read == 0 {
            return Err("заголовки оборвались".to_owned());
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            // Имена заголовков нечувствительны к регистру — так сказано в
            // самом протоколе, и клиенты этим пользуются.
            if name.trim().eq_ignore_ascii_case("x-init-data") {
                init_data = Some(value.trim().to_owned());
            }
        }
    }

    Ok(Request {
        method: method.to_owned(),
        path,
        init_data,
    })
}

/// Перенаправление на чужую схему.
///
/// Без тела: браузер его не покажет, а система, забирая ссылку себе, не
/// прочитает и подавно.
fn redirect(stream: &mut TcpStream, location: &str) -> Result<(), String> {
    // 302, а не 301: адрес подписки может смениться, а «навсегда» браузеры
    // запоминают и перестают спрашивать сервер вовсе.
    let head = format!(
        "HTTP/1.1 302 Found\r\n\
         Location: {location}\r\n\
         Content-Length: 0\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n"
    );

    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|error| format!("отправка: {error}"))
}

/// Отправить ответ и закрыть соединение.
fn send(stream: &mut TcpStream, status: u16, body: &str) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };

    // Не кешировать: страница спрашивает состояние подписки, и вчерашний
    // ответ здесь хуже, чем никакого.
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );

    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("отправка: {error}"))
}

#[cfg(test)]
mod tests {
    use super::day_month_year;

    /// Момент времени по дате, записанной по-человечески.
    ///
    /// Числа эпохи руками здесь не пишутся: в первой же попытке я промахнулся
    /// на двенадцать дней, и увидел это не я, а CI. Дата, записанная строкой,
    /// проверяется глазами; `1_787_097_600` — ничем.
    fn at(iso: &str) -> i64 {
        atlas_panel::from_iso8601(iso).unwrap_or_default()
    }

    #[test]
    fn a_date_is_shown_the_way_people_read_it() {
        assert_eq!(day_month_year(at("2026-08-31T00:00:00Z")), "31.08.2026");
    }

    /// Ведущие нули обязаны сохраняться: «1.1.2027» рядом с «31.08.2026»
    /// выглядит опечаткой, а не датой.
    #[test]
    fn single_digit_days_keep_their_zero() {
        assert_eq!(day_month_year(at("2027-01-01T00:00:00Z")), "01.01.2027");
    }

    /// Заодно проверка самого помощника: если бы он молча возвращал ноль,
    /// оба теста выше сравнивали бы «01.01.1970» сам с собой.
    #[test]
    fn the_helper_actually_parses_the_date() {
        assert!(at("2026-08-31T00:00:00Z") > 0);
        assert_ne!(at("2026-08-31T00:00:00Z"), at("2027-01-01T00:00:00Z"));
    }
}
