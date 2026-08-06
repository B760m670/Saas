//! C ABI ядра ATLAS.
//!
//! Граница, через которую с ядром говорят клиенты: Swift на iOS и
//! macOS, Kotlin на Android, что угодно на десктопе. Всё, что здесь
//! есть, — это тонкая оболочка вокруг [`atlas_dial`]; никакой своей
//! логики тут нет и быть не должно, иначе поведение клиента разойдётся
//! с поведением `atlas-proxy`.
//!
//! # Правила обращения
//!
//! - Все строки — UTF-8, оканчивающиеся нулём.
//! - Всё, что функция **вернула** строкой, освобождает вызывающий через
//!   [`atlas_string_free`]. Исключение — [`atlas_version`]: она отдаёт
//!   неизменяемую статическую строку, освобождать её нельзя.
//! - Возврат нуля (`NULL`) означает отказ. Причину забирают
//!   [`atlas_last_error`] — она своя у каждого потока и обнуляется при
//!   чтении.
//! - Дескриптор прокси создаётся [`atlas_proxy_start`] и уничтожается
//!   ровно один раз [`atlas_proxy_stop`]. После этого он недействителен.
//!
//! # Про панику
//!
//! Рабочее пространство собирает релиз с `panic = "abort"`. Значит
//! перехватить панику на границе **нельзя**: процесс завершится. Это
//! осознанный выбор — разматывать стек через границу C — неопределённое
//! поведение, и лучше честный обрыв, чем порча памяти. Защита строится
//! не на перехвате, а на запрете: `clippy` в этом рабочем пространстве
//! запрещает `panic!`, `unwrap` и `expect`, а всякая индексация должна
//! быть проверяемой.
//!
//! # Пример на C
//!
//! ```c
//! AtlasProxy *proxy = atlas_proxy_start("vless://…", "127.0.0.1:0", NULL);
//! if (!proxy) {
//!     char *why = atlas_last_error();
//!     fprintf(stderr, "не поднялся: %s\n", why);
//!     atlas_string_free(why);
//!     return 1;
//! }
//! char *where = atlas_proxy_address(proxy);
//! printf("слушает %s\n", where);
//! atlas_string_free(where);
//! atlas_proxy_stop(proxy);
//! ```

// Граница C без `unsafe` не выражается: сырые указатели приходят
// снаружи, и проверить их подлинность изнутри невозможно. Каждый
// небезопасный блок ниже сопровождён условием, при котором он верен.
#![allow(unsafe_code)]

use std::cell::RefCell;
use std::ffi::{c_char, c_uint, CStr, CString};
use std::time::Duration;

use atlas_dial::{DialOptions, Proxy};
use atlas_types::ProxyKey;

/// Версия ядра, оканчивающаяся нулём.
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

thread_local! {
    /// Причина последнего отказа в этом потоке.
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Запомнить причину отказа.
fn fail(reason: &str) {
    // Нулевой байт внутри причины сделал бы строку C короче; на этот
    // невероятный случай текст заменяется, а не теряется.
    let text = CString::new(reason)
        .unwrap_or_else(|_| CString::from(c"причина отказа содержит нулевой байт"));
    LAST_ERROR.with(|slot| slot.replace(Some(text)));
}

/// Отдать строку наружу, передав владение вызывающему.
fn give(text: &str) -> *mut c_char {
    match CString::new(text) {
        Ok(owned) => owned.into_raw(),
        Err(_) => {
            fail("строка содержит нулевой байт");
            core::ptr::null_mut()
        }
    }
}

/// Прочитать строку, пришедшую снаружи.
///
/// # Safety
///
/// `text` — либо ноль, либо годный указатель на строку C.
unsafe fn take(text: *const c_char, what: &str) -> Option<String> {
    if text.is_null() {
        fail(&format!("{what}: передан нулевой указатель"));
        return None;
    }
    // Условие: указатель не нулевой и, по договору вызывающего,
    // указывает на строку, оканчивающуюся нулём.
    match unsafe { CStr::from_ptr(text) }.to_str() {
        Ok(text) => Some(text.to_owned()),
        Err(_) => {
            fail(&format!("{what}: строка не в UTF-8"));
            None
        }
    }
}

/// Настройки соединения для стороны C.
///
/// Нулевой указатель вместо структуры означает «взять умолчания».
/// Нулевое поле времени означает то же самое для этого поля в
/// отдельности: так C-вызывающему не нужно знать наши константы.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AtlasOptions {
    /// Отправлять ли расширение ECH. Ноль — не отправлять.
    ///
    /// Обычно его надо отправлять: так делает браузер. Но встречаются
    /// сети, где приветствие с ECH рвут — см. `docs/09-lab.md`.
    pub ech: c_uint,
    /// Предел ожидания TCP, миллисекунды. Ноль — умолчание.
    pub connect_timeout_ms: c_uint,
    /// Предел ожидания чтения, миллисекунды. Ноль — умолчание.
    pub read_timeout_ms: c_uint,
}

/// Запущенный прокси со стороны C.
///
/// Устройство наружу не раскрывается: за границей это просто указатель.
#[derive(Debug)]
pub struct AtlasProxy(Proxy);

/// Версия ядра.
///
/// Строка статическая: освобождать её нельзя.
#[no_mangle]
pub extern "C" fn atlas_version() -> *const c_char {
    VERSION.as_ptr().cast::<c_char>()
}

/// Забрать причину последнего отказа в этом потоке.
///
/// Возвращает ноль, если отказов не было. Строку освобождает
/// вызывающий; повторный вызов вернёт ноль, пока не случится новый
/// отказ.
#[no_mangle]
pub extern "C" fn atlas_last_error() -> *mut c_char {
    LAST_ERROR.with(|slot| match slot.borrow_mut().take() {
        Some(text) => text.into_raw(),
        None => core::ptr::null_mut(),
    })
}

/// Освободить строку, выданную этой библиотекой.
///
/// Ноль допустим и ничего не делает.
///
/// # Safety
///
/// `text` получен от этой библиотеки и ещё не освобождался.
#[no_mangle]
pub unsafe extern "C" fn atlas_string_free(text: *mut c_char) {
    if text.is_null() {
        return;
    }
    // Условие: указатель выдан `CString::into_raw` и не освобождался.
    drop(unsafe { CString::from_raw(text) });
}

/// Разобрать ключ доступа и описать его в JSON.
///
/// Служит проверкой годности ключа перед тем, как его сохранять:
/// клиенту нужно показать пользователю, куда он собрался соединяться, и
/// отказать по-человечески, если ключ испорчен.
///
/// **Учётных данных в описании нет намеренно.** Описание уходит в
/// интерфейс и в журналы, а UUID — секрет, дающий доступ к точке
/// выхода.
///
/// # Safety
///
/// `uri` — годная строка C.
#[no_mangle]
pub unsafe extern "C" fn atlas_key_describe(uri: *const c_char) -> *mut c_char {
    // Условие: договор функции.
    let Some(uri) = (unsafe { take(uri, "ключ доступа") }) else {
        return core::ptr::null_mut();
    };
    let key = match ProxyKey::parse(&uri) {
        Ok(key) => key,
        Err(error) => {
            fail(&format!("ключ не разбирается: {error}"));
            return core::ptr::null_mut();
        }
    };

    let described = serde_json::json!({
        "protocol": format!("{:?}", key.protocol).to_lowercase(),
        "host": key.host,
        "port": key.port,
        "tag": key.tag,
        "flow": format!("{:?}", key.flow).to_lowercase(),
        "security": format!("{:?}", key.security.kind).to_lowercase(),
        "sni": key.security.sni,
        "alpn": key.security.alpn,
        "reality": key.security.reality.is_some(),
    });
    give(&described.to_string())
}

/// Поднять локальный прокси и начать обслуживание.
///
/// `listen` — адрес вида `127.0.0.1:1080`; порт `0` означает «любой
/// свободный», и тогда занятый адрес узнаётся через
/// [`atlas_proxy_address`]. `options` может быть нулём — тогда берутся
/// умолчания.
///
/// Возвращает ноль при отказе; причина — в [`atlas_last_error`].
///
/// # Safety
///
/// `uri` и `listen` — годные строки C; `options` — либо ноль, либо
/// годный указатель на [`AtlasOptions`].
#[no_mangle]
pub unsafe extern "C" fn atlas_proxy_start(
    uri: *const c_char,
    listen: *const c_char,
    options: *const AtlasOptions,
) -> *mut AtlasProxy {
    // Условие: договор функции.
    let Some(uri) = (unsafe { take(uri, "ключ доступа") }) else {
        return core::ptr::null_mut();
    };
    let Some(listen) = (unsafe { take(listen, "адрес прослушивания") }) else {
        return core::ptr::null_mut();
    };
    let key = match ProxyKey::parse(&uri) {
        Ok(key) => key,
        Err(error) => {
            fail(&format!("ключ не разбирается: {error}"));
            return core::ptr::null_mut();
        }
    };

    let mut dial = DialOptions::default();
    if !options.is_null() {
        // Условие: указатель не нулевой и, по договору, годен.
        let given = unsafe { *options };
        dial.ech = given.ech != 0;
        if given.connect_timeout_ms != 0 {
            dial.connect_timeout = Duration::from_millis(u64::from(given.connect_timeout_ms));
        }
        if given.read_timeout_ms != 0 {
            dial.read_timeout = Some(Duration::from_millis(u64::from(given.read_timeout_ms)));
        }
    }

    match Proxy::start(key, &listen, dial) {
        Ok(proxy) => Box::into_raw(Box::new(AtlasProxy(proxy))),
        Err(error) => {
            fail(&format!("прокси не поднялся на {listen}: {error}"));
            core::ptr::null_mut()
        }
    }
}

/// Занятый прокси адрес.
///
/// # Safety
///
/// `proxy` получен от [`atlas_proxy_start`] и ещё не остановлен.
#[no_mangle]
pub unsafe extern "C" fn atlas_proxy_address(proxy: *const AtlasProxy) -> *mut c_char {
    if proxy.is_null() {
        fail("прокси: передан нулевой указатель");
        return core::ptr::null_mut();
    }
    // Условие: указатель выдан `atlas_proxy_start` и ещё жив.
    let proxy = unsafe { &*proxy };
    give(&proxy.0.address().to_string())
}

/// Показания счётчиков в JSON.
///
/// # Safety
///
/// `proxy` получен от [`atlas_proxy_start`] и ещё не остановлен.
#[no_mangle]
pub unsafe extern "C" fn atlas_proxy_stats(proxy: *const AtlasProxy) -> *mut c_char {
    if proxy.is_null() {
        fail("прокси: передан нулевой указатель");
        return core::ptr::null_mut();
    }
    // Условие: указатель выдан `atlas_proxy_start` и ещё жив.
    let stats = unsafe { &*proxy }.0.stats();
    let described = serde_json::json!({
        "accepted": stats.accepted,
        "active": stats.active,
        "failed": stats.failed,
        "to_target": stats.to_target,
        "from_target": stats.from_target,
    });
    give(&described.to_string())
}

/// Остановить прокси и освободить дескриптор.
///
/// Новые соединения перестают приниматься; уже открытые доживают своё.
/// Ноль допустим и ничего не делает.
///
/// # Safety
///
/// `proxy` получен от [`atlas_proxy_start`] и останавливается ровно
/// один раз.
#[no_mangle]
pub unsafe extern "C" fn atlas_proxy_stop(proxy: *mut AtlasProxy) {
    if proxy.is_null() {
        return;
    }
    // Условие: указатель выдан `Box::into_raw` и не освобождался.
    let owned = unsafe { Box::from_raw(proxy) };
    owned.0.stop();
}
