//! Интерфейс платёжного сервиса.

use core::fmt;

use crate::event::PaymentEvent;
use crate::http::{Callback, Checkout};
use crate::order::Order;

/// Платёжный сервис.
///
/// Три метода покрывают весь обмен: выставить счёт, узнать из ответа ссылку
/// на оплату, разобрать уведомление. Всё, что бот знает о деньгах, проходит
/// через них, поэтому подключение нового сервиса — это один файл, а не
/// правки по всему коду.
pub trait Provider {
    /// Имя для логов и для отчёта пользователю, какой рельсой он платил.
    fn name(&self) -> &'static str;

    /// Что нужно сделать, чтобы получить оплату по заказу.
    fn checkout(&self, order: &Order) -> Result<Checkout, Error>;

    /// Достать ссылку на оплату из ответа сервиса.
    ///
    /// Вызывается только если [`Provider::checkout`] вернул
    /// [`Checkout::Request`](crate::http::Checkout::Request); остальным
    /// сервисам достаточно реализации по умолчанию.
    fn checkout_page(&self, _response: &[u8]) -> Result<String, Error> {
        Err(Error::Unsupported)
    }

    /// Проверить подпись уведомления и разобрать его.
    ///
    /// Единственный вход для внешних данных. Реализация обязана отвергнуть
    /// уведомление с негодной подписью **до** того, как посмотрит на его
    /// содержимое, — иначе о состоянии платежа рассказывает не сервис, а
    /// тот, кто первым нашёл адрес.
    fn callback(&self, callback: &Callback) -> Result<PaymentEvent, Error>;
}

/// Отказ при работе с платёжным сервисом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Сервис не поддерживает эту операцию.
    Unsupported,
    /// Подпись уведомления не сошлась.
    ///
    /// Отдельный вариант, потому что реакция особая: это не сбой обмена, а
    /// либо чужая попытка выдать себе подписку, либо разъехавшийся секрет.
    /// И то и другое требует внимания, а не повтора запроса.
    BadSignature,
    /// Уведомление или ответ не разобрались.
    Malformed(&'static str),
    /// Сервис ответил отказом своими словами.
    Rejected(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("сервис не поддерживает эту операцию"),
            Self::BadSignature => f.write_str("подпись уведомления не сошлась"),
            Self::Malformed(what) => write!(f, "не удалось разобрать: {what}"),
            Self::Rejected(reason) => write!(f, "сервис отказал: {reason}"),
        }
    }
}

impl core::error::Error for Error {}
