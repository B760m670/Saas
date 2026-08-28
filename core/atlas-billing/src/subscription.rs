//! Срок подписки: когда он кончается и как считается при продлении.

/// Момент времени в секундах эпохи.
///
/// Календарь здесь не нужен: срок отсчитывается сутками по 86400 секунд, а
/// не «тем же числом следующего месяца». Такой отсчёт не зависит ни от
/// часового пояса покупателя, ни от перевода часов, ни от длины месяца — и
/// совпадает с тем, что записано в тарифах (`Plan::days`).
pub type Timestamp = i64;

/// Секунд в сутках.
const DAY: i64 = 24 * 60 * 60;

/// Действует ли подписка в момент `now`.
///
/// Граница исключающая: в секунду `expires_at` подписка уже не действует.
#[must_use]
pub fn is_active(expires_at: Option<Timestamp>, now: Timestamp) -> bool {
    expires_at.is_some_and(|end| end > now)
}

/// Сколько дней ещё можно пользоваться — с округлением **вверх**.
///
/// Вниз округлять нельзя с обоих концов. Через десять минут после выдачи
/// трёх пробных дней остаётся 2 дня 23 часа, и округление вниз показало бы
/// «осталось 2 дня» — покупатель читает это как обман и идёт в поддержку.
/// А за полчаса до конца оно показало бы «осталось 0 дней» при работающем
/// VPN.
///
/// Вверх верно на обоих концах: 2 дня 23 часа — это и есть «ещё три дня
/// можно пользоваться», а полчаса — «сегодня ещё работает».
///
/// Правило живёт здесь, а не в боте, потому что то же число показывает
/// мини-приложение. Два места считали бы его по-разному ровно до первой
/// правки, и расхождение увидел бы покупатель.
#[must_use]
pub fn days_left(expires_at: Option<Timestamp>, now: Timestamp) -> i64 {
    expires_at.map_or(0, |end| {
        // `i64::div_ceil` пока нестабилен, поэтому вручную. Насыщение — на
        // случай нелепой даты из базы: переполнение дало бы отрицательное
        // число дней вместо большого.
        let left = end.saturating_sub(now).max(0);
        left.saturating_add(DAY - 1) / DAY
    })
}

/// Новый срок окончания после оплаты `days` суток.
///
/// **Сроки складываются, а не сбрасываются.** Заплатил за год, когда до
/// конца оставалось 40 дней, — получил 405 дней, а не 365.
///
/// Иначе покупатель наказан за то, что заплатил заранее, и выгодная для
/// него стратегия — тянуть до последнего дня. Создавать причины тянуть не
/// надо: человек, тянущий до последнего, однажды забудет совсем.
///
/// Если срок уже истёк, отсчёт идёт от момента оплаты, а не от старой
/// даты. Вернувшийся через полгода платит за полгода вперёд, а не
/// докупает прошлое.
///
/// Возвращает `None`, если `days` равно нулю или счёт переполняется, —
/// и то и другое означает ошибку в вызывающем коде, а не выбор человека.
#[must_use]
pub fn extend(expires_at: Option<Timestamp>, days: u32, now: Timestamp) -> Option<Timestamp> {
    if days == 0 {
        return None;
    }

    // Отсчёт от того, что дальше в будущем: от непрошедшего срока или от
    // сейчас. Просроченная дата в основание не годится — иначе оплата
    // частично уходила бы в прошлое.
    let base = match expires_at {
        Some(end) if end > now => end,
        _ => now,
    };

    i64::from(days).checked_mul(DAY)?.checked_add(base)
}

#[cfg(test)]
mod tests {
    use super::{extend, is_active, Timestamp, DAY};

    /// Произвольный момент, лишь бы не ноль: отсчёт от нуля скрыл бы
    /// ошибку вида «забыли прибавить основание».
    const NOW: Timestamp = 1_760_000_000;

    /// То самое обещание из docs/14-bot.md §6, ради которого модуль и
    /// существует: год, оплаченный за 40 дней до конца, даёт 405 дней.
    #[test]
    fn paying_early_adds_to_what_is_left() {
        let expires = NOW + 40 * DAY;
        assert_eq!(extend(Some(expires), 365, NOW), Some(NOW + 405 * DAY));
    }

    #[test]
    fn an_expired_subscription_counts_from_the_payment() {
        let long_gone = NOW - 180 * DAY;
        assert_eq!(extend(Some(long_gone), 30, NOW), Some(NOW + 30 * DAY));
    }

    /// Ровно в секунду окончания подписка уже не действует, значит и отсчёт
    /// идёт от сейчас. Иначе результат зависел бы от того, успел ли платёж
    /// прийти на секунду раньше.
    #[test]
    fn exactly_at_expiry_counts_from_now() {
        assert_eq!(extend(Some(NOW), 30, NOW), Some(NOW + 30 * DAY));
        assert!(!is_active(Some(NOW), NOW));
    }

    #[test]
    fn a_first_purchase_counts_from_now() {
        assert_eq!(extend(None, 3, NOW), Some(NOW + 3 * DAY));
    }

    /// Продление подряд накапливается: два месяца — это два месяца, а не
    /// один. Проверяется цепочкой, потому что ошибка «сброс вместо
    /// сложения» видна только со второго раза.
    #[test]
    fn repeated_renewals_accumulate() {
        let Some(after_first) = extend(None, 30, NOW) else {
            return;
        };
        let Some(after_second) = extend(Some(after_first), 30, NOW) else {
            return;
        };
        assert_eq!(after_second, NOW + 60 * DAY);
    }

    #[test]
    fn a_zero_day_plan_is_refused() {
        assert_eq!(extend(Some(NOW), 0, NOW), None);
        assert_eq!(extend(None, 0, NOW), None);
    }

    /// Переполнение не должно давать срок в прошлом — а именно это и вышло
    /// бы при сложении с переносом.
    #[test]
    fn an_absurd_term_overflows_to_nothing() {
        assert_eq!(extend(Some(i64::MAX - DAY), u32::MAX, NOW), None);
    }

    #[test]
    fn activity_is_decided_by_the_deadline_alone() {
        assert!(is_active(Some(NOW + 1), NOW));
        assert!(!is_active(Some(NOW - 1), NOW));
        assert!(!is_active(None, NOW));
    }
}
