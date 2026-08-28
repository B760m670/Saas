//! Время в том виде, в каком его понимает панель.
//!
//! Панель принимает и отдаёт даты строкой `2025-01-17T15:38:45.065Z`, а мы
//! внутри считаем секундами эпохи. Преобразование написано здесь, а не взято
//! готовой библиотекой, по одной причине: всё, что нужно, — это перевод между
//! числом секунд и календарём по Гринвичу, без часовых поясов, локалей и
//! правил перевода часов. Затаскивать ради этого зависимость с собственной
//! базой поясов значит принести с ней и её ошибки.
//!
//! Алгоритм — обычный счёт дней от условной эпохи с началом года в марте:
//! при таком сдвиге високосный день оказывается последним днём года, и вся
//! возня с февралём исчезает из формул.

/// Секунд в сутках.
const DAY: i64 = 86_400;

/// Сдвиг между началом счёта дней (1 марта 0000 года) и 1 января 1970.
const EPOCH_SHIFT: i64 = 719_468;

/// Записать момент времени так, как его ждёт панель.
///
/// Миллисекунды всегда нулевые: мы считаем секундами, и выдумывать точность,
/// которой нет, незачем.
#[must_use]
pub fn to_iso8601(seconds: i64) -> String {
    let days = seconds.div_euclid(DAY);
    let rest = seconds.rem_euclid(DAY);

    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z")
}

/// Прочитать момент времени, присланный панелью.
///
/// Разбирается только то, что панель действительно шлёт: дата, время и `Z`.
/// Дробная часть отбрасывается, смещения поясов не принимаются — их в ответах
/// панели не бывает, а тихо принять `+03:00` и посчитать его как `Z` значит
/// ошибиться на три часа в сроке подписки.
#[must_use]
pub fn from_iso8601(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, rest) = text.split_once('T')?;

    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Дробная часть секунд не нужна, но и не мешает.
    let time = rest.strip_suffix('Z')?;
    let time = time.split_once('.').map_or(time, |(head, _)| head);

    let mut parts = time.split(':');
    let hour: i64 = parts.next()?.parse().ok()?;
    let minute: i64 = parts.next()?.parse().ok()?;
    let second: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    Some(days * DAY + hour * 3600 + minute * 60 + second)
}

/// Календарная дата по числу дней от 1 января 1970.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + EPOCH_SHIFT;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_shifted + 2) / 5 + 1;
    let month = if month_shifted < 10 {
        month_shifted + 3
    } else {
        month_shifted - 9
    };

    let year = if month <= 2 { year + 1 } else { year };
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// Число дней от 1 января 1970 до календарной даты.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let month = i64::from(month);
    let day = i64::from(day);

    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(EPOCH_SHIFT)
}

#[cfg(test)]
mod tests {
    use super::{from_iso8601, to_iso8601};

    /// Сверено с календарём: каждая строка — настоящий момент времени.
    const KNOWN: [(i64, &str); 6] = [
        (0, "1970-01-01T00:00:00.000Z"),
        (1_760_000_000, "2025-10-09T08:53:20.000Z"),
        (1_767_225_600, "2026-01-01T00:00:00.000Z"),
        (1_788_000_000, "2026-08-29T10:40:00.000Z"),
        // 2000 год високосный, хотя делится на 100: правило про 400 лет.
        (951_782_400, "2000-02-29T00:00:00.000Z"),
        (4_102_444_800, "2100-01-01T00:00:00.000Z"),
    ];

    #[test]
    fn known_moments_are_written_correctly() {
        for (seconds, text) in KNOWN {
            assert_eq!(to_iso8601(seconds), text, "секунды {seconds}");
        }
    }

    #[test]
    fn known_moments_are_read_back() {
        for (seconds, text) in KNOWN {
            assert_eq!(from_iso8601(text), Some(seconds), "строка {text}");
        }
    }

    /// Ошибка на один день вокруг високосного — самая частая в таких
    /// преобразованиях, и заметить её можно только на этих трёх датах.
    #[test]
    fn the_leap_day_is_not_lost() {
        for (seconds, text) in [
            (951_868_800, "2000-03-01T00:00:00.000Z"),
            (1_709_164_800, "2024-02-29T00:00:00.000Z"),
            (1_709_251_200, "2024-03-01T00:00:00.000Z"),
        ] {
            assert_eq!(to_iso8601(seconds), text);
            assert_eq!(from_iso8601(text), Some(seconds));
        }
    }

    /// Проход по каждому дню на четыре года вперёд: если где-то в формулах
    /// сдвиг, он вылезет на границе месяца, а не в середине.
    #[test]
    fn every_day_survives_the_round_trip() {
        let start = 1_760_000_000 - 1_760_000_000 % 86_400;
        for day in 0..1_461 {
            let seconds = start + day * 86_400;
            assert_eq!(
                from_iso8601(&to_iso8601(seconds)),
                Some(seconds),
                "день номер {day}"
            );
        }
    }

    #[test]
    fn a_fractional_part_is_ignored() {
        assert_eq!(
            from_iso8601("2026-01-01T00:00:00.065Z"),
            Some(1_767_225_600)
        );
    }

    /// Смещение пояса принимать нельзя: молча посчитав `+03:00` как `Z`,
    /// мы ошиблись бы на три часа в сроке подписки.
    #[test]
    fn a_timezone_offset_is_refused() {
        assert_eq!(from_iso8601("2026-01-01T00:00:00+03:00"), None);
        assert_eq!(from_iso8601("2026-01-01T00:00:00"), None);
    }

    #[test]
    fn nonsense_is_refused() {
        for text in [
            "",
            "2026-01-01",
            "вчера",
            "2026-13-01T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-01-01T25:00:00Z",
            "2026-01-01T00:61:00Z",
            "2026-01-01T00:00Z",
        ] {
            assert_eq!(from_iso8601(text), None, "принято {text:?}");
        }
    }
}
