//! Ограничение полосы для трафика, уходящего на сайт прикрытия.
//!
//! # Что этим закрывается
//!
//! Посторонний, постучавшийся на точку выхода, получает сайт прикрытия
//! байт в байт. Это и есть скрытность REALITY — и одновременно открытый
//! пересыльщик: кто угодно вправе качать через нашу машину чужой сайт
//! сколько захочет, за наш трафик и с нашего адреса.
//!
//! На тарифе с квотой это прямые деньги: терабайт у Vultr стоит десять
//! долларов, и выкачать его через нас может любой, кто нашёл адрес.
//!
//! # Чего этим не закрывается
//!
//! **Это не делает нас неотличимыми.** Довод «подогнать полосу под
//! настоящий сайт, чтобы совпадала» звучит убедительно, но не
//! выдерживает проверки: мы **пересылаем**, а не отдаём, поэтому наша
//! полоса и так не выше, чем у канала до сайта прикрытия. Совпадение
//! ограничением не достигается, а неверно выбранное значение само
//! становится отличием — сайт, отдающий через нас втрое медленнее, чем
//! напрямую, заметен ровно так же, как отдающий втрое быстрее.
//!
//! Поэтому здесь честная защита от расхода, а не средство маскировки, и
//! по умолчанию ограничение **выключено**: значение обязан выбрать тот,
//! кто знает свой тариф.
//!
//! # Устройство
//!
//! Дырявое ведро с накоплением: [`Bucket::delay`] — чистая функция от
//! состояния и часов, поэтому проверяется без сна и без сети. Спит
//! только обёртка [`Limited`].

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// Сколько байт в секунду и какой всплеск допустим.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// Установившаяся скорость, байт в секунду.
    pub bytes_per_second: u64,
    /// Ёмкость ведра — сколько можно передать разом после простоя.
    ///
    /// Всплеск нужен: страница сайта прикрытия должна открываться
    /// быстро, иначе ограничение видно невооружённым глазом. Ограничение
    /// начинает работать на длинной выкачке, ради которой всё и делается.
    pub burst_bytes: u64,
}

impl Limit {
    /// Ограничение со всплеском в одну секунду скорости.
    #[must_use]
    pub const fn per_second(bytes: u64) -> Self {
        Self {
            bytes_per_second: bytes,
            burst_bytes: bytes,
        }
    }

    /// Задать ёмкость всплеска.
    #[must_use]
    pub const fn with_burst(mut self, bytes: u64) -> Self {
        self.burst_bytes = bytes;
        self
    }
}

/// Дырявое ведро.
#[derive(Debug)]
pub struct Bucket {
    limit: Limit,
    /// Баланс в наноединицах: байты × 1e9. **Со знаком.**
    ///
    /// Знак существен. Первая редакция хранила беззнаковое значение и
    /// при нехватке обнуляла его, а недостачу отдавала паузой. На бумаге
    /// это то же самое, на деле — нет: пока вызывающий спит, время идёт
    /// и кредит натекает, но следующий вызов срезал его потолком
    /// всплеска. При нулевом всплеске срезалось всё, и ограничение в
    /// 64 КБ/с давало 7,5 КБ/с — восьмикратная разница, пойманная
    /// сквозным тестом, а не рассуждением.
    ///
    /// Долг обязан храниться, а не забываться. Потолок применяется
    /// только сверху, к накоплению за простой.
    balance_nanos: i128,
    last: u64,
}

/// Наносекунд в секунде.
///
/// Знаковый тип: баланс уходит в минус, и приведение туда-сюда на
/// каждом умножении добавляло бы шум там, где важна арифметика.
const NANOS: i128 = 1_000_000_000;

impl Bucket {
    /// Полное ведро на указанных часах.
    #[must_use]
    pub const fn new(limit: Limit, now_nanos: u64) -> Self {
        Self {
            limit,
            balance_nanos: (limit.burst_bytes as i128) * NANOS,
            last: now_nanos,
        }
    }

    /// Сколько подождать, прежде чем пропускать `want` байт.
    ///
    /// Байты списываются в любом случае: ведро уходит в минус, и долг
    /// отрабатывается следующими вызовами. Иначе порция крупнее ёмкости
    /// не прошла бы никогда.
    pub fn delay(&mut self, want: u64, now_nanos: u64) -> Duration {
        let elapsed = i128::from(now_nanos.saturating_sub(self.last));
        self.last = now_nanos;

        let refill = elapsed.saturating_mul(i128::from(self.limit.bytes_per_second));
        let ceiling = i128::from(self.limit.burst_bytes).saturating_mul(NANOS);
        // Потолок только сверху: накопить за простой больше всплеска
        // нельзя, а вот уйти в минус — можно и нужно.
        self.balance_nanos = self.balance_nanos.saturating_add(refill).min(ceiling);
        self.balance_nanos = self
            .balance_nanos
            .saturating_sub(i128::from(want).saturating_mul(NANOS));

        if self.balance_nanos >= 0 {
            return Duration::ZERO;
        }

        // Ждём ровно столько, сколько нужно, чтобы долг натёк обратно.
        let rate = i128::from(self.limit.bytes_per_second.max(1));
        let wait_nanos = self.balance_nanos.unsigned_abs() / rate.unsigned_abs();
        Duration::from_nanos(u64::try_from(wait_nanos).unwrap_or(u64::MAX))
    }
}

/// Поток, пропускающий не быстрее заданного.
///
/// Оборачивает **пишущую** сторону: ограничивать чтение бессмысленно —
/// данные уже пришли и за них уже заплачено.
#[derive(Debug)]
pub struct Limited<T> {
    inner: T,
    bucket: Bucket,
    started: Instant,
}

impl<T> Limited<T> {
    /// Обернуть поток.
    #[must_use]
    pub fn new(inner: T, limit: Limit) -> Self {
        Self {
            inner,
            bucket: Bucket::new(limit, 0),
            started: Instant::now(),
        }
    }

    /// Поток внутри — чтобы закрыть его по окончании передачи.
    ///
    /// Без этого обёртка стоила бы дороже, чем даёт: пишущую сторону
    /// TCP надо закрывать явно, иначе собеседник ждёт до таймаута.
    /// Именно это и случилось при первом подключении ограничения —
    /// выкачка занимала не четыре секунды, а тридцать четыре.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Монотонные наносекунды от создания обёртки.
    fn now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

impl<T: Write> Write for Limited<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let wait = self.bucket.delay(buf.len() as u64, self.now());
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T: Read> Read for Limited<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Ведро на 1000 байт в секунду со всплеском в 1000 байт.
    fn bucket() -> Bucket {
        Bucket::new(Limit::per_second(1000), 0)
    }

    #[test]
    fn a_full_bucket_lets_the_burst_through_at_once() {
        let mut bucket = bucket();
        assert_eq!(bucket.delay(1000, 0), Duration::ZERO);
    }

    #[test]
    fn the_next_byte_after_the_burst_waits() {
        let mut bucket = bucket();
        assert_eq!(bucket.delay(1000, 0), Duration::ZERO);
        // Ведро пусто: сотня байт при тысяче в секунду — это 100 мс.
        assert_eq!(bucket.delay(100, 0), Duration::from_millis(100));
    }

    #[test]
    fn waiting_refills_the_bucket() {
        let mut bucket = bucket();
        assert_eq!(bucket.delay(1000, 0), Duration::ZERO);
        // Через полсекунды натекло 500 байт.
        assert_eq!(bucket.delay(500, 500_000_000), Duration::ZERO);
        assert_eq!(bucket.delay(1, 500_000_000), Duration::from_millis(1));
    }

    #[test]
    fn the_bucket_does_not_overfill_during_a_long_idle() {
        let mut bucket = bucket();
        // Час простоя не даёт права выкачать час трафика разом — иначе
        // ограничение обходилось бы паузой.
        let hour = 3_600 * 1_000_000_000;
        assert_eq!(bucket.delay(1000, hour), Duration::ZERO);
        assert_eq!(bucket.delay(1, hour), Duration::from_millis(1));
    }

    #[test]
    fn a_chunk_larger_than_the_burst_still_passes() {
        // Иначе порция крупнее ёмкости не прошла бы никогда, и
        // соединение вставало бы намертво.
        let mut bucket = bucket();
        assert_eq!(bucket.delay(5000, 0), Duration::from_secs(4));
        // Долг отработан авансом, дальше идём по расписанию.
        assert_eq!(bucket.delay(1000, 5_000_000_000), Duration::ZERO);
    }

    #[test]
    fn the_rate_holds_even_for_one_byte_writes() {
        // Порция в один байт — худший случай для округления: доля
        // секунды на байт мала, и учёт целыми байтами превратил бы её в
        // ноль или в единицу, то есть в совсем другую скорость.
        //
        // Проверяется то же, что и для крупных порций: за известное
        // время проходит заявленное количество.
        let mut bucket = Bucket::new(Limit::per_second(10_000).with_burst(0), 0);
        let mut passed = 0_u64;
        let mut clock = 0_u64;

        while clock < 1_000_000_000 {
            let wait = bucket.delay(1, clock);
            clock += u64::try_from(wait.as_nanos()).unwrap_or(0);
            if clock <= 1_000_000_000 {
                passed += 1;
            } else {
                break;
            }
        }
        assert!(
            (9_500..=10_500).contains(&passed),
            "за секунду по байту прошло {passed} вместо 10 000"
        );
    }

    #[test]
    fn a_partly_full_bucket_spends_what_it_has_before_waiting() {
        // Здесь и живёт потеря дроби, если её допустить: при нехватке
        // надо списать накопленное и ждать только недостающее. Если
        // вместо этого ждать всю порцию целиком, накопленное пропадает,
        // и ведро отдаёт меньше заявленного.
        let mut bucket = Bucket::new(Limit::per_second(1000).with_burst(1000), 0);
        assert_eq!(bucket.delay(1000, 0), Duration::ZERO);

        // Полсекунды простоя — натекло 500 байт. Просим 600.
        // Ждать положено только за недостающую сотню, то есть 100 мс.
        assert_eq!(bucket.delay(600, 500_000_000), Duration::from_millis(100));
    }

    #[test]
    fn the_measured_rate_matches_the_limit() {
        // Главная проверка: за известное время сквозь ведро проходит
        // столько, сколько заявлено, — а не «примерно» и не вдвое меньше.
        let mut bucket = Bucket::new(Limit::per_second(10_000).with_burst(0), 0);
        let mut passed = 0_u64;
        let mut clock = 0_u64;

        // Секунда модельного времени порциями по 100 байт.
        while clock < 1_000_000_000 {
            let wait = bucket.delay(100, clock);
            clock += u64::try_from(wait.as_nanos()).unwrap_or(0);
            if clock <= 1_000_000_000 {
                passed += 100;
            }
        }
        assert!(
            (9_500..=10_500).contains(&passed),
            "за секунду прошло {passed} байт вместо 10 000"
        );
    }

    #[test]
    fn a_wrapped_writer_still_delivers_every_byte() {
        // Ограничение задерживает, но не теряет и не режет.
        let mut sink = Limited::new(Vec::new(), Limit::per_second(1 << 20));
        let payload = vec![0x7_u8; 4096];
        sink.write_all(&payload).unwrap();
        sink.flush().unwrap();
        assert_eq!(sink.inner, payload);
    }

    #[test]
    fn a_generous_limit_costs_no_measurable_time() {
        // Ограничение, заданное с запасом, не должно замедлять ничего:
        // иначе им никто не станет пользоваться.
        let mut sink = Limited::new(Vec::new(), Limit::per_second(1 << 30));
        let started = Instant::now();
        for _ in 0..64 {
            sink.write_all(&[0_u8; 16 * 1024]).unwrap();
        }
        assert!(started.elapsed() < Duration::from_millis(200));
    }
}
