//! Окно повторов: защита от переигрывания записанного `ClientHello`.
//!
//! # Зачем
//!
//! Проверки метки — ключ, `shortId`, часы — говорят, что приветствие
//! **когда-то** составил кто-то, знающий учётные данные. Они ничего не
//! говорят о том, что это происходит **впервые**.
//!
//! Разница решающая. Противник, записавший чужое соединение, не сможет
//! достроить рукопожатие: секретной части эфемерной доли клиента у него
//! нет. Но ему это и не нужно — ему нужно, чтобы **сервер выдал себя**.
//! Отправив запись повторно, он получает от узла поведение REALITY
//! вместо проксирования на сайт прикрытия, и этого достаточно, чтобы
//! отличить точку выхода от обычного сайта. Ровно то активное
//! зондирование, против которого REALITY и придуман.
//!
//! # Почему это дёшево
//!
//! Признаком служит сама запечатанная метка — 32 байта из `session_id`.
//! Она получена шифрованием на ключе, выведенном из эфемерной доли
//! клиента, поэтому у двух честных соединений совпасть не может, а у
//! повтора совпадает всегда.
//!
//! Хранить её вечно не нужно: метка вне допустимого расхождения часов
//! отвергается и без нас. Значит, окна в два расхождения хватает —
//! запись, выпавшая из него, уже отклонена проверкой времени. Отсюда и
//! размер: он ограничен не числом соединений за всё время, а темпом
//! подключений за считанные минуты.
//!
//! # Чего окно не делает
//!
//! Оно не переживает перезапуск и не общается между процессами. Узел,
//! поднятый заново, примет повтор, попавший в окно времени. Закрыть это
//! можно только общим состоянием, и для одиночной точки выхода игра не
//! стоит свеч: перезапуск редок, а окно измеряется минутами.
//!
//! Отдельно стоит сказать, что **эталонная реализация REALITY этой
//! защиты не имеет вовсе**, а проверку часов там по умолчанию отключает
//! `MaxTimeDiff == 0`. Мы своим сервером ни с кем не связаны по
//! совместимости и можем позволить себе быть строже.

use crate::auth::SESSION_ID_LEN;

/// Верхняя граница числа записей в окне.
///
/// Нужна на случай потока правдоподобных приветствий: метки попадают
/// сюда только после успешной проверки, но противник с действующими
/// учётными данными может подключаться часто. При переполнении
/// вытесняется самая старая запись — то есть окно деградирует до более
/// короткого по времени, а не до неработающего.
pub const MAX_ENTRIES: usize = 8192;

/// Недавно принятые метки.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Пары «время приёма — метка», в порядке добавления.
    entries: Vec<(u32, [u8; SESSION_ID_LEN])>,
    horizon: u32,
    capacity: usize,
}

impl ReplayWindow {
    /// Создать окно, помнящее метки `horizon` секунд.
    ///
    /// Разумное значение — удвоенное допустимое расхождение часов:
    /// приветствие с меткой старше этого срока отвергается проверкой
    /// времени, и помнить его незачем.
    #[must_use]
    pub const fn new(horizon: u32) -> Self {
        Self {
            entries: Vec::new(),
            horizon,
            capacity: MAX_ENTRIES,
        }
    }

    /// Задать предел числа записей.
    #[must_use]
    pub const fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Сколько меток сейчас помнится.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Пусто ли окно.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Принять метку впервые.
    ///
    /// Возвращает `false`, если такая метка уже проходила — это повтор.
    /// Вызывать **после** всех остальных проверок: тогда в окно попадают
    /// только приветствия, которые в остальном приемлемы, и поток
    /// заведомо негодных его не забивает.
    pub fn accept(&mut self, now: u32, tag: [u8; SESSION_ID_LEN]) -> bool {
        self.expire(now);

        if self.entries.iter().any(|(_, seen)| *seen == tag) {
            return false;
        }

        // Вытеснение старейшей: окно укорачивается по времени, но не
        // перестаёт работать и не растёт в памяти без предела.
        while self.entries.len() >= self.capacity && !self.entries.is_empty() {
            self.entries.remove(0);
        }
        self.entries.push((now, tag));
        true
    }

    /// Выбросить всё, что старше горизонта.
    ///
    /// Очистка ленивая — на приёме, а не по таймеру: у крейта нет и не
    /// должно быть своих часов, время приходит снаружи. Между приёмами
    /// окно может держать устаревшие записи, но их число ограничено
    /// [`MAX_ENTRIES`], так что это вопрос памяти, а не корректности.
    ///
    /// Сравнение идёт по модулю разности, а не «раньше — позже»: часы,
    /// шагнувшие назад, не должны превращать окно в вечное хранилище.
    fn expire(&mut self, now: u32) {
        let horizon = self.horizon;
        self.entries
            .retain(|(seen_at, _)| now.abs_diff(*seen_at) <= horizon);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_same_tag_passes_only_once() {
        let mut window = ReplayWindow::new(240);
        let tag = [0x11; SESSION_ID_LEN];

        assert!(window.accept(1000, tag), "первое подключение проходит");
        assert!(!window.accept(1000, tag), "повтор обязан быть отвергнут");
        assert!(!window.accept(1100, tag), "и позже в окне — тоже");
    }

    #[test]
    fn distinct_tags_do_not_interfere() {
        let mut window = ReplayWindow::new(240);
        for byte in 0..64_u8 {
            assert!(window.accept(1000, [byte; SESSION_ID_LEN]));
        }
        assert_eq!(window.len(), 64);
    }

    #[test]
    fn a_tag_is_forgotten_past_the_horizon() {
        let mut window = ReplayWindow::new(240);
        let tag = [0x22; SESSION_ID_LEN];

        assert!(window.accept(1000, tag));
        // За горизонтом метка забывается — но такое приветствие к этому
        // моменту уже отвергается проверкой часов.
        assert!(window.accept(1000 + 241, tag));
        assert_eq!(window.len(), 1, "старая запись вычищена");
    }

    #[test]
    fn a_clock_step_backwards_does_not_make_the_window_permanent() {
        let mut window = ReplayWindow::new(240);
        assert!(window.accept(10_000, [0x33; SESSION_ID_LEN]));
        // Часы ушли назад на час: запись обязана быть вычищена, а не
        // остаться навсегда «в будущем».
        assert!(window.accept(6400, [0x44; SESSION_ID_LEN]));
        assert_eq!(window.len(), 1);
    }

    #[test]
    fn the_window_never_grows_past_its_capacity() {
        let mut window = ReplayWindow::new(240).with_capacity(16);
        for index in 0..1000_u32 {
            let mut tag = [0; SESSION_ID_LEN];
            tag[..4].copy_from_slice(&index.to_be_bytes());
            assert!(window.accept(1000, tag));
            assert!(window.len() <= 16, "предел обязан соблюдаться");
        }
    }

    #[test]
    fn eviction_shortens_the_window_but_keeps_it_working() {
        let mut window = ReplayWindow::new(240).with_capacity(4);
        let first = [0x55; SESSION_ID_LEN];
        assert!(window.accept(1000, first));
        assert!(!window.accept(1000, first), "пока помним — отвергаем");

        for index in 1..8_u32 {
            let mut tag = [0; SESSION_ID_LEN];
            tag[..4].copy_from_slice(&index.to_be_bytes());
            window.accept(1000, tag);
        }
        // Старейшую вытеснили, и она снова проходит. Это осознанная
        // деградация: лучше короткое окно, чем неограниченная память.
        assert!(window.accept(1000, first));
    }
}
