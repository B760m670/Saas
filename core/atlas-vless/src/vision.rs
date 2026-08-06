//! XTLS-Vision: паддинг против детекта TLS-in-TLS.
//!
//! # Задача
//!
//! Внутри нашего TLS едет ещё один TLS — к сайту назначения. Рукопожатие
//! внутреннего соединения имеет узнаваемый профиль длин записей, и он
//! просматривается сквозь внешнее шифрование: DPI не видит содержимое, но
//! видит размеры. Это и есть детект TLS-in-TLS, из-за которого REALITY без
//! Vision заметен.
//!
//! # Решение
//!
//! Первые блоки дополняются так, чтобы **длина блока перестала зависеть от
//! длины содержимого**. Формула это и обеспечивает: при содержимом короче
//! порога дополнение равно `случайное(0..jitter) + цель − длина
//! содержимого`, поэтому сумма содержимого и дополнения всегда равна
//! `цель + случайное(0..jitter)`. Наблюдателю остаётся ровно одна величина —
//! равномерный шум, не несущий сведений о полезной нагрузке.
//!
//! После нескольких блоков отправитель командой [`Command::Direct`]
//! переключается в прямой режим: дальше данные идут без обрамления, потому
//! что к этому моменту внутреннее рукопожатие уже позади и скрывать нечего,
//! а накладные расходы не нужны.
//!
//! Раскладка блока:
//!
//! ```text
//! [UUID 16 байт — только в первом блоке]
//! +---------+-------------+-------------+----------+----------+
//! | Command | ContentLen  | PaddingLen  | Content  | Padding  |
//! | 1 байт  | 2 байта, BE | 2 байта, BE | N байт   | M нулей  |
//! +---------+-------------+-------------+----------+----------+
//! ```

use atlas_crypto::rng::OsRng;

use crate::error::{Error, Result};

/// Длина заголовка блока без идентификатора.
pub const HEADER_LEN: usize = 5;
/// Длина идентификатора, предваряющего первый блок.
pub const UUID_LEN: usize = 16;
/// Предельный размер блока, принятый эталонной реализацией.
pub const MAX_BLOCK: usize = 8192;

/// Команда блока.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Обрамление продолжается.
    Continue,
    /// Последний обрамлённый блок в серии.
    End,
    /// Дальше данные идут без обрамления.
    Direct,
}

impl Command {
    /// Числовой код.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Continue => 0x00,
            Self::End => 0x01,
            Self::Direct => 0x02,
        }
    }

    /// Разобрать числовой код.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] для незнакомого кода.
    pub const fn from_code(code: u8) -> Result<Self> {
        match code {
            0x00 => Ok(Self::Continue),
            0x01 => Ok(Self::End),
            0x02 => Ok(Self::Direct),
            _ => Err(Error::Malformed("неизвестная команда Vision")),
        }
    }

    /// Прекращается ли обрамление после этого блока.
    #[must_use]
    pub const fn ends_padding(self) -> bool {
        matches!(self, Self::Direct)
    }
}

/// Параметры выбора длины дополнения.
///
/// Значения по умолчанию совпадают с эталонной реализацией. Менять их
/// в одностороннем порядке нельзя: набор длин — сам по себе признак, и
/// клиент с нестандартными параметрами выделяется из общей массы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padding {
    /// Порог, ниже которого применяется длинное дополнение.
    pub long_threshold: u32,
    /// Ширина случайной добавки при длинном дополнении.
    pub long_jitter: u32,
    /// Целевая длина при длинном дополнении.
    pub long_target: u32,
    /// Ширина случайной добавки при коротком дополнении.
    pub short_jitter: u32,
}

impl Default for Padding {
    fn default() -> Self {
        Self {
            long_threshold: 900,
            long_jitter: 500,
            long_target: 900,
            short_jitter: 256,
        }
    }
}

impl Padding {
    /// Вычислить длину дополнения для блока.
    fn length_for(self, content_len: usize, long: bool) -> usize {
        let content = u32::try_from(content_len).unwrap_or(u32::MAX);

        let raw = if long && content < self.long_threshold {
            // Сумма содержимого и дополнения равна long_target + шум,
            // то есть не зависит от длины содержимого. В этом весь смысл.
            uniform(self.long_jitter) + self.long_target.saturating_sub(content)
        } else {
            uniform(self.short_jitter)
        };

        let cap = MAX_BLOCK
            .saturating_sub(HEADER_LEN + UUID_LEN)
            .saturating_sub(content_len);
        (raw as usize).min(cap)
    }
}

/// Равномерное число в диапазоне `0..bound`.
fn uniform(bound: u32) -> u32 {
    if bound == 0 {
        return 0;
    }
    // Смещение от взятия по модулю здесь порядка 2^-53 и наблюдению
    // не поддаётся.
    let draw = u64::from_le_bytes(OsRng::bytes::<8>());
    u32::try_from(draw % u64::from(bound)).unwrap_or(0)
}

/// Отправляющая сторона: обрамляет блоки.
#[derive(Debug)]
pub struct Padder {
    uuid: Option<[u8; UUID_LEN]>,
    padding: Padding,
    finished: bool,
}

impl Padder {
    /// Создать обрамитель.
    ///
    /// Идентификатор предваряет первый блок: по нему принимающая сторона
    /// понимает, что поток обрамлён.
    #[must_use]
    pub const fn new(uuid: [u8; UUID_LEN]) -> Self {
        Self {
            uuid: Some(uuid),
            padding: Padding {
                long_threshold: 900,
                long_jitter: 500,
                long_target: 900,
                short_jitter: 256,
            },
            finished: false,
        }
    }

    /// Задать параметры дополнения.
    #[must_use]
    pub const fn with_padding(mut self, padding: Padding) -> Self {
        self.padding = padding;
        self
    }

    /// Прекращено ли обрамление.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Обрамить блок.
    ///
    /// `long` включает длинное дополнение — им обрамляются первые блоки,
    /// внутри которых идёт рукопожатие.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`], если содержимое не помещается в блок.
    pub fn wrap(&mut self, content: &[u8], command: Command, long: bool) -> Result<Vec<u8>> {
        let content_len = u16::try_from(content.len())
            .map_err(|_| Error::TooLong("блок Vision длиннее 65535 байт"))?;
        if content.len() + HEADER_LEN + UUID_LEN > MAX_BLOCK {
            return Err(Error::TooLong("блок Vision превышает предельный размер"));
        }

        let padding_len = self.padding.length_for(content.len(), long);
        let padding_field = u16::try_from(padding_len).unwrap_or(u16::MAX);

        let mut out = Vec::with_capacity(UUID_LEN + HEADER_LEN + content.len() + padding_len);
        if let Some(uuid) = self.uuid.take() {
            out.extend_from_slice(&uuid);
        }
        out.push(command.code());
        out.extend_from_slice(&content_len.to_be_bytes());
        out.extend_from_slice(&padding_field.to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding_len, 0);

        if command.ends_padding() {
            self.finished = true;
        }
        Ok(out)
    }
}

/// Принимающая сторона: снимает обрамление.
#[derive(Debug)]
pub struct Unpadder {
    uuid: [u8; UUID_LEN],
    buffer: Vec<u8>,
    state: State,
    /// Команда перехода в прямой режим уже встречена, но текущий блок
    /// ещё не дочитан. Переключаться сразу нельзя — потеряем содержимое.
    pending_direct: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Ждём идентификатор, по которому опознаётся обрамлённый поток.
    AwaitingPrefix,
    /// Читаем заголовок блока.
    Header,
    /// Читаем содержимое, осталось столько байт.
    Content { remaining: usize, padding: usize },
    /// Пропускаем дополнение, осталось столько байт.
    SkipPadding { remaining: usize },
    /// Обрамление закончилось, дальше данные идут как есть.
    Direct,
}

impl Unpadder {
    /// Создать снимающую сторону.
    #[must_use]
    pub const fn new(uuid: [u8; UUID_LEN]) -> Self {
        Self {
            uuid,
            buffer: Vec::new(),
            state: State::AwaitingPrefix,
            pending_direct: false,
        }
    }

    /// Перешёл ли поток в прямой режим.
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(self.state, State::Direct)
    }

    /// Сколько байт лежит в буфере, не составив целого блока.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// Добавить прочитанный из потока кусок.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    /// Извлечь всё содержимое, доступное на данный момент.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если заголовок блока содержит неизвестную
    /// команду.
    pub fn drain(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();

        loop {
            match self.state {
                State::AwaitingPrefix => {
                    // Для опознания нужен идентификатор и заголовок целиком.
                    if self.buffer.len() < UUID_LEN + HEADER_LEN {
                        break;
                    }
                    if self.buffer.get(..UUID_LEN) != Some(&self.uuid[..]) {
                        // Поток не обрамлён — отдаём как есть и больше
                        // не вмешиваемся.
                        self.state = State::Direct;
                        continue;
                    }
                    self.buffer.drain(..UUID_LEN);
                    self.state = State::Header;
                }

                State::Header => {
                    let Some(header) = self.buffer.get(..HEADER_LEN) else {
                        break;
                    };
                    let (command, content, padding) = match header {
                        [command, c_hi, c_lo, p_hi, p_lo] => (
                            Command::from_code(*command)?,
                            usize::from(u16::from_be_bytes([*c_hi, *c_lo])),
                            usize::from(u16::from_be_bytes([*p_hi, *p_lo])),
                        ),
                        _ => break,
                    };
                    self.buffer.drain(..HEADER_LEN);

                    // Команду запоминаем сейчас, а применяем после того,
                    // как блок дочитан: иначе потеряем его содержимое.
                    if command.ends_padding() {
                        self.pending_direct = true;
                    }
                    self.state = State::Content {
                        remaining: content,
                        padding,
                    };
                }

                State::Content { remaining, padding } => {
                    if remaining == 0 {
                        self.state = State::SkipPadding { remaining: padding };
                        continue;
                    }
                    if self.buffer.is_empty() {
                        break;
                    }
                    let take = remaining.min(self.buffer.len());
                    out.extend(self.buffer.drain(..take));
                    self.state = State::Content {
                        remaining: remaining - take,
                        padding,
                    };
                }

                State::SkipPadding { remaining } => {
                    if remaining == 0 {
                        self.state = if self.pending_direct {
                            State::Direct
                        } else {
                            State::Header
                        };
                        continue;
                    }
                    if self.buffer.is_empty() {
                        break;
                    }
                    let take = remaining.min(self.buffer.len());
                    self.buffer.drain(..take);
                    self.state = State::SkipPadding {
                        remaining: remaining - take,
                    };
                }

                State::Direct => {
                    out.append(&mut self.buffer);
                    break;
                }
            }
        }

        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const UUID: [u8; UUID_LEN] = [0x5a; UUID_LEN];

    fn round_trip(blocks: &[(Vec<u8>, Command, bool)]) -> Vec<u8> {
        let mut padder = Padder::new(UUID);
        let mut wire = Vec::new();
        for (content, command, long) in blocks {
            wire.extend(padder.wrap(content, *command, *long).unwrap());
        }

        let mut unpadder = Unpadder::new(UUID);
        unpadder.push(&wire);
        unpadder.drain().unwrap()
    }

    #[test]
    fn single_block_round_trips() {
        let content = b"tls handshake bytes".to_vec();
        let out = round_trip(&[(content.clone(), Command::Continue, true)]);
        assert_eq!(out, content);
    }

    #[test]
    fn block_length_does_not_depend_on_content_length() {
        // Главное свойство Vision. При длинном дополнении сумма содержимого
        // и дополнения равна цели плюс шум, поэтому длина блока о полезной
        // нагрузке ничего не говорит.
        let padding = Padding::default();
        let overhead = UUID_LEN + HEADER_LEN;
        let low = overhead + padding.long_target as usize;
        let high = low + padding.long_jitter as usize;

        for content_len in [0_usize, 1, 100, 500, 899] {
            let mut padder = Padder::new(UUID);
            let block = padder
                .wrap(&vec![0xab; content_len], Command::Continue, true)
                .unwrap();
            assert!(
                (low..=high).contains(&block.len()),
                "длина {} для содержимого {content_len} вышла из диапазона {low}..={high}",
                block.len()
            );
        }
    }

    #[test]
    fn observed_lengths_are_identical_across_content_sizes() {
        // Усиление предыдущего теста: множества наблюдаемых длин для
        // разных длин содержимого должны перекрываться, а не просто
        // попадать в общий диапазон.
        let sample = |content_len: usize| -> std::collections::HashSet<usize> {
            // Выборка должна с запасом покрыть все 500 возможных длин,
            // иначе пересечение мало просто по теории вероятностей.
            (0..4000)
                .map(|_| {
                    let mut padder = Padder::new(UUID);
                    padder
                        .wrap(&vec![0x11; content_len], Command::Continue, true)
                        .unwrap()
                        .len()
                })
                .collect()
        };

        let short = sample(10);
        let long = sample(800);
        let common = short.intersection(&long).count();
        let expected = Padding::default().long_jitter as usize;
        assert!(
            common > expected * 9 / 10,
            "распределения длин расходятся: общих значений {common} из ожидаемых ~{expected}"
        );
    }

    #[test]
    fn short_padding_keeps_length_close_to_content() {
        let padding = Padding::default();
        let mut padder = Padder::new(UUID);
        let block = padder
            .wrap(&vec![0x11; 2000], Command::Continue, true)
            .unwrap();
        let overhead = UUID_LEN + HEADER_LEN;
        assert!(block.len() >= overhead + 2000);
        assert!(block.len() <= overhead + 2000 + padding.short_jitter as usize);
    }

    #[test]
    fn reassembles_across_arbitrary_chunk_boundaries() {
        let mut padder = Padder::new(UUID);
        let mut wire = Vec::new();
        wire.extend(padder.wrap(b"first", Command::Continue, true).unwrap());
        wire.extend(padder.wrap(b"second", Command::Continue, true).unwrap());
        wire.extend(padder.wrap(b"third", Command::End, false).unwrap());

        for chunk_size in [1_usize, 7, 64, 500, wire.len()] {
            let mut unpadder = Unpadder::new(UUID);
            let mut out = Vec::new();
            for chunk in wire.chunks(chunk_size) {
                unpadder.push(chunk);
                out.extend(unpadder.drain().unwrap());
            }
            assert_eq!(out, b"firstsecondthird", "куски по {chunk_size} байт");
        }
    }

    #[test]
    fn direct_command_switches_to_raw_stream() {
        let mut padder = Padder::new(UUID);
        let mut wire = padder.wrap(b"padded", Command::Direct, true).unwrap();
        assert!(padder.is_finished());
        // После перехода данные идут без обрамления.
        wire.extend_from_slice(b"raw tail");

        let mut unpadder = Unpadder::new(UUID);
        unpadder.push(&wire);
        assert_eq!(unpadder.drain().unwrap(), b"paddedraw tail");
        assert!(unpadder.is_direct());
    }

    #[test]
    fn unrecognised_prefix_passes_through_untouched() {
        // Если поток не наш, вмешиваться нельзя.
        let mut unpadder = Unpadder::new(UUID);
        let payload = b"\x16\x03\x01 something entirely different".to_vec();
        unpadder.push(&payload);
        assert_eq!(unpadder.drain().unwrap(), payload);
        assert!(unpadder.is_direct());
    }

    #[test]
    fn empty_content_is_allowed() {
        // Первый блок Vision отправляется вообще без содержимого — только
        // чтобы спрятать длину заголовка VLESS.
        let out = round_trip(&[(Vec::new(), Command::Continue, true)]);
        assert!(out.is_empty());
    }

    #[test]
    fn padding_bytes_are_zero() {
        let mut padder = Padder::new(UUID);
        let block = padder.wrap(b"xy", Command::Continue, true).unwrap();
        let content_start = UUID_LEN + HEADER_LEN;
        let padding = block.get(content_start + 2..).unwrap();
        assert!(padding.iter().all(|b| *b == 0));
    }

    #[test]
    fn uuid_prefix_appears_only_once() {
        let mut padder = Padder::new(UUID);
        let first = padder.wrap(b"a", Command::Continue, true).unwrap();
        let second = padder.wrap(b"b", Command::Continue, true).unwrap();
        assert_eq!(first.get(..UUID_LEN), Some(&UUID[..]));
        assert_ne!(second.get(..UUID_LEN), Some(&UUID[..]));
        // Сравнивать длины блоков нельзя: дополнение у каждого своё.
        // Проверяем то, что от него не зависит, — длину поля содержимого.
        assert_eq!(second.get(1..3), Some(&1_u16.to_be_bytes()[..]));
    }

    #[test]
    fn rejects_unknown_command() {
        let mut unpadder = Unpadder::new(UUID);
        let mut wire = UUID.to_vec();
        wire.extend_from_slice(&[0x09, 0, 0, 0, 0]);
        unpadder.push(&wire);
        assert!(matches!(unpadder.drain(), Err(Error::Malformed(_))));
    }

    #[test]
    fn rejects_oversized_content() {
        let mut padder = Padder::new(UUID);
        assert!(matches!(
            padder.wrap(&vec![0_u8; MAX_BLOCK], Command::Continue, false),
            Err(Error::TooLong(_))
        ));
    }

    #[test]
    fn survives_arbitrary_garbage() {
        for seed in 0_u8..=255 {
            let mut unpadder = Unpadder::new(UUID);
            let noise: Vec<u8> = (0..seed).map(|i| i.wrapping_mul(seed) ^ 0x77).collect();
            unpadder.push(&noise);
            let _ = unpadder.drain();
        }
    }
}
