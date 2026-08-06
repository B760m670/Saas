//! Сессия VLESS поверх готового зашифрованного потока.
//!
//! Слой, который наконец соединяет разрозненные части: заголовок
//! запроса, ответ сервера и обрамление XTLS-Vision, — в один поток,
//! который снаружи выглядит как обычный `Read + Write`.
//!
//! # Что происходит по шагам
//!
//! ```text
//! клиент → сервер:  [заголовок запроса][полезная нагрузка…]
//! сервер → клиент:  [заголовок ответа ][полезная нагрузка…]
//! ```
//!
//! Заголовок запроса не отправляется отдельным пакетом: он копится и
//! уходит вместе с первой порцией данных. Так делает эталонная
//! реализация, и так же ведёт себя любой разумный клиент — отдельный
//! крошечный пакет перед данными сам по себе признак.
//!
//! # Когда обрамление прекращается
//!
//! Vision скрывает профиль длин **внутреннего** рукопожатия: сквозь
//! внешнее шифрование видны размеры записей, и по ним TLS-in-TLS
//! опознаётся. Как только внутреннее рукопожатие позади, скрывать
//! нечего, и обрамление только тратит трафик, — поэтому отправитель
//! командой [`vision::Command::Direct`] переключает поток в прямой
//! режим.
//!
//! Момент переключения определяется наблюдением за исходящим потоком:
//! он разбирается как последовательность записей TLS, и переход
//! происходит, когда мимо прошла вторая запись `application_data`.
//! Первая из них у TLS 1.3 — это `Finished` клиента; вторая означает,
//! что рукопожатие закончилось окончательно.
//!
//! Если поток вообще не похож на TLS, скрывать нечего с самого начала,
//! и прямой режим включается сразу.
//!
//! **Совместимость от этого решения не зависит.** Момент переключения —
//! односторонняя политика отправителя: получатель просто исполняет
//! команду, которую видит в заголовке блока. Наш выбор может отличаться
//! от эталонного по числу обрамлённых блоков, и обе стороны всё равно
//! договорятся.

use std::io::{self, Read, Write};

use crate::request::{Endpoint, Request, Response};
use crate::vision::{self, Padder, Unpadder};

/// Наибольший размер содержимого одного блока Vision.
const MAX_CONTENT: usize = vision::MAX_BLOCK - vision::HEADER_LEN - vision::UUID_LEN;

/// Сколько байт читать у нижележащего потока за раз.
const CHUNK: usize = 16 * 1024;

/// Режим потока.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Flow {
    /// Без обрамления: данные идут как есть.
    ///
    /// Годится только там, где внутри нет второго TLS, — иначе профиль
    /// длин записей выдаёт туннель.
    #[default]
    Plain,
    /// XTLS-Vision.
    Vision,
}

impl Flow {
    /// Значение поля `flow` в заголовке запроса.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "",
            Self::Vision => "xtls-rprx-vision",
        }
    }
}

/// Наблюдатель за исходящим потоком.
///
/// Разбирает его как последовательность записей TLS, не расшифровывая:
/// нужны только тип и длина из пятибайтового заголовка. По ним
/// определяется, идёт ли внутри второй TLS и закончилось ли его
/// рукопожатие.
#[derive(Debug, Default)]
struct Sniffer {
    /// Накопленная часть заголовка записи.
    header: Vec<u8>,
    /// Сколько байт текущей записи ещё не прошло мимо.
    remaining: usize,
    /// Сколько записей `application_data` уже прошло.
    application_records: usize,
    /// Похож ли поток на TLS. Решается по первой же записи.
    looks_like_tls: Option<bool>,
}

impl Sniffer {
    /// Внешний тип записи `application_data`.
    const APPLICATION_DATA: u8 = 23;
    /// Внешний тип записи рукопожатия.
    const HANDSHAKE: u8 = 22;
    /// После скольких записей `application_data` рукопожатие заведомо
    /// позади. Первая у TLS 1.3 — это `Finished` клиента.
    const RECORDS_AFTER_HANDSHAKE: usize = 2;

    fn observe(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.remaining > 0 {
                let step = self.remaining.min(data.len());
                self.remaining -= step;
                data = data.get(step..).unwrap_or_default();
                continue;
            }

            let need = vision::HEADER_LEN.saturating_sub(self.header.len());
            let step = need.min(data.len());
            self.header
                .extend_from_slice(data.get(..step).unwrap_or_default());
            data = data.get(step..).unwrap_or_default();

            if self.header.len() < vision::HEADER_LEN {
                return;
            }

            let (kind, length) = match self.header.as_slice() {
                [kind, major, _, hi, lo] => {
                    let plausible = *kind == Self::HANDSHAKE && *major == 0x03;
                    if self.looks_like_tls.is_none() {
                        self.looks_like_tls = Some(plausible);
                    }
                    (*kind, usize::from(u16::from_be_bytes([*hi, *lo])))
                }
                _ => return,
            };
            self.header.clear();

            if kind == Self::APPLICATION_DATA {
                self.application_records = self.application_records.saturating_add(1);
            }
            self.remaining = length;
        }
    }

    /// Пора ли переключаться в прямой режим.
    fn handshake_is_over(&self) -> bool {
        match self.looks_like_tls {
            // Не TLS — скрывать нечего с самого начала.
            Some(false) => true,
            Some(true) => self.application_records >= Self::RECORDS_AFTER_HANDSHAKE,
            None => false,
        }
    }

    /// Нужно ли длинное дополнение: пока идёт внутреннее рукопожатие.
    fn inside_handshake(&self) -> bool {
        self.looks_like_tls == Some(true) && !self.handshake_is_over()
    }
}

/// Сессия VLESS.
///
/// Оборачивает уже установленный зашифрованный поток — обычно
/// `atlas_tls::TlsStream` поверх REALITY.
#[derive(Debug)]
pub struct Session<S> {
    stream: S,
    inbound: Inbound,
    outbound: Outbound,
}

/// Состояние входящего направления.
///
/// Вынесено из [`Session`] отдельно не ради красоты: то же состояние
/// нужно [`SessionReader`], а держать две копии логики снятия
/// обрамления — верный способ развести их со временем.
#[derive(Debug)]
pub struct Inbound {
    /// Прочитан ли заголовок ответа.
    response_read: bool,
    unpadder: Option<Unpadder>,
    /// Расшифрованное и распакованное, но не отданное вызывающему.
    pending: Vec<u8>,
    consumed: usize,
    /// Сырой буфер для разбора заголовка ответа.
    raw: Vec<u8>,
}

/// Состояние исходящего направления.
#[derive(Debug)]
pub struct Outbound {
    flow: Flow,
    /// Заголовок запроса, ещё не ушедший в сеть.
    prefix: Option<Vec<u8>>,
    padder: Option<Padder>,
    sniffer: Sniffer,
}

impl Inbound {
    /// Прочитать и снять заголовок ответа.
    ///
    /// Заголовок короткий — версия, длина addons и сами addons, — но
    /// может приехать не целиком: это поток, а не пакеты.
    fn read_response(&mut self, stream: &mut impl Read) -> io::Result<()> {
        let mut buf = vec![0_u8; CHUNK];
        loop {
            match Response::decode(&self.raw) {
                Ok((_, rest)) => {
                    let consumed = self.raw.len() - rest.len();
                    let payload = self.raw.split_off(consumed);
                    self.raw = payload;
                    self.response_read = true;
                    return Ok(());
                }
                Err(_) if self.raw.len() < 512 => {
                    // Не хватает байт — дочитываем. Предел на всякий
                    // случай: заголовок ответа не бывает длинным, и
                    // бесконечно копить его нельзя.
                }
                Err(error) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    ))
                }
            }

            let read = stream.read(&mut buf)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "поток закрыт до заголовка ответа",
                ));
            }
            self.raw
                .extend_from_slice(buf.get(..read).unwrap_or_default());
        }
    }

    /// Пропустить накопленные сырые байты через снятие обрамления.
    fn absorb(&mut self) -> io::Result<()> {
        let raw = core::mem::take(&mut self.raw);
        if raw.is_empty() {
            return Ok(());
        }

        match self.unpadder.as_mut() {
            None => self.pending.extend_from_slice(&raw),
            Some(unpadder) => {
                unpadder.push(&raw);
                let content = unpadder.drain().map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })?;
                self.pending.extend_from_slice(&content);
            }
        }
        Ok(())
    }

    /// Отдать вызывающему очередную порцию, дочитывая при нужде.
    fn read_from(&mut self, stream: &mut impl Read, out: &mut [u8]) -> io::Result<usize> {
        if !self.response_read {
            self.read_response(stream)?;
            self.absorb()?;
        }

        let mut buf = vec![0_u8; CHUNK];
        loop {
            if let Some(rest) = self.pending.get(self.consumed..) {
                if !rest.is_empty() {
                    let take = rest.len().min(out.len());
                    if let (Some(dst), Some(src)) = (out.get_mut(..take), rest.get(..take)) {
                        dst.copy_from_slice(src);
                    }
                    self.consumed += take;
                    return Ok(take);
                }
            }
            self.pending.clear();
            self.consumed = 0;

            let read = stream.read(&mut buf)?;
            if read == 0 {
                return Ok(0);
            }
            self.raw
                .extend_from_slice(buf.get(..read).unwrap_or_default());
            self.absorb()?;
        }
    }
}

impl Outbound {
    /// Перешло ли обрамление в прямой режим.
    fn is_direct(&self) -> bool {
        self.padder.as_ref().is_none_or(Padder::is_finished)
    }

    /// Обрамить порцию и отправить её вместе с заголовком запроса.
    fn write_to(&mut self, stream: &mut impl Write, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        // Наблюдение идёт по исходному потоку, до обрамления: нас
        // интересуют записи внутреннего TLS, а не наши собственные блоки.
        self.sniffer.observe(data);

        let mut out = self.prefix.take().unwrap_or_default();

        match self.padder.as_mut() {
            None => out.extend_from_slice(data),
            Some(padder) if padder.is_finished() => out.extend_from_slice(data),
            Some(padder) => {
                let long = self.sniffer.inside_handshake();
                let over = self.sniffer.handshake_is_over();

                let mut chunks = data.chunks(MAX_CONTENT).peekable();
                while let Some(chunk) = chunks.next() {
                    // Прямой режим объявляется последним блоком порции:
                    // после него обрамления больше не будет.
                    let command = if over && chunks.peek().is_none() {
                        vision::Command::Direct
                    } else {
                        vision::Command::Continue
                    };
                    let block = padder.wrap(chunk, command, long).map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                    })?;
                    out.extend_from_slice(&block);
                }
            }
        }

        stream.write_all(&out)?;
        Ok(data.len())
    }

    /// Дослать заголовок запроса, если он ещё не ушёл.
    fn flush_to(&mut self, stream: &mut impl Write) -> io::Result<()> {
        // Заголовок, не ушедший с данными, обязан уйти хотя бы теперь:
        // иначе сервер не узнает, куда соединяться.
        if let Some(prefix) = self.prefix.take() {
            stream.write_all(&prefix)?;
        }
        stream.flush()
    }
}

impl<S: Read + Write> Session<S> {
    /// Начать сессию: подготовить заголовок запроса.
    ///
    /// В сеть ничего не уходит до первой записи — заголовок отправится
    /// вместе с данными.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`], если заголовок не кодируется.
    pub fn connect(
        stream: S,
        uuid: [u8; 16],
        destination: Endpoint,
        flow: Flow,
    ) -> io::Result<Self> {
        let mut request = Request::tcp(uuid, destination);
        if flow != Flow::Plain {
            request = request.with_flow(flow.as_str());
        }
        let prefix = request
            .encode()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;

        let (padder, unpadder) = match flow {
            Flow::Plain => (None, None),
            Flow::Vision => (Some(Padder::new(uuid)), Some(Unpadder::new(uuid))),
        };

        Ok(Self {
            stream,
            inbound: Inbound {
                response_read: false,
                unpadder,
                pending: Vec::new(),
                consumed: 0,
                raw: Vec::new(),
            },
            outbound: Outbound {
                flow,
                prefix: Some(prefix),
                padder,
                sniffer: Sniffer::default(),
            },
        })
    }

    /// Разобрать сессию обратно на части.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Режим потока.
    #[must_use]
    pub const fn flow(&self) -> Flow {
        self.outbound.flow
    }

    /// Перешло ли обрамление в прямой режим.
    #[must_use]
    pub fn is_direct(&self) -> bool {
        self.outbound.is_direct()
    }

    /// Разъять сессию на состояния направлений и сам канал.
    ///
    /// Канал отдаётся как есть: раздвоить его умеет только вызывающий.
    /// Собрать половины помогают [`SessionReader::new`] и
    /// [`SessionWriter::new`].
    #[must_use]
    pub fn into_parts(self) -> (Inbound, Outbound, S) {
        (self.inbound, self.outbound, self.stream)
    }
}

/// Читающая половина сессии.
#[derive(Debug)]
pub struct SessionReader<R> {
    stream: R,
    inbound: Inbound,
}

impl<R: Read> SessionReader<R> {
    /// Собрать половину из канала и состояния направления.
    #[must_use]
    pub const fn new(stream: R, inbound: Inbound) -> Self {
        Self { stream, inbound }
    }
}

impl<R: Read> Read for SessionReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.inbound.read_from(&mut self.stream, out)
    }
}

/// Пишущая половина сессии.
#[derive(Debug)]
pub struct SessionWriter<W> {
    stream: W,
    outbound: Outbound,
}

impl<W: Write> SessionWriter<W> {
    /// Собрать половину из канала и состояния направления.
    #[must_use]
    pub const fn new(stream: W, outbound: Outbound) -> Self {
        Self { stream, outbound }
    }

    /// Перешло ли обрамление в прямой режим.
    #[must_use]
    pub fn is_direct(&self) -> bool {
        self.outbound.is_direct()
    }
}

impl<W: Write> Write for SessionWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.outbound.write_to(&mut self.stream, data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.outbound.flush_to(&mut self.stream)
    }
}

impl<S: Read + Write> Read for Session<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.inbound.read_from(&mut self.stream, out)
    }
}

impl<S: Read + Write> Write for Session<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.outbound.write_to(&mut self.stream, data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.outbound.flush_to(&mut self.stream)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn the_sniffer_recognises_a_tls_stream() {
        let mut sniffer = Sniffer::default();
        // ClientHello, разбитый на куски произвольной длины.
        let mut record = vec![22, 0x03, 0x01, 0x02, 0x00];
        record.extend(core::iter::repeat_n(0xaa_u8, 512));
        for chunk in record.chunks(7) {
            sniffer.observe(chunk);
        }
        assert_eq!(sniffer.looks_like_tls, Some(true));
        assert!(sniffer.inside_handshake());
        assert!(!sniffer.handshake_is_over());
    }

    #[test]
    fn the_handshake_is_over_after_two_application_records() {
        let mut sniffer = Sniffer::default();
        let mut stream = vec![22, 0x03, 0x01, 0x00, 0x04];
        stream.extend([0; 4]);
        // Finished клиента — у TLS 1.3 это уже application_data.
        stream.extend([23, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb]);
        sniffer.observe(&stream);
        assert!(!sniffer.handshake_is_over(), "одной записи мало");

        sniffer.observe(&[23, 0x03, 0x03, 0x00, 0x01, 0xcc]);
        assert!(sniffer.handshake_is_over());
        assert!(!sniffer.inside_handshake());
    }

    #[test]
    fn a_stream_that_is_not_tls_goes_direct_immediately() {
        let mut sniffer = Sniffer::default();
        sniffer.observe(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n");
        assert_eq!(sniffer.looks_like_tls, Some(false));
        assert!(
            sniffer.handshake_is_over(),
            "скрывать нечего — обрамление ни к чему"
        );
        assert!(!sniffer.inside_handshake());
    }

    #[test]
    fn record_boundaries_are_tracked_across_chunks() {
        // Заголовок, разорванный посередине, не должен сбивать счёт.
        let mut whole = Sniffer::default();
        let mut split = Sniffer::default();

        let mut stream = Vec::new();
        for _ in 0..3 {
            stream.extend([23, 0x03, 0x03, 0x00, 0x03, 1, 2, 3]);
        }
        stream.splice(0..0, [22, 0x03, 0x01, 0x00, 0x01, 9]);

        whole.observe(&stream);
        for chunk in stream.chunks(1) {
            split.observe(chunk);
        }
        assert_eq!(
            whole.application_records, split.application_records,
            "разбиение на куски не должно менять счёт"
        );
        assert_eq!(whole.application_records, 3);
    }

    #[test]
    fn a_record_longer_than_the_chunk_is_skipped_whole() {
        let mut sniffer = Sniffer::default();
        let mut stream = vec![22, 0x03, 0x01, 0x40, 0x00];
        stream.extend(core::iter::repeat_n(0_u8, 0x4000));
        stream.extend([23, 0x03, 0x03, 0x00, 0x01, 0xff]);
        sniffer.observe(&stream);
        assert_eq!(
            sniffer.application_records, 1,
            "длинная запись не должна разъезжаться по границам"
        );
    }
}

/// Принятое соединение: сессия и то, куда клиент просит соединиться.
#[derive(Debug)]
pub struct Accepted<S> {
    /// Сессия для обмена данными.
    pub session: ServerSession<S>,
    /// Идентификатор пользователя из заголовка.
    pub uuid: [u8; 16],
    /// Куда соединяться.
    pub destination: Endpoint,
}

/// Разъятая сессия точки выхода.
#[derive(Debug)]
pub struct ServerParts<S> {
    /// Нижележащий поток.
    pub stream: S,
    /// Накладывающая сторона обрамления — для ответов клиенту.
    pub padder: Option<Padder>,
    /// Снимающая сторона — для того, что приходит от клиента.
    pub unpadder: Option<Unpadder>,
    /// Уже расшифрованное, но не отданное содержимое.
    pub buffered: Vec<u8>,
    /// Заголовок ответа, если он ещё не ушёл.
    pub response: Option<Vec<u8>>,
}

/// Сессия VLESS со стороны точки выхода.
///
/// Зеркало [`Session`]: тот же заголовок, то же обрамление, только
/// читается то, что там писалось, и наоборот.
#[derive(Debug)]
pub struct ServerSession<S> {
    stream: S,
    flow: Flow,

    /// Заголовок ответа, ещё не ушедший клиенту.
    prefix: Option<Vec<u8>>,

    padder: Option<Padder>,
    unpadder: Option<Unpadder>,
    sniffer: Sniffer,

    pending: Vec<u8>,
    consumed: usize,
    raw: Vec<u8>,
}

impl<S: Read + Write> ServerSession<S> {
    /// Принять соединение: прочитать заголовок запроса.
    ///
    /// Всё, что пришло следом за заголовком, сохраняется — это уже
    /// полезная нагрузка, в VLESS она идёт сразу за заголовком без
    /// разделителя.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidData`], если заголовок не разбирается или
    /// неправдоподобно длинен; [`io::ErrorKind::UnexpectedEof`] при
    /// обрыве до конца заголовка.
    pub fn accept(mut stream: S) -> io::Result<Accepted<S>> {
        /// Предел на заголовок: версия, идентификатор, addons, адрес.
        /// Доменное имя ограничено 255 байтами, всё остальное короче.
        const MAX_HEADER: usize = 1024;

        let mut raw = Vec::new();
        let mut buf = vec![0_u8; CHUNK];

        let (request, consumed) = loop {
            match Request::decode(&raw) {
                Ok((request, rest)) => {
                    let consumed = raw.len() - rest.len();
                    break (request, consumed);
                }
                Err(error) if raw.len() >= MAX_HEADER => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    ))
                }
                Err(_) => {}
            }

            let read = stream.read(&mut buf)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "поток закрыт до конца заголовка запроса",
                ));
            }
            raw.extend_from_slice(buf.get(..read).unwrap_or_default());
        };

        let destination = request.destination.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "команде требуется адрес назначения",
            )
        })?;

        let flow = match request.addons.flow.as_deref() {
            Some("xtls-rprx-vision") => Flow::Vision,
            _ => Flow::Plain,
        };
        let (padder, unpadder) = match flow {
            Flow::Plain => (None, None),
            Flow::Vision => (
                Some(Padder::new(request.uuid)),
                Some(Unpadder::new(request.uuid)),
            ),
        };

        let mut session =
            Self {
                stream,
                flow,
                prefix: Some(Response::empty().encode().map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                })?),
                padder,
                unpadder,
                sniffer: Sniffer::default(),
                pending: Vec::new(),
                consumed: 0,
                raw: raw.get(consumed..).unwrap_or_default().to_vec(),
            };
        session.absorb()?;

        Ok(Accepted {
            session,
            uuid: request.uuid,
            destination,
        })
    }

    /// Режим потока, объявленный клиентом.
    #[must_use]
    pub const fn flow(&self) -> Flow {
        self.flow
    }

    /// Разобрать сессию обратно на части.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Разъять сессию для перекачки в двух потоках.
    ///
    /// Обрамление в разных направлениях независимо: снимающая и
    /// накладывающая стороны не делят состояния. Возвращаются
    /// нижележащий поток, обе половины обрамления, уже расшифрованный
    /// остаток и ещё не отправленный заголовок ответа.
    #[must_use]
    pub fn into_parts(self) -> ServerParts<S> {
        ServerParts {
            stream: self.stream,
            padder: self.padder,
            unpadder: self.unpadder,
            buffered: self
                .pending
                .get(self.consumed..)
                .unwrap_or_default()
                .to_vec(),
            response: self.prefix,
        }
    }

    fn absorb(&mut self) -> io::Result<()> {
        let raw = core::mem::take(&mut self.raw);
        if raw.is_empty() {
            return Ok(());
        }
        match self.unpadder.as_mut() {
            None => self.pending.extend_from_slice(&raw),
            Some(unpadder) => {
                unpadder.push(&raw);
                let content = unpadder.drain().map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })?;
                self.pending.extend_from_slice(&content);
            }
        }
        Ok(())
    }
}

impl<S: Read + Write> Read for ServerSession<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut buf = vec![0_u8; CHUNK];
        loop {
            if let Some(rest) = self.pending.get(self.consumed..) {
                if !rest.is_empty() {
                    let take = rest.len().min(out.len());
                    if let (Some(dst), Some(src)) = (out.get_mut(..take), rest.get(..take)) {
                        dst.copy_from_slice(src);
                    }
                    self.consumed += take;
                    return Ok(take);
                }
            }
            self.pending.clear();
            self.consumed = 0;

            let read = self.stream.read(&mut buf)?;
            if read == 0 {
                return Ok(0);
            }
            self.raw
                .extend_from_slice(buf.get(..read).unwrap_or_default());
            self.absorb()?;
        }
    }
}

impl<S: Read + Write> Write for ServerSession<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        self.sniffer.observe(data);

        let mut out = self.prefix.take().unwrap_or_default();
        match self.padder.as_mut() {
            None => out.extend_from_slice(data),
            Some(padder) if padder.is_finished() => out.extend_from_slice(data),
            Some(padder) => {
                let long = self.sniffer.inside_handshake();
                let over = self.sniffer.handshake_is_over();

                let mut chunks = data.chunks(MAX_CONTENT).peekable();
                while let Some(chunk) = chunks.next() {
                    let command = if over && chunks.peek().is_none() {
                        vision::Command::Direct
                    } else {
                        vision::Command::Continue
                    };
                    let block = padder.wrap(chunk, command, long).map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                    })?;
                    out.extend_from_slice(&block);
                }
            }
        }

        self.stream.write_all(&out)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(prefix) = self.prefix.take() {
            self.stream.write_all(&prefix)?;
        }
        self.stream.flush()
    }
}
