//! Поток байт поверх кадров WebSocket.
//!
//! # Зачем это отдельно от кадров
//!
//! [`Frame`] и [`Decoder`] знают про кадры и ничего не знают про
//! соединение. VLESS же — потоковый протокол: он пишет заголовок,
//! читает ответ, гоняет данные и не должен знать слова «кадр» вовсе.
//! Здесь и стоит переходник: снаружи обычные [`Read`] и [`Write`],
//! внутри — обрамление.
//!
//! # Что здесь неочевидно
//!
//! **Управляющие кадры приходят посреди данных.** `Ping` может прилететь
//! между двумя фрагментами одного сообщения, и ответить на него надо
//! **сразу**, иначе посредник сочтёт соединение мёртвым и оборвёт его.
//! Поэтому чтение умеет писать: `Read` при виде `Ping` отправляет `Pong`
//! до того, как вернёт вызывающему хоть байт.
//!
//! **Границы кадров и границы чтений — разные вещи.** Один `read` из
//! сокета может принести половину кадра, полтора кадра или двадцать
//! кадров. Ни одно из этих чисел не совпадает с тем, сколько байт
//! попросил вызывающий.
//!
//! **Сообщение бывает фрагментировано.** Cloudflare дробит большие
//! сообщения, и `Continuation` — не редкий случай, а обычный. Собирать
//! обязательно.
//!
//! # Про ограничение длины
//!
//! Объявленную длину кадра нельзя принимать на веру: узел на том конце
//! — не наш, и заявленный гигабайт мы бы честно копили в памяти, пока
//! не кончилась бы память. Отсюда [`Stream::with_limit`].

use std::io::{self, Read, Write};

use super::frame::{Decoder, Frame, Opcode};
use super::handshake::{server_response, ClientHandshake};
use crate::error::Error;

/// Сколько читать из нижнего слоя за раз.
const CHUNK: usize = 16 * 1024;

/// Предел на длину одного кадра по умолчанию.
///
/// Больше, чем любое разумное сообщение прокси, и достаточно мало,
/// чтобы враждебный узел не смог заказать нам исчерпание памяти.
pub const DEFAULT_FRAME_LIMIT: usize = 4 * 1024 * 1024;

/// Сторона соединения.
///
/// Определяет одну вещь, зато обязательную: клиент **обязан**
/// маскировать кадры, сервер — обязан не маскировать. Посредник,
/// увидевший немаскированный кадр от клиента, вправе оборвать
/// соединение, и некоторые обрывают.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Мы подключаемся.
    Client,
    /// Мы принимаем.
    Server,
}

/// Соединение WebSocket как поток байт.
#[derive(Debug)]
pub struct Stream<S> {
    inner: S,
    role: Role,
    decoder: Decoder,
    limit: usize,
    /// Разобранные данные, ещё не отданные вызывающему.
    ready: Vec<u8>,
    /// Сколько из `ready` уже отдано.
    taken: usize,
    /// Накопленные части незавершённого сообщения.
    fragment: Vec<u8>,
    /// Идёт ли сборка фрагментированного сообщения.
    assembling: bool,
    /// Пришёл `Close` — данных больше не будет.
    finished: bool,
}

impl<S: Read + Write> Stream<S> {
    /// Подключиться: провести рукопожатие и вернуть готовый поток.
    ///
    /// `host` уходит в заголовок `Host`, `path` — в строку запроса. Для
    /// Cloudflare Workers путь несёт ещё и разделение клиентов, поэтому
    /// он не украшение.
    ///
    /// # Errors
    ///
    /// Ошибка ввода-вывода или [`Error::Handshake`], если ответ не тот.
    pub fn connect(mut inner: S, host: &str, path: &str) -> io::Result<Self> {
        let rest = Self::connect_with(&ClientHandshake::new(), &mut inner, host, path)?;
        let mut stream = Self::new(inner, Role::Client);
        // Сервер вправе приклеить первый кадр к ответу, и выбросить его
        // значило бы потерять начало разговора молча.
        stream.prime(&rest);
        Ok(stream)
    }

    /// То же, но с подготовленным рукопожатием — чтобы задать
    /// `User-Agent` и прочие заголовки под стать отпечатку TLS.
    ///
    /// Возвращает байты, пришедшие **после** заголовков: сервер вправе
    /// приклеить первый кадр к ответу, и потерять его нельзя.
    ///
    /// # Errors
    ///
    /// Ошибка ввода-вывода или [`Error::Handshake`].
    pub fn connect_with(
        handshake: &ClientHandshake,
        inner: &mut S,
        host: &str,
        path: &str,
    ) -> io::Result<Vec<u8>> {
        inner.write_all(handshake.request(host, path).as_bytes())?;
        inner.flush()?;

        let mut response = Vec::new();
        let mut chunk = [0_u8; CHUNK];
        loop {
            match handshake.verify(&response) {
                Ok(consumed) => return Ok(response.split_off(consumed)),
                Err(Error::Incomplete) => {}
                Err(error) => return Err(error.into()),
            }

            let read = inner.read(&mut chunk)?;
            if read == 0 {
                return Err(io::Error::from(Error::Handshake(
                    "соединение закрыто до конца рукопожатия",
                )));
            }
            response.extend_from_slice(chunk.get(..read).unwrap_or_default());

            // Заголовки без конца — тоже способ исчерпать память.
            if response.len() > DEFAULT_FRAME_LIMIT {
                return Err(io::Error::from(Error::Handshake(
                    "ответ на рукопожатие неправдоподобно длинный",
                )));
            }
        }
    }

    /// Принять соединение: прочитать запрос и ответить на него.
    ///
    /// Нужно своей точке выхода и проверкам. Возвращает поток и путь, о
    /// котором просил клиент, — по нему точка выхода различает своих.
    ///
    /// # Errors
    ///
    /// Ошибка ввода-вывода или [`Error::Handshake`], если запрос не тот.
    pub fn accept(mut inner: S) -> io::Result<(Self, String)> {
        let mut request = Vec::new();
        let mut chunk = [0_u8; CHUNK];
        let head_end = loop {
            if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break at;
            }
            let read = inner.read(&mut chunk)?;
            if read == 0 {
                return Err(io::Error::from(Error::Handshake(
                    "соединение закрыто до конца запроса",
                )));
            }
            request.extend_from_slice(chunk.get(..read).unwrap_or_default());
            if request.len() > DEFAULT_FRAME_LIMIT {
                return Err(io::Error::from(Error::Handshake(
                    "запрос неправдоподобно длинный",
                )));
            }
        };

        let head = core::str::from_utf8(request.get(..head_end).unwrap_or_default())
            .map_err(|_| io::Error::from(Error::Handshake("заголовки запроса не в UTF-8")))?;
        let mut lines = head.split("\r\n");

        let target = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| io::Error::from(Error::Handshake("не разбирается строка запроса")))?
            .to_owned();

        let mut key = None;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("sec-websocket-key") {
                    key = Some(value.trim().to_owned());
                }
            }
        }
        let key = key
            .ok_or_else(|| io::Error::from(Error::Handshake("в запросе нет Sec-WebSocket-Key")))?;

        inner.write_all(server_response(&key).as_bytes())?;
        inner.flush()?;

        let mut stream = Self::new(inner, Role::Server);
        // Клиент вправе приклеить первый кадр к запросу.
        let rest = request.split_off(head_end + 4);
        stream.decoder.push(&rest);
        Ok((stream, target))
    }

    /// Собрать поток поверх уже согласованного соединения.
    #[must_use]
    pub fn new(inner: S, role: Role) -> Self {
        Self {
            inner,
            role,
            decoder: Decoder::new(),
            limit: DEFAULT_FRAME_LIMIT,
            ready: Vec::new(),
            taken: 0,
            fragment: Vec::new(),
            assembling: false,
            finished: false,
        }
    }

    /// Задать предел на длину одного кадра.
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Добавить байты, прочитанные до передачи потока сюда.
    ///
    /// Так не теряется кадр, приклеенный к ответу на рукопожатие.
    pub fn prime(&mut self, bytes: &[u8]) {
        self.decoder.push(bytes);
    }

    /// Отправить `Close` и попрощаться.
    ///
    /// # Errors
    ///
    /// Ошибка ввода-вывода.
    pub fn close(&mut self) -> io::Result<()> {
        let frame = Frame {
            fin: true,
            opcode: Opcode::Close,
            // Код 1000 — «нормальное закрытие». Пустой `Close` тоже
            // законен, но некоторые посредники считают его обрывом.
            payload: 1000_u16.to_be_bytes().to_vec(),
        };
        self.send(&frame)?;
        self.inner.flush()
    }

    /// Вернуть нижний слой.
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn send(&mut self, frame: &Frame) -> io::Result<()> {
        let encoded = match self.role {
            Role::Client => frame.encode_masked(),
            Role::Server => frame.encode_unmasked(),
        }
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        self.inner.write_all(&encoded)
    }

    /// Разобрать всё, что уже лежит в сборщике, в `ready`.
    ///
    /// Возвращает `true`, если появились данные или соединение закрыто, —
    /// то есть если звать нижний слой снова незачем.
    fn drain(&mut self) -> io::Result<bool> {
        loop {
            if self.decoder.pending() > self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "кадр длиннее допустимого",
                ));
            }

            let frame = match self.decoder.next_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => return Ok(!self.ready.is_empty() || self.finished),
                Err(error) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    ))
                }
            };

            match frame.opcode {
                // Ответить обязаны немедленно: посредник, не получивший
                // `Pong`, считает соединение мёртвым.
                Opcode::Ping => {
                    self.send(&Frame::pong(frame.payload))?;
                    self.inner.flush()?;
                }
                Opcode::Pong => {}
                Opcode::Close => {
                    self.finished = true;
                    return Ok(true);
                }
                Opcode::Binary | Opcode::Text => {
                    if self.assembling {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "новое сообщение посреди фрагментированного",
                        ));
                    }
                    if frame.fin {
                        self.ready.extend_from_slice(&frame.payload);
                    } else {
                        self.fragment = frame.payload;
                        self.assembling = true;
                    }
                }
                Opcode::Continuation => {
                    if !self.assembling {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "продолжение без начала сообщения",
                        ));
                    }
                    self.fragment.extend_from_slice(&frame.payload);
                    if self.fragment.len() > self.limit {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "собранное сообщение длиннее допустимого",
                        ));
                    }
                    if frame.fin {
                        self.ready.append(&mut self.fragment);
                        self.assembling = false;
                    }
                }
            }
        }
    }
}

impl<S: Read + Write> Read for Stream<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            let left = self.ready.len() - self.taken;
            if left > 0 {
                let take = left.min(out.len());
                let from = self.taken;
                out.get_mut(..take)
                    .zip(self.ready.get(from..from + take))
                    .map(|(dst, src)| dst.copy_from_slice(src))
                    .ok_or_else(|| io::Error::other("нарушен учёт готовых байт"))?;
                self.taken += take;
                if self.taken == self.ready.len() {
                    self.ready.clear();
                    self.taken = 0;
                }
                return Ok(take);
            }

            if self.finished {
                return Ok(0);
            }

            // Сначала разобрать то, что уже лежит, и только потом идти в
            // нижний слой. Обратный порядок означал бы ожидание новых
            // байт при готовом кадре в буфере — то есть зависание на
            // ровном месте. Так и было: кадр, приклеенный к ответу на
            // рукопожатие, ждал бы следующего сообщения от сервера,
            // которого сервер не пошлёт, пока не получит наш запрос.
            if self.drain()? {
                continue;
            }

            let mut chunk = [0_u8; CHUNK];
            let read = self.inner.read(&mut chunk)?;
            if read == 0 {
                // Обрыв без `Close`. Для потока это конец данных, а не
                // ошибка: у прокси так заканчивается почти всякое
                // соединение.
                self.finished = true;
                return Ok(0);
            }
            self.decoder.push(chunk.get(..read).unwrap_or_default());
            self.drain()?;
        }
    }
}

impl<S: Read + Write> Write for Stream<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        // Одно обращение — один кадр. Дробить самим незачем: и TLS, и
        // TCP ниже разложат как надо, а лишние заголовки кадров только
        // добавили бы приметности.
        self.send(&Frame::binary(data.to_vec()))?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::sync::mpsc::{channel, Receiver, Sender};

    /// Двусторонняя труба: то, что записано с одной стороны, читается с
    /// другой. Нужна, чтобы гонять настоящее соединение без сети.
    #[derive(Debug)]
    struct Pipe {
        outgoing: Sender<Vec<u8>>,
        incoming: Receiver<Vec<u8>>,
        buffered: Vec<u8>,
        taken: usize,
    }

    impl Pipe {
        fn duplex() -> (Self, Self) {
            let (left_tx, left_rx) = channel();
            let (right_tx, right_rx) = channel();
            (
                Self {
                    outgoing: left_tx,
                    incoming: right_rx,
                    buffered: Vec::new(),
                    taken: 0,
                },
                Self {
                    outgoing: right_tx,
                    incoming: left_rx,
                    buffered: Vec::new(),
                    taken: 0,
                },
            )
        }
    }

    impl Read for Pipe {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.taken == self.buffered.len() {
                match self.incoming.recv() {
                    Ok(next) => {
                        self.buffered = next;
                        self.taken = 0;
                    }
                    // Другая сторона отпущена — это конец потока.
                    Err(_) => return Ok(0),
                }
            }
            let take = (self.buffered.len() - self.taken).min(out.len());
            out[..take].copy_from_slice(&self.buffered[self.taken..self.taken + take]);
            self.taken += take;
            Ok(take)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.outgoing
                .send(data.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "труба закрыта"))?;
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Пара согласованных потоков без рукопожатия — для проверок,
    /// которым важно обрамление, а не установка соединения.
    fn pair() -> (Stream<Pipe>, Stream<Pipe>) {
        let (a, b) = Pipe::duplex();
        (Stream::new(a, Role::Client), Stream::new(b, Role::Server))
    }

    #[test]
    fn a_handshake_puts_both_sides_into_frames() {
        let (client_pipe, server_pipe) = Pipe::duplex();

        let server = std::thread::spawn(move || {
            let (mut stream, target) = Stream::accept(server_pipe).expect("рукопожатие принято");
            let mut got = [0_u8; 64];
            let read = stream.read(&mut got).expect("чтение");
            stream.write_all("ответ".as_bytes()).expect("запись");
            (target, got[..read].to_vec())
        });

        let mut client =
            Stream::connect(client_pipe, "worker.example.workers.dev", "/tunnel").expect("connect");
        client.write_all("запрос VLESS".as_bytes()).expect("запись");

        let mut back = [0_u8; 64];
        let read = client.read(&mut back).expect("чтение ответа");
        assert_eq!(&back[..read], "ответ".as_bytes());

        let (target, got) = server.join().expect("поток сервера");
        assert_eq!(target, "/tunnel", "путь обязан дойти до точки выхода");
        assert_eq!(got, "запрос VLESS".as_bytes());
    }

    // Кадры от клиента обязаны быть маскированы. Посредники, включая
    // Cloudflare, вправе оборвать соединение, увидев обратное.
    #[test]
    fn the_client_masks_and_the_server_does_not() {
        let (mut client, mut server) = pair();
        client.write_all("раз".as_bytes()).expect("запись клиента");
        server.write_all("два".as_bytes()).expect("запись сервера");

        let mut probe = [0_u8; 16];
        let read = server.read(&mut probe).expect("сервер читает");
        assert_eq!(&probe[..read], "раз".as_bytes());

        // Проверка самих байт на проводе: бит маски — старший во втором
        // байте заголовка.
        let masked = Frame::binary("раз".as_bytes().to_vec())
            .encode_masked()
            .unwrap();
        let plain = Frame::binary("раз".as_bytes().to_vec())
            .encode_unmasked()
            .unwrap();
        assert_eq!(
            masked[1] & 0x80,
            0x80,
            "клиентский кадр обязан быть маскирован"
        );
        assert_eq!(plain[1] & 0x80, 0x00, "серверный кадр обязан быть открытым");
    }

    // Ровно тот случай, ради которого чтение умеет писать.
    #[test]
    fn a_ping_is_answered_before_data_is_returned() {
        let (mut client, mut server) = pair();

        server
            .send(&Frame::ping("жив?".as_bytes().to_vec()))
            .expect("ping");
        server
            .write_all("данные".as_bytes())
            .expect("данные следом");

        let mut got = [0_u8; 32];
        let read = client.read(&mut got).expect("чтение");
        assert_eq!(&got[..read], "данные".as_bytes());

        // Ответ обязан уже лежать в трубе.
        let mut back = [0_u8; 32];
        let read = server.inner.read(&mut back).expect("сервер читает ответ");
        let mut decoder = Decoder::new();
        decoder.push(&back[..read]);
        let frame = decoder.next_frame().expect("кадр").expect("есть кадр");
        assert_eq!(frame.opcode, Opcode::Pong);
        assert_eq!(frame.payload, "жив?".as_bytes());
    }

    // Cloudflare дробит большие сообщения, поэтому продолжение — не
    // экзотика, а обычный ход событий.
    #[test]
    fn a_fragmented_message_is_reassembled() {
        let (mut client, mut server) = pair();

        server
            .send(&Frame {
                fin: false,
                opcode: Opcode::Binary,
                payload: "нача".as_bytes().to_vec(),
            })
            .expect("первый фрагмент");
        server
            .send(&Frame {
                fin: false,
                opcode: Opcode::Continuation,
                payload: "ло и ".as_bytes().to_vec(),
            })
            .expect("середина");
        // Управляющий кадр посреди фрагментов — законно по RFC 6455.
        server.send(&Frame::ping(Vec::new())).expect("ping внутри");
        server
            .send(&Frame {
                fin: true,
                opcode: Opcode::Continuation,
                payload: "конец".as_bytes().to_vec(),
            })
            .expect("хвост");

        let mut got = Vec::new();
        let mut chunk = [0_u8; 8];
        while got.len() < "начало и конец".len() {
            let read = client.read(&mut chunk).expect("чтение");
            assert_ne!(read, 0, "поток кончился раньше сообщения");
            got.extend_from_slice(&chunk[..read]);
        }
        assert_eq!(String::from_utf8(got).unwrap(), "начало и конец");
    }

    // Границы кадров и границы чтений не совпадают никогда. Читатель,
    // который считает одно чтение одним кадром, разваливается именно
    // здесь.
    #[test]
    fn frame_boundaries_do_not_leak_into_reads() {
        let (mut client, mut server) = pair();
        for part in ["один", "два", "три"] {
            server.write_all(part.as_bytes()).expect("запись");
        }

        let mut got = Vec::new();
        let mut chunk = [0_u8; 3];
        while got.len() < "одиндватри".len() {
            let read = client.read(&mut chunk).expect("чтение");
            assert_ne!(read, 0);
            got.extend_from_slice(&chunk[..read]);
        }
        assert_eq!(String::from_utf8(got).unwrap(), "одиндватри");
    }

    #[test]
    fn a_close_frame_ends_the_stream() {
        let (mut client, mut server) = pair();
        server.write_all("последнее".as_bytes()).expect("запись");
        server.close().expect("закрытие");

        let mut got = [0_u8; 32];
        let read = client.read(&mut got).expect("данные до закрытия");
        assert_eq!(&got[..read], "последнее".as_bytes());
        assert_eq!(client.read(&mut got).expect("после закрытия"), 0);
    }

    // Обрыв без `Close` — обычное завершение для прокси, а не ошибка.
    #[test]
    fn a_silent_disconnect_is_end_of_stream_not_an_error() {
        let (mut client, server) = pair();
        drop(server);
        let mut got = [0_u8; 16];
        assert_eq!(client.read(&mut got).expect("обрыв не ошибка"), 0);
    }

    // Узел на том конце не наш. Заявленную длину нельзя копить на веру.
    #[test]
    fn an_oversized_frame_is_refused_instead_of_buffered() {
        let (mut client, mut server) = pair();
        client = client.with_limit(64);

        server.write_all(&vec![0_u8; 4096]).expect("большой кадр");

        let mut got = [0_u8; 16];
        let error = client.read(&mut got).expect_err("должно быть отказом");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_continuation_without_a_start_is_refused() {
        let (mut client, mut server) = pair();
        server
            .send(&Frame {
                fin: true,
                opcode: Opcode::Continuation,
                payload: "ниоткуда".as_bytes().to_vec(),
            })
            .expect("отправка");

        let mut got = [0_u8; 16];
        let error = client.read(&mut got).expect_err("должно быть отказом");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    // Ответ на рукопожатие и первый кадр приходят одним куском чаще, чем
    // кажется: так делает всякий сервер, который не ждёт лишнего обмена.
    // Проверяется и то, что `connect` не теряет довесок сам: сервер
    // вправе прислать ответ и первый кадр одним куском.
    #[test]
    fn connect_does_not_drop_a_frame_glued_to_the_response() {
        let (client_pipe, server_pipe) = Pipe::duplex();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = Stream::accept(server_pipe).expect("рукопожатие");
            stream.write_all("сразу".as_bytes()).expect("первый кадр");
            stream
        });

        let mut client =
            Stream::connect(client_pipe, "worker.example.workers.dev", "/t").expect("connect");
        let mut got = [0_u8; 32];
        let read = client.read(&mut got).expect("чтение");
        assert_eq!(&got[..read], "сразу".as_bytes());
        drop(server.join().expect("поток сервера"));
    }

    #[test]
    fn a_frame_glued_to_the_handshake_is_not_lost() {
        let handshake = ClientHandshake::new();
        let mut wire = server_response(handshake.key()).into_bytes();
        wire.extend_from_slice(
            &Frame::binary("первый".as_bytes().to_vec())
                .encode_unmasked()
                .unwrap(),
        );

        let (mut client_pipe, mut server_pipe) = Pipe::duplex();
        server_pipe.write_all(&wire).expect("ответ с довеском");

        let rest = Stream::connect_with(
            &handshake,
            &mut client_pipe,
            "worker.example.workers.dev",
            "/t",
        )
        .expect("рукопожатие");
        assert!(!rest.is_empty(), "кадр после заголовков обязан вернуться");

        let mut client = Stream::new(client_pipe, Role::Client);
        client.prime(&rest);
        let mut got = [0_u8; 16];
        let read = client.read(&mut got).expect("чтение приклеенного кадра");
        assert_eq!(&got[..read], "первый".as_bytes());
    }

    #[test]
    fn a_refused_upgrade_is_reported_as_a_handshake_error() {
        let (client_pipe, mut server_pipe) = Pipe::duplex();
        server_pipe
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
            .expect("отказ сервера");

        let error = Stream::connect(client_pipe, "worker.example.workers.dev", "/t")
            .expect_err("должно быть отказом");
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "отказ обязан быть про содержание ответа, а не про ввод-вывод"
        );
        assert!(
            error.to_string().contains("рукопожатие"),
            "причина обязана дожить до вызывающего: {error}"
        );
        let _ = &mut server_pipe;
    }
}
