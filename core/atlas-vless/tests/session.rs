//! Сквозной круг сессии VLESS против встречной стороны.
//!
//! Проверяется то, что до сих пор существовало порознь: заголовок
//! запроса уходит вместе с первой порцией данных, обрамление Vision
//! снимается, поток переключается в прямой режим и данные ходят в обе
//! стороны.

// Вход теста — байты, которые он же и породил.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::cell::RefCell;
use std::io::{Read, Write};
use std::rc::Rc;

use atlas_vless::session::{Flow, Session};
use atlas_vless::vision::{self, Padder, Unpadder};
use atlas_vless::{Address, Endpoint, Request, Response};

const UUID: [u8; 16] = [0x5a; 16];

/// Одно направление канала.
#[derive(Clone, Default)]
struct Wire(Rc<RefCell<Vec<u8>>>);

impl Wire {
    fn take(&self) -> Vec<u8> {
        core::mem::take(&mut self.0.borrow_mut())
    }
    fn put(&self, data: &[u8]) {
        self.0.borrow_mut().extend_from_slice(data);
    }
    fn len(&self) -> usize {
        self.0.borrow().len()
    }
}

/// Двусторонний канал в памяти.
struct Pipe {
    inbox: Wire,
    outbox: Wire,
}

impl Read for Pipe {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut inbox = self.inbox.0.borrow_mut();
        if inbox.is_empty() {
            return Ok(0);
        }
        let take = inbox.len().min(out.len());
        out[..take].copy_from_slice(&inbox[..take]);
        inbox.drain(..take);
        Ok(take)
    }
}

impl Write for Pipe {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.outbox.put(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Встречная сторона: точка выхода, разбирающая поток клиента.
struct ExitPoint {
    request: Option<Request>,
    unpadder: Unpadder,
    padder: Padder,
    responded: bool,
    /// Всё, что клиент прислал в качестве полезной нагрузки.
    received: Vec<u8>,
}

impl ExitPoint {
    fn new() -> Self {
        Self {
            request: None,
            unpadder: Unpadder::new(UUID),
            padder: Padder::new(UUID),
            responded: false,
            received: Vec::new(),
        }
    }

    /// Принять всё, что клиент успел написать.
    fn absorb(&mut self, up: &Wire) {
        let mut data = up.take();
        if data.is_empty() {
            return;
        }

        if self.request.is_none() {
            let (request, tail) = Request::decode(&data).expect("заголовок запроса");
            let rest: Vec<u8> = tail.to_vec();
            self.request = Some(request);
            data = rest;
        }

        self.unpadder.push(&data);
        let content = self.unpadder.drain().expect("снятие обрамления");
        self.received.extend_from_slice(&content);
    }

    /// Ответить клиенту.
    fn reply(&mut self, down: &Wire, payload: &[u8], command: vision::Command) {
        let mut out = Vec::new();
        if !self.responded {
            out.extend(Response::empty().encode().expect("заголовок ответа"));
            self.responded = true;
        }
        if self.padder.is_finished() {
            out.extend_from_slice(payload);
        } else {
            out.extend(
                self.padder
                    .wrap(payload, command, false)
                    .expect("обрамление ответа"),
            );
        }
        down.put(&out);
    }
}

fn endpoint() -> Endpoint {
    Endpoint::new(Address::Domain("example.org".to_owned()), 443)
}

/// Правдоподобная запись внутреннего TLS заданного типа и длины.
fn record(kind: u8, len: usize) -> Vec<u8> {
    let mut out = vec![kind, 0x03, if kind == 22 { 0x01 } else { 0x03 }];
    out.extend(u16::try_from(len).unwrap().to_be_bytes());
    out.extend(core::iter::repeat_n(0xab_u8, len));
    out
}

#[test]
fn the_request_header_travels_with_the_first_payload() {
    // Отдельный крошечный пакет перед данными — сам по себе признак.
    let up = Wire::default();
    let down = Wire::default();
    let mut client = Session::connect(
        Pipe {
            inbox: down.clone(),
            outbox: up.clone(),
        },
        UUID,
        endpoint(),
        Flow::Vision,
    )
    .unwrap();

    assert_eq!(up.len(), 0, "до первой записи в сеть ничего не уходит");

    client.write_all(&record(22, 300)).unwrap();
    assert!(up.len() > 0);

    let mut exit = ExitPoint::new();
    exit.absorb(&up);
    let request = exit.request.as_ref().unwrap();
    assert_eq!(request.uuid, UUID);
    assert_eq!(request.destination.as_ref(), Some(&endpoint()));
    assert_eq!(
        request.addons.flow.as_deref(),
        Some("xtls-rprx-vision"),
        "режим потока обязан быть объявлен в заголовке"
    );
    assert_eq!(exit.received, record(22, 300));
}

#[test]
fn payload_survives_the_round_trip_in_both_directions() {
    let up = Wire::default();
    let down = Wire::default();
    let mut client = Session::connect(
        Pipe {
            inbox: down.clone(),
            outbox: up.clone(),
        },
        UUID,
        endpoint(),
        Flow::Vision,
    )
    .unwrap();
    let mut exit = ExitPoint::new();

    let outbound = record(22, 700);
    client.write_all(&outbound).unwrap();
    exit.absorb(&up);
    assert_eq!(exit.received, outbound);

    exit.reply(&down, b"otvet servera", vision::Command::Continue);
    let mut buf = [0_u8; 64];
    let read = client.read(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"otvet servera");
}

#[test]
fn padding_hides_the_length_of_the_inner_handshake() {
    // Смысл Vision: длина блока не должна зависеть от длины содержимого.
    let mut lengths = std::collections::HashSet::new();

    for content in [40_usize, 300, 700, 850] {
        let up = Wire::default();
        let down = Wire::default();
        let mut client = Session::connect(
            Pipe {
                inbox: down,
                outbox: up.clone(),
            },
            UUID,
            endpoint(),
            Flow::Vision,
        )
        .unwrap();

        client.write_all(&record(22, content)).unwrap();
        // Вычитаем заголовок запроса: он одинаков и к обрамлению
        // отношения не имеет.
        let header = Request::tcp(UUID, endpoint())
            .with_flow("xtls-rprx-vision")
            .encode()
            .unwrap()
            .len();
        lengths.insert(up.len() - header);
    }

    // Все четыре блока обязаны попасть в один узкий диапазон, заданный
    // только шумом дополнения, а не размером содержимого.
    let min = lengths.iter().min().copied().unwrap();
    let max = lengths.iter().max().copied().unwrap();
    assert!(
        max - min <= 500,
        "разброс {} байт при содержимом от 40 до 850 — дополнение не работает",
        max - min
    );
}

#[test]
fn the_stream_switches_to_direct_once_the_inner_handshake_is_over() {
    let up = Wire::default();
    let down = Wire::default();
    let mut client = Session::connect(
        Pipe {
            inbox: down.clone(),
            outbox: up.clone(),
        },
        UUID,
        endpoint(),
        Flow::Vision,
    )
    .unwrap();
    let mut exit = ExitPoint::new();

    // Внутреннее рукопожатие TLS 1.3 глазами клиента.
    client.write_all(&record(22, 1500)).unwrap(); // ClientHello
    assert!(!client.is_direct());
    client.write_all(&record(23, 50)).unwrap(); // Finished клиента
    assert!(!client.is_direct(), "одной записи мало");

    client.write_all(&record(23, 200)).unwrap(); // первые данные
    assert!(
        client.is_direct(),
        "рукопожатие позади — обрамление ни к чему"
    );

    exit.absorb(&up);
    let mut expected = record(22, 1500);
    expected.extend(record(23, 50));
    expected.extend(record(23, 200));
    assert_eq!(exit.received, expected);

    // После перехода данные идут без обрамления — и всё равно доходят.
    client.write_all(b"posle perehoda").unwrap();
    exit.absorb(&up);
    expected.extend_from_slice(b"posle perehoda");
    assert_eq!(exit.received, expected);
}

#[test]
fn a_plain_flow_adds_nothing_at_all() {
    let up = Wire::default();
    let down = Wire::default();
    let mut client = Session::connect(
        Pipe {
            inbox: down.clone(),
            outbox: up.clone(),
        },
        UUID,
        endpoint(),
        Flow::Plain,
    )
    .unwrap();

    client.write_all(b"rovno eti bajty").unwrap();
    let sent = up.take();
    let header = Request::tcp(UUID, endpoint()).encode().unwrap();
    assert_eq!(sent, [header.as_slice(), b"rovno eti bajty"].concat());

    // И в обратную сторону — без обрамления.
    down.put(&Response::empty().encode().unwrap());
    down.put(b"otvet");
    let mut buf = [0_u8; 32];
    let read = client.read(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"otvet");
}

#[test]
fn a_large_write_is_split_into_blocks_and_reassembled() {
    let up = Wire::default();
    let down = Wire::default();
    let mut client = Session::connect(
        Pipe {
            inbox: down,
            outbox: up.clone(),
        },
        UUID,
        endpoint(),
        Flow::Vision,
    )
    .unwrap();
    let mut exit = ExitPoint::new();

    // Заведомо больше предельного размера блока Vision.
    let payload: Vec<u8> = (0..40_000_u32).map(|i| (i % 251) as u8).collect();
    client.write_all(&payload).unwrap();
    exit.absorb(&up);
    assert_eq!(exit.received, payload);
}

#[test]
fn the_response_header_may_arrive_in_pieces() {
    // Это поток, а не пакеты: заголовок ответа вправе приехать
    // по одному байту.
    let up = Wire::default();
    let down = Wire::default();
    let mut client = Session::connect(
        Pipe {
            inbox: down.clone(),
            outbox: up,
        },
        UUID,
        endpoint(),
        Flow::Plain,
    )
    .unwrap();

    let mut stream = Response::empty().encode().unwrap();
    stream.extend_from_slice(b"payload");

    let mut got = Vec::new();
    let mut buf = [0_u8; 8];
    for byte in stream {
        down.put(&[byte]);
        if let Ok(read) = client.read(&mut buf) {
            got.extend_from_slice(&buf[..read]);
        }
    }
    assert_eq!(got, b"payload");
}

#[test]
fn a_flush_without_data_still_sends_the_header() {
    // Иначе точка выхода не узнает, куда соединяться.
    let up = Wire::default();
    let down = Wire::default();
    let mut client = Session::connect(
        Pipe {
            inbox: down,
            outbox: up.clone(),
        },
        UUID,
        endpoint(),
        Flow::Plain,
    )
    .unwrap();

    client.flush().unwrap();
    let sent = up.take();
    let (request, rest) = Request::decode(&sent).unwrap();
    assert_eq!(request.destination.as_ref(), Some(&endpoint()));
    assert!(rest.is_empty(), "кроме заголовка ничего не ушло");
}
