//! Согласие двух реализаций одного протокола.
//!
//! Сквозной канал описан дважды: на Rust — в `src/edge.rs`, на
//! JavaScript — в `clients/worker/src/edge.js`. Иначе нельзя: клиент
//! живёт на телефоне, край — внутри Cloudflare Workers, и общего кода у
//! них быть не может.
//!
//! Два описания одного протокола расходятся всегда. Вопрос лишь в том,
//! узнаем ли мы об этом от сборки или от человека, у которого «просто
//! не подключается». Поэтому здесь настоящий разговор: Rust начинает
//! согласование, узел его продолжает, и обе стороны обязаны прийти к
//! одним ключам.
//!
//! # Почему узел живёт всё время разговора
//!
//! Ключи сессии появляются только **после** ответа края: до него
//! клиенту нечем шифровать. Одноразовый запуск узла этого не
//! выдерживает — эфемерная доля края умерла бы вместе с процессом.
//! Поэтому узел поднимается один раз и общается построчно, как
//! настоящий собеседник.
//!
//! # Почему проверка обязана быть перекрёстной
//!
//! Каждая сторона, проверенная сама с собой, доказывает лишь
//! внутреннюю согласованность. Два разных неверных вывода ключа так и
//! остались бы незамеченными: оба набора прошли бы, а соединения не
//! было бы.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use atlas_transport::edge::{Handshake, CLOCK_SKEW_SECS, SECRET_LEN};

/// Секрет и время закреплены: проверяется согласие реализаций, а не
/// работа генератора случайных чисел.
const SECRET: [u8; SECRET_LEN] = [
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
];
const NOW: u64 = 1_800_000_000;

fn unique() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Vec<u8> {
    text.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Край, поднятый узлом и отвечающий построчно.
struct Edge {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    scratch: std::path::PathBuf,
}

impl Edge {
    /// Поднять край с заданным секретом и часами.
    fn start(secret: &[u8; SECRET_LEN], now: u64) -> Self {
        let module = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../clients/worker/src/edge.js")
            .canonicalize()
            .expect("сторона края на JavaScript обязана лежать рядом с проектом");

        // Разговор построчный: команда и шестнадцатеричные байты. Ответ
        // — одна строка. Отказ — строка, начинающаяся с `ОТКАЗ`, чтобы
        // проверяемый отказ не выглядел как поломка самого узла.
        let program = format!(
            r#"
import {{ respond }} from {module:?};
import {{ createInterface }} from "node:readline";

const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const unhex = (a) => [...a].map((b) => b.toString(16).padStart(2, "0")).join("");

const secret = hex("{secret}");
let session = null;

const lines = createInterface({{ input: process.stdin }});
for await (const line of lines) {{
    const [command, payload] = line.trim().split(" ");
    try {{
        if (command === "hello") {{
            const result = await respond(secret, hex(payload), {now});
            session = result.session;
            console.log(unhex(result.response));
        }} else if (command === "open") {{
            const record = hex(payload);
            const opened = await session.open(record.slice(0, 2), record.slice(2));
            console.log(unhex(opened));
        }} else if (command === "seal") {{
            console.log(unhex(await session.seal(hex(payload))));
        }} else if (command === "quit") {{
            break;
        }} else {{
            console.log("ОТКАЗ неизвестная команда");
        }}
    }} catch (error) {{
        console.log("ОТКАЗ " + error.message);
    }}
}}
"#,
            module = module,
            secret = to_hex(secret),
            now = now,
        );

        let scratch = std::env::temp_dir().join(format!("atlas-edge-{}.mjs", unique()));
        std::fs::write(&scratch, program).unwrap();

        let mut child = Command::new("node")
            .arg(&scratch)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("узел обязан запускаться");

        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            scratch,
        }
    }

    /// Отправить команду и забрать одну строку ответа.
    fn ask(&mut self, command: &str, payload: &[u8]) -> String {
        writeln!(self.stdin, "{command} {}", to_hex(payload)).unwrap();
        self.stdin.flush().unwrap();

        let mut line = String::new();
        let read = self.stdout.read_line(&mut line).unwrap();
        assert_ne!(read, 0, "край умолк, не ответив на «{command}»");
        line.trim().to_owned()
    }

    /// Ответ, который обязан быть удачным.
    fn expect_bytes(&mut self, command: &str, payload: &[u8]) -> Vec<u8> {
        let line = self.ask(command, payload);
        assert!(
            !line.starts_with("ОТКАЗ"),
            "край отказал на «{command}»: {line}"
        );
        from_hex(&line)
    }
}

impl Drop for Edge {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit ");
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.scratch);
    }
}

/// Главное: обе стороны приходят к одним ключам и понимают записи друг
/// друга — в обе стороны.
#[test]
fn rust_and_javascript_agree_on_the_whole_channel() {
    let mut edge = Edge::start(&SECRET, NOW);

    let (handshake, hello) = Handshake::start(&SECRET, NOW);
    let response = edge.expect_bytes("hello", &hello);
    let mut client = handshake
        .finish(&response)
        .expect("клиент обязан принять ответ края: отпечаток считается одинаково");

    // Клиент → край.
    let record = client.seal("привет краю".as_bytes()).expect("шифрование");
    let opened = edge.expect_bytes("open", &record);
    assert_eq!(
        String::from_utf8(opened).unwrap(),
        "привет краю",
        "край не расшифровал запись клиента: ключи разошлись"
    );

    // Край → клиент.
    let reply = edge.expect_bytes("seal", "привет клиенту".as_bytes());
    let opened = client
        .open([reply[0], reply[1]], &reply[2..])
        .expect("клиент обязан открыть запись края");
    assert_eq!(String::from_utf8(opened).unwrap(), "привет клиенту");

    // Счётчики обязаны идти в ногу: вторая запись открывается только
    // если обе стороны увеличили номер одинаково.
    let second = client.seal("вторая".as_bytes()).expect("шифрование");
    assert_eq!(
        String::from_utf8(edge.expect_bytes("open", &second)).unwrap(),
        "вторая",
        "счётчики записей разошлись после первой"
    );
}

/// Длинная запись — та, где длина перестаёт помещаться в один байт и
/// заголовок начинает иметь значение.
#[test]
fn a_long_record_survives_the_crossing() {
    let mut edge = Edge::start(&SECRET, NOW);
    let (handshake, hello) = Handshake::start(&SECRET, NOW);
    let response = edge.expect_bytes("hello", &hello);
    let mut client = handshake.finish(&response).expect("согласование");

    let payload: Vec<u8> = (0..4096_u32).map(|i| (i % 251) as u8).collect();
    let record = client.seal(&payload).expect("шифрование");
    assert_eq!(
        edge.expect_bytes("open", &record),
        payload,
        "длинная запись пересекла границу реализаций с потерями"
    );
}

/// Посторонний без секрета не проходит и на стороне JavaScript — так
/// же, как не проходит на стороне Rust.
#[test]
fn javascript_refuses_a_hello_without_the_secret() {
    let mut edge = Edge::start(&SECRET, NOW);
    let (_, hello) = Handshake::start(&[9; SECRET_LEN], NOW);
    let line = edge.ask("hello", &hello);
    assert!(
        line.starts_with("ОТКАЗ"),
        "край обязан отвергнуть чужой секрет, а он ответил: {line}"
    );
}

/// Окно допуска часов обязано быть одинаковым: реализация, оказавшаяся
/// щедрее, продлевала бы срок годности перехваченного приветствия.
#[test]
fn both_sides_use_the_same_clock_window() {
    let (_, hello) = Handshake::start(&SECRET, NOW);

    // Ровно на границе — принимают обе.
    let mut on_edge = Edge::start(&SECRET, NOW + CLOCK_SKEW_SECS);
    let line = on_edge.ask("hello", &hello);
    assert!(
        !line.starts_with("ОТКАЗ"),
        "на границе окна край обязан принять, а он ответил: {line}"
    );
    assert!(
        atlas_transport::edge::respond(&SECRET, &hello, NOW + CLOCK_SKEW_SECS).is_ok(),
        "на границе окна сторона Rust обязана принять"
    );

    // На шаг дальше — отказывают обе.
    let mut past = Edge::start(&SECRET, NOW + CLOCK_SKEW_SECS + 1);
    let line = past.ask("hello", &hello);
    assert!(
        line.starts_with("ОТКАЗ"),
        "за границей окна край обязан отказать, а он ответил: {line}"
    );
    assert!(
        atlas_transport::edge::respond(&SECRET, &hello, NOW + CLOCK_SKEW_SECS + 1).is_err(),
        "за границей окна сторона Rust обязана отказать"
    );
}
