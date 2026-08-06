//! Перекачка в обе стороны: направления обязаны быть независимы.
//!
//! Полевая ошибка: локальный прокси гонял оба направления через один
//! поток-насос и очередь. Насос разбирал очередь на отправку **между**
//! блокирующими чтениями туннеля, поэтому клиент, заговоривший первым
//! после паузы, ждал ответа до предела чтения (тридцать секунд) и
//! получал обрыв.
//!
//! Через `curl` это выживало случайно: пачка сервера приходит
//! несколькими сегментами, чтения возвращались часто, и насос успевал
//! слить очередь между ними. Пятнадцать запросов подряд проходили без
//! единого отказа — измерение, которое ничего не доказывало.
//!
//! Здесь проверяется то, что там не проверялось: **собеседник молчит,
//! пока с ним не заговорят**. Никакой сегментации, спасающей случайно,
//! нет и быть не может.

// Вход теста — байты, которые он же и породил.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_dial::{dial_with, DialOptions, Target};
use atlas_exit::{ExitConfig, ExitPoint, Policy};
use atlas_reality::Server;
use atlas_types::ProxyKey;

const SNI: &str = "www.microsoft.com";
const UUID: &str = "11111111-2222-3333-4444-555555555555";

/// Предел чтения туннеля в этом тесте.
///
/// Намеренно короткий: при живой ошибке отказ наступал именно по нему,
/// и ждать настоящие тридцать секунд в наборе тестов незачем.
const READ_TIMEOUT: Duration = Duration::from_secs(4);

/// Собеседник, который не говорит первым.
///
/// Отвечает только на сказанное — ровно тот случай, где очередь между
/// блокирующими чтениями становится взаимной блокировкой.
fn spawn_silent_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut socket) = incoming else { break };
            std::thread::spawn(move || {
                let mut buf = [0_u8; 4096];
                while let Ok(read) = socket.read(&mut buf) {
                    if read == 0 {
                        break;
                    }
                    let mut answer = b"pong:".to_vec();
                    answer.extend_from_slice(&buf[..read]);
                    if socket.write_all(&answer).is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

/// Поднять точку выхода, вернув адрес и публичный ключ.
fn spawn_exit() -> (String, String) {
    let cover = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                drop(incoming);
            }
        });
        address
    };

    let reality = Server::generate().with_short_id(&[0xde, 0xad]).unwrap();
    let public_key = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reality.public_key())
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let point = Arc::new(ExitPoint::new(
        ExitConfig::new(reality, cover)
            .with_common_name(SNI)
            .with_policy(Policy {
                allow_private: true,
                ..Policy::default()
            }),
    ));
    std::thread::spawn(move || {
        let _ = point.serve(&listener);
    });
    (address, public_key)
}

fn key_for(exit: &str, public_key: &str, flow: &str) -> ProxyKey {
    ProxyKey::parse(&format!(
        "vless://{UUID}@{exit}?type=tcp&security=reality&sni={SNI}\
         &pbk={public_key}&sid=dead&fp=chrome{flow}#test"
    ))
    .unwrap()
}

fn options() -> DialOptions {
    DialOptions {
        ech: false,
        connect_timeout: Duration::from_secs(5),
        read_timeout: Some(READ_TIMEOUT),
        ..DialOptions::default()
    }
}

fn split_address(address: &str) -> (String, u16) {
    let (host, port) = address.rsplit_once(':').unwrap();
    (host.to_owned(), port.parse().unwrap())
}

/// Запись обязана уходить, пока чтение **уже** заблокировано.
///
/// Это и есть полевое условие, и проверять его надо именно так.
/// Последовательные «записал, потом прочитал» ничего не доказывают:
/// при живой ошибке они тоже прошли бы, потому что насос успевал
/// разобрать очередь до того, как уходил в чтение. Здесь читающий
/// поток запускается **первым** и заведомо висит в `read`, когда
/// пишущий заговаривает.
#[test]
fn a_write_goes_out_while_the_read_half_is_already_blocked() {
    for flow in ["&flow=xtls-rprx-vision", ""] {
        let destination = spawn_silent_echo();
        let (exit, public_key) = spawn_exit();
        let key = key_for(&exit, &public_key, flow);
        let (host, port) = split_address(&destination);

        let tunnel = dial_with(&key, &Target::domain(host, port), &options())
            .expect("туннель обязан подняться");
        let (mut reader, mut writer) = atlas_dial::split(tunnel).expect("туннель обязан разъяться");

        let (sender, receiver) = std::sync::mpsc::channel();
        let reading = std::thread::spawn(move || {
            let mut buf = [0_u8; 64];
            let read = reader.read(&mut buf).expect("ответ обязан дойти");
            let _ = sender.send(buf[..read].to_vec());
        });

        // Читающий поток заведомо уже висит в `read`: собеседник
        // молчит, пока с ним не заговорят.
        std::thread::sleep(Duration::from_millis(300));

        let started = Instant::now();
        writer.write_all(b"ping").unwrap();
        writer.flush().unwrap();

        // При живой ошибке ответа не будет вовсе: сказанное не уйдёт,
        // пока чтение не вернётся, а вернуться ему не с чего.
        let answer = receiver
            .recv_timeout(READ_TIMEOUT)
            .unwrap_or_else(|_| panic!("обрамление {flow:?}: ответа нет — направления связаны"));
        let elapsed = started.elapsed();
        let _ = reading.join();

        assert_eq!(
            answer, b"pong:ping",
            "обрамление {flow:?}: собеседник обязан получить сказанное"
        );
        assert!(
            elapsed < READ_TIMEOUT / 2,
            "обрамление {flow:?}: ответ пришёл за {elapsed:?}"
        );
    }
}

/// Обмен репликами в обе стороны не рассыпается на длинной серии.
#[test]
fn many_turns_survive_in_both_directions() {
    let destination = spawn_silent_echo();
    let (exit, public_key) = spawn_exit();
    let key = key_for(&exit, &public_key, "&flow=xtls-rprx-vision");
    let (host, port) = split_address(&destination);

    let tunnel =
        dial_with(&key, &Target::domain(host, port), &options()).expect("туннель обязан подняться");
    let (mut reader, mut writer) = atlas_dial::split(tunnel).expect("туннель обязан разъяться");

    for turn in 0..32_u32 {
        let question = format!("vopros-{turn}");
        writer.write_all(question.as_bytes()).unwrap();
        writer.flush().unwrap();

        let mut answer = Vec::new();
        let expected = format!("pong:{question}");
        let mut buf = [0_u8; 256];
        while answer.len() < expected.len() {
            let read = reader.read(&mut buf).expect("ответ обязан дойти");
            assert_ne!(read, 0, "реплика {turn}: туннель закрылся");
            answer.extend_from_slice(&buf[..read]);
        }
        assert_eq!(String::from_utf8_lossy(&answer), expected);
    }
}
