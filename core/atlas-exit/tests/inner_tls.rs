//! TLS внутри туннеля: наш клиент против нашего же сервера.
//!
//! Полевой запуск показал, что `atlas_tls::TlsStream`, поднятый **поверх**
//! туннеля, доводит рукопожатие до конца и дальше получает ноль байт.
//! Причиной оказался не туннель: `ClientConfig::with_alpn` ничего не
//! делал, на провод уходило `h2` из умолчания профиля, сервер его
//! выбирал — и вежливо прощался, не поняв HTTP/1.1. Разбор целиком —
//! в `docs/09-lab.md`, раздел 10.
//!
//! Здесь тот же случай собран в памяти и на петле: свой клиент, свой
//! туннель, своя точка выхода, свой сервер TLS на месте назначения.
//! Сервер назначения объявляет **`h2` первым** — иначе тест ничего не
//! проверял бы: с сервером, умеющим только `http/1.1`, выбор совпадал
//! с желаемым случайно, и первая редакция этого теста проходила при
//! живой ошибке.

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
use std::time::Duration;

use atlas_dial::{dial_with, DialOptions, Target};
use atlas_exit::{ExitConfig, ExitPoint, Policy};
use atlas_reality::Server;
use atlas_tls::server::{CertificateSource, Credentials, Pending, Ready, ServerConfig};
use atlas_tls::{Chrome, ClientConfig, ClientHello, TlsStream};
use atlas_types::ProxyKey;

const SNI: &str = "www.microsoft.com";
const UUID: &str = "11111111-2222-3333-4444-555555555555";

/// Обычный сервер TLS: любой клиент, самодельный сертификат.
///
/// Ключ и сертификат берутся из тех же кирпичей, что у REALITY, но
/// метки здесь нет и не нужно: это просто узел назначения, к которому
/// клиент идёт через туннель.
#[derive(Debug)]
struct PlainCertificates {
    name: String,
}

impl CertificateSource for PlainCertificates {
    fn accept(&self, _hello: &ClientHello, _raw: &[u8]) -> atlas_tls::Result<Box<dyn Pending>> {
        let key = atlas_crypto::sign::ClassicKey::generate();
        let certificate = atlas_reality::cert::issue::temporary_certificate(
            &key.public_key(),
            &self.name,
            atlas_reality::now_seconds(),
            &[0x11; 64],
            None,
        );
        Ok(Box::new(Ready(Credentials {
            chain: vec![certificate],
            key,
        })))
    }
}

/// Поднять сервер TLS, отвечающий заданной строкой на любой запрос.
fn spawn_tls_destination(banner: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();

    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(socket) = incoming else { break };
            std::thread::spawn(move || {
                let config = ServerConfig::new(Box::new(PlainCertificates {
                    name: "destination.test".to_owned(),
                }))
                .with_alpn(vec!["h2".to_owned(), "http/1.1".to_owned()]);

                let Ok(mut stream) = atlas_exit::accept_tls(socket, config) else {
                    return;
                };
                let mut buf = [0_u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(banner.as_bytes());
                let _ = stream.flush();
            });
        }
    });
    address
}

/// Поднять точку выхода, вернув адрес и ключ доступа.
fn spawn_exit() -> (String, String) {
    let cover = {
        // Сайт прикрытия здесь не важен: посторонних в этом тесте нет.
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
        read_timeout: Some(Duration::from_secs(10)),
        ..DialOptions::default()
    }
}

fn split_address(address: &str) -> (String, u16) {
    let (host, port) = address.rsplit_once(':').unwrap();
    (host.to_owned(), port.parse().unwrap())
}

/// Обёртка: туннель как обычный поток для внутреннего TLS.
struct Inner(atlas_dial::Tunnel);

impl Read for Inner {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(out)
    }
}

impl Write for Inner {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.write(data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[test]
fn our_tls_client_works_inside_our_own_tunnel() {
    for flow in ["&flow=xtls-rprx-vision", ""] {
        let destination = spawn_tls_destination("OTVET IZNUTRI");
        let (exit, public_key) = spawn_exit();
        let key = key_for(&exit, &public_key, flow);
        let (host, port) = split_address(&destination);

        let tunnel = dial_with(&key, &Target::domain(host, port), &options())
            .expect("туннель обязан подняться");

        let mut inner = TlsStream::connect(
            Inner(tunnel),
            ClientConfig::new("destination.test")
                .with_profile(Chrome::v141().without_ech())
                .with_alpn(vec!["http/1.1".to_owned()]),
        )
        .expect("внутреннее рукопожатие обязано пройти");

        assert_eq!(
            inner.alpn(),
            Some("http/1.1"),
            "обрамление {flow:?}: сервер предпочитает h2, но мы его не предлагали"
        );

        inner.write_all(b"zapros").unwrap();
        inner.flush().unwrap();

        let mut answer = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            match inner.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => answer.extend_from_slice(&buf[..read]),
            }
        }
        assert_eq!(
            String::from_utf8_lossy(&answer),
            "OTVET IZNUTRI",
            "обрамление {flow:?}: ответ обязан дойти сквозь оба слоя TLS"
        );
    }
}
