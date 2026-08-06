//! Сквозные проверки клиента против встречной реализации.
//!
//! Эталонные векторы RFC 8448 доказывают, что вычисления верны, а живые
//! соединения (`examples/connect.rs`) — что мы договариваемся с чужими
//! серверами. Но ни то, ни другое не проверяется на сборке: следа для
//! ветвей вроде `HelloRetryRequest`, сжатого сертификата или смены
//! ключей в RFC нет, а живая сеть в CI недоступна.
//!
//! Поэтому здесь стоит встречная сторона — маленький сервер TLS 1.3,
//! собранный из тех же кирпичей. Да, обе стороны наши, и общая ошибка в
//! понимании протокола так не ловится. Ровно поэтому этот файл
//! **дополняет**, а не заменяет два других способа проверки: RFC
//! отвечает за арифметику, живые серверы — за совместимость, а этот
//! файл — за то, что редкие ветви автомата вообще исполняются и
//! исполняются одинаково от сборки к сборке.

// Вход этого файла — байты, которые породили мы сами в этом же файле,
// а не сеть. Падение теста на индексе здесь и есть желаемое поведение:
// оно означает, что раскладка байт разошлась с ожидаемой.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write as _;

use atlas_tls::bytes::{Reader, Writer};
use atlas_tls::client::{AcceptAnyServer, ClientConfig, Connection, PeerIdentity, ServerVerifier};
use atlas_tls::handshake::{
    build_message, HandshakeType, MessageReader, ServerHello, Transcript,
    HELLO_RETRY_REQUEST_RANDOM,
};
use atlas_tls::keyexchange::{Group, KeyExchange};
use atlas_tls::keyschedule::{traffic_keys, verify_data, Hash, KeySchedule};
use atlas_tls::record::{Aead, ContentType, Protection};
use atlas_tls::{ext, ClientHello, Error};

/// Что сервер должен сделать необычного.
#[derive(Debug, Clone, Copy, Default)]
struct ServerOptions {
    /// Ответить `HelloRetryRequest` и потребовать эту группу.
    retry_to: Option<Group>,
    /// Согласиться на ALPS.
    alps: bool,
    /// Прислать сжатый сертификат.
    compress_certificate: bool,
    /// Запросить сертификат клиента.
    request_certificate: bool,
    /// Приложить `cookie` к `HelloRetryRequest`.
    cookie: bool,
    /// Шифронабор: `0x1301` или `0x1302`.
    cipher_suite: u16,
    /// Прислать прикладные данные сразу за своим `Finished`, не дожидаясь
    /// `Finished` клиента. TLS 1.3 это разрешает — данные 0.5-RTT.
    early_data: Option<&'static [u8]>,
}

impl ServerOptions {
    fn new() -> Self {
        Self {
            cipher_suite: 0x1301,
            ..Self::default()
        }
    }
}

/// Встречная сторона: ровно столько TLS 1.3, сколько нужно клиенту.
struct TestServer {
    options: ServerOptions,
    hash: Hash,
    aead: Aead,
    transcript: Transcript,
    schedule: Option<KeySchedule>,
    client_handshake_secret: Vec<u8>,
    server_handshake_secret: Vec<u8>,
    client_application_secret: Vec<u8>,
    server_application_secret: Vec<u8>,
    read: Option<Protection>,
    write: Option<Protection>,
    pending_keys: Option<(Protection, Protection)>,
    retried: bool,
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    plaintext: Vec<u8>,
    finished: bool,
}

impl TestServer {
    fn new(options: ServerOptions) -> Self {
        let hash = Hash::for_cipher_suite(options.cipher_suite).unwrap();
        Self {
            options,
            hash,
            aead: Aead::for_cipher_suite(options.cipher_suite).unwrap(),
            transcript: Transcript::new(hash),
            schedule: None,
            client_handshake_secret: Vec::new(),
            server_handshake_secret: Vec::new(),
            client_application_secret: Vec::new(),
            server_application_secret: Vec::new(),
            read: None,
            write: None,
            pending_keys: None,
            retried: false,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            plaintext: Vec::new(),
            finished: false,
        }
    }

    fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }

    /// Принять поток от клиента и ответить.
    ///
    /// Потоковый, а не «запись за раз»: клиент вправе слать записи
    /// любыми кусками, и сервер обязан это переживать.
    fn feed(&mut self, data: &[u8]) {
        self.incoming.extend_from_slice(data);
        loop {
            let Some(header) = self.incoming.get(..5) else {
                return;
            };
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let total = 5 + length;
            if self.incoming.len() < total {
                return;
            }
            let record = self.incoming[..total].to_vec();
            self.incoming.drain(..total);
            self.record(&record);

            // Ключи приложения ставятся сразу после принятого Finished:
            // следующая запись клиента поедет уже ими.
            if self.finished {
                self.switch_to_application_keys();
            }
        }
    }

    fn record(&mut self, record: &[u8]) {
        let outer = record[0];
        if outer == ContentType::ChangeCipherSpec.code() {
            return;
        }

        let (content_type, body) = match self.read.as_mut() {
            None => (ContentType::from_code(outer).unwrap(), record[5..].to_vec()),
            Some(protection) => protection.decrypt(record).expect("расшифровка клиента"),
        };

        match content_type {
            ContentType::Handshake => {
                let mut reader = MessageReader::new();
                reader.push(&body);
                while let Some(message) = reader.next_message().unwrap() {
                    self.message(&message);
                }
            }
            ContentType::ApplicationData => self.plaintext.extend_from_slice(&body),
            _ => {}
        }
    }

    fn message(&mut self, message: &atlas_tls::handshake::Message) {
        match message.msg_type {
            HandshakeType::ClientHello => self.client_hello(message),
            HandshakeType::EncryptedExtensions | HandshakeType::Certificate => {
                // ALPS клиента и пустой сертификат: только в транскрипт.
                self.transcript.extend(&message.raw);
            }
            HandshakeType::KeyUpdate => {
                self.client_application_secret =
                    next_secret(self.hash, &self.client_application_secret);
                let (hash, aead) = (self.hash, self.aead);
                self.read = Some(
                    Protection::new(
                        aead,
                        traffic_keys(hash, &self.client_application_secret, aead.key_len()),
                    )
                    .unwrap(),
                );
            }
            HandshakeType::Finished => {
                let expected = verify_data(
                    self.hash,
                    &self.client_handshake_secret,
                    &self.transcript.hash(),
                );
                assert_eq!(message.body, expected, "Finished клиента не сошёлся");
                self.transcript.extend(&message.raw);
                self.finished = true;
            }
            other => panic!("сервер не ждал сообщения {other:?}"),
        }
    }

    fn client_hello(&mut self, message: &atlas_tls::handshake::Message) {
        let hello = ClientHello::parse(&message.raw).expect("разбор ClientHello");
        let shares = parse_key_share(&hello);

        if let Some(group) = self.options.retry_to.filter(|_| !self.retried) {
            self.retried = true;
            self.transcript.extend(&message.raw);
            self.transcript.replace_with_message_hash();
            self.send_hello_retry_request(&hello, group);
            return;
        }

        // Выбираем первую предложенную настоящую группу.
        let (group, client_share) = shares
            .iter()
            .find_map(|(code, share)| Group::from_code(*code).map(|g| (g, share.clone())))
            .expect("клиент не предложил ни одной известной группы");
        if let Some(required) = self.options.retry_to {
            assert_eq!(
                group, required,
                "второе приветствие обязано нести группу HRR"
            );
            assert_eq!(shares.len(), 1, "во втором приветствии только одна доля");
        }

        self.transcript.extend(&message.raw);
        let (server_share, shared) = KeyExchange::respond(group, &client_share).unwrap();
        self.send_server_hello(&hello, group, &server_share);

        let mut schedule = KeySchedule::new(self.hash);
        schedule.enter_handshake(&shared);
        let transcript_hash = self.transcript.hash();
        self.client_handshake_secret = schedule.client_handshake_traffic_secret(&transcript_hash);
        self.server_handshake_secret = schedule.server_handshake_traffic_secret(&transcript_hash);
        self.schedule = Some(schedule);

        let (hash, aead) = (self.hash, self.aead);
        self.read = Some(
            Protection::new(
                aead,
                traffic_keys(hash, &self.client_handshake_secret, aead.key_len()),
            )
            .unwrap(),
        );
        self.write = Some(
            Protection::new(
                aead,
                traffic_keys(hash, &self.server_handshake_secret, aead.key_len()),
            )
            .unwrap(),
        );

        self.send_flight();
    }

    fn send_hello_retry_request(&mut self, hello: &ClientHello, group: Group) {
        let mut extensions = vec![
            raw_extension(ext::SUPPORTED_VERSIONS, &0x0304_u16.to_be_bytes()),
            raw_extension(ext::KEY_SHARE, &group.code().to_be_bytes()),
        ];
        if self.options.cookie {
            let mut w = Writer::new();
            w.nested_u16(|b| b.bytes(b"cookie-value")).unwrap();
            extensions.push(raw_extension(ext::COOKIE, &w.finish()));
        }

        let body = server_hello_body(
            HELLO_RETRY_REQUEST_RANDOM,
            &hello.session_id,
            self.options.cipher_suite,
            &extensions,
        );
        let message = build_message(HandshakeType::ServerHello, &body).unwrap();
        self.transcript.extend(&message);
        self.outgoing.extend_from_slice(&plaintext_record(&message));
    }

    fn send_server_hello(&mut self, hello: &ClientHello, group: Group, share: &[u8]) {
        let mut key_share = Writer::new();
        key_share.u16(group.code());
        key_share.nested_u16(|b| b.bytes(share)).unwrap();

        let extensions = vec![
            raw_extension(ext::SUPPORTED_VERSIONS, &0x0304_u16.to_be_bytes()),
            raw_extension(ext::KEY_SHARE, &key_share.finish()),
        ];
        let body = server_hello_body(
            [0x5a; 32],
            &hello.session_id,
            self.options.cipher_suite,
            &extensions,
        );
        let message = build_message(HandshakeType::ServerHello, &body).unwrap();
        self.transcript.extend(&message);
        self.outgoing.extend_from_slice(&plaintext_record(&message));
    }

    fn send_flight(&mut self) {
        // EncryptedExtensions: ALPN и, если попросили, ALPS.
        let mut alpn = Writer::new();
        alpn.nested_u16(|list| {
            let _ = list.nested_u8(|name| name.bytes(b"h2"));
        })
        .unwrap();
        let mut extensions = vec![raw_extension(ext::ALPN, &alpn.finish())];
        if self.options.alps {
            extensions.push(raw_extension(ext::APPLICATION_SETTINGS_V2, b"accept-ch"));
        }
        let mut w = Writer::new();
        w.nested_u16(|list| list.bytes(&extensions.concat()))
            .unwrap();
        self.emit(HandshakeType::EncryptedExtensions, &w.finish());

        if self.options.request_certificate {
            // Пустой контекст и пустой список расширений.
            self.emit(HandshakeType::CertificateRequest, &[0x00, 0x00, 0x00]);
        }

        let certificate = certificate_message(&fake_certificate());
        if self.options.compress_certificate {
            let compressed = brotli_compress(&certificate);
            let mut body = Writer::new();
            body.u16(2); // brotli
            let len = u32::try_from(certificate.len()).unwrap().to_be_bytes();
            body.bytes(&len[1..]);
            body.nested_u24(|b| b.bytes(&compressed)).unwrap();
            self.emit(HandshakeType::CompressedCertificate, &body.finish());
        } else {
            self.emit(HandshakeType::Certificate, &certificate);
        }

        // Подпись настоящей не бывает: клиент в этих тестах принимает
        // сервер по заданному правилу, а не по цепочке.
        let mut verify = Writer::new();
        verify.u16(0x0804);
        verify.nested_u16(|b| b.bytes(&[0x11; 64])).unwrap();
        self.emit(HandshakeType::CertificateVerify, &verify.finish());

        let data = verify_data(
            self.hash,
            &self.server_handshake_secret,
            &self.transcript.hash(),
        );
        self.emit(HandshakeType::Finished, &data);

        // Ключи приложения — от транскрипта по Finished сервера.
        let early = self.options.early_data;
        let after = self.transcript.hash();
        let schedule = self.schedule.as_mut().unwrap();
        schedule.enter_master();
        let server_app = schedule.server_application_traffic_secret(&after);
        let client_app = schedule.client_application_traffic_secret(&after);
        self.server_application_secret.clone_from(&server_app);
        self.client_application_secret.clone_from(&client_app);

        let (hash, aead) = (self.hash, self.aead);
        let write = Protection::new(aead, traffic_keys(hash, &server_app, aead.key_len())).unwrap();
        let read = Protection::new(aead, traffic_keys(hash, &client_app, aead.key_len())).unwrap();

        match early {
            // Данные 0.5-RTT уходят той же порцией, что и хвост пачки:
            // клиент увидит их в одном чтении с `Finished` сервера.
            Some(payload) => {
                self.write = Some(write);
                self.send_application_data(payload);
                self.pending_keys = Some((read, self.write.take().unwrap()));
            }
            None => self.pending_keys = Some((read, write)),
        }
    }

    fn emit(&mut self, msg_type: HandshakeType, body: &[u8]) {
        let message = build_message(msg_type, body).unwrap();
        self.transcript.extend(&message);
        let record = self
            .write
            .as_mut()
            .unwrap()
            .encrypt(ContentType::Handshake, &message, 0)
            .unwrap();
        self.outgoing.extend_from_slice(&record);
    }

    /// Перейти на ключи приложения — после того, как принят `Finished`.
    fn switch_to_application_keys(&mut self) {
        if let Some((read, write)) = self.pending_keys.take() {
            self.read = Some(read);
            self.write = Some(write);
        }
    }

    /// Сменить свой ключ записи и, при желании, попросить о том же клиента.
    fn send_key_update(&mut self, request: bool) {
        let body = [u8::from(request)];
        let message = build_message(HandshakeType::KeyUpdate, &body).unwrap();
        // Сообщение уходит ещё старым ключом.
        let record = self
            .write
            .as_mut()
            .unwrap()
            .encrypt(ContentType::Handshake, &message, 0)
            .unwrap();
        self.outgoing.extend_from_slice(&record);

        self.server_application_secret = next_secret(self.hash, &self.server_application_secret);
        let (hash, aead) = (self.hash, self.aead);
        self.write = Some(
            Protection::new(
                aead,
                traffic_keys(hash, &self.server_application_secret, aead.key_len()),
            )
            .unwrap(),
        );
    }

    fn send_application_data(&mut self, data: &[u8]) {
        let record = self
            .write
            .as_mut()
            .unwrap()
            .encrypt(ContentType::ApplicationData, data, 0)
            .unwrap();
        self.outgoing.extend_from_slice(&record);
    }
}

/// Следующий секрет трафика по RFC 8446, раздел 7.2.
fn next_secret(hash: Hash, secret: &[u8]) -> Vec<u8> {
    atlas_tls::keyschedule::expand_label(hash, secret, "traffic upd", &[], hash.len())
}

fn server_hello_body(
    random: [u8; 32],
    session_id: &[u8],
    cipher_suite: u16,
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(0x0303);
    w.bytes(&random);
    w.nested_u8(|b| b.bytes(session_id)).unwrap();
    w.u16(cipher_suite);
    w.u8(0);
    w.nested_u16(|b| b.bytes(&extensions.concat())).unwrap();
    w.finish()
}

fn raw_extension(ext_type: u16, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(ext_type);
    w.nested_u16(|b| b.bytes(body)).unwrap();
    w.finish()
}

fn plaintext_record(message: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(ContentType::Handshake.code());
    w.u16(0x0303);
    w.nested_u16(|b| b.bytes(message)).unwrap();
    w.finish()
}

/// Правдоподобный по структуре, но выдуманный сертификат.
fn fake_certificate() -> Vec<u8> {
    let mut der = vec![0x30, 0x82, 0x01, 0x00];
    der.extend(core::iter::repeat_n(0xa5_u8, 256));
    der
}

fn certificate_message(der: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.nested_u8(|b| b.bytes(&[])).unwrap(); // пустой контекст
    w.nested_u24(|list| {
        let _ = list.nested_u24(|entry| entry.bytes(der));
        let _ = list.nested_u16(|ext| ext.bytes(&[]));
    })
    .unwrap();
    w.finish()
}

fn brotli_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
    writer.write_all(data).unwrap();
    drop(writer);
    out
}

fn parse_key_share(hello: &ClientHello) -> Vec<(u16, Vec<u8>)> {
    let extension = hello
        .extensions
        .iter()
        .find(|e| e.ext_type == ext::KEY_SHARE)
        .expect("нет key_share");
    let mut outer = Reader::new(&extension.body);
    let mut list = Reader::new(outer.vec_u16().unwrap());
    let mut out = Vec::new();
    while !list.is_empty() {
        let group = list.u16().unwrap();
        let share = list.vec_u16().unwrap();
        out.push((group, share.to_vec()));
    }
    out
}

/// Прогнать рукопожатие до конца, вернув обе стороны.
fn handshake(options: ServerOptions, config: ClientConfig) -> (Connection, TestServer) {
    let mut client = Connection::new(config).expect("клиент");
    let mut server = TestServer::new(options);

    for _ in 0..8 {
        let from_client = client.take_output();
        if !from_client.is_empty() {
            server.feed(&from_client);
        }
        let from_server = server.take_output();
        if from_server.is_empty() && from_client.is_empty() {
            break;
        }
        if !from_server.is_empty() {
            client.read_tls(&from_server).expect("приём");
            client.process().expect("разбор");
        }
    }
    (client, server)
}

// ── Тесты ────────────────────────────────────────────────────────────

#[test]
fn plain_handshake_completes_on_both_groups() {
    for group in [Group::X25519, Group::X25519MlKem768] {
        let mut config = ClientConfig::new("example.org");
        config.groups = vec![group];
        let (client, server) = handshake(ServerOptions::new(), config);

        assert!(!client.is_handshaking(), "{group:?}: клиент не завершил");
        assert!(server.finished, "{group:?}: сервер не принял Finished");
        assert_eq!(client.group(), Some(group));
        assert_eq!(client.alpn(), Some("h2"));
        assert!(client.peer_certificate().is_some());
    }
}

#[test]
fn both_cipher_suites_work() {
    for suite in [0x1301_u16, 0x1302] {
        let options = ServerOptions {
            cipher_suite: suite,
            ..ServerOptions::new()
        };
        let (client, server) = handshake(options, ClientConfig::new("example.org"));
        assert!(server.finished, "0x{suite:04x}");
        assert_eq!(client.cipher_suite(), Some(suite));
    }
}

#[test]
fn hello_retry_request_is_honoured() {
    let mut config = ClientConfig::new("example.org");
    config.groups = vec![Group::X25519];

    let options = ServerOptions {
        retry_to: Some(Group::X25519MlKem768),
        cookie: true,
        ..ServerOptions::new()
    };
    let (client, server) = handshake(options, config);

    assert!(
        client.was_retried(),
        "повтор приветствия должен быть отмечен"
    );
    assert!(server.finished, "рукопожатие после HRR обязано сойтись");
    assert_eq!(client.group(), Some(Group::X25519MlKem768));

    // Cookie обязан вернуться во втором приветствии.
    assert!(
        client
            .client_hello()
            .extensions
            .iter()
            .any(|e| e.ext_type == ext::COOKIE),
        "cookie сервера обязан быть возвращён"
    );
}

#[test]
fn a_retry_to_any_advertised_group_is_survivable() {
    // Профиль объявляет четыре группы, а долю шлёт для двух. Значит,
    // сервер вправе запросить любую из оставшихся — и на каждой из них
    // рукопожатие обязано сойтись. Иначе объявление группы, которую мы
    // не умеем, превращается в гарантированный обрыв.
    for requested in [Group::Secp256r1, Group::Secp384r1, Group::X25519MlKem768] {
        let mut config = ClientConfig::new("example.org");
        config.groups = vec![Group::X25519];

        let options = ServerOptions {
            retry_to: Some(requested),
            ..ServerOptions::new()
        };
        let (client, server) = handshake(options, config);

        assert!(server.finished, "{requested:?}: рукопожатие не сошлось");
        assert_eq!(client.group(), Some(requested));
        assert!(client.was_retried());
    }
}

#[test]
fn hello_retry_request_keeps_the_first_hello_intact() {
    // RFC 8446 разрешает изменить во втором приветствии только key_share,
    // cookie и early_data. Для нас это не формальность: REALITY кладёт в
    // `session_id` метку, привязанную к доле x25519, и подмена поля
    // сделала бы метку нерасшифровываемой. А `random` входит в
    // транскрипт, и его смена развалила бы `Finished`.
    let mut client = Connection::new({
        let mut config = ClientConfig::new("example.org");
        config.groups = vec![Group::X25519];
        config
    })
    .unwrap();

    let first = ClientHello::parse(&client.take_output()[5..]).unwrap();

    let options = ServerOptions {
        retry_to: Some(Group::X25519MlKem768),
        cookie: true,
        ..ServerOptions::new()
    };
    let mut server = TestServer::new(options);
    // Первое приветствие серверу отдаём сами: клиент уже отдал вывод.
    server.feed(&plaintext_record(&first.to_handshake().unwrap()));

    let retry = server.take_output();
    client.read_tls(&retry).unwrap();
    client.process().unwrap();

    let second = ClientHello::parse(&client.take_output()[6..]).unwrap();

    assert_eq!(
        second.random, first.random,
        "random обязан остаться прежним"
    );
    assert_eq!(
        second.session_id, first.session_id,
        "session_id обязан остаться прежним — на нём держится метка REALITY"
    );
    assert_eq!(second.cipher_suites, first.cipher_suites);

    let types = |hello: &ClientHello| -> Vec<u16> {
        hello
            .extensions
            .iter()
            .map(|e| e.ext_type)
            .filter(|t| *t != ext::COOKIE && *t != ext::PADDING)
            .collect()
    };
    assert_eq!(
        types(&second),
        types(&first),
        "состав и порядок расширений обязаны сохраниться"
    );

    // key_share обязан смениться: одна доля запрошенной группы.
    let shares = parse_key_share(&second);
    assert_eq!(
        shares.len(),
        1,
        "во втором приветствии только запрошенная группа"
    );
    assert_eq!(shares[0].0, Group::X25519MlKem768.code());
    assert_eq!(shares[0].1.len(), Group::X25519MlKem768.client_share_len());
}

#[test]
fn key_update_rekeys_both_directions() {
    let (mut client, mut server) =
        handshake(ServerOptions::new(), ClientConfig::new("example.org"));

    // Сервер просит смены ключей и меняет свои.
    server.send_key_update(true);
    let out = server.take_output();
    client.read_tls(&out).unwrap();
    client.process().unwrap();

    // Клиент обязан был ответить своим KeyUpdate и сменить ключ записи.
    let answer = client.take_output();
    assert!(!answer.is_empty(), "клиент обязан ответить на KeyUpdate");
    server.feed(&answer);

    // После смены данные обязаны ходить в обе стороны.
    server.send_application_data(b"posle");
    let out = server.take_output();
    client.read_tls(&out).unwrap();
    client.process().unwrap();
    assert_eq!(client.take_plaintext(), b"posle");

    client.send(b"tuda".as_slice()).unwrap();
    server.feed(&client.take_output());
    assert_eq!(server.plaintext, b"tuda");
}

#[test]
fn alps_makes_the_client_send_its_own_encrypted_extensions() {
    let options = ServerOptions {
        alps: true,
        ..ServerOptions::new()
    };
    let (client, server) = handshake(options, ClientConfig::new("example.org"));
    // Сервер проверяет Finished клиента по своему транскрипту; если бы
    // клиент не прислал ALPS-сообщение или прислал его не в том месте,
    // проверка внутри TestServer уже упала бы.
    assert!(server.finished);
    assert!(!client.is_handshaking());
}

#[test]
fn compressed_certificate_is_decompressed() {
    let options = ServerOptions {
        compress_certificate: true,
        ..ServerOptions::new()
    };
    let (client, server) = handshake(options, ClientConfig::new("example.org"));
    assert!(server.finished);
    assert_eq!(
        client.peer_certificate().and_then(|c| c.end_entity()),
        Some(fake_certificate().as_slice()),
        "разжатая цепочка обязана совпасть с исходной"
    );
}

#[test]
fn certificate_request_is_answered_with_an_empty_certificate() {
    let options = ServerOptions {
        request_certificate: true,
        ..ServerOptions::new()
    };
    let (client, server) = handshake(options, ClientConfig::new("example.org"));
    assert!(
        server.finished,
        "пустой сертификат обязан войти в транскрипт"
    );
    assert!(!client.is_handshaking());
}

#[test]
fn application_data_flows_in_both_directions() {
    let (mut client, mut server) =
        handshake(ServerOptions::new(), ClientConfig::new("example.org"));

    client.send(b"privet".as_slice()).unwrap();
    server.feed(&client.take_output());
    assert_eq!(server.plaintext, b"privet");

    server.send_application_data(b"otvet");
    let out = server.take_output();
    client.read_tls(&out).unwrap();
    client.process().unwrap();
    assert_eq!(client.take_plaintext(), b"otvet");
}

#[test]
fn a_long_message_is_split_into_records_and_reassembled() {
    let (mut client, mut server) =
        handshake(ServerOptions::new(), ClientConfig::new("example.org"));

    // Заведомо больше одной записи.
    let payload: Vec<u8> = (0..50_000_u32).map(|i| (i % 251) as u8).collect();
    client.send(&payload).unwrap();
    let stream = client.take_output();
    assert!(
        stream.len() > 1 << 14,
        "должно получиться несколько записей"
    );

    // Кормим сервер по кусочкам, не совпадающим с границами записей.
    for chunk in stream.chunks(1000) {
        server.feed(chunk);
    }
    assert_eq!(server.plaintext, payload);
}

#[test]
fn a_refusing_verifier_stops_the_handshake() {
    #[derive(Debug)]
    struct Refuse;
    impl ServerVerifier for Refuse {
        fn verify(&self, _peer: &PeerIdentity<'_>) -> atlas_tls::Result<()> {
            Err(Error::Untrusted("проверка отклонена в тесте"))
        }
    }

    let config = ClientConfig::new("example.org").with_verifier(Box::new(Refuse));
    let mut client = Connection::new(config).unwrap();
    let mut server = TestServer::new(ServerOptions::new());
    server.feed(&client.take_output());

    let out = server.take_output();
    client.read_tls(&out).unwrap();
    let outcome = client.process();
    assert!(matches!(outcome, Err(Error::Untrusted(_))), "{outcome:?}");
}

#[test]
fn the_verifier_sees_the_certificate_and_the_signed_hash() {
    #[derive(Debug)]
    struct Inspect;
    impl ServerVerifier for Inspect {
        fn verify(&self, peer: &PeerIdentity<'_>) -> atlas_tls::Result<()> {
            assert_eq!(peer.server_name, "example.org");
            assert_eq!(
                peer.certificate.end_entity(),
                Some(fake_certificate().as_slice())
            );
            assert_eq!(peer.certificate_verify.algorithm, 0x0804);
            assert_eq!(peer.transcript_hash.len(), 32);
            Ok(())
        }
    }

    let config = ClientConfig::new("example.org").with_verifier(Box::new(Inspect));
    let (_, server) = handshake(ServerOptions::new(), config);
    assert!(server.finished);
}

#[test]
fn a_tampered_server_finished_is_rejected() {
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    let mut server = TestServer::new(ServerOptions::new());
    server.feed(&client.take_output());

    let mut out = server.take_output();
    // Портим последний байт последней записи — это тег Finished.
    let last = out.len() - 1;
    out[last] ^= 0xff;

    client.read_tls(&out).unwrap();
    let outcome = client.process();
    assert!(
        outcome.is_err(),
        "испорченная пачка обязана быть отвергнута"
    );
}

#[test]
fn sending_before_the_handshake_is_refused() {
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    assert!(client.send(b"rano".as_slice()).is_err());
}

#[test]
fn the_client_accepts_any_record_boundaries() {
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    let mut server = TestServer::new(ServerOptions::new());
    server.feed(&client.take_output());
    let out = server.take_output();

    // По одному байту: клиент обязан собрать записи сам.
    for byte in &out {
        client.read_tls(core::slice::from_ref(byte)).unwrap();
        client.process().unwrap();
    }
    assert!(!client.is_handshaking());
    assert_eq!(client.alpn(), Some("h2"));
}

#[test]
fn a_server_that_echoes_a_different_session_id_is_rejected() {
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    let hello_bytes = client.take_output();

    let mut server = TestServer::new(ServerOptions::new());
    server.feed(&hello_bytes);
    let mut out = server.take_output();

    // Заголовок записи 5 байт, заголовок сообщения 4, версия 2, random 32,
    // затем длина session_id и он сам.
    let session_id_at = 5 + 4 + 2 + 32 + 1;
    out[session_id_at] ^= 0xff;

    client.read_tls(&out).unwrap();
    assert!(matches!(client.process(), Err(Error::Protocol(_))));
}

#[test]
fn a_server_that_stays_on_tls12_is_reported_as_such() {
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    let hello = ClientHello::parse(&client.take_output()[5..]).unwrap();

    // ServerHello без supported_versions — так отвечает сервер TLS 1.2.
    let body = server_hello_body([0x5a; 32], &hello.session_id, 0x1301, &[]);
    let message = build_message(HandshakeType::ServerHello, &body).unwrap();
    client.read_tls(&plaintext_record(&message)).unwrap();

    assert!(
        matches!(client.process(), Err(Error::Unsupported(_))),
        "диагноз обязан быть про версию, а не про session_id"
    );
}

#[test]
fn a_plaintext_alert_before_the_keys_is_surfaced() {
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    let _ = client.take_output();
    // fatal(2), handshake_failure(40)
    client
        .read_tls(&[21, 0x03, 0x03, 0x00, 0x02, 0x02, 40])
        .unwrap();
    assert_eq!(client.process(), Err(Error::Alert(40)));
}

#[test]
fn hello_retry_request_twice_is_refused() {
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    let hello = ClientHello::parse(&client.take_output()[5..]).unwrap();

    let retry = |session_id: &[u8]| {
        let extensions = vec![
            raw_extension(ext::SUPPORTED_VERSIONS, &0x0304_u16.to_be_bytes()),
            raw_extension(ext::KEY_SHARE, &Group::X25519.code().to_be_bytes()),
        ];
        let body = server_hello_body(HELLO_RETRY_REQUEST_RANDOM, session_id, 0x1301, &extensions);
        plaintext_record(&build_message(HandshakeType::ServerHello, &body).unwrap())
    };

    // Клиент предлагает обе группы, поэтому запрос x25519 сам по себе
    // недопустим — сервер просит долю, которая уже прислана.
    client.read_tls(&retry(&hello.session_id)).unwrap();
    assert!(matches!(client.process(), Err(Error::Protocol(_))));
}

#[test]
fn the_reference_server_hello_is_still_parsed_the_same_way() {
    // Страховка от того, что правки автомата поломают разбор.
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    let hello = ClientHello::parse(&client.take_output()[5..]).unwrap();
    let extensions = vec![
        raw_extension(ext::SUPPORTED_VERSIONS, &0x0304_u16.to_be_bytes()),
        raw_extension(ext::KEY_SHARE, &[0x00, 0x1d, 0x00, 0x20]),
    ];
    let body = server_hello_body([1; 32], &hello.session_id, 0x1301, &extensions);
    let parsed = ServerHello::parse(&body).unwrap();
    assert_eq!(parsed.selected_version(), Some(0x0304));
    assert!(!parsed.is_hello_retry_request());
}

#[test]
fn a_verifier_can_be_used_only_for_measurement() {
    // AcceptAnyServer существует и работает — но только для разведки.
    let config = ClientConfig::new("example.org").with_verifier(Box::new(AcceptAnyServer));
    let (client, server) = handshake(ServerOptions::new(), config);
    assert!(server.finished);
    assert!(!client.is_handshaking());
}

#[test]
fn the_second_hello_is_preceded_by_change_cipher_spec() {
    // Проверка самой раскладки байт второй пачки: сначала запись
    // совместимости, потом приветствие. Тест на смещения, от которых
    // зависит разбор в соседних тестах.
    let mut client = Connection::new({
        let mut config = ClientConfig::new("example.org");
        config.groups = vec![Group::X25519];
        config
    })
    .unwrap();
    let first = ClientHello::parse(&client.take_output()[5..]).unwrap();

    let mut server = TestServer::new(ServerOptions {
        retry_to: Some(Group::X25519MlKem768),
        ..ServerOptions::new()
    });
    server.feed(&plaintext_record(&first.to_handshake().unwrap()));
    let retry = server.take_output();
    client.read_tls(&retry).unwrap();
    client.process().unwrap();

    let out = client.take_output();
    assert_eq!(
        &out[..6],
        &[20, 0x03, 0x03, 0x00, 0x01, 0x01],
        "первой идёт запись change_cipher_spec"
    );
    assert_eq!(out[6], 22, "затем запись рукопожатия");
    assert_eq!(out[11], 1, "и в ней ClientHello");
}

#[test]
fn a_plaintext_alert_after_the_keys_is_refused() {
    // До установки ключей открытое предупреждение — единственный способ
    // сервера объяснить отказ, и его надо понимать. После установки
    // ключей всё зашифрованное помечено снаружи как `application_data`,
    // поэтому открытая запись здесь означает вставку в поток. Принимать
    // её значило бы дать любому, кто способен вклиниться в TCP, гасить
    // соединение одним пакетом с убедительной причиной.
    let (mut client, _) = handshake(ServerOptions::new(), ClientConfig::new("example.org"));
    client
        .read_tls(&[21, 0x03, 0x03, 0x00, 0x02, 0x02, 80])
        .unwrap();
    assert_eq!(
        client.process(),
        Err(Error::Protocol("открытая запись после установки ключей"))
    );
}

#[test]
fn an_error_is_terminal_and_keeps_its_diagnosis() {
    // Любая ошибка разбора в TLS терминальна. Живой автомат после неё
    // означал бы право противника на вторую попытку в том же соединении.
    let (mut client, _) = handshake(ServerOptions::new(), ClientConfig::new("example.org"));
    client
        .read_tls(&[21, 0x03, 0x03, 0x00, 0x02, 0x02, 80])
        .unwrap();
    let first = client.process().unwrap_err();

    assert!(!client.is_handshaking());
    assert_eq!(client.failure(), Some(first));
    assert_eq!(
        client.process(),
        Err(first),
        "повторный вызов обязан вернуть ту же ошибку, а не новую"
    );
    assert_eq!(client.send(b"posle".as_slice()), Err(first));
    assert_eq!(client.read_tls("ещё байты".as_bytes()), Err(first));
}

#[test]
fn a_dead_connection_does_not_keep_parsing() {
    // Конкретный сценарий: сервер прислал непонятный шифронабор. Раньше
    // автомат оставался жив и на следующей записи выдавал уже другой
    // диагноз, продолжая разбирать недоверенный ввод.
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    let hello = ClientHello::parse(&client.take_output()[5..]).unwrap();

    let extensions = vec![
        raw_extension(ext::SUPPORTED_VERSIONS, &0x0304_u16.to_be_bytes()),
        raw_extension(ext::KEY_SHARE, &[0x00, 0x1d, 0x00, 0x20]),
    ];
    let body = server_hello_body([0x5a; 32], &hello.session_id, 0xffff, &extensions);
    let record = plaintext_record(&build_message(HandshakeType::ServerHello, &body).unwrap());

    client.read_tls(&record).unwrap();
    let first = client.process().unwrap_err();
    assert!(matches!(first, Error::Unsupported(_)), "{first:?}");

    // Тот же ввод ещё раз: ответ обязан не измениться.
    assert_eq!(client.read_tls(&record), Err(first));
    assert_eq!(client.process(), Err(first));
}

#[test]
fn the_client_survives_arbitrary_garbage() {
    // Вход клиента — данные противника. Паниковать нельзя ни на чём.
    for seed in 0_u16..=600 {
        let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
        let _ = client.take_output();
        let noise: Vec<u8> = (0..(seed % 400))
            .map(|i| (i.wrapping_mul(seed) ^ 0x5b) as u8)
            .collect();
        let _ = client.read_tls(&noise);
        let _ = client.process();
    }
}

#[test]
fn a_flood_without_a_complete_record_is_bounded() {
    let mut client = Connection::new(ClientConfig::new("example.org")).unwrap();
    let _ = client.take_output();
    // Заголовок обещает больше, чем когда-либо придёт.
    let mut outcome = Ok(());
    for _ in 0..2000 {
        if outcome.is_err() {
            break;
        }
        outcome = client.read_tls(&[22; 4096]);
    }
    assert!(outcome.is_err(), "буфер обязан иметь предел");
}

/// Канал, отдающий пачку сервера **одним куском**, как это делает любое
/// промежуточное звено: туннель, прокси, да и просто TCP при удачном
/// стечении. Прямому соединению склейка почти не грозит, и потому
/// ошибки такого рода живут долго и всплывают только в поле.
struct BatchingPipe {
    server: TestServer,
    to_client: Vec<u8>,
    consumed: usize,
}

impl std::io::Read for BatchingPipe {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let rest = self.to_client.get(self.consumed..).unwrap_or_default();
        if rest.is_empty() {
            return Ok(0);
        }
        let take = rest.len().min(out.len());
        out[..take].copy_from_slice(&rest[..take]);
        self.consumed += take;
        Ok(take)
    }
}

impl std::io::Write for BatchingPipe {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.server.feed(data);
        let batch = self.server.take_output();
        self.to_client.extend_from_slice(&batch);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn application_data_glued_to_the_handshake_is_not_lost() {
    use std::io::Read as _;

    // Регрессия. Рукопожатие расшифровывало прикладные данные, пришедшие
    // в одном чтении с последней пачкой сервера, и молча выбрасывало их:
    // чтение начиналось с пустого буфера и уходило блокироваться на
    // сокете, а отправитель считал, что всё доставил.
    const EARLY: &[u8] = b"dannye srazu za rukopozhatiem";

    let pipe = BatchingPipe {
        server: TestServer::new(ServerOptions {
            early_data: Some(EARLY),
            ..ServerOptions::new()
        }),
        to_client: Vec::new(),
        consumed: 0,
    };

    let mut stream =
        atlas_tls::TlsStream::connect(pipe, ClientConfig::new("example.org")).expect("рукопожатие");

    let mut got = Vec::new();
    let mut buf = [0_u8; 256];
    while let Ok(read) = stream.read(&mut buf) {
        if read == 0 {
            break;
        }
        got.extend_from_slice(&buf[..read]);
    }

    assert_eq!(
        got, EARLY,
        "данные, склеенные с рукопожатием, обязаны дойти"
    );
}

/// Список ALPN из настроек обязан доходить до провода.
///
/// Полевая ошибка: `ClientConfig::with_alpn` молча ничего не делал —
/// приветствие собиралось из умолчания профиля. Вызывающий просил
/// `http/1.1`, сервер выбирал `h2` из списка, которого никто не хотел,
/// и дальше собеседники говорили на разных языках: рукопожатие
/// проходило, запрос уходил, ответа не было никогда.
#[test]
fn configured_alpn_reaches_the_wire() {
    let config = ClientConfig::new("example.org").with_alpn(vec!["http/1.1".to_owned()]);
    let mut client = Connection::new(config).expect("клиент");
    let hello = ClientHello::parse(&client.take_output()[5..]).unwrap();

    assert_eq!(
        hello.alpn(),
        vec!["http/1.1".to_owned()],
        "в приветствии обязан быть ровно тот список, о котором просили"
    );
}

/// Пустой список ALPN — ошибка настройки, а не приветствие без расширения.
#[test]
fn empty_alpn_is_refused_up_front() {
    let config = ClientConfig::new("example.org").with_alpn(Vec::new());
    assert!(Connection::new(config).is_err());
}

/// Сервер не вправе выбрать протокол, которого мы не предлагали.
///
/// Тестовый сервер всегда отвечает `h2`; клиент предлагает только
/// `http/1.1`. RFC 7301 §3.2 такой ответ запрещает, и молча принимать
/// его нельзя: это ровно тот случай, когда соединение поднимается, а
/// говорить по нему не о чем.
#[test]
fn alpn_outside_our_offer_is_rejected() {
    let config = ClientConfig::new("example.org").with_alpn(vec!["http/1.1".to_owned()]);
    let mut client = Connection::new(config).expect("клиент");
    let mut server = TestServer::new(ServerOptions::new());

    let mut failure = None;
    for _ in 0..8 {
        let from_client = client.take_output();
        if !from_client.is_empty() {
            server.feed(&from_client);
        }
        let from_server = server.take_output();
        if from_server.is_empty() && from_client.is_empty() {
            break;
        }
        if !from_server.is_empty() {
            client.read_tls(&from_server).expect("приём");
            if let Err(error) = client.process() {
                failure = Some(error);
                break;
            }
        }
    }

    let error = failure.expect("чужой ALPN обязан оборвать рукопожатие");
    assert!(
        matches!(error, Error::Protocol(text) if text.contains("ALPN")),
        "ожидалась жалоба на ALPN, получено: {error:?}"
    );
}
