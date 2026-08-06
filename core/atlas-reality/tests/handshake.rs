//! Сквозной круг REALITY поверх настоящего клиента TLS.
//!
//! Соединяет то, что до сих пор проверялось порознь: печать метки внутри
//! `Connection`, приём метки сервером, вычисление обеими сторонами
//! **одного и того же** ключа и построение на нём временного
//! сертификата, который клиент затем принимает.
//!
//! Ключевое утверждение — общий ключ сходится, хотя стороны приходят к
//! нему разными путями: клиент из секретной части своей доли `x25519` и
//! открытого ключа точки, точка из своего приватного ключа и открытой
//! доли клиента.

// Вход теста — байты, которые он же и породил. Падение на индексе или
// панике здесь и есть желаемое поведение: значит, раскладка разошлась.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use hmac::{KeyInit as _, Mac as _, SimpleHmac};
use sha2::Sha512;

use atlas_reality::tls::{Sealer, Verifier};
use atlas_reality::Server;
use atlas_tls::bytes::Reader;
use atlas_tls::client::{ClientConfig, Connection, PeerIdentity, ServerVerifier};
use atlas_tls::fingerprint::{ja4, Transport};
use atlas_tls::handshake::{Certificate, CertificateVerify};
use atlas_tls::{ext, ClientHello};

const SHORT_ID: [u8; 2] = [0xde, 0xad];
const VERSION: [u8; 3] = [26, 3, 27];
const NOW: u32 = 1_800_000_000;
const SNI: &str = "www.microsoft.com";

/// Открытый ключ `x25519` клиента — там, где его берёт настоящий сервер.
fn client_x25519(hello: &ClientHello) -> [u8; 32] {
    let extension = hello
        .extensions
        .iter()
        .find(|e| e.ext_type == ext::KEY_SHARE)
        .unwrap();
    let mut outer = Reader::new(&extension.body);
    let mut list = Reader::new(outer.vec_u16().unwrap());
    while !list.is_empty() {
        let group = list.u16().unwrap();
        let share = list.vec_u16().unwrap();
        if group == atlas_tls::profile::X25519 {
            return share.try_into().unwrap();
        }
    }
    panic!("в приветствии нет доли x25519");
}

/// Собрать временный сертификат, как это делает точка выхода.
fn exit_point_certificate(auth_key: &[u8; 32]) -> Certificate {
    const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(u8::try_from(value.len()).unwrap());
        } else {
            out.extend([0x81, u8::try_from(value.len()).unwrap()]);
        }
        out.extend_from_slice(value);
        out
    }
    fn bit_string(value: &[u8]) -> Vec<u8> {
        let mut body = vec![0_u8];
        body.extend_from_slice(value);
        der(0x03, &body)
    }

    // Одноразовый ключ Ed25519 точки выхода.
    let public_key = [0x4b_u8; 32];
    let mut mac = SimpleHmac::<Sha512>::new_from_slice(auth_key).unwrap();
    mac.update(&public_key);
    let signature = mac.finalize().into_bytes().to_vec();

    let mut tbs = Vec::new();
    tbs.extend(der(0xa0, &der(0x02, &[0x02])));
    tbs.extend(der(0x02, &[0x01]));
    tbs.extend(der(0x30, &OID_ED25519));
    tbs.extend(der(0x30, &[]));
    tbs.extend(der(0x30, &[]));
    tbs.extend(der(0x30, &[]));
    let mut spki = Vec::new();
    spki.extend(der(0x30, &OID_ED25519));
    spki.extend(bit_string(&public_key));
    tbs.extend(der(0x30, &spki));

    let mut body = Vec::new();
    body.extend(der(0x30, &tbs));
    body.extend(der(0x30, &OID_ED25519));
    body.extend(bit_string(&signature));
    let cert = der(0x30, &body);

    let mut message = vec![0_u8];
    let entry_len = u32::try_from(cert.len()).unwrap().to_be_bytes();
    let mut list = Vec::new();
    list.extend(&entry_len[1..]);
    list.extend_from_slice(&cert);
    list.extend([0x00, 0x00]);
    let list_len = u32::try_from(list.len()).unwrap().to_be_bytes();
    message.extend(&list_len[1..]);
    message.extend(list);
    Certificate::parse(&message).unwrap()
}

/// Приветствие, которое реально ушло бы в сеть.
fn sealed_hello(connection: &mut Connection) -> Vec<u8> {
    let output = connection.take_output();
    // Запись: тип, версия, двухбайтовая длина.
    output[5..].to_vec()
}

#[test]
fn the_whole_round_closes() {
    let mut server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let sealer = Sealer::new(server.public_key(), &SHORT_ID, VERSION, NOW).unwrap();
    let key_cell = sealer.auth_key();

    let config = ClientConfig::new(SNI)
        .with_sealer(Box::new(sealer))
        .with_verifier(Box::new(Verifier::new(key_cell.clone())));
    let mut client = Connection::new(config).unwrap();

    let handshake = sealed_hello(&mut client);
    let hello = ClientHello::parse(&handshake).unwrap();

    // Точка выхода принимает метку.
    let client_public = client_x25519(&hello);
    let marker = server
        .authenticate(&handshake, &client_public, NOW)
        .unwrap();
    assert_eq!(marker.version, VERSION);
    assert_eq!(&marker.short_id[..2], &SHORT_ID);

    // И приходит к тому же ключу, что клиент, — разными путями.
    let server_key = server.auth_key_for(&handshake, &client_public).unwrap();
    assert_eq!(
        Some(server_key),
        key_cell.get(),
        "обе стороны обязаны получить один ключ"
    );

    // Построенный на нём сертификат клиент принимает.
    let certificate = exit_point_certificate(&server_key);
    let verify = CertificateVerify {
        algorithm: 0x0807,
        signature: vec![0x11; 64],
    };
    let verifier = Verifier::new(key_cell);
    assert!(verifier
        .verify(&PeerIdentity {
            server_name: SNI,
            certificate: &certificate,
            certificate_verify: &verify,
            transcript_hash: &[0x22; 32],
            client_hello: &handshake,
            server_hello: b"server hello",
        })
        .is_ok());
}

#[test]
fn a_foreign_exit_point_is_not_accepted() {
    // Клиент настроен на одну точку, отвечает другая — с собственным,
    // тоже правильным по форме сертификатом.
    let ours = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let sealer = Sealer::new(ours.public_key(), &SHORT_ID, VERSION, NOW).unwrap();
    let key_cell = sealer.auth_key();

    let config = ClientConfig::new(SNI)
        .with_sealer(Box::new(sealer))
        .with_verifier(Box::new(Verifier::new(key_cell.clone())));
    let mut client = Connection::new(config).unwrap();
    let handshake = sealed_hello(&mut client);

    let mut stranger = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let hello = ClientHello::parse(&handshake).unwrap();
    let client_public = client_x25519(&hello);

    // Чужая точка нашу метку даже не откроет.
    assert!(stranger
        .authenticate(&handshake, &client_public, NOW)
        .is_err());

    // А сертификат, построенный на её ключе, клиент отвергнет.
    let their_key = stranger.auth_key_for(&handshake, &client_public).unwrap();
    let certificate = exit_point_certificate(&their_key);
    let verify = CertificateVerify {
        algorithm: 0x0807,
        signature: vec![0x11; 64],
    };
    assert!(Verifier::new(key_cell)
        .verify(&PeerIdentity {
            server_name: SNI,
            certificate: &certificate,
            certificate_verify: &verify,
            transcript_hash: &[0x22; 32],
            client_hello: &handshake,
            server_hello: b"server hello",
        })
        .is_err());
}

#[test]
fn sealing_inside_the_client_does_not_disturb_the_fingerprint() {
    // Смысл REALITY в том, что метка неотличима от случайного
    // идентификатора сессии. Если бы печать меняла отпечаток, вся
    // маскировка сертификата была бы бессмысленна.
    let server = Server::generate().with_short_id(&SHORT_ID).unwrap();

    let plain = Connection::new(ClientConfig::new(SNI)).unwrap();
    let plain_ja4 = ja4(plain.client_hello(), Transport::Tcp).to_string_full();

    let sealer = Sealer::new(server.public_key(), &SHORT_ID, VERSION, NOW).unwrap();
    let sealed = Connection::new(
        ClientConfig::new(SNI)
            .with_sealer(Box::new(sealer))
            .with_verifier(Box::new(Verifier::new(atlas_reality::AuthKey::new()))),
    )
    .unwrap();

    assert_eq!(
        ja4(sealed.client_hello(), Transport::Tcp).to_string_full(),
        plain_ja4
    );
    assert_eq!(
        sealed.client_hello().session_id.len(),
        32,
        "длина поля обязана остаться браузерной"
    );
}

#[test]
fn a_replayed_hello_is_refused_by_the_exit_point() {
    // Полный круг для защиты от повтора: приветствие, собранное
    // настоящим клиентом, повторённое в окне времени.
    let mut server = Server::generate().with_short_id(&SHORT_ID).unwrap();
    let sealer = Sealer::new(server.public_key(), &SHORT_ID, VERSION, NOW).unwrap();

    let config = ClientConfig::new(SNI)
        .with_sealer(Box::new(sealer.clone()))
        .with_verifier(Box::new(Verifier::new(sealer.auth_key())));
    let mut client = Connection::new(config).unwrap();
    let handshake = sealed_hello(&mut client);

    let hello = ClientHello::parse(&handshake).unwrap();
    let client_public = client_x25519(&hello);

    assert!(server.authenticate(&handshake, &client_public, NOW).is_ok());
    assert!(
        server
            .authenticate(&handshake, &client_public, NOW + 30)
            .is_err(),
        "повтор обязан быть отвергнут"
    );
}
