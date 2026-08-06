//! Приёмка сервера по общему секрету вместо цепочки сертификатов.
//!
//! Проверяется то, ради чего REALITY существует: клиент отличает **свою**
//! точку выхода от настоящего сайта прикрытия, стоящего по тому же
//! адресу, — и не по цепочке сертификатов, которая у сайта прикрытия
//! безупречна, а по знанию общего секрета.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use hmac::{KeyInit as _, Mac as _, SimpleHmac};
use sha2::Sha512;

use atlas_reality::cert::ED25519_PUBLIC_LEN;
use atlas_reality::tls::{AuthKey, Verifier};
use atlas_tls::client::{PeerIdentity, ServerVerifier};
use atlas_tls::handshake::{Certificate, CertificateVerify};

const AUTH_KEY: [u8; 32] = [0x5a; 32];
const CLIENT_HELLO: &[u8] = b"client hello bytes";
const SERVER_HELLO: &[u8] = b"server hello bytes";

// ── Сборка временного сертификата, как его делает точка выхода ───────

fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(u8::try_from(value.len()).unwrap());
    } else if value.len() < 0x100 {
        out.extend([0x81, u8::try_from(value.len()).unwrap()]);
    } else {
        let len = u16::try_from(value.len()).unwrap().to_be_bytes();
        out.extend([0x82, len[0], len[1]]);
    }
    out.extend_from_slice(value);
    out
}

fn bit_string(value: &[u8]) -> Vec<u8> {
    let mut body = vec![0_u8];
    body.extend_from_slice(value);
    der(0x03, &body)
}

/// Временный сертификат: ключ Ed25519 и произвольное значение подписи.
fn certificate(
    public_key: &[u8; ED25519_PUBLIC_LEN],
    signature: &[u8],
    extension: Option<&[u8]>,
) -> Vec<u8> {
    const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

    let mut tbs = Vec::new();
    tbs.extend(der(0xa0, &der(0x02, &[0x02])));
    tbs.extend(der(0x02, &[0x01, 0x23]));
    tbs.extend(der(0x30, &OID_ED25519));
    tbs.extend(der(0x30, &der(0x31, &[])));
    tbs.extend(der(0x30, &[]));
    tbs.extend(der(0x30, &der(0x31, &[])));

    let mut spki = Vec::new();
    spki.extend(der(0x30, &OID_ED25519));
    spki.extend(bit_string(public_key));
    tbs.extend(der(0x30, &spki));

    if let Some(value) = extension {
        let mut entry = Vec::new();
        entry.extend(der(0x06, &[0x55, 0x1d, 0x0e]));
        entry.extend(der(0x04, value));
        tbs.extend(der(0xa3, &der(0x30, &der(0x30, &entry))));
    }

    let mut body = Vec::new();
    body.extend(der(0x30, &tbs));
    body.extend(der(0x30, &OID_ED25519));
    body.extend(bit_string(signature));
    der(0x30, &body)
}

/// Сообщение `Certificate` вокруг одного DER.
fn certificate_message(der_bytes: &[u8]) -> Certificate {
    let mut body = vec![0_u8]; // пустой контекст запроса
    let entry_len = u32::try_from(der_bytes.len()).unwrap().to_be_bytes();
    let mut list = Vec::new();
    list.extend(&entry_len[1..]);
    list.extend_from_slice(der_bytes);
    list.extend([0x00, 0x00]); // пустые расширения записи

    let list_len = u32::try_from(list.len()).unwrap().to_be_bytes();
    body.extend(&list_len[1..]);
    body.extend(list);

    Certificate::parse(&body).unwrap()
}

/// Подпись, которую кладёт в сертификат настоящая точка выхода.
fn reality_signature(auth_key: &[u8; 32], public_key: &[u8; ED25519_PUBLIC_LEN]) -> Vec<u8> {
    let mut mac = SimpleHmac::<Sha512>::new_from_slice(auth_key).unwrap();
    mac.update(public_key);
    mac.finalize().into_bytes().to_vec()
}

/// Сообщение, которое точка выхода подписывает ключом ML-DSA-65.
fn post_quantum_message(
    auth_key: &[u8; 32],
    public_key: &[u8; ED25519_PUBLIC_LEN],
    client_hello: &[u8],
    server_hello: &[u8],
) -> Vec<u8> {
    let mut mac = SimpleHmac::<Sha512>::new_from_slice(auth_key).unwrap();
    mac.update(public_key);
    mac.update(client_hello);
    mac.update(server_hello);
    mac.finalize().into_bytes().to_vec()
}

fn ready_key(value: [u8; 32]) -> AuthKey {
    AuthKey::from_shared(value)
}

fn check(verifier: &Verifier, certificate: &Certificate) -> atlas_tls::Result<()> {
    let verify = CertificateVerify {
        algorithm: 0x0807,
        signature: vec![0x11; 64],
    };
    verifier.verify(&PeerIdentity {
        server_name: "www.microsoft.com",
        certificate,
        certificate_verify: &verify,
        transcript_hash: &[0x22; 32],
        client_hello: CLIENT_HELLO,
        server_hello: SERVER_HELLO,
    })
}

// ── Тесты ────────────────────────────────────────────────────────────

#[test]
fn our_exit_point_is_recognised() {
    let public_key = [0x77_u8; ED25519_PUBLIC_LEN];
    let signature = reality_signature(&AUTH_KEY, &public_key);
    let message = certificate_message(&certificate(&public_key, &signature, None));

    let verifier = Verifier::new(ready_key(AUTH_KEY));
    assert!(
        check(&verifier, &message).is_ok(),
        "своя точка обязана пройти"
    );
}

#[test]
fn a_real_certificate_of_the_cover_site_is_refused() {
    // Настоящий сайт прикрытия предъявляет валидную цепочку — и именно
    // поэтому не проходит: подписи по общему секрету у него нет.
    let public_key = [0x77_u8; ED25519_PUBLIC_LEN];
    let message = certificate_message(&certificate(&public_key, &[0x42; 64], None));

    let verifier = Verifier::new(ready_key(AUTH_KEY));
    assert!(check(&verifier, &message).is_err());
}

#[test]
fn a_wrong_auth_key_is_refused() {
    // Тот же сертификат, но клиент договорился о другом секрете —
    // значит, между нами кто-то есть.
    let public_key = [0x77_u8; ED25519_PUBLIC_LEN];
    let signature = reality_signature(&AUTH_KEY, &public_key);
    let message = certificate_message(&certificate(&public_key, &signature, None));

    let verifier = Verifier::new(ready_key([0x5b; 32]));
    assert!(check(&verifier, &message).is_err());
}

#[test]
fn a_signature_for_another_key_is_refused() {
    // Подпись честная, но сделана для другого открытого ключа: попытка
    // переиспользовать перехваченное значение.
    let public_key = [0x77_u8; ED25519_PUBLIC_LEN];
    let stolen = reality_signature(&AUTH_KEY, &[0x88; ED25519_PUBLIC_LEN]);
    let message = certificate_message(&certificate(&public_key, &stolen, None));

    let verifier = Verifier::new(ready_key(AUTH_KEY));
    assert!(check(&verifier, &message).is_err());
}

#[test]
fn a_verification_before_the_marker_was_sealed_is_refused() {
    // Ключ не вычислен — значит, печати не было. Принимать сервер не на
    // чем.
    let public_key = [0x77_u8; ED25519_PUBLIC_LEN];
    let signature = reality_signature(&AUTH_KEY, &public_key);
    let message = certificate_message(&certificate(&public_key, &signature, None));

    let verifier = Verifier::new(AuthKey::new());
    assert!(check(&verifier, &message).is_err());
}

#[test]
fn every_single_bit_of_the_signature_matters() {
    let public_key = [0x77_u8; ED25519_PUBLIC_LEN];
    let signature = reality_signature(&AUTH_KEY, &public_key);
    let verifier = Verifier::new(ready_key(AUTH_KEY));

    for index in 0..signature.len() {
        for bit in [0x01_u8, 0x80] {
            let mut spoiled = signature.clone();
            spoiled[index] ^= bit;
            let message = certificate_message(&certificate(&public_key, &spoiled, None));
            assert!(
                check(&verifier, &message).is_err(),
                "байт {index}, бит {bit:#04x}"
            );
        }
    }
}

#[test]
fn the_post_quantum_signature_is_required_when_configured() {
    let public_key = [0x77_u8; ED25519_PUBLIC_LEN];
    let signature = reality_signature(&AUTH_KEY, &public_key);

    let signing = atlas_crypto::sign::SigningKey::generate();
    let pq_public = signing.post_quantum_public_key();

    let message = post_quantum_message(&AUTH_KEY, &public_key, CLIENT_HELLO, SERVER_HELLO);
    let pq_signature = signing.sign_post_quantum(&message);

    let good = certificate_message(&certificate(&public_key, &signature, Some(&pq_signature)));
    let verifier = Verifier::new(ready_key(AUTH_KEY)).with_post_quantum(pq_public.clone());
    assert!(
        check(&verifier, &good).is_ok(),
        "правильная постквантовая подпись обязана пройти"
    );

    // Без расширения — отказ, хотя HMAC сошёлся.
    let missing = certificate_message(&certificate(&public_key, &signature, None));
    assert!(check(&verifier, &missing).is_err());

    // Подпись под другим сообщением — отказ.
    let other = post_quantum_message(&AUTH_KEY, &public_key, b"other hello", SERVER_HELLO);
    let wrong = certificate_message(&certificate(
        &public_key,
        &signature,
        Some(&signing.sign_post_quantum(&other)),
    ));
    assert!(
        check(&verifier, &wrong).is_err(),
        "подпись обязана быть привязана к этому рукопожатию"
    );
}

#[test]
fn without_the_post_quantum_key_the_extension_is_ignored() {
    // Точка выхода может присылать расширение всегда; клиент, которому
    // постквантовый ключ не задан, просто на него не смотрит.
    let public_key = [0x77_u8; ED25519_PUBLIC_LEN];
    let signature = reality_signature(&AUTH_KEY, &public_key);
    let message = certificate_message(&certificate(&public_key, &signature, Some(&[0xff; 100])));

    let verifier = Verifier::new(ready_key(AUTH_KEY));
    assert!(check(&verifier, &message).is_ok());
}

#[test]
fn a_malformed_certificate_gives_the_same_answer_as_a_wrong_one() {
    // Наружу уходит одна ошибка независимо от причины: различать
    // «не разобрался» и «не сошёлся» — значит дать зонду оракул.
    let verifier = Verifier::new(ready_key(AUTH_KEY));

    let public_key = [0x77_u8; ED25519_PUBLIC_LEN];
    let wrong = certificate_message(&certificate(&public_key, &[0x42; 64], None));
    let garbage = certificate_message(&[0x30, 0x03, 0x02, 0x01, 0x00]);

    let a = check(&verifier, &wrong).unwrap_err();
    let b = check(&verifier, &garbage).unwrap_err();
    assert_eq!(a, b);
}
