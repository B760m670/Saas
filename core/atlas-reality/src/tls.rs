//! Связка REALITY с клиентом TLS.
//!
//! Два конца одной верёвки. На исходящей стороне метка запечатывается в
//! готовое приветствие; на входящей — сервер обязан доказать, что знает
//! тот же общий секрет. Между ними лежит ключ, который вычисляется один
//! раз при печати и передаётся проверке через [`AuthKey`].
//!
//! # Что проверяется вместо цепочки сертификатов
//!
//! Настоящая цепочка сервера прикрытия всегда валидна и не доказывает
//! ничего: любой может поставить перед собой чужой сайт. Точка выхода
//! доказывает себя иначе — присылает временный сертификат с ключом
//! Ed25519, в поле подписи которого лежит не подпись, а
//! `HMAC-SHA512(authKey, открытый_ключ)`. Вычислить это значение может
//! только тот, кто знает приватный ключ точки: `authKey` выведен из
//! обмена нашей эфемерной доли с ним.
//!
//! Совпадение длин не случайно: `HMAC-SHA512` и подпись Ed25519 — по
//! шестьдесят четыре байта, поэтому подделка проходит любую проверку
//! формы и отличима только знанием секрета.
//!
//! # Постквантовая проверка
//!
//! При заданном ключе ML-DSA-65 сервер обязан дополнительно подписать
//! `HMAC-SHA512(authKey, открытый_ключ ‖ ClientHello ‖ ServerHello)` и
//! положить подпись в первое расширение сертификата. Это привязывает
//! доказательство к конкретному рукопожатию и переживает появление
//! квантовой машины: `HMAC` остаётся стойким, а подпись перестаёт
//! зависеть от стойкости X25519.
//!
//! # Чего эта проверка не даёт
//!
//! Она **не** отличает «за адресом настоящий сайт» от «нас
//! перенаправили»: в обоих случаях сертификат просто не проходит
//! проверку. Различать их клиент не должен — снаружи эти случаи и не
//! различаются, в этом и смысл REALITY.

use std::sync::{Arc, Mutex, OnceLock};

use hmac::{KeyInit as _, Mac as _, SimpleHmac};
use sha2::Sha512;

use atlas_tls::client::{HelloSealer, PeerIdentity, ServerVerifier};
use atlas_tls::keyexchange::KeyShares;
use atlas_tls::profile::{X25519, X25519_MLKEM768};

use crate::auth;
use crate::cert::TemporaryCertificate;
use crate::marker::{Marker, SHORT_ID_LEN};
use crate::{Error, Result};

/// Ключ, вычисленный при печати метки и нужный при проверке сервера.
///
/// Печать и проверка происходят в разное время и в разных местах
/// клиента, поэтому ключ передаётся через общую ячейку, а не через
/// возвращаемое значение. Записывается ровно один раз.
#[derive(Debug, Clone, Default)]
pub struct AuthKey(Arc<OnceLock<[u8; 32]>>);

impl AuthKey {
    /// Создать пустую ячейку.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Значение, если печать уже состоялась.
    #[must_use]
    pub fn get(&self) -> Option<[u8; 32]> {
        self.0.get().copied()
    }

    /// Заполнить ячейку заранее известным значением.
    ///
    /// Клиенту это не нужно — он получает ключ из печати метки. Нужно
    /// **точке выхода**: она вычисляет тот же ключ из своей приватной
    /// части и доли клиента, и по нему строит временный сертификат.
    #[must_use]
    pub fn from_shared(value: [u8; 32]) -> Self {
        let cell = Self::default();
        cell.set(value);
        cell
    }

    fn set(&self, value: [u8; 32]) {
        let _ = self.0.set(value);
    }
}

/// Печать метки в готовое приветствие.
#[derive(Debug, Clone)]
pub struct Sealer {
    server_public: [u8; 32],
    short_id: [u8; SHORT_ID_LEN],
    version: [u8; 3],
    timestamp: u32,
    key: AuthKey,
}

impl Sealer {
    /// Создать печать.
    ///
    /// `timestamp` — текущее время в секундах эпохи. Оно передаётся
    /// снаружи, а не берётся из системных часов: крейт не должен зависеть
    /// от источника времени, а тесты обязаны быть воспроизводимыми.
    ///
    /// # Errors
    ///
    /// [`Error::ShortIdTooLong`], если идентификатор длиннее восьми байт.
    pub fn new(
        server_public: [u8; 32],
        short_id: &[u8],
        version: [u8; 3],
        timestamp: u32,
    ) -> Result<Self> {
        Ok(Self {
            server_public,
            short_id: Marker::new(version, 0, short_id)?.short_id,
            version,
            timestamp,
            key: AuthKey::new(),
        })
    }

    /// Ячейка с ключом — её же получает проверка сервера.
    #[must_use]
    pub fn auth_key(&self) -> AuthKey {
        self.key.clone()
    }
}

impl HelloSealer for Sealer {
    fn seal(&self, handshake: &mut [u8], shares: &KeyShares) -> atlas_tls::Result<()> {
        // Классическая доля, а при её отсутствии — половина X25519
        // внутри гибридной. Такой же порядок у эталонной реализации: она
        // сперва ищет группу `x25519`, и лишь потом лезет в гибрид.
        // Отдельной пары для REALITY не заводится — иначе на проводе
        // появился бы открытый ключ, которого у браузера не бывает.
        let exchange = shares
            .find(X25519)
            .or_else(|| shares.find(X25519_MLKEM768))
            .ok_or(atlas_tls::Error::Protocol(
                "REALITY: в приветствии нет доли x25519",
            ))?;

        let secret = exchange.agree_x25519(&self.server_public)?;

        let random = auth::random_of_public(handshake)
            .map_err(|_| atlas_tls::Error::Malformed("REALITY: приветствие не той формы"))?;
        let key = auth::derive_auth_key(&secret, &random);
        self.key.set(key);

        let marker = Marker {
            version: self.version,
            timestamp: self.timestamp,
            short_id: self.short_id,
        };
        auth::seal(handshake, &key, marker)
            .map_err(|_| atlas_tls::Error::Malformed("REALITY: метка не запечаталась"))
    }
}

/// Проверка сервера по общему секрету вместо цепочки сертификатов.
#[derive(Debug, Clone)]
pub struct Verifier {
    key: AuthKey,
    mldsa65: Option<Vec<u8>>,
}

impl Verifier {
    /// Создать проверку, привязанную к ячейке ключа.
    #[must_use]
    pub const fn new(key: AuthKey) -> Self {
        Self { key, mldsa65: None }
    }

    /// Потребовать дополнительную подпись ML-DSA-65.
    ///
    /// Аргумент — открытый ключ точки выхода в постквантовой схеме. Без
    /// него подлинность держится только на X25519, то есть на
    /// доквантовом предположении.
    #[must_use]
    pub fn with_post_quantum(mut self, public_key: Vec<u8>) -> Self {
        self.mldsa65 = Some(public_key);
        self
    }
}

impl ServerVerifier for Verifier {
    fn verify(&self, peer: &PeerIdentity<'_>) -> atlas_tls::Result<()> {
        let outcome = self.check(peer);
        // Наружу уходит одна и та же ошибка независимо от причины:
        // «сертификат не разобрался», «ключ не Ed25519» и «HMAC не
        // сошёлся» снаружи обязаны выглядеть одинаково.
        outcome.map_err(|_| atlas_tls::Error::Untrusted("REALITY: сервер не наша точка выхода"))
    }
}

impl Verifier {
    fn check(&self, peer: &PeerIdentity<'_>) -> Result<()> {
        let key = self.key.get().ok_or(Error::NotOurServer)?;
        let der = peer.certificate.end_entity().ok_or(Error::NotOurServer)?;
        let certificate = TemporaryCertificate::parse(der)?;

        let Ok(mut mac) = SimpleHmac::<Sha512>::new_from_slice(&key) else {
            return Err(Error::NotOurServer);
        };
        mac.update(&certificate.public_key);

        // Значение снимается с копии: тот же самый HMAC продолжается
        // дальше записями рукопожатия для постквантовой проверки.
        let expected = mac.clone().finalize().into_bytes();
        if !constant_time_eq(&expected, &certificate.signature) {
            return Err(Error::NotOurServer);
        }

        let Some(public_key) = self.mldsa65.as_ref() else {
            return Ok(());
        };

        // Постквантовая половина: тот же HMAC, продолженный записями
        // рукопожатия, подписан ключом ML-DSA-65 и лежит в расширении.
        let extension = certificate
            .first_extension
            .as_ref()
            .ok_or(Error::NotOurServer)?;
        mac.update(peer.client_hello);
        mac.update(peer.server_hello);
        let message = mac.finalize().into_bytes();

        let verifying = atlas_crypto::sign::PostQuantumKey::from_bytes(public_key)
            .map_err(|_| Error::NotOurServer)?;
        if verifying.verify(&message, extension) {
            Ok(())
        } else {
            Err(Error::NotOurServer)
        }
    }
}

/// Сравнение, не зависящее от места первого расхождения.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Источник временного сертификата для серверной стороны TLS.
///
/// Точка выхода не имеет своего сертификата и не может его иметь: любой
/// выпущенный на её имя документ попал бы в журналы прозрачности и стал
/// бы поводом для блокировки. Вместо этого она порождает сертификат
/// заново на каждое соединение — из метки, которую клиент спрятал в
/// `session_id`, и из своего приватного ключа.
///
/// # Что происходит с чужими
///
/// Отказ означает, что метка не открылась: перед нами не наш клиент, а
/// зонд, сканер или случайный браузер. Вызывающий обязан поступить с
/// таким соединением так же, как поступил бы сайт прикрытия, — то есть
/// проксировать его туда без изменений. Именно на этом держится
/// неотличимость: посторонний видит настоящий чужой сайт, потому что
/// перед ним и есть настоящий чужой сайт.
#[derive(Debug)]
pub struct Certificates {
    /// Серверная сторона REALITY. Под замком, потому что окно повторов
    /// изменяется на каждом соединении, а соединения приходят
    /// одновременно.
    server: Mutex<crate::Server>,
    /// Имя, которое ставится в сертификат.
    common_name: String,
    /// Ключ ML-DSA-65 для постквантового подтверждения, если включено.
    post_quantum: Option<Arc<atlas_crypto::sign::SigningKey>>,
}

impl Certificates {
    /// Создать источник поверх серверной стороны REALITY.
    ///
    /// `common_name` — обычно домен сайта прикрытия: сертификат видит
    /// только наш клиент, и то не проверяет имя, но правдоподобное
    /// значение ничего не стоит.
    #[must_use]
    pub fn new(server: crate::Server, common_name: impl Into<String>) -> Self {
        Self {
            server: Mutex::new(server),
            common_name: common_name.into(),
            post_quantum: None,
        }
    }

    /// Подписывать сертификат ещё и ключом ML-DSA-65.
    #[must_use]
    pub fn with_post_quantum(mut self, key: Arc<atlas_crypto::sign::SigningKey>) -> Self {
        self.post_quantum = Some(key);
        self
    }
}

impl atlas_tls::server::CertificateSource for Certificates {
    fn accept(
        &self,
        hello: &atlas_tls::ClientHello,
        raw: &[u8],
    ) -> atlas_tls::Result<Box<dyn atlas_tls::server::Pending>> {
        let client_public = client_x25519(hello)
            .ok_or(atlas_tls::Error::Untrusted("в приветствии нет доли x25519"))?;

        let now = crate::now_seconds();
        let mut server = self
            .server
            .lock()
            .map_err(|_| atlas_tls::Error::Untrusted("состояние точки выхода повреждено"))?;

        // Метка либо открывается нашим ключом, либо нет. Третьего не
        // дано, и подробностей наружу не уходит: различать «не тот
        // ключ», «не тот shortId» и «повтор» — значит дать зонду оракул.
        server
            .authenticate(raw, &client_public, now)
            .map_err(|_| atlas_tls::Error::Untrusted("метка не наша"))?;
        let auth_key = server
            .auth_key_for(raw, &client_public)
            .map_err(|_| atlas_tls::Error::Untrusted("общий ключ не выводится"))?;
        drop(server);

        Ok(Box::new(PendingCertificate {
            auth_key,
            client_hello: raw.to_vec(),
            common_name: self.common_name.clone(),
            now,
            post_quantum: self.post_quantum.clone(),
        }))
    }
}

/// Клиент признан своим; осталось дождаться `ServerHello`.
#[derive(Debug)]
struct PendingCertificate {
    auth_key: [u8; 32],
    client_hello: Vec<u8>,
    common_name: String,
    now: u32,
    post_quantum: Option<Arc<atlas_crypto::sign::SigningKey>>,
}

impl atlas_tls::server::Pending for PendingCertificate {
    fn finish(
        self: Box<Self>,
        server_hello: &[u8],
    ) -> atlas_tls::Result<atlas_tls::server::Credentials> {
        // Ключ Ed25519 — свой на каждое соединение. Эталонная
        // реализация держит его константой в коде; свежий не хуже и не
        // лучше по стойкости (подлинность доказывает `HMAC`, а не он),
        // зато не превращает утечку одной константы в общую для всех.
        let key = atlas_crypto::sign::ClassicKey::generate();
        let public_key = key.public_key();

        let Ok(mut mac) = SimpleHmac::<Sha512>::new_from_slice(&self.auth_key) else {
            return Err(atlas_tls::Error::Untrusted("HMAC не заводится"));
        };
        mac.update(&public_key);
        let signature = mac.clone().finalize().into_bytes().to_vec();

        // Постквантовая подпись покрывает оба приветствия — потому её и
        // нельзя было сделать раньше, до сборки ответа.
        let extension = self.post_quantum.as_ref().map(|signing| {
            mac.update(&self.client_hello);
            mac.update(server_hello);
            let message = mac.finalize().into_bytes();
            signing.sign_post_quantum(&message)
        });

        let certificate = crate::cert::issue::temporary_certificate(
            &public_key,
            &self.common_name,
            self.now,
            &signature,
            extension.as_deref(),
        );

        Ok(atlas_tls::server::Credentials {
            chain: vec![certificate],
            key,
        })
    }
}

/// Открытый ключ `x25519` клиента из расширения `key_share`.
///
/// Тот же порядок, что и на клиентской стороне: классическая доля
/// первой, половина гибридной — запасным вариантом.
fn client_x25519(hello: &atlas_tls::ClientHello) -> Option<[u8; 32]> {
    use atlas_tls::bytes::Reader;

    let extension = hello.extension(atlas_tls::ext::KEY_SHARE)?;
    let mut outer = Reader::new(&extension.body);
    let mut list = Reader::new(outer.vec_u16().ok()?);

    let mut classic = None;
    let mut hybrid = None;
    while !list.is_empty() {
        let group = list.u16().ok()?;
        let share = list.vec_u16().ok()?;
        if group == X25519 && share.len() == 32 {
            classic = share.try_into().ok();
        } else if group == X25519_MLKEM768 && share.len() == 1216 {
            hybrid = share.get(1184..).and_then(|tail| tail.try_into().ok());
        }
    }
    classic.or(hybrid)
}
