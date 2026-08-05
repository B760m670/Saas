//! Профили браузеров — наборы, из которых собирается `ClientHello`.
//!
//! Профиль задаёт не только списки значений, но и правила их размещения:
//! где стоят значения GREASE, что перемешивается, а что обязано остаться
//! на месте. Отпечаток определяется всем этим целиком.
//!
//! # Почему расширения перемешиваются
//!
//! Chrome с версии 110 перемешивает порядок расширений при каждом
//! соединении. Фиксированный порядок у нас означал бы постоянный JA3 при
//! браузерном JA4 — сочетание, которого у настоящего Chrome не бывает, и
//! которое само по себе является признаком. Поэтому перемешиваем и мы.

use atlas_crypto::rng::OsRng;

use crate::error::Result;
use crate::ext;
use crate::grease;
use crate::hello::{ClientHello, Extension, LEGACY_VERSION};

/// Группа `X25519MLKEM768` — гибридный постквантовый обмен ключами.
pub const X25519_MLKEM768: u16 = 0x11ec;
/// Группа `x25519`.
pub const X25519: u16 = 0x001d;
/// Группа `secp256r1`.
pub const SECP256R1: u16 = 0x0017;
/// Группа `secp384r1`.
pub const SECP384R1: u16 = 0x0018;

/// Длина, до которой Chrome дополняет `ClientHello`.
const PADDING_TARGET: usize = 512;

/// Шифронаборы Chrome в порядке отправки, без GREASE.
const CHROME_CIPHERS: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];

/// Алгоритмы подписи Chrome. Порядок значим: в JA4 они не сортируются.
const CHROME_SIGNATURE_ALGORITHMS: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// Входные данные для сборки `ClientHello`.
#[derive(Debug, Clone)]
pub struct HelloParams {
    /// Значение SNI. Для REALITY это домен сайта прикрытия.
    pub server_name: String,
    /// Список ALPN.
    pub alpn: Vec<String>,
    /// Записи `key_share`: группа и открытый ключ.
    pub key_shares: Vec<(u16, Vec<u8>)>,
    /// Значение `legacy_session_id`.
    ///
    /// Обычно 32 случайных байта. REALITY помещает сюда зашифрованную
    /// метку, которая снаружи неотличима от случайных данных.
    pub session_id: Vec<u8>,
}

impl HelloParams {
    /// Параметры по умолчанию для указанного имени: ALPN `h2, http/1.1`,
    /// случайный `session_id`, пустой `key_share`.
    #[must_use]
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            key_shares: Vec::new(),
            session_id: OsRng::bytes::<32>().to_vec(),
        }
    }

    /// Задать записи `key_share`.
    #[must_use]
    pub fn with_key_shares(mut self, shares: Vec<(u16, Vec<u8>)>) -> Self {
        self.key_shares = shares;
        self
    }

    /// Задать `legacy_session_id`.
    #[must_use]
    pub fn with_session_id(mut self, session_id: Vec<u8>) -> Self {
        self.session_id = session_id;
        self
    }
}

/// Профиль Chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chrome {
    /// Объявлять ли постквантовую группу `X25519MLKEM768`.
    ///
    /// Соответствует Chrome 124 и новее. Влияет на JA3 (список групп), но
    /// не на JA4 — тот хэширует типы расширений, а не их содержимое.
    pub post_quantum: bool,
    /// Перемешивать ли расширения, как это делает настоящий Chrome.
    ///
    /// Выключается только в тестах, где нужен воспроизводимый порядок.
    pub shuffle: bool,
}

impl Default for Chrome {
    fn default() -> Self {
        Self {
            post_quantum: true,
            shuffle: true,
        }
    }
}

impl Chrome {
    /// Профиль без постквантовой группы — соответствует Chrome до 124.
    #[must_use]
    pub const fn classic() -> Self {
        Self {
            post_quantum: false,
            shuffle: true,
        }
    }

    /// Собрать `ClientHello`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TooLong`], если какое-либо поле не помещается в свою
    /// длину — на практике недостижимо для разумных входных данных.
    pub fn client_hello(&self, params: &HelloParams) -> Result<ClientHello> {
        let groups = if self.post_quantum {
            vec![
                grease::pick(),
                X25519_MLKEM768,
                X25519,
                SECP256R1,
                SECP384R1,
            ]
        } else {
            vec![grease::pick(), X25519, SECP256R1, SECP384R1]
        };

        let alpn: Vec<&str> = params.alpn.iter().map(String::as_str).collect();

        // Середина — всё, кроме обрамляющих GREASE и завершающего padding.
        let mut middle = vec![
            ext::server_name(&params.server_name),
            Extension::empty(ext::EXTENDED_MASTER_SECRET),
            ext::renegotiation_info(),
            ext::supported_groups(&groups),
            ext::ec_point_formats(&[0]),
            Extension::empty(ext::SESSION_TICKET),
            ext::alpn(&alpn),
            ext::status_request(),
            ext::signature_algorithms(&CHROME_SIGNATURE_ALGORITHMS),
            Extension::empty(ext::SIGNED_CERTIFICATE_TIMESTAMP),
            ext::key_share(&params.key_shares),
            ext::psk_key_exchange_modes(&[1]),
            ext::supported_versions(&[grease::pick(), 0x0304, 0x0303]),
            // 2 — brotli, единственный алгоритм, который шлёт Chrome.
            ext::compress_certificate(&[0x0002]),
            ext::application_settings(&["h2"]),
        ];

        if self.shuffle {
            shuffle(&mut middle);
        }

        let mut extensions = Vec::with_capacity(middle.len() + 3);
        extensions.push(Extension::empty(grease::pick()));
        extensions.append(&mut middle);
        extensions.push(Extension::empty(grease::pick()));

        let mut hello = ClientHello {
            legacy_version: LEGACY_VERSION,
            random: OsRng::bytes::<32>(),
            session_id: params.session_id.clone(),
            cipher_suites: with_leading_grease(&CHROME_CIPHERS),
            compression_methods: vec![0],
            extensions,
        };

        // Padding добавляется последним и только если сообщение короче
        // целевой длины — ровно так это делает BoringSSL. Наличие или
        // отсутствие этого расширения меняет счётчик в JA4, поэтому
        // порядок действий здесь важен.
        if let Some(len) = padding_len(&hello)? {
            hello.extensions.push(ext::padding(len));
        }

        Ok(hello)
    }
}

/// Сколько байт добить, чтобы сообщение достигло целевой длины.
///
/// Возвращает `None`, если сообщение уже не короче цели.
fn padding_len(hello: &ClientHello) -> Result<Option<usize>> {
    // Четыре байта заголовка самого расширения: тип и длина.
    const EXTENSION_OVERHEAD: usize = 4;

    let current = hello.to_handshake()?.len();
    Ok((current + EXTENSION_OVERHEAD < PADDING_TARGET)
        .then(|| PADDING_TARGET - current - EXTENSION_OVERHEAD))
}

/// Список шифров с ведущим значением GREASE, как у браузеров.
fn with_leading_grease(ciphers: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(ciphers.len() + 1);
    out.push(grease::pick());
    out.extend_from_slice(ciphers);
    out
}

/// Перемешивание Фишера — Йетса на системном источнике случайности.
fn shuffle(items: &mut [Extension]) {
    for i in (1..items.len()).rev() {
        // Отбрасывание по модулю здесь допустимо: смещение порядка 2^-56
        // на диапазоне до 18 элементов не поддаётся наблюдению.
        let bound = i as u64 + 1;
        let draw = u64::from_le_bytes(OsRng::bytes::<8>()) % bound;
        let j = usize::try_from(draw).unwrap_or(i);
        items.swap(i, j);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fingerprint::{ja3, ja4, Transport};

    fn params() -> HelloParams {
        HelloParams::new("www.microsoft.com")
            .with_key_shares(vec![(X25519, vec![0x11; 32])])
            .with_session_id(vec![0x22; 32])
    }

    #[test]
    fn grease_frames_the_extension_list() {
        let hello = Chrome::default().client_hello(&params()).unwrap();
        let first = hello.extensions.first().unwrap().ext_type;
        assert!(grease::is_grease(first), "первое расширение — GREASE");

        // Последним идёт padding, перед ним — второе значение GREASE.
        let types: Vec<u16> = hello.extensions.iter().map(|e| e.ext_type).collect();
        let greases = types.iter().filter(|t| grease::is_grease(**t)).count();
        assert_eq!(greases, 2);
    }

    #[test]
    fn cipher_list_starts_with_grease() {
        let hello = Chrome::default().client_hello(&params()).unwrap();
        assert!(grease::is_grease(*hello.cipher_suites.first().unwrap()));
        assert_eq!(hello.cipher_suites.len(), CHROME_CIPHERS.len() + 1);
    }

    #[test]
    fn shuffling_changes_order_but_not_ja4() {
        let profile = Chrome::default();
        let mut orders = std::collections::HashSet::new();
        let mut fingerprints = std::collections::HashSet::new();

        for _ in 0..32 {
            let hello = profile.client_hello(&params()).unwrap();
            orders.insert(
                hello
                    .extensions
                    .iter()
                    .map(|e| e.ext_type)
                    .collect::<Vec<_>>(),
            );
            fingerprints.insert(ja4(&hello, Transport::Tcp).to_string_full());
        }

        assert!(orders.len() > 1, "порядок расширений обязан меняться");
        assert_eq!(fingerprints.len(), 1, "JA4 обязан оставаться одним");
    }

    #[test]
    fn shuffling_makes_ja3_unstable_just_like_chrome() {
        let profile = Chrome::default();
        let hashes: std::collections::HashSet<String> = (0..32)
            .map(|_| ja3(&profile.client_hello(&params()).unwrap()).hash)
            .collect();
        assert!(
            hashes.len() > 1,
            "постоянный JA3 при браузерном JA4 сам был бы признаком"
        );
    }

    #[test]
    fn message_is_padded_to_target_length() {
        let hello = Chrome::classic().client_hello(&params()).unwrap();
        assert_eq!(hello.to_handshake().unwrap().len(), PADDING_TARGET);
    }

    #[test]
    fn post_quantum_flag_only_moves_ja3() {
        let pq = Chrome {
            post_quantum: true,
            shuffle: false,
        }
        .client_hello(&params())
        .unwrap();
        let classic = Chrome {
            post_quantum: false,
            shuffle: false,
        }
        .client_hello(&params())
        .unwrap();

        assert_ne!(ja3(&pq).hash, ja3(&classic).hash);
        assert_eq!(
            ja4(&pq, Transport::Tcp).c,
            ja4(&classic, Transport::Tcp).c,
            "JA4_c хэширует типы расширений, а не их содержимое"
        );
    }

    #[test]
    fn hello_survives_round_trip() {
        let hello = Chrome::default().client_hello(&params()).unwrap();
        let parsed = ClientHello::parse(&hello.to_handshake().unwrap()).unwrap();
        assert_eq!(hello, parsed);
    }
}
