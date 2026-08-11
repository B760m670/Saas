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

    /// Задать список ALPN.
    ///
    /// Отступление от списка Chrome видно наблюдателю, поэтому менять
    /// его стоит только осознанно — например, когда поверх соединения
    /// говорит наш собственный протокол, а не браузер.
    #[must_use]
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn;
        self
    }
}

/// Группа `secp521r1`.
pub const SECP521R1: u16 = 0x0019;
/// Группа `ffdhe2048` — конечное поле, объявляет Firefox.
pub const FFDHE2048: u16 = 0x0100;
/// Группа `ffdhe3072`.
pub const FFDHE3072: u16 = 0x0101;

/// Шифронаборы Firefox в порядке отправки.
///
/// Отличается от [`CHROME_CIPHERS`] и составом, и порядком. Самое
/// заметное — второе место: Firefox ставит туда `ChaCha20` (`0x1303`), а
/// Chrome — AES-256 (`0x1302`). Один этот обмен местами уже разводит
/// два браузера в JA3 и JA4.
const FIREFOX_CIPHERS: [u16; 17] = [
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];

/// Алгоритмы подписи Firefox. Длиннее списка Chrome и в другом порядке.
const FIREFOX_SIGNATURE_ALGORITHMS: [u16; 11] = [
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];

/// Алгоритмы в `delegated_credentials` — только ECDSA.
const FIREFOX_DELEGATED_CREDENTIALS: [u16; 4] = [0x0403, 0x0503, 0x0603, 0x0203];

/// Предел длины записи, который объявляет Firefox.
const FIREFOX_RECORD_SIZE_LIMIT: u16 = 0x4001;

/// Алгоритмы сжатия сертификата у Firefox: zlib, brotli, zstd.
///
/// Chrome объявляет только brotli — ещё одно различие в теле расширения,
/// а не в его наличии.
const FIREFOX_CERT_COMPRESSION: [u16; 3] = [0x0001, 0x0002, 0x0003];

/// Профиль Firefox.
///
/// # Чем он отличается от Chrome и почему это важно
///
/// Различие не косметическое. Три вещи отличают Firefox структурно:
///
/// 1. **GREASE нет нигде.** Ни в шифрах, ни в расширениях, ни в группах,
///    ни в `supported_versions`. У Chrome он в четырёх местах сразу.
/// 2. **Порядок расширений постоянный.** Firefox не перемешивает их, и
///    поэтому его JA3 стабилен — тогда как у Chrome он обязан плавать.
///    Перемешивание здесь было бы такой же ошибкой, как его отсутствие
///    у Chrome.
/// 3. **Свои расширения:** `record_size_limit` и `delegated_credentials`
///    есть у Firefox и отсутствуют у Chrome; ALPS и `trust_anchors`,
///    наоборот, чисто хромовские. Ещё Firefox не шлёт ни
///    `session_ticket`, ни `psk_key_exchange_modes`, ни `padding` —
///    последнее означает, что приветствие **не добивается** до 512 байт.
///
/// # Зачем он нам
///
/// По измерениям схемы фильтрации, действующей с июня 2026, отпечатки
/// Chrome, Safari и iOS попадают в подозрительное ведро, а Firefox,
/// Android и Edge проходят. Профиль Chrome ставил нас в это ведро по
/// построению.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Firefox {
    /// Слать ли `encrypted_client_hello`.
    ///
    /// Смысл тот же, что у [`Chrome::ech`], но длина полезной нагрузки
    /// своя — см. [`ext::FIREFOX_ECH_PAYLOAD`].
    pub ech: bool,
}

impl Default for Firefox {
    fn default() -> Self {
        Self::v148()
    }
}

impl Firefox {
    /// Профиль Firefox 148.
    #[must_use]
    pub const fn v148() -> Self {
        Self { ech: true }
    }

    /// Тот же профиль без `encrypted_client_hello`.
    #[must_use]
    pub const fn without_ech(mut self) -> Self {
        self.ech = false;
        self
    }

    /// Группы, для которых профиль обязан приложить долю в `key_share`.
    ///
    /// Firefox шлёт три доли, Chrome — две. Список отдаётся отсюда, а не
    /// задаётся рядом с профилем, потому что разойтись им нельзя:
    /// приветствие с семью объявленными группами и двумя долями не
    /// принадлежит ни одному браузеру.
    #[must_use]
    pub fn key_share_groups() -> [u16; 3] {
        [X25519_MLKEM768, X25519, SECP256R1]
    }

    /// Собрать `ClientHello`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TooLong`], если какое-либо поле не помещается в свою
    /// длину — на практике недостижимо для разумных входных данных.
    pub fn client_hello(&self, params: &HelloParams) -> Result<ClientHello> {
        let groups = [
            X25519_MLKEM768,
            X25519,
            SECP256R1,
            SECP384R1,
            SECP521R1,
            FFDHE2048,
            FFDHE3072,
        ];

        let alpn: Vec<&str> = params.alpn.iter().map(String::as_str).collect();

        // Порядок фиксирован и повторяет живой Firefox. Ни перемешивания,
        // ни обрамляющих GREASE: и то, и другое — приметы Chrome.
        let mut extensions = vec![
            ext::server_name(&params.server_name),
            Extension::empty(ext::EXTENDED_MASTER_SECRET),
            ext::renegotiation_info(),
            ext::supported_groups(&groups),
            ext::ec_point_formats(&[0]),
            ext::alpn(&alpn),
            ext::status_request(),
            ext::delegated_credentials(&FIREFOX_DELEGATED_CREDENTIALS),
            Extension::empty(ext::SIGNED_CERTIFICATE_TIMESTAMP),
            ext::key_share(&params.key_shares),
            ext::supported_versions(&[0x0304, 0x0303]),
            ext::signature_algorithms(&FIREFOX_SIGNATURE_ALGORITHMS),
            ext::record_size_limit(FIREFOX_RECORD_SIZE_LIMIT),
            ext::compress_certificate(&FIREFOX_CERT_COMPRESSION),
        ];

        if self.ech {
            extensions.push(ext::ech_grease_with(ext::FIREFOX_ECH_PAYLOAD));
        }

        // Padding нет намеренно: Firefox не добивает приветствие до
        // круглой длины, и добивка сама стала бы отличием.
        Ok(ClientHello {
            legacy_version: LEGACY_VERSION,
            random: OsRng::bytes::<32>(),
            session_id: params.session_id.clone(),
            cipher_suites: FIREFOX_CIPHERS.to_vec(),
            compression_methods: vec![0],
            extensions,
        })
    }
}

/// Профиль отпечатка: какой браузер имитируется.
///
/// Обёртка нужна, чтобы выбор браузера доходил до места сборки
/// приветствия целиком — вместе со списком групп, который у браузеров
/// разный и не имеет права разойтись с профилем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Chrome.
    Chrome(Chrome),
    /// Firefox.
    Firefox(Firefox),
}

impl Default for Profile {
    fn default() -> Self {
        Self::Firefox(Firefox::v148())
    }
}

impl From<Chrome> for Profile {
    fn from(profile: Chrome) -> Self {
        Self::Chrome(profile)
    }
}

impl From<Firefox> for Profile {
    fn from(profile: Firefox) -> Self {
        Self::Firefox(profile)
    }
}

impl Profile {
    /// Собрать `ClientHello`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TooLong`] при переполнении поля длины.
    pub fn client_hello(&self, params: &HelloParams) -> Result<ClientHello> {
        match self {
            Self::Chrome(profile) => profile.client_hello(params),
            Self::Firefox(profile) => profile.client_hello(params),
        }
    }

    /// Тот же профиль без `encrypted_client_hello`.
    #[must_use]
    pub const fn without_ech(self) -> Self {
        match self {
            Self::Chrome(profile) => Self::Chrome(profile.without_ech()),
            Self::Firefox(profile) => Self::Firefox(profile.without_ech()),
        }
    }

    /// Коды групп, для которых профиль обязан приложить долю в `key_share`.
    ///
    /// Число долей — часть отпечатка, и оно у браузеров разное: Chrome
    /// шлёт две, Firefox три. Поэтому список берётся у профиля, а не
    /// настраивается рядом с ним: разойдясь, они дали бы приветствие,
    /// которого не бывает ни у одного браузера.
    #[must_use]
    pub fn key_share_group_codes(&self) -> Vec<u16> {
        match self {
            Self::Chrome(_) => vec![X25519_MLKEM768, X25519],
            Self::Firefox(_) => Firefox::key_share_groups().to_vec(),
        }
    }
}

/// Поколение Chrome, которое имитирует профиль.
///
/// Набор расширений у Chrome меняется каждые несколько релизов, и каждое
/// изменение сдвигает отпечаток. Поэтому профиль привязан к поколению,
/// а не «к Chrome вообще».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Generation {
    /// Chrome 141: ALPS на кодовой точке `0x44cd`, GREASE-ECH,
    /// `trust_anchors`, постквантовая группа `X25519MLKEM768`.
    ///
    /// Сверен с живым захватом — `testdata/chromium-141-linux.json`.
    #[default]
    V141,
    /// Chrome до 124: без постквантовой группы и без новых расширений,
    /// ALPS на кодовой точке `0x4469`.
    ///
    /// Оставлено потому, что отпечаток этого поколения опубликован и
    /// служит независимым ориентиром.
    Legacy,
}

impl Generation {
    /// Объявляет ли поколение постквантовую группу.
    #[must_use]
    pub const fn post_quantum(self) -> bool {
        matches!(self, Self::V141)
    }
}

/// Профиль Chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Chrome {
    /// Имитируемое поколение.
    pub generation: Generation,
    /// Перемешивать ли расширения, как это делает настоящий Chrome.
    ///
    /// Захват Chromium 141 подтверждает перемешивание: значения GREASE
    /// стоят первым и последним, а середина идёт в произвольном порядке.
    /// Выключается только в тестах, где нужен воспроизводимый порядок.
    pub shuffle: bool,
    /// Слать ли `encrypted_client_hello` со случайным содержимым.
    ///
    /// Chrome шлёт его всегда, поэтому по умолчанию шлём и мы, и любое
    /// другое значение — отступление от отпечатка браузера.
    ///
    /// Отключается ровно для одного случая: промежуточный узел на пути
    /// рвёт соединение при виде этого расширения. Такое встречается —
    /// в среде, где ведётся разработка, шлюз сбрасывает **любое**
    /// приветствие с `0xfe0d`, независимо от адресата (см.
    /// `docs/09-lab.md`). Выбор между «отличаться от Chrome» и «вообще
    /// не соединиться» делает вызывающий, а в будущем — бандит выбора
    /// стратегии по результатам попыток.
    pub ech: bool,
}

impl Chrome {
    /// Профиль Chrome 141.
    #[must_use]
    pub const fn v141() -> Self {
        Self {
            generation: Generation::V141,
            shuffle: true,
            ech: true,
        }
    }

    /// Профиль поколения до 124.
    #[must_use]
    pub const fn classic() -> Self {
        Self {
            generation: Generation::Legacy,
            shuffle: true,
            ech: true,
        }
    }

    /// Тот же профиль, но без `encrypted_client_hello`.
    ///
    /// Отпечаток при этом меняется — см. поле [`Chrome::ech`].
    #[must_use]
    pub const fn without_ech(mut self) -> Self {
        self.ech = false;
        self
    }

    /// Собрать `ClientHello`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TooLong`], если какое-либо поле не помещается в свою
    /// длину — на практике недостижимо для разумных входных данных.
    pub fn client_hello(&self, params: &HelloParams) -> Result<ClientHello> {
        // Одно значение GREASE на два списка. Chrome ставит его первым и в
        // `supported_groups`, и в `key_share`; если бы значения разошлись
        // или запись в `key_share` отсутствовала, наблюдателю хватило бы
        // сверки двух расширений между собой, чтобы отличить нас от
        // браузера. Проверено по живому захвату: группа `0x9a9a` стоит в
        // обоих списках, доля — один нулевой байт.
        let groups_grease = grease::pick();
        let groups = if self.generation.post_quantum() {
            vec![groups_grease, X25519_MLKEM768, X25519, SECP256R1, SECP384R1]
        } else {
            vec![groups_grease, X25519, SECP256R1, SECP384R1]
        };

        let mut key_shares = Vec::with_capacity(params.key_shares.len() + 1);
        key_shares.push((groups_grease, vec![0x00]));
        key_shares.extend(params.key_shares.iter().cloned());

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
            ext::key_share(&key_shares),
            ext::psk_key_exchange_modes(&[1]),
            ext::supported_versions(&[grease::pick(), 0x0304, 0x0303]),
            // 2 — brotli, единственный алгоритм, который шлёт Chrome.
            ext::compress_certificate(&[0x0002]),
        ];

        match self.generation {
            Generation::V141 => {
                middle.push(ext::application_settings_v2(&["h2"]));
                middle.push(ext::trust_anchors());
                // Браузер шлёт ECH всегда: при отсутствии конфигурации у
                // сервера — со случайным содержимым. Не слать его теперь
                // значит отличаться от Chrome.
                if self.ech {
                    middle.push(ext::ech_grease());
                }
            }
            Generation::Legacy => middle.push(ext::application_settings(&["h2"])),
        }

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

/// Пересобрать приветствие для второго круга после `HelloRetryRequest`.
///
/// RFC 8446, раздел 4.1.2 разрешает изменить ровно три вещи: долю
/// `key_share`, добавить `cookie` и убрать `early_data`. Всё остальное —
/// случайное поле, `session_id`, порядок расширений — обязано остаться
/// прежним, иначе сервер обязан оборвать соединение. Отсюда правка на
/// месте вместо повторной сборки: пересборка перемешала бы расширения
/// заново и выдала бы нас даже там, где сервер не проверяет.
///
/// # Errors
///
/// [`crate::Error::TooLong`] при переполнении поля длины.
pub(crate) fn rebuild_for_retry(
    hello: &mut ClientHello,
    key_share: &Extension,
    cookie: Option<&Extension>,
) -> Result<()> {
    hello.extensions.retain(|e| e.ext_type != ext::PADDING);

    for extension in &mut hello.extensions {
        if extension.ext_type == ext::KEY_SHARE {
            extension.body.clone_from(&key_share.body);
        }
    }

    if let Some(cookie) = cookie {
        if !hello.extensions.iter().any(|e| e.ext_type == ext::COOKIE) {
            // Не первым и не последним: края заняты значениями GREASE,
            // и сдвинуть их значило бы изменить отпечаток.
            let span = hello.extensions.len().saturating_sub(1).max(1);
            let draw = u64::from_le_bytes(OsRng::bytes::<8>()) % span as u64;
            let at = usize::try_from(draw).unwrap_or(1).max(1);
            hello.extensions.insert(at, cookie.clone());
        }
    }

    if let Some(len) = padding_len(hello)? {
        hello.extensions.push(ext::padding(len));
    }
    Ok(())
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
        let hello = Chrome::v141().client_hello(&params()).unwrap();
        let first = hello.extensions.first().unwrap().ext_type;
        assert!(grease::is_grease(first), "первое расширение — GREASE");

        // Последним идёт padding, перед ним — второе значение GREASE.
        let types: Vec<u16> = hello.extensions.iter().map(|e| e.ext_type).collect();
        let greases = types.iter().filter(|t| grease::is_grease(**t)).count();
        assert_eq!(greases, 2);
    }

    #[test]
    fn cipher_list_starts_with_grease() {
        let hello = Chrome::v141().client_hello(&params()).unwrap();
        assert!(grease::is_grease(*hello.cipher_suites.first().unwrap()));
        assert_eq!(hello.cipher_suites.len(), CHROME_CIPHERS.len() + 1);
    }

    #[test]
    fn shuffling_changes_order_but_not_ja4() {
        let profile = Chrome::v141();
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
        let profile = Chrome::v141();
        let hashes: std::collections::HashSet<String> = (0..32)
            .map(|_| ja3(&profile.client_hello(&params()).unwrap()).hash)
            .collect();
        assert!(
            hashes.len() > 1,
            "постоянный JA3 при браузерном JA4 сам был бы признаком"
        );
    }

    #[test]
    fn grease_group_appears_in_both_lists_with_the_same_value() {
        let hello = Chrome::v141().client_hello(&params()).unwrap();

        let groups = hello
            .extensions
            .iter()
            .find(|e| e.ext_type == ext::SUPPORTED_GROUPS)
            .unwrap();
        let first_group = crate::bytes::Reader::new(&groups.body)
            .list_u16()
            .unwrap()
            .first()
            .copied()
            .unwrap();

        let key_share = hello
            .extensions
            .iter()
            .find(|e| e.ext_type == ext::KEY_SHARE)
            .unwrap();
        let mut outer = crate::bytes::Reader::new(&key_share.body);
        let mut list = crate::bytes::Reader::new(outer.vec_u16().unwrap());
        let first_share_group = list.u16().unwrap();
        let first_share = list.vec_u16().unwrap();

        assert!(grease::is_grease(first_group));
        assert_eq!(
            first_share_group, first_group,
            "GREASE в key_share обязан совпадать с GREASE в supported_groups"
        );
        assert_eq!(first_share, [0x00], "доля GREASE — один нулевой байт");

        // Настоящая доля идёт следом и не потеряна.
        assert_eq!(list.u16().unwrap(), X25519);
        assert_eq!(list.vec_u16().unwrap().len(), 32);
    }

    #[test]
    fn disabling_ech_removes_exactly_one_extension_and_shifts_the_fingerprint() {
        let with = Chrome::v141().client_hello(&params()).unwrap();
        let without = Chrome::v141()
            .without_ech()
            .client_hello(&params())
            .unwrap();

        assert!(with
            .extensions
            .iter()
            .any(|e| e.ext_type == ext::ENCRYPTED_CLIENT_HELLO));
        assert!(!without
            .extensions
            .iter()
            .any(|e| e.ext_type == ext::ENCRYPTED_CLIENT_HELLO));

        // Отпечаток обязан измениться: иначе отключение было бы бесплатным,
        // а оно не бесплатно, и это должно быть видно.
        assert_ne!(
            ja4(&with, Transport::Tcp).to_string_full(),
            ja4(&without, Transport::Tcp).to_string_full()
        );
    }

    #[test]
    fn message_is_padded_to_target_length() {
        let hello = Chrome::classic().client_hello(&params()).unwrap();
        assert_eq!(hello.to_handshake().unwrap().len(), PADDING_TARGET);
    }

    #[test]
    fn generations_differ_in_extensions_but_not_ciphers() {
        let modern = Chrome {
            shuffle: false,
            ..Chrome::v141()
        }
        .client_hello(&params())
        .unwrap();
        let legacy = Chrome {
            shuffle: false,
            ..Chrome::classic()
        }
        .client_hello(&params())
        .unwrap();

        // Поколения различаются и набором групп, и набором расширений.
        assert_ne!(ja3(&modern).hash, ja3(&legacy).hash);
        assert_ne!(
            ja4(&modern, Transport::Tcp).c,
            ja4(&legacy, Transport::Tcp).c
        );
        // А вот список шифров у них общий — он не менялся годами.
        assert_eq!(
            ja4(&modern, Transport::Tcp).b,
            ja4(&legacy, Transport::Tcp).b
        );
    }

    #[test]
    fn hello_survives_round_trip() {
        let hello = Chrome::v141().client_hello(&params()).unwrap();
        let parsed = ClientHello::parse(&hello.to_handshake().unwrap()).unwrap();
        assert_eq!(hello, parsed);
    }

    /// Параметры с тремя долями — столько прикладывает Firefox.
    fn firefox_params() -> HelloParams {
        HelloParams::new("www.microsoft.com")
            .with_key_shares(vec![
                (X25519_MLKEM768, vec![0x33; 1216]),
                (X25519, vec![0x11; 32]),
                (SECP256R1, vec![0x44; 65]),
            ])
            .with_session_id(vec![0x22; 32])
    }

    #[test]
    fn firefox_sends_no_grease_anywhere() {
        let hello = Firefox::v148().client_hello(&firefox_params()).unwrap();

        assert!(
            !hello.cipher_suites.iter().copied().any(grease::is_grease),
            "GREASE в шифрах — примета Chrome"
        );
        assert!(
            !hello
                .extensions
                .iter()
                .any(|e| grease::is_grease(e.ext_type)),
            "GREASE среди расширений — примета Chrome"
        );

        let groups = hello
            .extensions
            .iter()
            .find(|e| e.ext_type == ext::SUPPORTED_GROUPS)
            .unwrap();
        let list = crate::bytes::Reader::new(&groups.body).list_u16().unwrap();
        assert!(!list.iter().copied().any(grease::is_grease));

        let versions = hello
            .extensions
            .iter()
            .find(|e| e.ext_type == ext::SUPPORTED_VERSIONS)
            .unwrap();
        assert_eq!(versions.body, vec![0x04, 0x03, 0x04, 0x03, 0x03]);
    }

    #[test]
    fn firefox_order_is_fixed_so_ja3_is_stable() {
        // Обратное к `shuffling_makes_ja3_unstable_just_like_chrome`:
        // у Firefox порядок расширений постоянный, и плавающий JA3 выдал
        // бы нас ровно так же, как постоянный выдал бы Chrome.
        let profile = Firefox::v148();
        let hashes: std::collections::HashSet<String> = (0..32)
            .map(|_| ja3(&profile.client_hello(&firefox_params()).unwrap()).hash)
            .collect();
        assert_eq!(hashes.len(), 1, "порядок у Firefox не плавает");
    }

    #[test]
    fn firefox_carries_its_own_extensions_and_none_of_chromes() {
        let hello = Firefox::v148().client_hello(&firefox_params()).unwrap();
        let has = |t: u16| hello.extensions.iter().any(|e| e.ext_type == t);

        // Свои.
        assert!(has(ext::RECORD_SIZE_LIMIT));
        assert!(has(ext::DELEGATED_CREDENTIALS));

        // Чужие: ALPS и trust_anchors шлёт только Chrome.
        assert!(!has(ext::APPLICATION_SETTINGS));
        assert!(!has(ext::APPLICATION_SETTINGS_V2));
        assert!(!has(ext::TRUST_ANCHORS));

        // Этих Firefox не шлёт вовсе, а Chrome шлёт все три.
        assert!(!has(ext::SESSION_TICKET));
        assert!(!has(ext::PSK_KEY_EXCHANGE_MODES));
        assert!(!has(ext::PADDING), "Firefox не добивает приветствие");
    }

    #[test]
    fn firefox_is_not_padded_to_chromes_target() {
        let hello = Firefox::v148().client_hello(&firefox_params()).unwrap();
        assert_ne!(
            hello.to_handshake().unwrap().len(),
            PADDING_TARGET,
            "совпадение с длиной Chrome означало бы, что добивка вернулась"
        );
    }

    #[test]
    fn firefox_and_chrome_are_different_browsers_to_an_observer() {
        let firefox = Firefox::v148().client_hello(&firefox_params()).unwrap();
        let chrome = Chrome::v141().client_hello(&params()).unwrap();

        assert_ne!(ja3(&firefox).hash, ja3(&chrome).hash);

        let ff = ja4(&firefox, Transport::Tcp);
        let cr = ja4(&chrome, Transport::Tcp);
        assert_ne!(ff.to_string_full(), cr.to_string_full());
        // Различаются и списком шифров, и набором расширений — то есть не
        // порядком, а существом.
        assert_ne!(ff.b, cr.b, "списки шифров обязаны различаться");
        assert_ne!(ff.c, cr.c, "наборы расширений обязаны различаться");
    }

    #[test]
    fn firefox_cipher_list_matches_the_reference() {
        let hello = Firefox::v148().client_hello(&firefox_params()).unwrap();
        // Без ведущего GREASE, поэтому длина ровно как в эталоне.
        assert_eq!(hello.cipher_suites, FIREFOX_CIPHERS.to_vec());
        // Второй шифронабор — ChaCha20, и это главное отличие от Chrome,
        // у которого там AES-256.
        assert_eq!(hello.cipher_suites.get(1).copied().unwrap(), 0x1303);
        assert_eq!(CHROME_CIPHERS.get(1).copied().unwrap(), 0x1302);
    }

    #[test]
    fn firefox_ech_payload_differs_from_chromes() {
        let firefox = Firefox::v148().client_hello(&firefox_params()).unwrap();
        let chrome = Chrome::v141().client_hello(&params()).unwrap();

        let body = |h: &ClientHello| {
            h.extensions
                .iter()
                .find(|e| e.ext_type == ext::ENCRYPTED_CLIENT_HELLO)
                .map(|e| e.body.len())
        };

        let ff = body(&firefox).unwrap();
        let cr = body(&chrome).unwrap();
        assert_ne!(ff, cr, "длина ECH наблюдаема и обязана различаться");
        assert_eq!(ff - cr, ext::FIREFOX_ECH_PAYLOAD - ext::CHROME_ECH_PAYLOAD);
    }

    #[test]
    fn disabling_ech_removes_it_from_firefox_too() {
        let without = Firefox::v148()
            .without_ech()
            .client_hello(&firefox_params())
            .unwrap();
        assert!(!without
            .extensions
            .iter()
            .any(|e| e.ext_type == ext::ENCRYPTED_CLIENT_HELLO));
        // Последним тогда остаётся сжатие сертификата, а не что попало.
        assert_eq!(
            without.extensions.last().unwrap().ext_type,
            ext::COMPRESS_CERTIFICATE
        );
    }

    #[test]
    fn firefox_hello_survives_round_trip() {
        let hello = Firefox::v148().client_hello(&firefox_params()).unwrap();
        let parsed = ClientHello::parse(&hello.to_handshake().unwrap()).unwrap();
        assert_eq!(hello, parsed);
    }

    #[test]
    fn profile_reports_the_shares_its_hello_needs() {
        // Число долей — часть отпечатка. Если список групп разойдётся с
        // профилем, приветствие перестанет принадлежать браузеру, и
        // заметить это по одному лишь `client_hello` уже нельзя.
        assert_eq!(
            Profile::from(Firefox::v148()).key_share_group_codes().len(),
            3
        );
        assert_eq!(
            Profile::from(Chrome::v141()).key_share_group_codes().len(),
            2
        );

        let hello = Firefox::v148().client_hello(&firefox_params()).unwrap();
        let key_share = hello
            .extensions
            .iter()
            .find(|e| e.ext_type == ext::KEY_SHARE)
            .unwrap();
        let mut outer = crate::bytes::Reader::new(&key_share.body);
        let mut list = crate::bytes::Reader::new(outer.vec_u16().unwrap());
        let mut seen = Vec::new();
        while let Ok(group) = list.u16() {
            let _ = list.vec_u16().unwrap();
            seen.push(group);
        }
        assert_eq!(seen, Firefox::key_share_groups().to_vec());
    }

    #[test]
    fn default_profile_is_firefox() {
        // Значение по умолчанию — это то, что уйдёт в сеть у всех, кто не
        // выбирал профиль осознанно. Chrome здесь означал бы, что мы сами
        // ставим себя в подозрительное ведро фильтра.
        assert!(matches!(Profile::default(), Profile::Firefox(_)));
    }
}
