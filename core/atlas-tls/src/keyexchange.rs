//! Обмен ключами TLS 1.3, включая гибридную постквантовую группу.
//!
//! # Почему это не `atlas_crypto::kem`
//!
//! В [`atlas_crypto::kem`] живёт **наш** гибрид: там общий секрет
//! получается прогоном обеих половин и всего транскрипта обмена через
//! BLAKE3. Это сильнее, и для своего протокола мы пользуемся именно им.
//!
//! Здесь же нужна совместимость с чужими серверами, поэтому комбинатор
//! ровно такой, какой предписан `draft-kwiatkowski-tls-ecdhe-mlkem`:
//! простая конкатенация двух секретов, без всякого хэширования. TLS 1.3
//! сам заводит общий секрет в HKDF вместе с хэшем транскрипта, так что
//! конкатенации здесь достаточно.
//!
//! # Порядок половин на проводе
//!
//! Порядок половин в `X25519MLKEM768` — место, где легко ошибиться, и
//! ошибка проявится только как несовпадение секретов на живом сервере.
//! Он проверен не по тексту черновика, а по живому захвату Chromium 141
//! (`testdata/chromium-141-linux.json`): если считать, что первыми идут
//! 1184 байта ML-KEM, то все 768 коэффициентов открытого ключа лежат
//! ниже модуля 3329; при обратном порядке 138 коэффициентов выходят за
//! границу. Значит, ML-KEM впереди:
//!
//! ```text
//! доля клиента (1216): [ ML-KEM-768 ek 1184 ][ X25519 pub 32 ]
//! доля сервера (1120): [ ML-KEM-768 ct 1088 ][ X25519 pub 32 ]
//! общий секрет  (64):  [ ML-KEM ss     32   ][ X25519 ss   32 ]
//! ```
//!
//! У группы `SecP256r1MLKEM768` порядок обратный — ещё одна причина не
//! обобщать этот код «на все гибриды» без отдельной проверки.

use ml_kem::{Decapsulate as _, Encapsulate as _, Generate as _, KeyExport as _, TryKeyInit as _};

use atlas_crypto::rng::OsRng;

use crate::error::{Error, Result};
use crate::profile::{X25519, X25519_MLKEM768};

/// Длина открытого ключа X25519.
pub const X25519_LEN: usize = 32;
/// Длина открытого ключа (ключа инкапсуляции) ML-KEM-768.
pub const MLKEM_PUBLIC_LEN: usize = 1184;
/// Длина шифртекста ML-KEM-768.
pub const MLKEM_CIPHERTEXT_LEN: usize = 1088;
/// Длина общего секрета ML-KEM-768.
pub const MLKEM_SHARED_LEN: usize = 32;

/// Группа обмена ключами.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// Классический `x25519`.
    X25519,
    /// Гибрид `X25519MLKEM768` — то, что Chrome ставит первым и что
    /// выбирает большинство современных серверов.
    X25519MlKem768,
}

impl Group {
    /// Числовой код группы на проводе.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::X25519 => X25519,
            Self::X25519MlKem768 => X25519_MLKEM768,
        }
    }

    /// Разобрать числовой код.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            X25519 => Some(Self::X25519),
            X25519_MLKEM768 => Some(Self::X25519MlKem768),
            _ => None,
        }
    }

    /// Длина доли клиента.
    #[must_use]
    pub const fn client_share_len(self) -> usize {
        match self {
            Self::X25519 => X25519_LEN,
            Self::X25519MlKem768 => MLKEM_PUBLIC_LEN + X25519_LEN,
        }
    }

    /// Длина доли сервера.
    ///
    /// У гибрида она короче клиентской: сервер шлёт шифртекст, а не
    /// открытый ключ.
    #[must_use]
    pub const fn server_share_len(self) -> usize {
        match self {
            Self::X25519 => X25519_LEN,
            Self::X25519MlKem768 => MLKEM_CIPHERTEXT_LEN + X25519_LEN,
        }
    }

    /// Длина общего секрета.
    #[must_use]
    pub const fn shared_secret_len(self) -> usize {
        match self {
            Self::X25519 => X25519_LEN,
            Self::X25519MlKem768 => MLKEM_SHARED_LEN + X25519_LEN,
        }
    }
}

/// Одна сгенерированная доля обмена ключами.
///
/// Секретная часть не покидает структуру: наружу отдаётся только доля
/// для отправки и, после ответа сервера, общий секрет.
pub struct KeyExchange {
    group: Group,
    x: x25519_dalek::StaticSecret,
    pq: Option<ml_kem::DecapsulationKey768>,
    share: Vec<u8>,
}

impl core::fmt::Debug for KeyExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "KeyExchange {{ group: {:?}, share: {} байт, secret: <скрыто> }}",
            self.group,
            self.share.len()
        )
    }
}

impl KeyExchange {
    /// Сгенерировать долю для указанной группы.
    #[must_use]
    pub fn generate(group: Group) -> Self {
        let mut rng = OsRng;
        let x = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let x_public = x25519_dalek::PublicKey::from(&x);

        let (pq, share) = match group {
            Group::X25519 => (None, x_public.as_bytes().to_vec()),
            Group::X25519MlKem768 => {
                let dk = ml_kem::DecapsulationKey768::generate_from_rng(&mut rng);
                let mut share = Vec::with_capacity(MLKEM_PUBLIC_LEN + X25519_LEN);
                share.extend_from_slice(&dk.encapsulation_key().to_bytes());
                share.extend_from_slice(x_public.as_bytes());
                (Some(dk), share)
            }
        };

        Self {
            group,
            x,
            pq,
            share,
        }
    }

    /// Группа этой доли.
    #[must_use]
    pub const fn group(&self) -> Group {
        self.group
    }

    /// Доля для отправки в расширении `key_share`.
    #[must_use]
    pub fn share(&self) -> &[u8] {
        &self.share
    }

    /// Вычислить общий секрет из доли сервера.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если доля сервера имеет неверную длину или
    /// классическая половина вырождена.
    pub fn complete(&self, peer_share: &[u8]) -> Result<Vec<u8>> {
        if peer_share.len() != self.group.server_share_len() {
            return Err(Error::Malformed("доля сервера неверной длины"));
        }

        match (self.group, self.pq.as_ref()) {
            (Group::X25519, _) => Ok(self.agree_x25519(peer_share)?.to_vec()),
            (Group::X25519MlKem768, Some(dk)) => {
                let (ct_raw, x_raw) = peer_share
                    .split_at_checked(MLKEM_CIPHERTEXT_LEN)
                    .ok_or(Error::Malformed("доля сервера неверной длины"))?;

                let ct = ml_kem::ml_kem_768::Ciphertext::try_from(ct_raw)
                    .map_err(|_| Error::Malformed("шифртекст ML-KEM-768 неверной длины"))?;
                let pq_shared = dk.decapsulate(&ct);
                let x_shared = self.agree_x25519(x_raw)?;

                // Конкатенация без хэширования — так предписывает черновик.
                let mut out = Vec::with_capacity(self.group.shared_secret_len());
                out.extend_from_slice(pq_shared.as_slice());
                out.extend_from_slice(&x_shared);
                Ok(out)
            }
            (Group::X25519MlKem768, None) => {
                Err(Error::Malformed("постквантовая половина не сгенерирована"))
            }
        }
    }

    /// Ответить на долю клиента со стороны сервера.
    ///
    /// У классической группы стороны симметричны, у гибридной — нет:
    /// клиент присылает ключ инкапсуляции, сервер отвечает шифртекстом.
    /// Поэтому серверная сторона — отдельная функция, а не тот же
    /// [`KeyExchange::complete`].
    ///
    /// Возвращает долю для `ServerHello` и общий секрет.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если доля клиента неверной длины или
    /// содержит недопустимый ключ.
    pub fn respond(group: Group, client_share: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if client_share.len() != group.client_share_len() {
            return Err(Error::Malformed("доля клиента неверной длины"));
        }

        match group {
            Group::X25519 => {
                let ours = Self::generate(Group::X25519);
                let shared = ours.agree_x25519(client_share)?;
                Ok((ours.share().to_vec(), shared.to_vec()))
            }
            Group::X25519MlKem768 => {
                let (ek_raw, x_raw) = client_share
                    .split_at_checked(MLKEM_PUBLIC_LEN)
                    .ok_or(Error::Malformed("доля клиента неверной длины"))?;

                let ek = ml_kem::EncapsulationKey768::new_from_slice(ek_raw)
                    .map_err(|_| Error::Malformed("ключ инкапсуляции ML-KEM-768"))?;
                let mut rng = OsRng;
                let (ct, pq_shared) = ek.encapsulate_with_rng(&mut rng);

                let ours = Self::generate(Group::X25519);
                let x_shared = ours.agree_x25519(x_raw)?;

                let mut share = Vec::with_capacity(group.server_share_len());
                share.extend_from_slice(ct.as_slice());
                share.extend_from_slice(ours.share());

                let mut shared = Vec::with_capacity(group.shared_secret_len());
                shared.extend_from_slice(pq_shared.as_slice());
                shared.extend_from_slice(&x_shared);

                Ok((share, shared))
            }
        }
    }

    /// Договориться по X25519 с произвольным открытым ключом.
    ///
    /// Нужно REALITY: там из секретного ключа доли `x25519` и постоянного
    /// открытого ключа сервера получается ключ, которым шифруется метка
    /// внутри `session_id`. Отдельная доля обмена для этого не заводится —
    /// иначе на проводе появился бы лишний открытый ключ.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если ключ не 32 байта или результат вырожден.
    pub fn agree_x25519(&self, peer_public: &[u8]) -> Result<[u8; X25519_LEN]> {
        let raw: [u8; X25519_LEN] = peer_public
            .try_into()
            .map_err(|_| Error::Malformed("открытый ключ X25519 не 32 байта"))?;
        let shared = self.x.diffie_hellman(&x25519_dalek::PublicKey::from(raw));

        // Точка малого порядка даёт нулевой секрет. Продолжать с ним
        // означает согласиться на предопределённый противником ключ.
        if !shared.was_contributory() {
            return Err(Error::Malformed("вырожденный общий секрет X25519"));
        }
        Ok(shared.to_bytes())
    }
}

/// Набор долей, предложенных в одном `ClientHello`.
///
/// Chrome предлагает сразу две — гибридную и классическую, — чтобы не
/// нарваться на `HelloRetryRequest` ни от нового, ни от старого сервера.
/// Мы делаем так же: лишний круг рукопожатия виден на проводе как
/// отдельная пара пакетов и сам по себе является признаком.
#[derive(Debug)]
pub struct KeyShares {
    entries: Vec<KeyExchange>,
}

impl KeyShares {
    /// Сгенерировать доли для перечисленных групп, в порядке предпочтения.
    #[must_use]
    pub fn generate(groups: &[Group]) -> Self {
        Self {
            entries: groups.iter().copied().map(KeyExchange::generate).collect(),
        }
    }

    /// Набор, который предлагает Chrome: гибрид, затем классика.
    #[must_use]
    pub fn chrome() -> Self {
        Self::generate(&[Group::X25519MlKem768, Group::X25519])
    }

    /// Записи для расширения `key_share`.
    #[must_use]
    pub fn wire(&self) -> Vec<(u16, Vec<u8>)> {
        self.entries
            .iter()
            .map(|e| (e.group().code(), e.share().to_vec()))
            .collect()
    }

    /// Добавить долю для ещё не предложенной группы.
    ///
    /// Нужно при `HelloRetryRequest`: прежние доли остаются на месте,
    /// потому что из секретной части `x25519` выводится ключ метки
    /// REALITY, а `legacy_session_id` во втором приветствии менять
    /// нельзя. Повторная генерация той же группы не делается.
    pub fn push(&mut self, group: Group) {
        if self.find(group.code()).is_none() {
            self.entries.push(KeyExchange::generate(group));
        }
    }

    /// Найти долю по коду группы.
    #[must_use]
    pub fn find(&self, group_code: u16) -> Option<&KeyExchange> {
        self.entries.iter().find(|e| e.group().code() == group_code)
    }

    /// Доля классической группы `x25519` — та, которой пользуется REALITY.
    #[must_use]
    pub fn x25519(&self) -> Option<&KeyExchange> {
        self.find(X25519)
    }

    /// Сколько долей в наборе.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Пуст ли набор.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Модуль ML-KEM. Коэффициенты открытого ключа лежат строго ниже него.
    const Q: u16 = 3329;

    /// Распаковать 12-битные коэффициенты, как это делает `ByteDecode_12`.
    fn unpack12(bytes: &[u8]) -> Vec<u16> {
        bytes
            .chunks_exact(3)
            .flat_map(|c| {
                let (a, b, d) = (u16::from(c[0]), u16::from(c[1]), u16::from(c[2]));
                [a | ((b & 0x0f) << 8), (b >> 4) | (d << 4)]
            })
            .collect()
    }

    #[test]
    fn x25519_shares_agree() {
        let client = KeyExchange::generate(Group::X25519);
        let server = KeyExchange::generate(Group::X25519);

        let ours = client.complete(server.share()).unwrap();
        let theirs = server.complete(client.share()).unwrap();
        assert_eq!(ours, theirs);
        assert_eq!(ours.len(), Group::X25519.shared_secret_len());
    }

    #[test]
    fn hybrid_share_has_the_wire_layout_of_the_draft() {
        let kx = KeyExchange::generate(Group::X25519MlKem768);
        assert_eq!(kx.share().len(), 1216);

        // Первые 1184 байта обязаны разбираться как открытый ключ ML-KEM:
        // 768 коэффициентов ниже модуля плюс 32 байта затравки.
        let coefficients = unpack12(&kx.share()[..MLKEM_PUBLIC_LEN - 32]);
        assert_eq!(coefficients.len(), 768);
        assert!(
            coefficients.iter().all(|c| *c < Q),
            "ML-KEM должен идти первым"
        );
    }

    #[test]
    fn hybrid_matches_the_layout_of_a_live_chromium_hello() {
        // Тот же тест, но на чужой доле: захват настоящего браузера.
        const CAPTURE: &str = include_str!("../testdata/chromium-141-linux.json");
        let doc: serde_json::Value = serde_json::from_str(CAPTURE).unwrap();
        let hex = doc["client_hello_hex"].as_str().unwrap();
        let raw: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();

        let hello = crate::ClientHello::parse(&raw).unwrap();
        let key_share = hello
            .extensions
            .iter()
            .find(|e| e.ext_type == crate::ext::KEY_SHARE)
            .unwrap();

        // Найти долю гибридной группы внутри расширения.
        let mut r = crate::bytes::Reader::new(&key_share.body);
        let mut list = crate::bytes::Reader::new(r.vec_u16().unwrap());
        let mut hybrid = None;
        while !list.is_empty() {
            let group = list.u16().unwrap();
            let share = list.vec_u16().unwrap();
            if group == X25519_MLKEM768 {
                hybrid = Some(share.to_vec());
            }
        }
        let hybrid = hybrid.unwrap();
        assert_eq!(hybrid.len(), 1216);

        let mlkem_first = unpack12(&hybrid[..MLKEM_PUBLIC_LEN - 32]);
        let x25519_first = unpack12(&hybrid[X25519_LEN..MLKEM_PUBLIC_LEN + X25519_LEN - 32]);
        assert_eq!(
            mlkem_first.iter().filter(|c| **c >= Q).count(),
            0,
            "при порядке «ML-KEM впереди» все коэффициенты допустимы"
        );
        assert!(
            x25519_first.iter().filter(|c| **c >= Q).count() > 0,
            "обратный порядок должен давать недопустимые коэффициенты"
        );
    }

    #[test]
    fn both_groups_agree_between_client_and_server() {
        for group in [Group::X25519, Group::X25519MlKem768] {
            let client = KeyExchange::generate(group);
            let (server_share, server_secret) =
                KeyExchange::respond(group, client.share()).unwrap();

            assert_eq!(server_share.len(), group.server_share_len());
            assert_eq!(server_secret.len(), group.shared_secret_len());
            assert_eq!(
                client.complete(&server_share).unwrap(),
                server_secret,
                "{group:?}: стороны обязаны сойтись"
            );
        }
    }

    #[test]
    fn server_side_rejects_a_bad_client_share() {
        for group in [Group::X25519, Group::X25519MlKem768] {
            assert!(KeyExchange::respond(group, &[0x11; 7]).is_err());
            // Правильная длина, но заведомо недопустимое содержимое.
            let bogus = vec![0xff; group.client_share_len()];
            let outcome = KeyExchange::respond(group, &bogus);
            if group == Group::X25519MlKem768 {
                assert!(outcome.is_err(), "ключ инкапсуляции обязан проверяться");
            }
        }
    }

    #[test]
    fn rejects_a_peer_share_of_the_wrong_length() {
        let kx = KeyExchange::generate(Group::X25519MlKem768);
        for len in [0_usize, 32, 1088, 1119, 1121, 1216] {
            assert!(kx.complete(&vec![0x11; len]).is_err(), "длина {len}");
        }
    }

    #[test]
    fn rejects_a_degenerate_x25519_share() {
        let kx = KeyExchange::generate(Group::X25519);
        // Точка нулевого порядка: общий секрет предопределён.
        assert!(kx.complete(&[0_u8; 32]).is_err());
    }

    #[test]
    fn chrome_offers_both_groups_in_order() {
        let shares = KeyShares::chrome();
        let wire = shares.wire();
        assert_eq!(wire.len(), 2);
        assert_eq!(wire[0].0, X25519_MLKEM768);
        assert_eq!(wire[0].1.len(), 1216);
        assert_eq!(wire[1].0, X25519);
        assert_eq!(wire[1].1.len(), 32);
        assert!(shares.x25519().is_some());
    }

    #[test]
    fn every_generated_share_is_distinct() {
        let a = KeyShares::chrome();
        let b = KeyShares::chrome();
        assert_ne!(a.wire(), b.wire(), "доли обязаны быть эфемерными");
    }

    #[test]
    fn group_codes_round_trip() {
        for group in [Group::X25519, Group::X25519MlKem768] {
            assert_eq!(Group::from_code(group.code()), Some(group));
            assert_eq!(
                KeyExchange::generate(group).share().len(),
                group.client_share_len()
            );
        }
        assert_eq!(
            Group::from_code(0x0017),
            None,
            "secp256r1 пока не поддержан"
        );
    }
}
