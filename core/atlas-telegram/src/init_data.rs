//! Разбор и проверка строки `initData`.

use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Насколько старой может быть строка, по умолчанию — сутки.
///
/// Telegram выдаёт `initData` один раз при открытии приложения, и всё время
/// сеанса она не меняется. Слишком короткий срок выкидывал бы человека из
/// приложения посреди работы; слишком длинный оставляет украденной строке
/// долгую жизнь. Сутки — обычный для этого выбор.
pub const DEFAULT_MAX_AGE: i64 = 24 * 60 * 60;

/// Допуск на расхождение часов между нами и Telegram.
const CLOCK_SKEW: i64 = 5 * 60;

/// Почему строку нельзя принять.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// В строке нет поля `hash`.
    #[error("в initData нет подписи")]
    MissingHash,

    /// Подпись не той длины или не шестнадцатеричная.
    #[error("подпись имеет недопустимый вид")]
    MalformedHash,

    /// Подпись не сошлась. Строку изменили либо ключ бота не тот.
    #[error("подпись не сошлась")]
    BadSignature,

    /// Одно и то же поле встретилось дважды.
    ///
    /// Проверять при этом пришлось бы одно значение, а использовать другое —
    /// ровно та щель, через которую подпись обходят.
    #[error("поле {0} встречается более одного раза")]
    DuplicateField(String),

    /// Поле не разбирается как `ключ=значение`.
    #[error("поле без знака равенства")]
    MalformedField,

    /// Значение не является допустимой строкой после раскодирования.
    #[error("значение поля {0} не читается")]
    UndecodableValue(String),

    /// Нет поля `auth_date`.
    #[error("в initData нет времени выдачи")]
    MissingAuthDate,

    /// `auth_date` не число.
    #[error("время выдачи не разбирается")]
    MalformedAuthDate,

    /// Строка выдана слишком давно.
    #[error("initData выдана {age} с назад, допустимо {max_age} с")]
    Expired { age: i64, max_age: i64 },

    /// Строка выдана в будущем — дальше, чем объясняется расхождением часов.
    #[error("время выдачи в будущем на {0} с")]
    FromTheFuture(i64),

    /// Нет поля `user` либо оно не содержит идентификатора.
    #[error("в initData нет пользователя")]
    MissingUser,

    /// Поле `user` не разбирается как JSON.
    #[error("поле user не разбирается")]
    MalformedUser,
}

/// Проверенные данные. Создать эту структуру иначе, чем через [`verify`],
/// нельзя — значит наличие её на руках уже означает пройденную проверку.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    user_id: i64,
    auth_date: i64,
    username: Option<String>,
}

impl Verified {
    /// Идентификатор пользователя Telegram — наш первичный ключ.
    #[must_use]
    pub const fn user_id(&self) -> i64 {
        self.user_id
    }

    /// Когда Telegram выдал строку, в секундах эпохи.
    #[must_use]
    pub const fn auth_date(&self) -> i64 {
        self.auth_date
    }

    /// Имя пользователя, если оно у него есть. Только для показа: оно
    /// меняется по желанию владельца и ключом быть не может.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
}

#[derive(Deserialize)]
struct TelegramUser {
    id: i64,
    username: Option<String>,
}

/// Проверить строку `initData` ключом бота.
///
/// `now` — текущее время в секундах эпохи, `max_age` — предельный возраст
/// строки (см. [`DEFAULT_MAX_AGE`]). Время передаётся снаружи намеренно:
/// иначе истечение срока было бы нечем проверить в тестах.
///
/// # Как устроена проверка
///
/// 1. Из строки убирается поле `hash` — остальные остаются, включая
///    `signature`, если Telegram его прислал.
/// 2. Оставшиеся поля сортируются по имени и склеиваются переводами строк
///    в виде `ключ=значение`.
/// 3. Ключ подписи выводится как `HMAC-SHA256("WebAppData", токен_бота)`.
/// 4. Им подписывается склеенная строка, результат сравнивается с `hash`.
///
/// Порядок полей задан сортировкой, а не порядком в запросе: клиент волен
/// прислать их как угодно.
pub fn verify(raw: &str, bot_token: &str, now: i64, max_age: i64) -> Result<Verified, Error> {
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut received_hash: Option<String> = None;

    for pair in raw.split('&').filter(|part| !part.is_empty()) {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(Error::MalformedField);
        };

        let key = decode(key).ok_or_else(|| Error::UndecodableValue(key.to_owned()))?;
        let value = decode(value).ok_or_else(|| Error::UndecodableValue(key.clone()))?;

        if key == "hash" {
            if received_hash.is_some() {
                return Err(Error::DuplicateField(key));
            }
            received_hash = Some(value);
            continue;
        }

        if fields.iter().any(|(existing, _)| existing == &key) {
            return Err(Error::DuplicateField(key));
        }
        fields.push((key, value));
    }

    let received_hash = received_hash.ok_or(Error::MissingHash)?;
    if received_hash.len() != 64 || !received_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::MalformedHash);
    }

    fields.sort_by(|(left, _), (right, _)| left.cmp(right));
    let check_string = fields
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");

    let expected = sign(bot_token, &check_string)?;

    // Сравнение за постоянное время. Обычное `==` останавливается на первом
    // несовпавшем байте, и по времени ответа подпись подбирается по одному
    // символу за раз.
    let matches: bool = expected
        .as_bytes()
        .ct_eq(received_hash.to_ascii_lowercase().as_bytes())
        .into();
    if !matches {
        return Err(Error::BadSignature);
    }

    // Дальше — только после того, как подпись сошлась. Разбирать содержимое
    // непроверенной строки незачем: до этой точки все значения чужие.
    let find = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };

    let auth_date: i64 = find("auth_date")
        .ok_or(Error::MissingAuthDate)?
        .parse()
        .map_err(|_| Error::MalformedAuthDate)?;

    let age = now.saturating_sub(auth_date);
    if age < -CLOCK_SKEW {
        return Err(Error::FromTheFuture(-age));
    }
    if age > max_age {
        return Err(Error::Expired { age, max_age });
    }

    let user: TelegramUser = serde_json::from_str(find("user").ok_or(Error::MissingUser)?)
        .map_err(|_| Error::MalformedUser)?;

    Ok(Verified {
        user_id: user.id,
        auth_date,
        username: user.username,
    })
}

/// Подписать строку проверки ключом, выведенным из токена бота.
fn sign(bot_token: &str, check_string: &str) -> Result<String, Error> {
    // Ключ подписи — это сам токен, подписанный постоянной строкой
    // «WebAppData». Порядок здесь обратный привычному: ключом выступает
    // константа, сообщением — токен.
    let mut derive = HmacSha256::new_from_slice(b"WebAppData").map_err(|_| Error::BadSignature)?;
    derive.update(bot_token.as_bytes());
    let secret = derive.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&secret).map_err(|_| Error::BadSignature)?;
    mac.update(check_string.as_bytes());

    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn decode(value: &str) -> Option<String> {
    percent_decode_str(value)
        .decode_utf8()
        .ok()
        .map(std::borrow::Cow::into_owned)
}

#[cfg(test)]
mod tests {
    use super::{sign, verify, Error, DEFAULT_MAX_AGE};

    const TOKEN: &str = "123456:AAHkTestTokenForUnitTestsOnly";
    const NOW: i64 = 1_760_000_000;

    /// Собрать строку с настоящей подписью — как её собрал бы Telegram.
    fn signed(fields: &[(&str, &str)]) -> String {
        let mut sorted: Vec<_> = fields.to_vec();
        sorted.sort_by_key(|(left, _)| *left);
        let check = sorted
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("\n");

        let Ok(hash) = sign(TOKEN, &check) else {
            return String::new();
        };

        let mut query = fields
            .iter()
            .map(|(key, value)| format!("{key}={}", encode(value)))
            .collect::<Vec<_>>();
        query.push(format!("hash={hash}"));
        query.join("&")
    }

    /// Кодирование, достаточное для тестовых значений: JSON пользователя
    /// содержит символы, которые в строке запроса имеют своё значение.
    fn encode(value: &str) -> String {
        value
            .chars()
            .map(|c| match c {
                '{' => "%7B".to_owned(),
                '}' => "%7D".to_owned(),
                '"' => "%22".to_owned(),
                ':' => "%3A".to_owned(),
                ',' => "%2C".to_owned(),
                ' ' => "%20".to_owned(),
                '&' => "%26".to_owned(),
                '=' => "%3D".to_owned(),
                other => other.to_string(),
            })
            .collect()
    }

    fn user(id: i64) -> String {
        format!(r#"{{"id":{id},"first_name":"Иван","username":"ivan"}}"#)
    }

    fn ordinary() -> String {
        signed(&[
            ("query_id", "AAHdF6IQAAAAAN0XohDhrOrc"),
            ("user", &user(42)),
            ("auth_date", &NOW.to_string()),
        ])
    }

    #[test]
    fn an_honest_string_passes() {
        let verified = verify(&ordinary(), TOKEN, NOW, DEFAULT_MAX_AGE);
        assert!(verified.is_ok(), "честная строка отвергнута: {verified:?}");
        if let Ok(verified) = verified {
            assert_eq!(verified.user_id(), 42);
            assert_eq!(verified.username(), Some("ivan"));
            assert_eq!(verified.auth_date(), NOW);
        }
    }

    /// Главная проверка всего модуля: подменённый номер обязан не пройти.
    /// Именно так выглядит попытка открыть чужую подписку.
    #[test]
    fn a_swapped_user_id_is_rejected() {
        let honest = ordinary();
        let forged = honest.replace("%3A42%2C", "%3A43%2C");
        assert_ne!(honest, forged, "подмена не состоялась, тест бессмыслен");
        assert_eq!(
            verify(&forged, TOKEN, NOW, DEFAULT_MAX_AGE),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn another_bots_token_does_not_open_our_data() {
        assert_eq!(
            verify(
                &ordinary(),
                "999999:AnotherBotEntirely",
                NOW,
                DEFAULT_MAX_AGE
            ),
            Err(Error::BadSignature)
        );
    }

    /// Поле, приписанное к подписанной строке, меняет строку проверки —
    /// значит подпись обязана разойтись.
    #[test]
    fn an_appended_field_is_rejected() {
        let tampered = format!("{}&is_premium=true", ordinary());
        assert_eq!(
            verify(&tampered, TOKEN, NOW, DEFAULT_MAX_AGE),
            Err(Error::BadSignature)
        );
    }

    /// Дважды присланное поле — попытка развести проверяемое значение и
    /// используемое. Отвергается до вычисления подписи.
    #[test]
    fn a_repeated_field_is_rejected() {
        let tampered = format!("{}&auth_date=1", ordinary());
        assert_eq!(
            verify(&tampered, TOKEN, NOW, DEFAULT_MAX_AGE),
            Err(Error::DuplicateField("auth_date".to_owned()))
        );
    }

    #[test]
    fn a_second_hash_is_rejected() {
        let tampered = format!("{}&hash={}", ordinary(), "0".repeat(64));
        assert_eq!(
            verify(&tampered, TOKEN, NOW, DEFAULT_MAX_AGE),
            Err(Error::DuplicateField("hash".to_owned()))
        );
    }

    #[test]
    fn a_string_without_a_hash_is_rejected() {
        assert_eq!(
            verify(
                "user=%7B%22id%22%3A42%7D&auth_date=1",
                TOKEN,
                NOW,
                DEFAULT_MAX_AGE
            ),
            Err(Error::MissingHash)
        );
    }

    #[test]
    fn a_hash_of_the_wrong_shape_is_rejected() {
        for bad in ["abc", &"z".repeat(64), &"a".repeat(63)] {
            let tampered = format!("auth_date=1&hash={bad}");
            assert_eq!(
                verify(&tampered, TOKEN, NOW, DEFAULT_MAX_AGE),
                Err(Error::MalformedHash),
                "принята подпись {bad:?}"
            );
        }
    }

    /// Регистр подписи не должен влиять на исход: разные клиенты присылают
    /// её по-разному, а отвергнутый честный пользователь — это обращение
    /// в поддержку.
    #[test]
    fn an_uppercase_hash_still_passes() {
        let string = ordinary();
        assert!(
            string.contains("hash="),
            "тестовая строка собрана без подписи"
        );
        let Some((body, hash)) = string.rsplit_once("hash=") else {
            return;
        };
        let upper = format!("{body}hash={}", hash.to_ascii_uppercase());
        assert!(verify(&upper, TOKEN, NOW, DEFAULT_MAX_AGE).is_ok());
    }

    #[test]
    fn a_stale_string_is_rejected() {
        let age = DEFAULT_MAX_AGE + 1;
        assert_eq!(
            verify(&ordinary(), TOKEN, NOW + age, DEFAULT_MAX_AGE),
            Err(Error::Expired {
                age,
                max_age: DEFAULT_MAX_AGE
            })
        );
    }

    /// Ровно на границе строка ещё действительна: иначе срок жизни зависел
    /// бы от того, в какую секунду пришёл запрос.
    #[test]
    fn the_last_permitted_second_still_passes() {
        assert!(verify(&ordinary(), TOKEN, NOW + DEFAULT_MAX_AGE, DEFAULT_MAX_AGE).is_ok());
    }

    /// Небольшое расхождение часов — обычное дело, отвергать из-за него
    /// нельзя.
    #[test]
    fn a_slightly_fast_clock_is_tolerated() {
        assert!(verify(&ordinary(), TOKEN, NOW - 60, DEFAULT_MAX_AGE).is_ok());
    }

    #[test]
    fn a_wildly_future_string_is_rejected() {
        assert!(matches!(
            verify(&ordinary(), TOKEN, NOW - 3600, DEFAULT_MAX_AGE),
            Err(Error::FromTheFuture(_))
        ));
    }

    #[test]
    fn a_string_without_a_user_is_rejected() {
        let without = signed(&[("auth_date", &NOW.to_string())]);
        assert_eq!(
            verify(&without, TOKEN, NOW, DEFAULT_MAX_AGE),
            Err(Error::MissingUser)
        );
    }

    #[test]
    fn a_string_without_an_auth_date_is_rejected() {
        let without = signed(&[("user", &user(42))]);
        assert_eq!(
            verify(&without, TOKEN, NOW, DEFAULT_MAX_AGE),
            Err(Error::MissingAuthDate)
        );
    }

    /// Поле `signature` Telegram присылает для сторонней проверки, но из
    /// строки проверки оно не выбрасывается — иначе подпись не сойдётся ни
    /// у одного пользователя, у которого оно есть.
    #[test]
    fn a_signature_field_takes_part_in_the_check() {
        let with_signature = signed(&[
            ("user", &user(42)),
            ("auth_date", &NOW.to_string()),
            ("signature", "abcdef0123456789"),
        ]);
        assert!(verify(&with_signature, TOKEN, NOW, DEFAULT_MAX_AGE).is_ok());
    }

    #[test]
    fn an_empty_string_is_rejected() {
        assert_eq!(
            verify("", TOKEN, NOW, DEFAULT_MAX_AGE),
            Err(Error::MissingHash)
        );
    }

    #[test]
    fn a_field_without_an_equals_sign_is_rejected() {
        assert_eq!(
            verify("brokenfield", TOKEN, NOW, DEFAULT_MAX_AGE),
            Err(Error::MalformedField)
        );
    }
}
