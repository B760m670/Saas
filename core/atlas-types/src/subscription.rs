//! Разбор подписок — списков ключей, отдаваемых по HTTP.
//!
//! Общепринятого формата нет. На практике встречается: список URI по строке
//! на ключ, тот же список целиком в base64, и то же самое с произвольными
//! комментариями и пустыми строками внутри.

use crate::b64;
use crate::error::Error;
use crate::key::ProxyKey;

/// Результат разбора подписки.
#[derive(Debug, Clone, Default)]
pub struct Subscription {
    /// Успешно разобранные ключи.
    pub keys: Vec<ProxyKey>,
    /// Строки, которые разобрать не удалось, вместе с причиной.
    ///
    /// Не отбрасываются молча: пользователю важно знать, что часть подписки
    /// не импортировалась, и почему.
    pub rejected: Vec<(String, Error)>,
}

impl Subscription {
    /// Разобрать тело подписки.
    ///
    /// Сначала пробуем как есть, затем — как base64 от такого же списка.
    /// Ошибку не возвращаем: подписка с одним битым ключом из ста должна
    /// импортироваться.
    #[must_use]
    pub fn parse(body: &str) -> Self {
        let direct = Self::parse_lines(body);
        if !direct.keys.is_empty() {
            return direct;
        }

        match b64::decode_str(body, "subscription") {
            Ok(decoded) => {
                let nested = Self::parse_lines(&decoded);
                if nested.keys.is_empty() {
                    direct
                } else {
                    nested
                }
            }
            Err(_) => direct,
        }
    }

    fn parse_lines(body: &str) -> Self {
        let mut out = Self::default();
        for line in body.lines() {
            let line = line.trim();
            // Пустые строки и комментарии — не ошибка, просто пропускаем.
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            match ProxyKey::parse(line) {
                Ok(key) => out.keys.push(key),
                Err(err) => out.rejected.push((line.to_owned(), err)),
            }
        }
        out
    }

    /// Количество успешно разобранных ключей.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Не удалось разобрать ни одного ключа.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
vless://11111111-2222-3333-4444-555555555555@a.example:443?security=reality&pbk=K&sni=w.example&flow=xtls-rprx-vision#Первая
# комментарий

trojan://secret@b.example:443?security=tls&sni=b.example#Вторая
это не ключ
";

    #[test]
    fn parses_plain_list_and_reports_rejects() {
        let sub = Subscription::parse(SAMPLE);
        assert_eq!(sub.len(), 2);
        assert_eq!(sub.rejected.len(), 1);
        assert_eq!(sub.rejected[0].0, "это не ключ");
    }

    #[test]
    fn parses_base64_wrapped_list() {
        let sub = Subscription::parse(&b64::encode(SAMPLE));
        assert_eq!(sub.len(), 2);
    }

    #[test]
    fn empty_body_yields_nothing() {
        assert!(Subscription::parse("").is_empty());
    }
}
