//! Вход на сайт через бота: коды входа и сессии браузера.
//!
//! Как устроено и почему — в `db/migrations/0017_web_login.sql`. Код и
//! сессия в базу попадают только хешем (`sha256` самой базы), поэтому сюда
//! передаются как есть, а сравниваются уже хеши.

use crate::{Error, Store};

/// Хеш строки, посчитанный базой, — одинаково при записи и при поиске.
const HASH: &str = "encode(sha256(convert_to($1, 'UTF8')), 'hex')";

/// Чем кончилась проверка кода входа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginCheck {
    /// Ещё не подтверждён в боте — подождать.
    Pending,
    /// Подтверждён и обменян на сессию этого человека.
    Signed(i64),
    /// Кода нет, он просрочен или уже обменян.
    Gone,
}

impl Store {
    /// Завести код входа на `ttl` секунд. Заодно убирает давно мёртвые коды
    /// и сессии — других мест, где бы они чистились, нет.
    pub fn create_login(&mut self, code: &str, now: i64, ttl: i64) -> Result<(), Error> {
        self.client.execute(
            "DELETE FROM login_requests WHERE expires_at < to_timestamp($1::bigint) - interval '1 day'",
            &[&now],
        )?;
        self.client.execute(
            "DELETE FROM web_sessions WHERE expires_at < to_timestamp($1::bigint)",
            &[&now],
        )?;
        self.client.execute(
            &format!(
                "INSERT INTO login_requests (code_hash, created_at, expires_at)
                 VALUES ({HASH}, to_timestamp($2::bigint), to_timestamp($3::bigint))"
            ),
            &[&code, &now, &now.saturating_add(ttl)],
        )?;
        Ok(())
    }

    /// Человек нажал в боте «Подтвердить вход». `false` — код неизвестен,
    /// просрочен или уже подтверждён (возможно, кем-то другим).
    pub fn confirm_login(&mut self, code: &str, telegram_id: i64, now: i64) -> Result<bool, Error> {
        let changed = self.client.execute(
            &format!(
                "UPDATE login_requests
                    SET telegram_id = $2, confirmed_at = to_timestamp($3::bigint)
                  WHERE code_hash = {HASH}
                    AND confirmed_at IS NULL
                    AND expires_at > to_timestamp($3::bigint)"
            ),
            &[&code, &telegram_id, &now],
        )?;
        Ok(changed > 0)
    }

    /// Сайт спрашивает, подтверждён ли код. Подтверждён — код гасится и
    /// заводится сессия `session` на `ttl` секунд. Одной транзакцией: два
    /// одновременных опроса не получат две сессии.
    pub fn take_login(
        &mut self,
        code: &str,
        session: &str,
        now: i64,
        ttl: i64,
    ) -> Result<LoginCheck, Error> {
        let mut tx = self.client.transaction()?;
        let Some(row) = tx.query_opt(
            &format!(
                "SELECT telegram_id FROM login_requests
                  WHERE code_hash = {HASH}
                    AND consumed_at IS NULL
                    AND expires_at > to_timestamp($2::bigint)
                  FOR UPDATE"
            ),
            &[&code, &now],
        )?
        else {
            return Ok(LoginCheck::Gone);
        };
        let Some(telegram_id): Option<i64> = row.try_get(0)? else {
            return Ok(LoginCheck::Pending);
        };

        tx.execute(
            &format!(
                "UPDATE login_requests SET consumed_at = to_timestamp($2::bigint)
                  WHERE code_hash = {HASH}"
            ),
            &[&code, &now],
        )?;
        tx.execute(
            &format!(
                "INSERT INTO web_sessions (token_hash, telegram_id, created_at, expires_at)
                 VALUES ({HASH}, $2, to_timestamp($3::bigint), to_timestamp($4::bigint))"
            ),
            &[&session, &telegram_id, &now, &now.saturating_add(ttl)],
        )?;
        tx.commit()?;
        Ok(LoginCheck::Signed(telegram_id))
    }

    /// Чья это сессия. `None` — нет такой или истекла.
    pub fn session_user(&mut self, session: &str, now: i64) -> Result<Option<i64>, Error> {
        let row = self.client.query_opt(
            &format!(
                "SELECT telegram_id FROM web_sessions
                  WHERE token_hash = {HASH} AND expires_at > to_timestamp($2::bigint)"
            ),
            &[&session, &now],
        )?;
        Ok(match row {
            Some(row) => Some(row.try_get(0)?),
            None => None,
        })
    }

    /// Выйти: сессия перестаёт работать сразу.
    pub fn drop_session(&mut self, session: &str) -> Result<(), Error> {
        self.client.execute(
            &format!("DELETE FROM web_sessions WHERE token_hash = {HASH}"),
            &[&session],
        )?;
        Ok(())
    }
}
