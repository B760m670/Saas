//! Новости и турниры приглашений.
//!
//! Правила турнира — в `db/migrations/0014_news_tournaments.sql`: кто
//! засчитывается и почему. Здесь — как это считается.

use atlas_billing::subscription;

use crate::{Error, Store};

/// Сколько дней подписки за место. Первое — 3 месяца, второе и третье —
/// по 2, с четвёртого по десятое — по месяцу.
#[must_use]
pub const fn prize_days(place: i64) -> Option<i32> {
    match place {
        1 => Some(90),
        2 | 3 => Some(60),
        4..=10 => Some(30),
        _ => None,
    }
}

/// Сколько призовых мест.
pub const PRIZE_PLACES: i64 = 10;

/// Новость.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct News {
    pub id: i64,
    pub title: String,
    pub body: String,
    pub created_at: i64,
}

/// Идущий или последний турнир.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tournament {
    pub id: i64,
    pub starts_at: i64,
    pub ends_at: i64,
    pub min_score: i32,
    pub finished_at: Option<i64>,
    /// С какого момента турнир на паузе. `None` — идёт.
    pub paused_at: Option<i64>,
}

/// Строка таблицы турнира.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    /// Место по порядку: 1, 2, 3… Ничья решается тем, кто набрал раньше.
    pub place: i64,
    pub telegram_id: i64,
    pub name: Option<String>,
    pub score: i64,
}

/// Выданный приз.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prize {
    pub place: i64,
    pub telegram_id: i64,
    pub score: i64,
    pub days: i32,
    /// До какого срока теперь подписка.
    pub expires_at: i64,
}

/// Чем кончилась попытка начать турнир.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Started {
    Started(i64),
    /// Уже идёт другой.
    AlreadyRunning,
}

/// Таблица очков. Одна на всё: и для показа, и для подведения итогов —
/// иначе показанное место однажды разошлось бы с выданным призом.
///
/// `$1` — номер турнира. Засчитывается приглашённый, пришедший во время
/// турнира, но не во время паузы, и подключившийся до его конца. Ничья —
/// выше тот, чьё последнее засчитанное подключение раньше.
const STANDINGS: &str = "
    WITH t AS (SELECT starts_at, ends_at, paused_at FROM tournaments WHERE id = $1),
    scored AS (
        SELECT friend.invited_by AS inviter,
               COUNT(*) AS score,
               MAX(friend.connected_at) AS reached
          FROM users AS friend, t
         WHERE friend.invited_by IS NOT NULL
           AND friend.created_at >= t.starts_at
           AND friend.created_at < t.ends_at
           AND friend.connected_at IS NOT NULL
           AND friend.connected_at < t.ends_at
           AND (t.paused_at IS NULL OR friend.created_at < t.paused_at)
           AND NOT EXISTS (
                 SELECT 1 FROM tournament_pauses AS p
                  WHERE p.tournament_id = $1
                    AND friend.created_at >= p.from_at
                    AND friend.created_at < p.to_at)
         GROUP BY friend.invited_by
    )
    SELECT ROW_NUMBER() OVER (ORDER BY score DESC, reached, inviter)::bigint,
           inviter, users.display_name, score::bigint
      FROM scored JOIN users ON users.telegram_id = scored.inviter
     ORDER BY 1";

fn tournament(row: &postgres::Row) -> Result<Tournament, Error> {
    Ok(Tournament {
        id: row.try_get(0)?,
        starts_at: row.try_get(1)?,
        ends_at: row.try_get(2)?,
        min_score: row.try_get(3)?,
        finished_at: row.try_get(4)?,
        paused_at: row.try_get(5)?,
    })
}

const TOURNAMENT_COLUMNS: &str = "id,
    FLOOR(EXTRACT(EPOCH FROM starts_at))::bigint,
    FLOOR(EXTRACT(EPOCH FROM ends_at))::bigint,
    min_score,
    FLOOR(EXTRACT(EPOCH FROM finished_at))::bigint,
    FLOOR(EXTRACT(EPOCH FROM paused_at))::bigint";

impl Store {
    // --- имя и подключение ------------------------------------------------

    /// Запомнить имя для таблицы турнира. Пустое и слишком длинное не
    /// пишется: показывать нечего или это не имя.
    pub fn remember_name(&mut self, telegram_id: i64, name: &str) -> Result<(), Error> {
        let name: String = name.trim().chars().take(64).collect();
        if name.is_empty() {
            return Ok(());
        }
        self.client.execute(
            "UPDATE users SET display_name = $2
              WHERE telegram_id = $1 AND display_name IS DISTINCT FROM $2",
            &[&telegram_id, &name],
        )?;
        Ok(())
    }

    /// Приглашённые идущего турнира, про которых ещё неизвестно, подключились
    /// ли они. Их проверяют в панели по одному.
    pub fn unconfirmed_invitees(&mut self, now: i64, limit: i64) -> Result<Vec<i64>, Error> {
        self.client
            .query(
                "SELECT friend.telegram_id
                   FROM users AS friend, tournaments AS t
                  WHERE t.finished_at IS NULL
                    AND friend.invited_by IS NOT NULL
                    AND friend.connected_at IS NULL
                    AND friend.panel_id IS NOT NULL
                    AND friend.created_at >= t.starts_at
                    AND friend.created_at < t.ends_at
                    AND t.ends_at > to_timestamp($1::bigint)
                  ORDER BY friend.created_at
                  LIMIT $2",
                &[&now, &limit],
            )?
            .iter()
            .map(|row| Ok(row.try_get(0)?))
            .collect()
    }

    /// Панель увидела трафик: человек подключился.
    pub fn mark_connected(&mut self, telegram_id: i64, now: i64) -> Result<(), Error> {
        self.client.execute(
            "UPDATE users SET connected_at = to_timestamp($2::bigint)
              WHERE telegram_id = $1 AND connected_at IS NULL",
            &[&telegram_id, &now],
        )?;
        Ok(())
    }

    // --- новости ----------------------------------------------------------

    /// Опубликовать новость. Возвращает её номер.
    pub fn publish_news(
        &mut self,
        author_id: i64,
        title: &str,
        body: &str,
        pushed: bool,
        now: i64,
    ) -> Result<i64, Error> {
        let row = self.client.query_one(
            "INSERT INTO news (title, body, author_id, pushed, created_at)
             VALUES ($1, $2, $3, $4, to_timestamp($5::bigint))
             RETURNING id",
            &[&title, &body, &author_id, &pushed, &now],
        )?;
        Ok(row.try_get(0)?)
    }

    /// Последние новости, новые сверху.
    pub fn latest_news(&mut self, limit: i64) -> Result<Vec<News>, Error> {
        self.client
            .query(
                "SELECT id, title, body, FLOOR(EXTRACT(EPOCH FROM created_at))::bigint
                   FROM news ORDER BY created_at DESC, id DESC LIMIT $1",
                &[&limit],
            )?
            .iter()
            .map(|row| {
                Ok(News {
                    id: row.try_get(0)?,
                    title: row.try_get(1)?,
                    body: row.try_get(2)?,
                    created_at: row.try_get(3)?,
                })
            })
            .collect()
    }

    /// Сколько новостей человек не видел.
    pub fn unread_news(&mut self, telegram_id: i64) -> Result<i64, Error> {
        let row = self.client.query_one(
            "SELECT COUNT(*)::bigint FROM news
              WHERE created_at > COALESCE(
                    (SELECT news_seen_at FROM users WHERE telegram_id = $1),
                    '-infinity')",
            &[&telegram_id],
        )?;
        Ok(row.try_get(0)?)
    }

    /// Человек открыл ленту.
    pub fn mark_news_seen(&mut self, telegram_id: i64, now: i64) -> Result<(), Error> {
        self.client.execute(
            "UPDATE users SET news_seen_at = to_timestamp($2::bigint) WHERE telegram_id = $1",
            &[&telegram_id, &now],
        )?;
        Ok(())
    }

    /// Выключить или включить новости сообщением в бот.
    pub fn set_news_muted(&mut self, telegram_id: i64, muted: bool) -> Result<(), Error> {
        self.client.execute(
            "UPDATE users SET news_muted = $2 WHERE telegram_id = $1",
            &[&telegram_id, &muted],
        )?;
        Ok(())
    }

    /// Выключены ли новости в боте.
    pub fn news_muted(&mut self, telegram_id: i64) -> Result<bool, Error> {
        let row = self.client.query_opt(
            "SELECT news_muted FROM users WHERE telegram_id = $1",
            &[&telegram_id],
        )?;
        Ok(match row {
            Some(row) => row.try_get(0)?,
            None => false,
        })
    }

    /// Кому разослать новость сообщением.
    pub fn news_recipients(&mut self) -> Result<Vec<i64>, Error> {
        self.client
            .query(
                "SELECT telegram_id FROM users WHERE NOT news_muted ORDER BY telegram_id",
                &[],
            )?
            .iter()
            .map(|row| Ok(row.try_get(0)?))
            .collect()
    }

    // --- турниры ----------------------------------------------------------

    /// Начать турнир сейчас и на `days` дней.
    pub fn start_tournament(
        &mut self,
        admin_id: i64,
        days: u32,
        min_score: i32,
        now: i64,
    ) -> Result<Started, Error> {
        let ends_at = now.saturating_add(i64::from(days) * 24 * 60 * 60);
        let row = self.client.query_opt(
            "INSERT INTO tournaments (starts_at, ends_at, min_score, created_by)
             VALUES (to_timestamp($1::bigint), to_timestamp($2::bigint), $3, $4)
             ON CONFLICT DO NOTHING
             RETURNING id",
            &[&now, &ends_at, &min_score, &admin_id],
        )?;
        Ok(match row {
            Some(row) => Started::Started(row.try_get(0)?),
            None => Started::AlreadyRunning,
        })
    }

    /// Продлить идущий турнир на `days` дней. Возвращает новый срок; `None` —
    /// турнир не идёт.
    pub fn extend_tournament(&mut self, days: u32) -> Result<Option<i64>, Error> {
        let row = self.client.query_opt(
            "UPDATE tournaments
                SET ends_at = ends_at + make_interval(days => $1::int)
              WHERE finished_at IS NULL
              RETURNING FLOOR(EXTRACT(EPOCH FROM ends_at))::bigint",
            &[&i32::try_from(days).unwrap_or(0)],
        )?;
        Ok(match row {
            Some(row) => Some(row.try_get(0)?),
            None => None,
        })
    }

    /// Идущий турнир.
    pub fn open_tournament(&mut self) -> Result<Option<Tournament>, Error> {
        let row = self.client.query_opt(
            &format!("SELECT {TOURNAMENT_COLUMNS} FROM tournaments WHERE finished_at IS NULL"),
            &[],
        )?;
        row.as_ref().map(tournament).transpose()
    }

    /// Последний турнир с подведёнными итогами. Выключенный итогов не
    /// имеет и сюда не попадает.
    pub fn last_finished_tournament(&mut self) -> Result<Option<Tournament>, Error> {
        let row = self.client.query_opt(
            &format!(
                "SELECT {TOURNAMENT_COLUMNS} FROM tournaments
                  WHERE finished_at IS NOT NULL AND NOT cancelled
                  ORDER BY finished_at DESC LIMIT 1"
            ),
            &[],
        )?;
        row.as_ref().map(tournament).transpose()
    }

    /// Таблица турнира целиком, по местам.
    pub fn standings(&mut self, tournament_id: i64) -> Result<Vec<Standing>, Error> {
        self.client
            .query(STANDINGS, &[&tournament_id])?
            .iter()
            .map(|row| {
                Ok(Standing {
                    place: row.try_get(0)?,
                    telegram_id: row.try_get(1)?,
                    name: row.try_get(2)?,
                    score: row.try_get(3)?,
                })
            })
            .collect()
    }

    /// Призы завершённого турнира.
    pub fn prizes_of(&mut self, tournament_id: i64) -> Result<Vec<Prize>, Error> {
        self.client
            .query(
                "SELECT p.place::bigint, p.telegram_id, p.score::bigint, p.days,
                        COALESCE(FLOOR(EXTRACT(EPOCH FROM u.expires_at))::bigint, 0)
                   FROM tournament_prizes AS p JOIN users AS u USING (telegram_id)
                  WHERE p.tournament_id = $1 ORDER BY p.place",
                &[&tournament_id],
            )?
            .iter()
            .map(|row| {
                Ok(Prize {
                    place: row.try_get(0)?,
                    telegram_id: row.try_get(1)?,
                    score: row.try_get(2)?,
                    days: row.try_get(3)?,
                    expires_at: row.try_get(4)?,
                })
            })
            .collect()
    }

    /// Подвести итоги и выдать призы. Одной транзакцией: турнир берётся под
    /// замок, и второй вызов (круг бота и кнопка в админке одновременно)
    /// найдёт его уже завершённым и не выдаст призы второй раз.
    ///
    /// `None` — турнира нет или он уже завершён.
    pub fn finish_tournament(
        &mut self,
        tournament_id: i64,
        now: i64,
    ) -> Result<Option<Vec<Prize>>, Error> {
        let mut tx = self.client.transaction()?;

        let Some(row) = tx.query_opt(
            "SELECT min_score FROM tournaments
              WHERE id = $1 AND finished_at IS NULL FOR UPDATE",
            &[&tournament_id],
        )?
        else {
            return Ok(None);
        };
        let min_score: i32 = row.try_get(0)?;

        let winners: Vec<(i64, i64, i64)> = tx
            .query(STANDINGS, &[&tournament_id])?
            .iter()
            .map(|row| Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(3)?)))
            .collect::<Result<_, Error>>()?;

        let mut prizes = Vec::new();
        // Места даются только набравшим порог, и подряд: не дотянувший до
        // порога не занимает место, которое досталось бы следующему.
        let qualified = winners
            .into_iter()
            .filter(|(_, _, score)| *score >= i64::from(min_score))
            .take(usize::try_from(PRIZE_PLACES).unwrap_or(10));

        for (place, (_, telegram_id, score)) in (1_i64..).zip(qualified) {
            let Some(days) = prize_days(place) else {
                break;
            };

            let current: Option<i64> = tx
                .query_one(
                    "SELECT FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint FROM users
                      WHERE telegram_id = $1 FOR UPDATE",
                    &[&telegram_id],
                )?
                .try_get(0)?;
            let Some(expires_at) =
                subscription::extend(current, u32::try_from(days).unwrap_or(0), now)
            else {
                return Err(Error::Inconsistent("срок приза не считается"));
            };

            tx.execute(
                "UPDATE users SET expires_at = to_timestamp($2::bigint) WHERE telegram_id = $1",
                &[&telegram_id, &expires_at],
            )?;
            tx.execute(
                "INSERT INTO tournament_prizes (tournament_id, place, telegram_id, score, days)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &tournament_id,
                    &i32::try_from(place).unwrap_or(i32::MAX),
                    &telegram_id,
                    &i32::try_from(score).unwrap_or(i32::MAX),
                    &days,
                ],
            )?;
            prizes.push(Prize {
                place,
                telegram_id,
                score,
                days,
                expires_at,
            });
        }

        tx.execute(
            "UPDATE tournaments SET finished_at = to_timestamp($2::bigint) WHERE id = $1",
            &[&tournament_id, &now],
        )?;
        tx.commit()?;
        Ok(Some(prizes))
    }

    /// Поставить идущий турнир на паузу. `false` — турнир не идёт или уже
    /// на паузе.
    ///
    /// Очки остаются как были; новые приглашённые, пока пауза, не
    /// засчитываются (`STANDINGS`).
    pub fn pause_tournament(&mut self, now: i64) -> Result<bool, Error> {
        let changed = self.client.execute(
            "UPDATE tournaments SET paused_at = to_timestamp($1::bigint)
              WHERE finished_at IS NULL AND paused_at IS NULL",
            &[&now],
        )?;
        Ok(changed > 0)
    }

    /// Снять паузу: срок сдвигается на её длину, и турнир продолжается с
    /// того места, где остановился. Возвращает новый срок; `None` — турнир
    /// не на паузе.
    pub fn resume_tournament(&mut self, now: i64) -> Result<Option<i64>, Error> {
        let mut tx = self.client.transaction()?;
        let Some(row) = tx.query_opt(
            "SELECT id, paused_at FROM tournaments
              WHERE finished_at IS NULL AND paused_at IS NOT NULL FOR UPDATE",
            &[],
        )?
        else {
            return Ok(None);
        };
        let id: i64 = row.try_get(0)?;

        // Пауза записывается, чтобы пришедшие в неё не засчитались и потом.
        // `GREATEST` — на случай часов, ушедших назад: пауза не бывает
        // отрицательной.
        tx.execute(
            "INSERT INTO tournament_pauses (tournament_id, from_at, to_at)
             SELECT id, paused_at, GREATEST(paused_at, to_timestamp($2::bigint))
               FROM tournaments WHERE id = $1",
            &[&id, &now],
        )?;
        let row = tx.query_one(
            "UPDATE tournaments
                SET ends_at = ends_at + GREATEST(to_timestamp($2::bigint) - paused_at, interval '0'),
                    paused_at = NULL
              WHERE id = $1
              RETURNING FLOOR(EXTRACT(EPOCH FROM ends_at))::bigint",
            &[&id, &now],
        )?;
        let ends_at: i64 = row.try_get(0)?;
        tx.commit()?;
        Ok(Some(ends_at))
    }

    /// Выключить идущий турнир: закрыть без итогов и призов. Следующий
    /// начнётся с нуля — очки считаются от его собственного начала.
    /// Возвращает номер выключенного; `None` — турнир не идёт.
    pub fn cancel_tournament(&mut self, now: i64) -> Result<Option<i64>, Error> {
        let row = self.client.query_opt(
            "UPDATE tournaments
                SET finished_at = to_timestamp($1::bigint), cancelled = true
              WHERE finished_at IS NULL
              RETURNING id",
            &[&now],
        )?;
        Ok(match row {
            Some(row) => Some(row.try_get(0)?),
            None => None,
        })
    }

    /// Турниры, срок которых вышел, а итоги не подведены. Турнир на паузе
    /// не кончается: его время стоит.
    pub fn due_tournament(&mut self, now: i64) -> Result<Option<i64>, Error> {
        let row = self.client.query_opt(
            "SELECT id FROM tournaments
              WHERE finished_at IS NULL AND paused_at IS NULL
                AND ends_at <= to_timestamp($1::bigint)",
            &[&now],
        )?;
        Ok(match row {
            Some(row) => Some(row.try_get(0)?),
            None => None,
        })
    }
}
