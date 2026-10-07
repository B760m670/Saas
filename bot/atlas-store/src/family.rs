//! Гости: близкие, которым владелец дал свою подписку.
//!
//! У гостя своя запись и своя ссылка, а срок — владельца: его переносит
//! триггер `guests_follow_owner` (`db/migrations/0012_family.sql`). Здесь —
//! кто кого пригласил, сколько мест и кто их занял.

use crate::{Error, Store};

/// Сколько живёт приглашение, секунд. Неделя: приглашение пересылают
/// родным, и отвечают они не сразу. Дольше — и забытая ссылка в чужой
/// переписке осталась бы рабочим пропуском.
pub const INVITE_LIFETIME: i64 = 7 * 24 * 60 * 60;

/// Сколько гостей разрешает тариф.
///
/// То же правило записано в `atlas_bot::catalog::Tier::guests` — там оно
/// нужно витрине, здесь базе. Совпадение сторожит тест в `gloria`.
/// Без тарифа (платил до их появления, проба) гостей нет.
#[must_use]
pub fn guest_slots(tier: Option<&str>) -> i64 {
    match tier {
        Some("personal") => 1,
        Some("family") => 4,
        _ => 0,
    }
}

/// Чем кончилась попытка пригласить.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invited {
    /// Приглашение заведено.
    Created,
    /// Тариф без гостей: подписки нет, она кончилась или куплена до тарифов.
    NotEligible,
    /// Все места заняты.
    NoSlots,
}

/// Чем кончилось принятие приглашения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// Принято: теперь гость этого владельца, срок — до этого момента.
    Joined { owner_id: i64, expires_at: i64 },
    /// Такого приглашения нет, оно использовано или просрочено.
    Invalid,
    /// Своё же приглашение.
    OwnInvite,
    /// Подписка владельца кончилась или тариф больше не даёт гостей.
    OwnerInactive,
    /// Места кончились, пока приглашение шло.
    NoSlots,
    /// У человека своя оплаченная подписка — менять её на гостевую мы не
    /// станем молча: он потерял бы безлимит.
    HasOwnSubscription,
    /// Он уже чей-то гость.
    AlreadyGuest,
    /// У него самого есть гости: гостю гостей не положено.
    HasGuests,
}

/// Гость, как его видит владелец.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guest {
    /// Номер в Telegram.
    pub telegram_id: i64,
    /// С какого момента гость.
    pub since: i64,
    /// Номер в панели — по нему владелец видит расход гостя.
    pub panel_id: Option<i64>,
}

impl Store {
    /// Завести приглашение.
    ///
    /// Места проверяются здесь и ещё раз при принятии: приглашение места не
    /// занимает, пока его не приняли, — иначе пересланная и забытая ссылка
    /// держала бы место неделю.
    pub fn create_invite(&mut self, owner_id: i64, code: &str, now: i64) -> Result<Invited, Error> {
        let row = self.client.query_opt(
            "SELECT tier, expires_at > to_timestamp($2::bigint), owner_id IS NOT NULL,
                    (SELECT count(*) FROM users AS g WHERE g.owner_id = users.telegram_id)
               FROM users WHERE telegram_id = $1",
            &[&owner_id, &now],
        )?;
        let Some(row) = row else {
            return Ok(Invited::NotEligible);
        };
        let tier: Option<String> = row.try_get(0)?;
        let active: Option<bool> = row.try_get(1)?;
        let is_guest: bool = row.try_get(2)?;
        let guests: i64 = row.try_get(3)?;

        if active != Some(true) || is_guest || guest_slots(tier.as_deref()) == 0 {
            return Ok(Invited::NotEligible);
        }
        if guests >= guest_slots(tier.as_deref()) {
            return Ok(Invited::NoSlots);
        }

        self.client.execute(
            "INSERT INTO invites (code, owner_id, created_at)
             VALUES ($1, $2, to_timestamp($3::bigint))",
            &[&code, &owner_id, &now],
        )?;
        Ok(Invited::Created)
    }

    /// Принять приглашение.
    ///
    /// Одной транзакцией, и владелец берётся под замок: двое, принявшие два
    /// приглашения на последнее место одновременно, иначе заняли бы его оба.
    ///
    /// Человек к этому моменту уже заведён (`ensure_subscriber`): он пришёл
    /// в бота по ссылке.
    pub fn accept_invite(
        &mut self,
        guest_id: i64,
        code: &str,
        now: i64,
    ) -> Result<Accepted, Error> {
        let mut tx = self.client.transaction()?;

        let Some(invite) = tx.query_opt(
            "SELECT owner_id FROM invites
              WHERE code = $1 AND used_by IS NULL
                AND created_at > to_timestamp($2::bigint) - make_interval(secs => $3::bigint)
              FOR UPDATE",
            &[&code, &now, &INVITE_LIFETIME],
        )?
        else {
            return Ok(Accepted::Invalid);
        };
        let owner_id: i64 = invite.try_get(0)?;
        if owner_id == guest_id {
            return Ok(Accepted::OwnInvite);
        }

        let owner = tx.query_one(
            "SELECT tier, FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint, owner_id IS NOT NULL,
                    (SELECT count(*) FROM users AS g WHERE g.owner_id = users.telegram_id)
               FROM users WHERE telegram_id = $1 FOR UPDATE",
            &[&owner_id],
        )?;
        let tier: Option<String> = owner.try_get(0)?;
        let owner_expires: Option<i64> = owner.try_get(1)?;
        let owner_is_guest: bool = owner.try_get(2)?;
        let guests: i64 = owner.try_get(3)?;

        let Some(owner_expires) = owner_expires.filter(|at| *at > now) else {
            return Ok(Accepted::OwnerInactive);
        };
        if owner_is_guest || guest_slots(tier.as_deref()) == 0 {
            return Ok(Accepted::OwnerInactive);
        }
        if guests >= guest_slots(tier.as_deref()) {
            return Ok(Accepted::NoSlots);
        }

        let guest = tx.query_one(
            "SELECT owner_id IS NOT NULL,
                    expires_at > to_timestamp($2::bigint)
                      AND EXISTS (SELECT 1 FROM orders
                                   WHERE orders.telegram_id = users.telegram_id
                                     AND orders.status = 'paid'),
                    EXISTS (SELECT 1 FROM users AS g WHERE g.owner_id = users.telegram_id)
               FROM users WHERE telegram_id = $1 FOR UPDATE",
            &[&guest_id, &now],
        )?;
        let already_guest: bool = guest.try_get(0)?;
        let paid_active: Option<bool> = guest.try_get(1)?;
        let has_guests: bool = guest.try_get(2)?;

        if already_guest {
            return Ok(Accepted::AlreadyGuest);
        }
        if has_guests {
            return Ok(Accepted::HasGuests);
        }
        if paid_active == Some(true) {
            return Ok(Accepted::HasOwnSubscription);
        }

        tx.execute(
            "UPDATE users
                SET owner_id = $2, guest_since = to_timestamp($3::bigint),
                    expires_at = to_timestamp($4::bigint)
              WHERE telegram_id = $1",
            &[&guest_id, &owner_id, &now, &owner_expires],
        )?;
        tx.execute(
            "UPDATE invites SET used_by = $2, used_at = to_timestamp($3::bigint) WHERE code = $1",
            &[&code, &guest_id, &now],
        )?;
        tx.commit()?;

        Ok(Accepted::Joined {
            owner_id,
            expires_at: owner_expires,
        })
    }

    /// Отключить гостя. `false` — это не его гость.
    ///
    /// Срок гостя кончается сейчас, а не стирается: очередь увидит
    /// прошедшую дату и переведёт его на бесплатный доступ — тот же путь,
    /// что у кончившейся подписки.
    pub fn remove_guest(&mut self, owner_id: i64, guest_id: i64, now: i64) -> Result<bool, Error> {
        let removed = self.client.execute(
            "UPDATE users
                SET owner_id = NULL, guest_since = NULL,
                    expires_at = LEAST(expires_at, to_timestamp($3::bigint))
              WHERE telegram_id = $2 AND owner_id = $1",
            &[&owner_id, &guest_id, &now],
        )?;
        Ok(removed > 0)
    }

    /// Гости владельца, пришедшие раньше — первыми.
    pub fn guests_of(&mut self, owner_id: i64) -> Result<Vec<Guest>, Error> {
        self.client
            .query(
                "SELECT telegram_id, FLOOR(EXTRACT(EPOCH FROM guest_since))::bigint, panel_id
                   FROM users WHERE owner_id = $1
                  ORDER BY guest_since, telegram_id",
                &[&owner_id],
            )?
            .iter()
            .map(|row| {
                Ok(Guest {
                    telegram_id: row.try_get(0)?,
                    since: row.try_get(1)?,
                    panel_id: row.try_get(2)?,
                })
            })
            .collect()
    }
}
