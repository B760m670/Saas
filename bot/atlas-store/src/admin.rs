//! Запросы админки: сводка, карточка покупателя, ручные действия.
//!
//! Всё, что меняет состояние, пишет строку в `admin_log` в той же
//! транзакции. Действие без следа — это вопрос «почему у него срок до
//! марта», на который через месяц никто не ответит.

use atlas_billing::subscription;

use crate::{Error, Store, Subscriber};

/// Сколько дней можно добавить за одно ручное продление.
///
/// Десять лет — не цель, а предохранитель от опечатки: лишний ноль в поле
/// «дней» не должен подарить человеку подписку до следующего века.
pub const MAX_MANUAL_DAYS: u32 = 3650;

/// Сводка для первого экрана админки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Сколько всего людей заходило в бота.
    pub users: i64,
    /// Срок идёт, и была хоть одна оплата.
    pub active_paid: i64,
    /// Срок идёт, оплат не было: проба.
    pub active_trial: i64,
    /// Срок был и кончился.
    pub expired: i64,
    /// Срока не было никогда: зашёл и не взял даже пробу.
    pub never: i64,
    /// Получено сегодня, копейки. Сутки — по Москве.
    pub revenue_today: i64,
    /// Получено с начала месяца, копейки. Месяц — по Москве.
    pub revenue_month: i64,
    /// Оплат сегодня.
    pub payments_today: i64,
    /// Оплат с начала месяца.
    pub payments_month: i64,
    /// Последние оплаты, свежие первыми.
    pub recent: Vec<Payment>,
}

/// Одна оплата, как её показывает админка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    /// Кто платил. `None` — платёж без заказа, такого быть не должно.
    pub telegram_id: Option<i64>,
    /// Тариф заказа.
    pub plan: Option<String>,
    /// Сколько пришло, копейки.
    pub amount: i64,
    /// Через кого.
    pub provider: String,
    /// Когда, секунды эпохи.
    pub at: i64,
}

/// Запись журнала админки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Кто сделал.
    pub admin_id: i64,
    /// `extend` или `reissue`.
    pub action: String,
    /// Подробности: для продления — число дней.
    pub detail: String,
    /// Когда.
    pub at: i64,
}

/// Карточка покупателя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// То же, что видит бот.
    pub subscriber: Subscriber,
    /// Когда пришёл впервые.
    pub created_at: i64,
    /// Кто привёл.
    pub invited_by: Option<i64>,
    /// Какие отряды панель подтвердила: `paid`, `free` или ничего.
    pub panel_plan: Option<String>,
    /// Оплаты, свежие первыми.
    pub payments: Vec<Payment>,
    /// Что с ним делали в админке, свежее первым.
    pub log: Vec<LogEntry>,
}

/// Чем кончилось ручное продление.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extended {
    /// Продлено, новый срок.
    Until(i64),
    /// Такого человека нет: в бота он не заходил.
    NoSuchUser,
}

impl Store {
    /// Сводка для первого экрана.
    ///
    /// Границы суток и месяца — по Москве: выручку «за сегодня» владелец
    /// сверяет со своими сутками, а не с гринвичскими.
    pub fn admin_summary(&mut self, now: i64) -> Result<Summary, Error> {
        let counts = self.client.query_one(
            "SELECT count(*),
                    count(*) FILTER (WHERE expires_at > to_timestamp($1::bigint) AND paid),
                    count(*) FILTER (WHERE expires_at > to_timestamp($1::bigint) AND NOT paid),
                    count(*) FILTER (WHERE expires_at <= to_timestamp($1::bigint)),
                    count(*) FILTER (WHERE expires_at IS NULL)
               FROM (SELECT expires_at,
                            EXISTS (SELECT 1 FROM orders
                                     WHERE orders.telegram_id = users.telegram_id
                                       AND orders.status = 'paid') AS paid
                       FROM users) AS u",
            &[&now],
        )?;

        let money = self.client.query_one(
            "WITH bounds AS (
                 SELECT date_trunc('day', to_timestamp($1::bigint) AT TIME ZONE 'Europe/Moscow')
                            AT TIME ZONE 'Europe/Moscow' AS day,
                        date_trunc('month', to_timestamp($1::bigint) AT TIME ZONE 'Europe/Moscow')
                            AT TIME ZONE 'Europe/Moscow' AS month
             )
             SELECT COALESCE(sum(amount_minor) FILTER (WHERE received_at >= bounds.day), 0)::bigint,
                    COALESCE(sum(amount_minor) FILTER (WHERE received_at >= bounds.month), 0)::bigint,
                    count(*) FILTER (WHERE received_at >= bounds.day),
                    count(*) FILTER (WHERE received_at >= bounds.month)
               FROM payments, bounds
              WHERE status = 'paid' AND currency = 'RUB'",
            &[&now],
        )?;

        let recent = self.payments_where(None, 10)?;

        Ok(Summary {
            users: counts.try_get(0)?,
            active_paid: counts.try_get(1)?,
            active_trial: counts.try_get(2)?,
            expired: counts.try_get(3)?,
            never: counts.try_get(4)?,
            revenue_today: money.try_get(0)?,
            revenue_month: money.try_get(1)?,
            payments_today: money.try_get(2)?,
            payments_month: money.try_get(3)?,
            recent,
        })
    }

    /// Карточка покупателя. `None` — в бота он не заходил.
    ///
    /// Покупатель не заводится, если его нет: админка смотрит, а не создаёт.
    pub fn admin_card(&mut self, telegram_id: i64) -> Result<Option<Card>, Error> {
        let Some(row) = self.client.query_opt(
            "SELECT telegram_id,
                    FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint,
                    FLOOR(EXTRACT(EPOCH FROM panel_expires_at))::bigint,
                    FLOOR(EXTRACT(EPOCH FROM trial_granted_at))::bigint,
                    panel_id, subscription_url,
                    EXISTS (SELECT 1 FROM orders
                             WHERE orders.telegram_id = users.telegram_id
                               AND orders.status = 'paid'),
                    FLOOR(EXTRACT(EPOCH FROM created_at))::bigint,
                    invited_by, panel_plan, tier
               FROM users WHERE telegram_id = $1",
            &[&telegram_id],
        )?
        else {
            return Ok(None);
        };

        let subscriber = Subscriber {
            telegram_id: row.try_get(0)?,
            expires_at: row.try_get(1)?,
            panel_expires_at: row.try_get(2)?,
            trial_granted_at: row.try_get(3)?,
            panel_id: row.try_get(4)?,
            subscription_url: row.try_get(5)?,
            has_paid: row.try_get(6)?,
            tier: row.try_get(10)?,
        };

        let log = self
            .client
            .query(
                "SELECT admin_id, action, detail, FLOOR(EXTRACT(EPOCH FROM created_at))::bigint
                   FROM admin_log WHERE target_id = $1
                  ORDER BY created_at DESC, id DESC LIMIT 20",
                &[&telegram_id],
            )?
            .iter()
            .map(|row| {
                Ok(LogEntry {
                    admin_id: row.try_get(0)?,
                    action: row.try_get(1)?,
                    detail: row.try_get(2)?,
                    at: row.try_get(3)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Some(Card {
            subscriber,
            created_at: row.try_get(7)?,
            invited_by: row.try_get(8)?,
            panel_plan: row.try_get(9)?,
            payments: self.payments_where(Some(telegram_id), 20)?,
            log,
        }))
    }

    /// Продлить подписку руками.
    ///
    /// Срок считает `subscription::extend` — то же правило, что у оплаты:
    /// действующую подписку продлевает от её конца, кончившуюся — от сейчас.
    /// Второго правила для ручного продления нет и быть не должно.
    ///
    /// В панель срок не везётся отсюда: продление ставит человека в очередь
    /// (`panel_work`), и та же очередь, что возит оплаты, отвезёт и его.
    ///
    /// Строка в журнале пишется в той же транзакции: продление без следа
    /// невозможно.
    pub fn admin_extend(
        &mut self,
        admin_id: i64,
        telegram_id: i64,
        days: u32,
        now: i64,
    ) -> Result<Extended, Error> {
        if days == 0 || days > MAX_MANUAL_DAYS {
            return Err(Error::Inconsistent("число дней вне допустимого"));
        }

        let mut tx = self.client.transaction()?;

        let Some(row) = tx.query_opt(
            "SELECT FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint
               FROM users WHERE telegram_id = $1 FOR UPDATE",
            &[&telegram_id],
        )?
        else {
            return Ok(Extended::NoSuchUser);
        };
        let current: Option<i64> = row.try_get(0)?;

        let Some(expires_at) = subscription::extend(current, days, now) else {
            return Err(Error::Inconsistent("срок не считается"));
        };

        tx.execute(
            "UPDATE users SET expires_at = to_timestamp($2::bigint) WHERE telegram_id = $1",
            &[&telegram_id, &expires_at],
        )?;
        tx.execute(
            "INSERT INTO admin_log (admin_id, action, target_id, detail)
             VALUES ($1, 'extend', $2, $3)",
            &[&admin_id, &telegram_id, &days.to_string()],
        )?;
        tx.commit()?;

        Ok(Extended::Until(expires_at))
    }

    /// Оплаты: все или одного человека, свежие первыми.
    fn payments_where(
        &mut self,
        telegram_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<Payment>, Error> {
        self.client
            .query(
                "SELECT orders.telegram_id, orders.plan, payments.amount_minor, payments.provider,
                        FLOOR(EXTRACT(EPOCH FROM payments.received_at))::bigint
                   FROM payments
                   LEFT JOIN orders ON orders.id = payments.order_id
                  WHERE payments.status = 'paid'
                    AND ($1::bigint IS NULL OR orders.telegram_id = $1)
                  ORDER BY payments.received_at DESC, payments.id DESC
                  LIMIT $2",
                &[&telegram_id, &limit],
            )?
            .iter()
            .map(|row| {
                Ok(Payment {
                    telegram_id: row.try_get(0)?,
                    plan: row.try_get(1)?,
                    amount: row.try_get(2)?,
                    provider: row.try_get(3)?,
                    at: row.try_get(4)?,
                })
            })
            .collect()
    }
}
