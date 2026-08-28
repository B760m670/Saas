//! Хранилище бота: покупатели, заказы, платежи.
//!
//! # Про время
//!
//! В базе сроки лежат как `TIMESTAMPTZ`, в коде — как секунды эпохи. Перевод
//! делает сама база (`to_timestamp` и `EXTRACT(EPOCH …)`), а не библиотека дат
//! на нашей стороне. Так в проекте не появляется третьего представления
//! времени, а часовой пояс сервера перестаёт что-либо значить: между Rust и
//! PostgreSQL ходит одно число.
//!
//! # Про зачисление
//!
//! Единственное место, где ошибка стоит денег, — [`Store::settle`]. Оно
//! написано так, чтобы повтор был безопасен при любом раскладе: та же
//! проверка стоит и ограничением в схеме, и порядком действий в транзакции.
//! Ниже подробности на месте.

#![forbid(unsafe_code)]

use atlas_billing::invoice::TakenAmounts;
use atlas_billing::money::{Currency, Money};
use atlas_billing::subscription;
use postgres::{Client, NoTls, Transaction};

/// Отказ при работе с хранилищем.
#[derive(Debug)]
pub enum Error {
    /// Не удалось поговорить с базой.
    Database(postgres::Error),
    /// В базе лежит то, чего там быть не может.
    ///
    /// Отдельно от сбоя связи: сбой лечится повтором, а это — правкой.
    Inconsistent(&'static str),
}

impl From<postgres::Error> for Error {
    fn from(error: postgres::Error) -> Self {
        Self::Database(error)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "база: {error}"),
            Self::Inconsistent(what) => write!(f, "в базе несогласованность: {what}"),
        }
    }
}

impl core::error::Error for Error {}

/// Покупатель, каким он записан у нас.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscriber {
    /// Идентификатор в Telegram.
    pub telegram_id: i64,
    /// До какого момента действует подписка.
    pub expires_at: Option<i64>,
    /// Когда выдавалась проба. `None` — не выдавалась ни разу.
    pub trial_granted_at: Option<i64>,
    /// Номер в панели.
    pub panel_id: Option<i64>,
    /// Ссылка на подписку — выдаётся один раз и живёт всё время.
    pub subscription_url: Option<String>,
}

/// Один человек, до которого панель ещё не доехала.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelWork {
    /// Кому.
    pub telegram_id: i64,
    /// Он же в панели.
    pub panel_id: i64,
    /// Какую дату везём.
    pub expires_at: i64,
}

/// Чем кончилась попытка выдать пробу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trial {
    /// Проба выдана, подписка действует до этого момента.
    Granted { expires_at: i64 },
    /// Проба этому человеку уже выдавалась. Навсегда.
    AlreadyUsed,
}

/// Чем кончилось зачисление платежа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// Заказ закрыт, подписка продлена до этого момента.
    Extended { expires_at: i64 },
    /// Такой платёж уже учитывался — повтор доставки.
    AlreadyCounted,
    /// Заказ был закрыт раньше, другим платежом.
    OrderAlreadyPaid,
    /// Заплачено меньше выставленного. Подписка не выдана, решает человек.
    Underpaid,
    /// Такого заказа нет.
    NoSuchOrder,
}

/// Открытый счёт для админского экрана.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Номер заказа.
    pub id: String,
    /// Кому выставлен.
    pub telegram_id: i64,
    /// Какой тариф.
    pub plan: String,
    /// Сумма, по которой платёж узнаётся в уведомлении банка.
    pub amount: Money,
}

/// Хранилище.
pub struct Store {
    client: Client,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Store")
    }
}

impl Store {
    /// Подключиться к базе.
    pub fn connect(url: &str) -> Result<Self, Error> {
        Ok(Self {
            client: Client::connect(url, NoTls)?,
        })
    }

    /// Найти покупателя, заведя его, если это первый приход.
    ///
    /// Одним запросом, а не «посмотреть и вставить»: два `/start` подряд с
    /// разных устройств иначе спорят за одну строку.
    pub fn ensure_subscriber(&mut self, telegram_id: i64) -> Result<Subscriber, Error> {
        let row = self.client.query_one(
            "INSERT INTO users (telegram_id) VALUES ($1)
             ON CONFLICT (telegram_id) DO UPDATE SET telegram_id = EXCLUDED.telegram_id
             RETURNING telegram_id,
                       EXTRACT(EPOCH FROM expires_at)::bigint,
                       EXTRACT(EPOCH FROM trial_granted_at)::bigint,
                       panel_id, subscription_url",
            &[&telegram_id],
        )?;

        Ok(Subscriber {
            telegram_id: row.try_get(0)?,
            expires_at: row.try_get(1)?,
            trial_granted_at: row.try_get(2)?,
            panel_id: row.try_get(3)?,
            subscription_url: row.try_get(4)?,
        })
    }

    /// Запомнить, кем человек стал в панели.
    pub fn link_to_panel(
        &mut self,
        telegram_id: i64,
        panel_id: i64,
        subscription_url: &str,
    ) -> Result<(), Error> {
        self.client.execute(
            "UPDATE users SET panel_id = $2, subscription_url = $3 WHERE telegram_id = $1",
            &[&telegram_id, &panel_id, &subscription_url],
        )?;
        Ok(())
    }

    /// Кому надо отвезти дату в панель.
    ///
    /// Работа определяется расхождением двух дат: нашей и той, которую панель
    /// подтвердила. Совпали — делать нечего, и запрос не возвращает ни строки;
    /// так он и выглядит почти всегда.
    ///
    /// Гасить просроченных не наше дело: панель меняет статусы сама по той
    /// дате, что у неё записана (`user.expired` — её собственное событие).
    /// Поэтому здесь одна дата, а не два состояния.
    pub fn panel_work(&mut self, limit: i64) -> Result<Vec<PanelWork>, Error> {
        let rows = self.client.query(
            "SELECT telegram_id, panel_id, EXTRACT(EPOCH FROM expires_at)::bigint
               FROM users
              WHERE panel_id IS NOT NULL
                AND expires_at IS NOT NULL
                AND expires_at IS DISTINCT FROM panel_expires_at
              ORDER BY telegram_id
              LIMIT $1",
            &[&limit],
        )?;

        rows.iter()
            .map(|row| {
                Ok(PanelWork {
                    telegram_id: row.try_get(0)?,
                    panel_id: row.try_get(1)?,
                    expires_at: row.try_get(2)?,
                })
            })
            .collect()
    }

    /// Отметить, что панель приняла эту дату.
    ///
    /// Отметка ставится **той датой, которую отвозили**, а не текущим
    /// значением `expires_at`: между чтением очереди и ответом панели человек
    /// мог оплатить ещё раз. Записав нынешнее значение, мы объявили бы
    /// согласованной дату, которой панель не видела, и продление потерялось
    /// бы молча. При таком же условии строка просто останется в очереди.
    pub fn mark_panel_synced(&mut self, telegram_id: i64, sent: i64) -> Result<(), Error> {
        self.client.execute(
            "UPDATE users
                SET panel_expires_at = to_timestamp($2::bigint)
              WHERE telegram_id = $1 AND expires_at = to_timestamp($2::bigint)",
            &[&telegram_id, &sent],
        )?;
        Ok(())
    }

    /// Выдать пробный период.
    ///
    /// Одна проба на один аккаунт, навсегда. Проверка стоит в запросе
    /// (`WHERE trial_granted_at IS NULL`), а не в коде до него: между
    /// «посмотрели» и «записали» помещается второй `/start`, и человек
    /// получил бы пробу дважды. Третьим рубежом стоит триггер в схеме,
    /// запрещающий менять отметку.
    pub fn grant_trial(&mut self, telegram_id: i64, days: u32, now: i64) -> Result<Trial, Error> {
        let Some(expires_at) = subscription::extend(None, days, now) else {
            return Err(Error::Inconsistent("нулевой срок пробы"));
        };

        let updated = self.client.query_opt(
            "UPDATE users
                SET trial_granted_at = to_timestamp($3::bigint), expires_at = to_timestamp($2::bigint)
              WHERE telegram_id = $1 AND trial_granted_at IS NULL
              RETURNING EXTRACT(EPOCH FROM expires_at)::bigint",
            &[&telegram_id, &expires_at, &now],
        )?;

        match updated {
            Some(row) => Ok(Trial::Granted {
                expires_at: row.try_get(0)?,
            }),
            None => Ok(Trial::AlreadyUsed),
        }
    }

    /// Суммы счетов, которые ещё ждут оплаты.
    ///
    /// `lifetime` — сколько живёт счёт. Истёкшие в набор не входят: их суммы
    /// снова свободны.
    pub fn taken_amounts(&mut self, now: i64, lifetime: i64) -> Result<TakenAmounts, Error> {
        let rows = self.client.query(
            "SELECT amount_minor FROM orders
              WHERE status = 'pending' AND created_at > to_timestamp($1::bigint)",
            &[&(now - lifetime)],
        )?;

        let mut taken = TakenAmounts::new();
        for row in rows {
            let minor: i64 = row.try_get(0)?;
            let minor = u64::try_from(minor)
                .map_err(|_| Error::Inconsistent("сумма заказа отрицательна"))?;
            taken.insert(minor);
        }
        Ok(taken)
    }

    /// Открытые счета, от новых к старым.
    ///
    /// То, что видит владелец в админском экране: сумма, по которой он
    /// узнаёт платёж в уведомлении банка, и кому этот счёт принадлежит.
    pub fn pending_orders(&mut self, now: i64, lifetime: i64) -> Result<Vec<Pending>, Error> {
        let rows = self.client.query(
            "SELECT id, telegram_id, plan, amount_minor, currency
               FROM orders
              WHERE status = 'pending' AND created_at > to_timestamp($1::bigint)
              ORDER BY created_at DESC
              LIMIT 20",
            &[&(now - lifetime)],
        )?;

        let mut pending = Vec::new();
        for row in rows {
            let minor: i64 = row.try_get(3)?;
            let currency: String = row.try_get(4)?;
            let Some(currency) = Currency::parse(&currency) else {
                return Err(Error::Inconsistent("валюта заказа неизвестна"));
            };
            let minor = u64::try_from(minor)
                .map_err(|_| Error::Inconsistent("сумма заказа отрицательна"))?;
            pending.push(Pending {
                id: row.try_get(0)?,
                telegram_id: row.try_get(1)?,
                plan: row.try_get(2)?,
                amount: Money::from_minor(minor, currency),
            });
        }
        Ok(pending)
    }

    /// Записать выставленный счёт.
    ///
    /// Время передаётся снаружи, а не берётся из `now()` базы. Часы должны
    /// быть **одни**: срок подписки считается по времени приложения, и если
    /// `created_at` ставила бы база, у заказа могло бы оказаться время оплаты
    /// раньше времени создания. Заодно это делает проверяемым всё, что
    /// зависит от срока жизни счёта.
    pub fn open_order(
        &mut self,
        id: &str,
        telegram_id: i64,
        plan: &str,
        days: u32,
        amount: Money,
        now: i64,
    ) -> Result<(), Error> {
        let minor = i64::try_from(amount.minor())
            .map_err(|_| Error::Inconsistent("сумма не помещается в базу"))?;
        self.client.execute(
            "INSERT INTO orders (id, telegram_id, plan, days, amount_minor, currency, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7::bigint))",
            &[
                &id,
                &telegram_id,
                &plan,
                &i32::try_from(days).unwrap_or(i32::MAX),
                &minor,
                &amount.currency().code(),
                &now,
            ],
        )?;
        Ok(())
    }

    /// Найти открытый счёт по пришедшей сумме.
    ///
    /// Именно так рублёвый канал узнаёт, чей платёж: банк сообщает только
    /// сумму, а по ней однозначно находится единственный открытый счёт.
    pub fn order_by_amount(
        &mut self,
        amount: Money,
        now: i64,
        lifetime: i64,
    ) -> Result<Option<String>, Error> {
        let minor = i64::try_from(amount.minor())
            .map_err(|_| Error::Inconsistent("сумма не помещается в базу"))?;
        let row = self.client.query_opt(
            "SELECT id FROM orders
              WHERE status = 'pending' AND amount_minor = $1 AND currency = $2
                AND created_at > to_timestamp($3::bigint)
              ORDER BY created_at
              LIMIT 1",
            &[&minor, &amount.currency().code(), &(now - lifetime)],
        )?;
        Ok(match row {
            Some(row) => Some(row.try_get(0)?),
            None => None,
        })
    }

    /// Пересоздать схему. **Только для тестов.**
    ///
    /// Метод отказывается работать, если имя базы не содержит `test`. Это не
    /// формальность: опечатка в адресе подключения иначе стёрла бы боевую
    /// базу — ту единственную вещь в хозяйстве, которую не восстановить.
    pub fn reset_for_tests(&mut self, schema: &str) -> Result<(), Error> {
        let row = self.client.query_one("SELECT current_database()", &[])?;
        let name: String = row.try_get(0)?;
        if !name.contains("test") {
            return Err(Error::Inconsistent(
                "отказ пересоздавать схему: имя базы не содержит test",
            ));
        }
        self.client
            .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")?;
        self.client.batch_execute(schema)?;
        Ok(())
    }

    /// Зачислить платёж и продлить подписку.
    ///
    /// Всё одной транзакцией, и порядок действий выбран так, чтобы повтор был
    /// безопасен при любом раскладе:
    ///
    /// 1. Платёж записывается первым, `ON CONFLICT DO NOTHING`. Повторная
    ///    доставка того же уведомления упирается в `UNIQUE (provider,
    ///    provider_ref)` и не делает больше ничего.
    /// 2. Заказ берётся `FOR UPDATE`, поэтому второй платёж по тому же заказу
    ///    ждёт, а не считает срок одновременно с первым.
    /// 3. Срок считает `subscription::extend` — то же правило, что везде.
    ///
    /// Без первого пункта год превращался бы в два года по цене одного, а
    /// заметил бы это не журнал, а бухгалтерия.
    #[allow(clippy::too_many_arguments)]
    pub fn settle(
        &mut self,
        order_id: &str,
        provider: &str,
        provider_ref: &str,
        paid: Money,
        payload: &str,
        now: i64,
    ) -> Result<Settled, Error> {
        let mut tx = self.client.transaction()?;
        let outcome = settle_in(
            &mut tx,
            order_id,
            provider,
            provider_ref,
            paid,
            payload,
            now,
        )?;
        tx.commit()?;
        Ok(outcome)
    }
}

#[allow(clippy::too_many_arguments)]
fn settle_in(
    tx: &mut Transaction<'_>,
    order_id: &str,
    provider: &str,
    provider_ref: &str,
    paid: Money,
    payload: &str,
    now: i64,
) -> Result<Settled, Error> {
    let paid_minor = i64::try_from(paid.minor())
        .map_err(|_| Error::Inconsistent("сумма не помещается в базу"))?;

    // 1. Заказ под замком. Второй платёж по тому же заказу подождёт здесь, а
    //    не станет считать срок одновременно с первым.
    let order = tx.query_opt(
        "SELECT status, days, amount_minor, currency, telegram_id
           FROM orders WHERE id = $1 FOR UPDATE",
        &[&order_id],
    )?;

    // 2. Платёж записывается в любом случае — даже если заказ неизвестен или
    //    уже закрыт. Деньги пришли, и запись о них не выбрасывается: именно
    //    по ней разбирают спор «я платил, а подписки нет». Незнакомый заказ
    //    даёт платёж без привязки, а не потерянный платёж.
    let linked = order.as_ref().map(|_| order_id);
    let recorded = tx.query_opt(
        "INSERT INTO payments
             (provider, provider_ref, order_id, amount_minor, currency, status, payload, received_at)
         VALUES ($1, $2, $3, $4, $5, 'paid', $6::text::jsonb, to_timestamp($7::bigint))
         ON CONFLICT (provider, provider_ref) DO NOTHING
         RETURNING id",
        &[&provider, &provider_ref, &linked, &paid_minor, &paid.currency().code(), &payload, &now],
    )?;

    // Повторная доставка того же уведомления останавливается здесь: ограничение
    // UNIQUE (provider, provider_ref) не даёт записать платёж дважды, а раз он
    // уже был записан — значит и обработан.
    if recorded.is_none() {
        return Ok(Settled::AlreadyCounted);
    }

    let Some(order) = order else {
        return Ok(Settled::NoSuchOrder);
    };

    let status: String = order.try_get(0)?;
    if status != "pending" {
        return Ok(Settled::OrderAlreadyPaid);
    }

    let days: i32 = order.try_get(1)?;
    let expected_minor: i64 = order.try_get(2)?;
    let currency: String = order.try_get(3)?;
    let telegram_id: i64 = order.try_get(4)?;

    let Some(currency) = Currency::parse(&currency) else {
        return Err(Error::Inconsistent("валюта заказа неизвестна"));
    };

    // Недоплата не выдаёт подписку. Порог «ну почти столько же» не задаётся:
    // с него начинается недостача, которую никто не заметит. Чужая валюта
    // сюда же: сравнивать рубли с USDT по числу — верный способ отдать год
    // за копейки.
    if paid.currency() != currency || paid_minor < expected_minor {
        return Ok(Settled::Underpaid);
    }

    tx.execute(
        "UPDATE orders SET status = 'paid', paid_at = to_timestamp($2::bigint) WHERE id = $1",
        &[&order_id, &now],
    )?;

    // 3. Срок считаем мы, а не база и не панель: то же правило, что везде.
    let user = tx.query_one(
        "SELECT EXTRACT(EPOCH FROM expires_at)::bigint FROM users
          WHERE telegram_id = $1 FOR UPDATE",
        &[&telegram_id],
    )?;
    let current: Option<i64> = user.try_get(0)?;

    let days = u32::try_from(days).map_err(|_| Error::Inconsistent("отрицательный срок заказа"))?;
    let Some(expires_at) = subscription::extend(current, days, now) else {
        return Err(Error::Inconsistent("срок не считается"));
    };

    tx.execute(
        "UPDATE users SET expires_at = to_timestamp($2::bigint) WHERE telegram_id = $1",
        &[&telegram_id, &expires_at],
    )?;

    Ok(Settled::Extended { expires_at })
}
