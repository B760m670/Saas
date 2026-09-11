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
//! Обратно дробь **отбрасывается**, а не округляется: `::bigint` от
//! `EXTRACT` округляет по правилам арифметики, и 259200,7 секунды стали бы
//! 259201. Остаток дней считается с округлением вверх, поэтому одной лишней
//! секунды хватает, чтобы показать покупателю день, которого у него нет.
//! Сами мы пишем целыми секундами, но дату можно поправить и руками в psql —
//! отсюда `FLOOR`.
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
use postgres::{Client, NoTls, Row, Transaction};

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
    /// Дата, которую в последний раз подтвердила панель.
    ///
    /// Совпадает с [`Self::expires_at`] — значит наших неувезённых изменений
    /// нет, и расхождение с панелью означало бы правку в самой панели.
    /// Расходится — значит очередь ещё не доехала, и решает она.
    pub panel_expires_at: Option<i64>,
    /// Когда выдавалась проба. `None` — не выдавалась ни разу.
    pub trial_granted_at: Option<i64>,
    /// Номер в панели.
    pub panel_id: Option<i64>,
    /// Ссылка на подписку — выдаётся один раз и живёт всё время.
    pub subscription_url: Option<String>,
    /// Была ли хоть одна оплата.
    ///
    /// Нужно, чтобы отличить пробу от купленного: по одному сроку они
    /// неразличимы, а называть пробу «активной подпиской» значит однажды
    /// удивить человека окончанием, которого он не ждал.
    pub has_paid: bool,
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
    /// Была ли хоть одна оплата.
    ///
    /// От этого зависит потолок трафика, который уезжает вместе с датой:
    /// у пробы он есть, у оплаченной подписки его нет. Без этого поля
    /// заплативший остался бы с потолком пробы — то есть купил бы месяц и
    /// упёрся в пять гигабайт.
    pub has_paid: bool,
}

/// Кому и о чём пора напомнить.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reminder {
    /// Кому.
    pub telegram_id: i64,
    /// Какое из трёх: `day_before`, `same_day`, `after_3d`.
    pub kind: String,
    /// К какому сроку относится. Входит в отметку об отправке: продливший
    /// человек получает новый набор напоминаний, а не молчание.
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
    /// Сколько покупатель говорит, что отправил. `None` — молчит.
    ///
    /// Не подтверждение оплаты: поступление видит только владелец счёта.
    /// Нужно, когда отправлено не выставленное — по нашей сумме такой
    /// платёж не находится, а по названной находится сразу.
    ///
    /// Может расходиться с [`Self::amount`], и в этом весь смысл. Может
    /// быть и `None` при уже нажатой кнопке: так выглядят отметки,
    /// поставленные до того, как сумму начали спрашивать.
    pub claimed: Option<Money>,
}

/// Разобрать строку вида «номер, сумма, валюта» в номер и сумму.
///
/// Отдельная функция, потому что так отвечают два запроса и ошибаться в
/// разборе они обязаны одинаково.
fn named_order(row: Row) -> Result<(String, Money), Error> {
    let minor: i64 = row.try_get(1)?;
    let currency: String = row.try_get(2)?;
    let Some(currency) = Currency::parse(&currency) else {
        return Err(Error::Inconsistent("валюта заказа неизвестна"));
    };
    let minor =
        u64::try_from(minor).map_err(|_| Error::Inconsistent("сумма заказа отрицательна"))?;

    Ok((row.try_get(0)?, Money::from_minor(minor, currency)))
}

/// Названная покупателем сумма из строки `/pending`.
///
/// Нажатие без суммы (отметка, поставленная до того, как её начали
/// спрашивать) отвечает `None` — так же, как отсутствие нажатия. Для
/// владельца это одно и то же: подсказки нет, ищет он сам.
fn claimed_amount(row: &Row, currency: Currency) -> Result<Option<Money>, Error> {
    if !row.try_get::<_, bool>(5)? {
        return Ok(None);
    }

    let Some(minor) = row.try_get::<_, Option<i64>>(6)? else {
        return Ok(None);
    };
    let minor =
        u64::try_from(minor).map_err(|_| Error::Inconsistent("названная сумма отрицательна"))?;

    Ok(Some(Money::from_minor(minor, currency)))
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
                       FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint,
                       FLOOR(EXTRACT(EPOCH FROM panel_expires_at))::bigint,
                       FLOOR(EXTRACT(EPOCH FROM trial_granted_at))::bigint,
                       panel_id, subscription_url,
                       EXISTS (SELECT 1 FROM orders
                                WHERE orders.telegram_id = users.telegram_id
                                  AND orders.status = 'paid')",
            &[&telegram_id],
        )?;

        Ok(Subscriber {
            telegram_id: row.try_get(0)?,
            expires_at: row.try_get(1)?,
            panel_expires_at: row.try_get(2)?,
            trial_granted_at: row.try_get(3)?,
            panel_id: row.try_get(4)?,
            subscription_url: row.try_get(5)?,
            has_paid: row.try_get(6)?,
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

    /// Забыть, что человек заведён в панели.
    ///
    /// Нужно, когда панель отвечает «такого нет»: пользователя удалили руками
    /// или панель переставили. Наш номер и адрес подписки при этом указывают
    /// в пустоту, и всякое продление обречено молча падать.
    ///
    /// Стирается и `panel_expires_at`: без этого строка осталась бы в очереди
    /// навсегда — даты расходятся, а везти их некуда.
    ///
    /// Срок **не** трогается: он оплачен, и потерять его из-за чужой уборки в
    /// панели человек не должен. По пустому адресу подписки бот заведёт
    /// пользователя заново при первом же обращении.
    pub fn forget_panel_link(&mut self, telegram_id: i64) -> Result<(), Error> {
        self.client.execute(
            "UPDATE users
                SET panel_id = NULL, subscription_url = NULL, panel_expires_at = NULL
              WHERE telegram_id = $1",
            &[&telegram_id],
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
    ///
    /// **Прошедшие даты в очередь не попадают.** Панель отказывается ставить
    /// срок задним числом и отвечает `400`; такая строка не уедет никогда, а
    /// очередь будет долбиться в неё каждые полминуты до скончания века.
    /// Именно это у нас и происходило сутками.
    ///
    /// Терять при этом нечего: просроченного панель погасила сама по своей
    /// дате, и рассказывать ей о прошлом незачем. А если её дата почему-то
    /// осталась в будущем, разницу заметит сверка (`reconcile` в `gloria`) и
    /// примет то, что записано в панели.
    pub fn panel_work(&mut self, limit: i64, now: i64) -> Result<Vec<PanelWork>, Error> {
        let rows = self.client.query(
            "SELECT telegram_id, panel_id, FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint,
                    EXISTS (SELECT 1 FROM orders
                             WHERE orders.telegram_id = users.telegram_id
                               AND orders.status = 'paid')
               FROM users
              WHERE panel_id IS NOT NULL
                AND expires_at IS NOT NULL
                AND expires_at > to_timestamp($2::bigint)
                AND expires_at IS DISTINCT FROM panel_expires_at
              ORDER BY telegram_id
              LIMIT $1",
            &[&limit, &now],
        )?;

        rows.iter()
            .map(|row| {
                Ok(PanelWork {
                    telegram_id: row.try_get(0)?,
                    panel_id: row.try_get(1)?,
                    expires_at: row.try_get(2)?,
                    has_paid: row.try_get(3)?,
                })
            })
            .collect()
    }

    /// Найти ссылку на подписку по её хвосту.
    ///
    /// Хвост — это и есть ключ: кто его знает, тот уже имеет доступ к
    /// подписке. Поэтому отдельного удостоверения здесь не требуется, а
    /// подставить чужой хвост можно только зная его.
    ///
    /// Нужно для перехода в клиент: встроенный браузер Telegram не отдаёт
    /// системе переход на чужую схему, и кнопка ведёт на наш обычный
    /// https-адрес, который отвечает перенаправлением на `happ://…`.
    /// Собирать этот адрес из настроек нельзя — адрес панели и адрес
    /// подписки могут не совпадать, — поэтому берётся тот, что записан.
    pub fn subscription_url_ending_with(&mut self, tail: &str) -> Result<Option<String>, Error> {
        let row = self.client.query_opt(
            "SELECT subscription_url FROM users
              WHERE subscription_url IS NOT NULL
                AND right(subscription_url, length($1) + 1) = '/' || $1
              LIMIT 1",
            &[&tail],
        )?;
        row.map(|row| row.try_get(0))
            .transpose()
            .map_err(Into::into)
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

    /// Принять за истину то, что записано в панели.
    ///
    /// Очередь возит даты **в одну сторону**: от нас к панели. Правка срока
    /// руками в самой панели до нашей базы не доезжает никак — и кабинет
    /// показывает «истекла» человеку, у которого VPN работает. Ровно на это
    /// мы и напоролись.
    ///
    /// Ставятся обе даты сразу. `expires_at` — чтобы кабинет говорил правду.
    /// `panel_expires_at` — чтобы строка не попала в очередь: иначе на
    /// следующем же круге очередь увезла бы в панель прежнюю дату и отменила
    /// ручную правку, а через круг мы приняли бы её обратно. Дата качалась бы
    /// между двумя значениями, и кто прав, не выяснилось бы никогда.
    pub fn adopt_from_panel(&mut self, telegram_id: i64, expires_at: i64) -> Result<(), Error> {
        self.client.execute(
            "UPDATE users
                SET expires_at = to_timestamp($2::bigint),
                    panel_expires_at = to_timestamp($2::bigint)
              WHERE telegram_id = $1",
            &[&telegram_id, &expires_at],
        )?;
        Ok(())
    }

    /// Кому пора напомнить об окончании подписки.
    ///
    /// Три вида, и у каждого своё окно:
    ///
    /// | Вид | Когда | Слово в сообщении |
    /// |---|---|---|
    /// | `day_before` | за 23–25 часов до окончания | «завтра» |
    /// | `same_day`   | в последние 3 часа | «сегодня» |
    /// | `after_3d`   | через 3–4 суток после | — |
    ///
    /// **Окна узкие, и это не придирка.** «Завтра» верно ровно тогда, когда
    /// до окончания остались сутки: отмерь мы шире, у человека с окончанием
    /// в 20:00 сообщение ушло бы в 08:00 того же дня со словом «завтра».
    /// Ровно двадцать четыре часа — единственная точка, где «завтра» верно
    /// при любом часовом поясе, а его мы не знаем. Два часа допуска дают
    /// промах у тех, чья подписка кончается в первом часу ночи; в обмен
    /// круг может пропустить пару минут и ничего не потерять.
    ///
    /// Окна не пересекаются: иначе человек с остатком в пару часов получил
    /// бы два сообщения подряд.
    ///
    /// **Окна ограничены с обеих сторон** намеренно. Без нижней границы
    /// первый же круг после выкладки разослал бы «ваша подписка истекла»
    /// всем, кто когда-либо уходил, — годовой давности в том числе.
    ///
    /// Уже отправленное отсеивается по `reminders_sent`, причём вместе с
    /// датой окончания: продливший подписку получает новый набор
    /// напоминаний, а не молчание из-за отметки от прошлого срока.
    ///
    /// Первые два уходят, **пока подписка ещё работает**: сообщение об уже
    /// случившемся рассказывает человеку то, что он и так заметил сам, а
    /// предупреждение до окончания — это возможность продлить без перерыва.
    pub fn due_reminders(&mut self, now: i64, limit: i64) -> Result<Vec<Reminder>, Error> {
        let rows = self.client.query(
            "SELECT u.telegram_id,
                    k.kind,
                    FLOOR(EXTRACT(EPOCH FROM u.expires_at))::bigint
               FROM users u
               CROSS JOIN (VALUES ('day_before'), ('same_day'), ('after_3d')) AS k(kind)
              WHERE u.expires_at IS NOT NULL
                AND CASE k.kind
                      WHEN 'day_before' THEN
                           u.expires_at >  to_timestamp($1::bigint) + interval '23 hours'
                       AND u.expires_at <= to_timestamp($1::bigint) + interval '25 hours'
                      WHEN 'same_day' THEN
                           u.expires_at >  to_timestamp($1::bigint)
                       AND u.expires_at <= to_timestamp($1::bigint) + interval '3 hours'
                      ELSE
                           u.expires_at <= to_timestamp($1::bigint) - interval '3 days'
                       AND u.expires_at >  to_timestamp($1::bigint) - interval '4 days'
                    END
                AND NOT EXISTS (
                      SELECT 1 FROM reminders_sent r
                       WHERE r.telegram_id = u.telegram_id
                         AND r.kind = k.kind
                         AND r.expires_at = u.expires_at)
              ORDER BY u.telegram_id, k.kind
              LIMIT $2",
            &[&now, &limit],
        )?;

        rows.iter()
            .map(|row| {
                Ok(Reminder {
                    telegram_id: row.try_get(0)?,
                    kind: row.try_get(1)?,
                    expires_at: row.try_get(2)?,
                })
            })
            .collect()
    }

    /// Запомнить, что напоминание отправлено.
    ///
    /// Ставится **после** отправки, а не до. Не дошло сообщение — отметки
    /// нет, и следующий круг попробует снова. Обратный порядок терял бы
    /// напоминание молча, а напоминание за три дня — самый дешёвый способ
    /// продлить подписку: человек просто забывает.
    ///
    /// Повторная отметка не ошибка: ключ составной, и `ON CONFLICT` гасит
    /// гонку между двумя кругами.
    pub fn mark_reminded(
        &mut self,
        telegram_id: i64,
        kind: &str,
        expires_at: i64,
    ) -> Result<(), Error> {
        self.client.execute(
            "INSERT INTO reminders_sent (telegram_id, kind, expires_at)
             VALUES ($1, $2, to_timestamp($3::bigint))
             ON CONFLICT DO NOTHING",
            &[&telegram_id, &kind, &expires_at],
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
              RETURNING FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint",
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

    /// Открытые счета — сначала те, кто говорит, что уже перевёл.
    ///
    /// То, что видит владелец в админском экране: сумма, по которой он
    /// узнаёт платёж в уведомлении банка, и кому этот счёт принадлежит.
    ///
    /// Порядок не украшение. Список читают, когда в выписке лежит перевод, и
    /// первым в нём должен стоять тот, кто вероятнее всего его и сделал, —
    /// нажавший «Я оплатил». Остальные ждут своей очереди буквально.
    pub fn pending_orders(&mut self, now: i64, lifetime: i64) -> Result<Vec<Pending>, Error> {
        let rows = self.client.query(
            "SELECT id, telegram_id, plan, amount_minor, currency,
                    claimed_at IS NOT NULL, claimed_minor
               FROM orders
              WHERE status = 'pending' AND created_at > to_timestamp($1::bigint)
              ORDER BY claimed_at DESC NULLS LAST, created_at DESC
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
                claimed: claimed_amount(&row, currency)?,
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
    /// Кому выставлен заказ.
    ///
    /// Номера Telegram в платёжном сервисе нет и быть не должно, поэтому
    /// после зачисления покупатель находится по номеру заказа, а не по
    /// чему-либо в ответе сервиса.
    pub fn order_buyer(&mut self, order_id: &str) -> Result<Option<i64>, Error> {
        let row = self
            .client
            .query_opt("SELECT telegram_id FROM orders WHERE id = $1", &[&order_id])?;
        Ok(match row {
            Some(row) => Some(row.try_get(0)?),
            None => None,
        })
    }

    pub fn order_by_amount(
        &mut self,
        amount: Money,
        now: i64,
        lifetime: i64,
    ) -> Result<Option<(String, i64)>, Error> {
        let minor = i64::try_from(amount.minor())
            .map_err(|_| Error::Inconsistent("сумма не помещается в базу"))?;
        let row = self.client.query_opt(
            "SELECT id, telegram_id FROM orders
              WHERE status = 'pending' AND amount_minor = $1 AND currency = $2
                AND created_at > to_timestamp($3::bigint)
              ORDER BY created_at
              LIMIT 1",
            &[&minor, &amount.currency().code(), &(now - lifetime)],
        )?;
        Ok(match row {
            // Вместе с номером заказа возвращается и кому он выставлен:
            // человека надо известить, что оплата зачислена. Без этого он
            // заплатил и остался в тишине — а тишина после платежа читается
            // как «деньги пропали».
            Some(row) => Some((row.try_get(0)?, row.try_get(1)?)),
            None => None,
        })
    }

    /// Найти счета, по которым покупатель **сказал**, что отправил столько.
    ///
    /// Второй способ опознать платёж, и нужен он ровно там, где отказывает
    /// первый. По сумме счёта находится тот, кто ввёл названное; а кто
    /// округлил 198,97 до 199, по 198,97 не находится никогда — он этих
    /// денег не отправлял.
    ///
    /// Зато он сказал, сколько отправил, и в выписке лежит именно это
    /// число. Значит владельцу достаточно того, что он видит в банке, и
    /// номер покупателя ему набирать не нужно.
    ///
    /// Возвращается **список**, а не один: сказать «отправил 199» могут
    /// двое, и тогда решать должен человек. Молча взять первого значило бы
    /// продлить подписку не тому, у кого лежат деньги.
    pub fn orders_claiming(
        &mut self,
        amount: Money,
        now: i64,
        lifetime: i64,
    ) -> Result<Vec<(String, i64, Money)>, Error> {
        let minor = i64::try_from(amount.minor())
            .map_err(|_| Error::Inconsistent("сумма не помещается в базу"))?;

        let rows = self.client.query(
            "SELECT id, telegram_id, amount_minor, currency FROM orders
              WHERE status = 'pending' AND claimed_minor = $1 AND currency = $2
                AND created_at > to_timestamp($3::bigint)
              ORDER BY claimed_at DESC
              LIMIT 20",
            &[&minor, &amount.currency().code(), &(now - lifetime)],
        )?;

        let mut found = Vec::new();
        for row in rows {
            let invoiced: i64 = row.try_get(2)?;
            let currency: String = row.try_get(3)?;
            let Some(currency) = Currency::parse(&currency) else {
                return Err(Error::Inconsistent("валюта заказа неизвестна"));
            };
            let invoiced = u64::try_from(invoiced)
                .map_err(|_| Error::Inconsistent("сумма заказа отрицательна"))?;

            found.push((
                row.try_get(0)?,
                row.try_get(1)?,
                Money::from_minor(invoiced, currency),
            ));
        }
        Ok(found)
    }

    /// Найти открытый счёт человека — когда сумма не сошлась.
    ///
    /// Обычный путь один: заплатили 198,63 — значит заплатил тот, кому мы
    /// назвали 198,63. Но человек может отправить 200 «по-хорошему», округлив
    /// вверх, или 199 по памяти. Тогда совпадения нет, деньги пришли, а
    /// зачислить их нечему.
    ///
    /// Это запасной выход для владельца: он видит в `/pending`, кто ждёт, и
    /// закрывает счёт по номеру человека, а не по сумме.
    ///
    /// Берётся **самый свежий** открытый счёт: если человек нажимал тариф
    /// дважды, платил он, скорее всего, по последнему — тот и висит у него
    /// на экране.
    pub fn pending_order_of(
        &mut self,
        telegram_id: i64,
        now: i64,
        lifetime: i64,
    ) -> Result<Option<(String, Money)>, Error> {
        let row = self.client.query_opt(
            "SELECT id, amount_minor, currency FROM orders
              WHERE status = 'pending' AND telegram_id = $1
                AND created_at > to_timestamp($2::bigint)
              ORDER BY created_at DESC
              LIMIT 1",
            &[&telegram_id, &(now - lifetime)],
        )?;

        row.map(named_order).transpose()
    }

    /// Отметить, что покупатель сказал «я оплатил», и сколько отправил.
    ///
    /// Отметка **не подтверждение**: нажимает её покупатель, а поступление
    /// видит только владелец счёта. Она нужна там, где перестаёт работать
    /// уникальный хвост копеек, — когда отправили не то, что выставлено.
    ///
    /// Хвост отвечает на вопрос «чей платёж», пока сумма совпадает до
    /// копейки. Круглые 199 или 200 не принадлежат никому намеренно: иначе
    /// платёж по памяти зачислился бы чужому заказу. Такой перевод уходит в
    /// ручной разбор — и там нужно знать, кто сколько отправил.
    ///
    /// Одного «я оплатил» для этого мало. Если двое нажали, а в выписке
    /// лежат 200 и 199, отметка говорит, что оба ждут, и молчит о том, кто
    /// из них кто. Поэтому вместе с ней хранится `sent` — **слова
    /// покупателя** о том, сколько он отправил. Знает это только он: банк
    /// сообщает владельцу сумму и не сообщает отправителя.
    ///
    /// Возвращается счёт с **нашей** суммой, а не с названной: расхождение
    /// между ними и есть то, ради чего всё это заведено.
    ///
    /// Отмечается тот же счёт, что вернул бы [`Store::pending_order_of`], —
    /// самый свежий открытый. Повторное нажатие переставляет и время, и
    /// сумму: человек, ошибшийся кнопкой, вправе нажать ещё раз, и верным
    /// считается последнее сказанное.
    pub fn mark_claimed(
        &mut self,
        telegram_id: i64,
        sent: Money,
        now: i64,
        lifetime: i64,
    ) -> Result<Option<(String, Money)>, Error> {
        let minor = i64::try_from(sent.minor())
            .map_err(|_| Error::Inconsistent("названная сумма не помещается в BIGINT"))?;

        let row = self.client.query_opt(
            "UPDATE orders
                SET claimed_at = to_timestamp($2::bigint), claimed_minor = $4
              WHERE id = (SELECT id FROM orders
                           WHERE status = 'pending' AND telegram_id = $1
                             AND created_at > to_timestamp($3::bigint)
                           ORDER BY created_at DESC
                           LIMIT 1)
          RETURNING id, amount_minor, currency",
            &[&telegram_id, &now, &(now - lifetime), &minor],
        )?;

        row.map(named_order).transpose()
    }

    // --- поддержка --------------------------------------------------------

    /// Запомнить, кому переслано обращение.
    ///
    /// По этой записи владелец и отвечает: он пишет свайпом, Telegram
    /// сообщает номер процитированного сообщения, а кто за ним стоит —
    /// известно только отсюда.
    pub fn remember_support_message(
        &mut self,
        admin_chat_id: i64,
        admin_message_id: i64,
        telegram_id: i64,
    ) -> Result<(), Error> {
        self.client.execute(
            "INSERT INTO support_messages (admin_chat_id, admin_message_id, telegram_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (admin_chat_id, admin_message_id) DO NOTHING",
            &[&admin_chat_id, &admin_message_id, &telegram_id],
        )?;
        Ok(())
    }

    /// Кому отвечает владелец, процитировавший это сообщение.
    ///
    /// `None` означает «не наше сообщение»: владелец ответил на что-то
    /// постороннее — на свою же заметку, на старое обращение из времён до
    /// этой таблицы. Отправлять такой ответ некому, и придумывать получателя
    /// нельзя: письмо уйдёт чужому.
    pub fn support_recipient(
        &mut self,
        admin_chat_id: i64,
        admin_message_id: i64,
    ) -> Result<Option<i64>, Error> {
        let row = self.client.query_opt(
            "SELECT telegram_id FROM support_messages
              WHERE admin_chat_id = $1 AND admin_message_id = $2",
            &[&admin_chat_id, &admin_message_id],
        )?;
        Ok(match row {
            Some(row) => Some(row.try_get(0)?),
            None => None,
        })
    }

    /// Запомнить выбранную тему обращения.
    pub fn set_support_topic(
        &mut self,
        telegram_id: i64,
        topic: &str,
        now: i64,
    ) -> Result<(), Error> {
        self.client.execute(
            "UPDATE users SET support_topic = $2,
                              support_topic_at = to_timestamp($3::bigint)
              WHERE telegram_id = $1",
            &[&telegram_id, &topic, &now],
        )?;
        Ok(())
    }

    /// Свежая тема этого человека, если он выбирал её недавно.
    ///
    /// Старая не возвращается намеренно. Выбравший тему полчаса назад пишет,
    /// скорее всего, о ней; выбравший неделю назад — вряд ли, и подпись «о
    /// чём речь» ввела бы владельца в заблуждение вернее, чем её отсутствие.
    pub fn support_topic(
        &mut self,
        telegram_id: i64,
        now: i64,
        fresh_for: i64,
    ) -> Result<Option<String>, Error> {
        let row = self.client.query_opt(
            "SELECT support_topic FROM users
              WHERE telegram_id = $1
                AND support_topic IS NOT NULL
                AND support_topic_at > to_timestamp($2::bigint)",
            &[&telegram_id, &(now - fresh_for)],
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
        "SELECT FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint FROM users
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
