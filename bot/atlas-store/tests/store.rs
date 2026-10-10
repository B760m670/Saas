//! Проверка хранилища на настоящем PostgreSQL.
//!
//! Заглушки здесь бесполезны: всё, что стоит проверять, — это поведение
//! ограничений, блокировок и транзакций, то есть ровно то, чего у заглушки
//! нет. Поэтому тесты идут против живой базы.
//!
//! Запуск:
//!
//! ```sh
//! GLORIA_TEST_DATABASE_URL=postgres://postgres@/gloria_test cargo test -p atlas-store
//! ```
//!
//! Без переменной тесты молча пропускаются: у того, кто просто собирает
//! проект, базы под рукой может не быть.

use atlas_billing::money::{Currency, Money};
use atlas_store::{prize_days, Extended, Settled, Started, Store, Trial, MAX_MANUAL_DAYS};

const DAY: i64 = 86_400;
const NOW: i64 = 1_760_000_000;
const LIFETIME: i64 = 20 * 60;

fn rub(minor: u64) -> Money {
    Money::from_minor(minor, Currency::Rub)
}

/// База одна на все тесты, и каждый пересоздаёт схему. Значит идти они
/// обязаны по очереди — иначе один стирает данные другого посреди работы, и
/// провалы получаются случайными. Замок здесь, а не флагом запуска: флаг
/// забывается, а это условие обязательное.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Свежая схема на каждый тест, чтобы они не зависели друг от друга.
///
/// Пропуск и провал здесь — разные вещи, и путать их дорого.
///
/// **Переменной нет** — тесты пропускаются: у того, кто просто собирает
/// проект, базы под рукой может не быть.
///
/// **Переменная есть, а база недоступна** — это провал. Раньше здесь стоял
/// тихий выход, и в CI, где база поднимается службой, все одиннадцать
/// проверок проходили бы вхолостую: «зелёный» означал бы «не проверено».
fn store() -> Option<(Store, std::sync::MutexGuard<'static, ()>)> {
    let guard = match ONE_AT_A_TIME.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let Ok(url) = std::env::var("GLORIA_TEST_DATABASE_URL") else {
        return None;
    };

    let connected = Store::connect(&url);
    assert!(
        connected.is_ok(),
        "GLORIA_TEST_DATABASE_URL задана, но подключиться не вышло: {:?}",
        connected.err().map(|error| error.to_string())
    );
    let Ok(mut store) = connected else {
        return None;
    };

    // Миграции применяются подряд, все до единой. Проверять код против одной
    // лишь первой значит проверять схему, которой на сервере уже нет.
    let prepared = store.reset_for_tests(concat!(
        include_str!("../../../db/migrations/0001_init.sql"),
        "\n",
        include_str!("../../../db/migrations/0002_panel_sync.sql"),
        "\n",
        include_str!("../../../db/migrations/0003_last_day_reminder.sql"),
        "\n",
        include_str!("../../../db/migrations/0004_reminder_days.sql"),
        "\n",
        include_str!("../../../db/migrations/0005_claimed_orders.sql"),
        "\n",
        include_str!("../../../db/migrations/0006_claimed_amount.sql"),
        "\n",
        include_str!("../../../db/migrations/0007_support.sql"),
        "\n",
        include_str!("../../../db/migrations/0008_support_one_at_a_time.sql"),
        "\n",
        include_str!("../../../db/migrations/0009_bonuses.sql"),
        "\n",
        include_str!("../../../db/migrations/0010_free_plan.sql"),
        "\n",
        include_str!("../../../db/migrations/0011_admin_log.sql"),
        "\n",
        include_str!("../../../db/migrations/0012_family.sql"),
        "\n",
        include_str!("../../../db/migrations/0013_one_tier.sql"),
        "\n",
        include_str!("../../../db/migrations/0014_news_tournaments.sql"),
        "\n",
        include_str!("../../../db/migrations/0015_tournament_pause.sql"),
    ));
    assert!(
        prepared.is_ok(),
        "схему подготовить не вышло: {:?}",
        prepared.err().map(|error| error.to_string())
    );

    Some((store, guard))
}

fn subscriber(store: &mut Store, id: i64) {
    let _ = store.ensure_subscriber(id);
}

/// Развернуть ответ базы, а не промолчать о нём.
///
/// Обычное здесь `let Ok(x) = … else { return }` тихо заканчивает тест, и
/// это ровно то, что нужно, когда базы нет вовсе. Но так же тихо оно
/// проглатывает и настоящую ошибку запроса — забытую в списке миграцию,
/// например. Проверка, закончившаяся до первого `assert`, считается
/// пройденной, и «зелёный» тогда означает «не проверено».
///
/// Так и вышло: `whoever_says_they_paid_comes_first` прошёл на схеме без
/// `claimed_at`, потому что первый же запрос отказал и увёл тест из-под
/// проверок.
fn expect<T>(result: Result<T, atlas_store::Error>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => unreachable!("{what}: {error}"),
    }
}

#[test]
fn a_second_start_does_not_create_a_second_person() {
    let Some((mut store, _lock)) = store() else {
        return;
    };

    let Ok(first) = store.ensure_subscriber(42) else {
        return;
    };
    let Ok(second) = store.ensure_subscriber(42) else {
        return;
    };
    assert_eq!(first, second);
    assert_eq!(first.expires_at, None);
    assert_eq!(first.trial_granted_at, None);
}

/// Одна проба на аккаунт, навсегда. Обойти это — три бесплатных дня, а
/// нечаянно выдать дважды проще, чем кажется.
#[test]
fn the_trial_is_granted_exactly_once() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);

    assert_eq!(
        store.grant_trial(42, 3, NOW).ok(),
        Some(Trial::Granted {
            expires_at: NOW + 3 * DAY
        })
    );

    // Второй раз — даже спустя год.
    assert_eq!(
        store.grant_trial(42, 3, NOW + 365 * DAY).ok(),
        Some(Trial::AlreadyUsed)
    );
}

#[test]
fn a_paid_order_extends_the_subscription() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.open_order("u42-d30-01", 42, "d30", 30, rub(19_899), NOW);

    assert_eq!(
        store
            .settle("u42-d30-01", "yookassa", "pay-1", rub(19_899), "{}", NOW)
            .ok(),
        Some(Settled::Extended {
            expires_at: NOW + 30 * DAY
        })
    );
}

/// Главная проверка всего слоя. Платёжные сервисы повторяют доставку, пока
/// не получат 200, и повторяют её же после сетевого сбоя. Второй раз не
/// должен давать ни дня.
#[test]
fn the_same_payment_delivered_twice_gives_nothing_extra() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.open_order("u42-d365-01", 42, "d365", 365, rub(128_999), NOW);

    let first = store
        .settle(
            "u42-d365-01",
            "yookassa",
            "pay-777",
            rub(128_999),
            "{}",
            NOW,
        )
        .ok();
    assert_eq!(
        first,
        Some(Settled::Extended {
            expires_at: NOW + 365 * DAY
        })
    );

    let second = store
        .settle(
            "u42-d365-01",
            "yookassa",
            "pay-777",
            rub(128_999),
            "{}",
            NOW,
        )
        .ok();
    assert_eq!(
        second,
        Some(Settled::AlreadyCounted),
        "год стал двумя годами"
    );

    // И срок не сдвинулся.
    let Ok(user) = store.ensure_subscriber(42) else {
        return;
    };
    assert_eq!(user.expires_at, Some(NOW + 365 * DAY));
}

/// Другой платёж по уже закрытому заказу тоже не должен продлевать.
#[test]
fn a_second_payment_for_the_same_order_is_refused() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.open_order("u42-d30-02", 42, "d30", 30, rub(19_899), NOW);

    let _ = store.settle("u42-d30-02", "yookassa", "pay-1", rub(19_899), "{}", NOW);
    assert_eq!(
        store
            .settle("u42-d30-02", "yookassa", "pay-2", rub(19_899), "{}", NOW)
            .ok(),
        Some(Settled::OrderAlreadyPaid)
    );
}

/// Заплатил за год, когда до конца ещё 40 дней, — получил 405 дней.
#[test]
fn renewals_add_up_instead_of_resetting() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);

    let _ = store.open_order("u42-d30-a", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.settle("u42-d30-a", "yookassa", "p1", rub(19_899), "{}", NOW);

    // Через 20 дней докупает год: 10 оставшихся + 365.
    let later = NOW + 20 * DAY;
    let _ = store.open_order("u42-d365-a", 42, "d365", 365, rub(128_999), NOW);
    assert_eq!(
        store
            .settle("u42-d365-a", "yookassa", "p2", rub(128_999), "{}", later)
            .ok(),
        Some(Settled::Extended {
            expires_at: NOW + 30 * DAY + 365 * DAY
        })
    );
}

/// Недоплата не выдаёт подписку и не закрывает заказ: решает человек.
#[test]
fn an_underpayment_does_not_hand_out_a_subscription() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.open_order("u42-d30-03", 42, "d30", 30, rub(19_899), NOW);

    assert_eq!(
        store
            .settle("u42-d30-03", "yookassa", "pay-low", rub(10_000), "{}", NOW)
            .ok(),
        Some(Settled::Underpaid)
    );

    let Ok(user) = store.ensure_subscriber(42) else {
        return;
    };
    assert_eq!(user.expires_at, None, "подписка выдана за неполную оплату");

    // Заказ остался открытым — по нему ещё можно доплатить.
    assert_eq!(
        store.order_by_amount(rub(19_899), NOW, LIFETIME).ok(),
        Some(Some(("u42-d30-03".to_owned(), 42)))
    );
}

/// Переплата подписку выдаёт: покупатель не виноват, что округлил вверх.
#[test]
fn an_overpayment_still_hands_out_the_subscription() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.open_order("u42-d30-04", 42, "d30", 30, rub(19_899), NOW);

    assert_eq!(
        store
            .settle("u42-d30-04", "yookassa", "pay-more", rub(20_000), "{}", NOW)
            .ok(),
        Some(Settled::Extended {
            expires_at: NOW + 30 * DAY
        })
    );
}

/// Суммы открытых счетов — то, из чего выбирается следующая уникальная.
/// Оплаченные и просроченные в набор входить не должны, иначе хвосты
/// кончатся на ровном месте.
#[test]
fn only_open_invoices_hold_their_amounts() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);

    let _ = store.open_order("open-1", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.open_order("open-2", 42, "d30", 30, rub(19_898), NOW);
    let _ = store.open_order("paid-1", 42, "d30", 30, rub(19_897), NOW);
    let _ = store.settle("paid-1", "yookassa", "p-paid", rub(19_897), "{}", NOW);

    let Ok(taken) = store.taken_amounts(NOW, LIFETIME) else {
        return;
    };
    assert!(taken.contains(19_899));
    assert!(taken.contains(19_898));
    assert!(!taken.contains(19_897), "оплаченный счёт держит сумму");

    // Спустя срок жизни счёта суммы освобождаются.
    let Ok(later) = store.taken_amounts(NOW + LIFETIME + 1, LIFETIME) else {
        return;
    };
    assert!(later.is_empty(), "просроченные счета держат суммы");
}

/// Так рублёвый канал узнаёт, чей платёж: банк сообщает только сумму.
#[test]
fn a_payment_finds_its_order_by_the_amount_alone() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    subscriber(&mut store, 43);

    let _ = store.open_order("for-42", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.open_order("for-43", 43, "d30", 30, rub(19_898), NOW);

    assert_eq!(
        store.order_by_amount(rub(19_898), NOW, LIFETIME).ok(),
        Some(Some(("for-43".to_owned(), 43))),
        "по сумме находится не тот счёт или не тот покупатель"
    );
    // Круглая сумма не принадлежит никому — уходит в ручной разбор.
    assert_eq!(
        store.order_by_amount(rub(19_900), NOW, LIFETIME).ok(),
        Some(None)
    );
}

/// Платёж находится по тому, что человек сказал, а не только по счёту.
///
/// Владелец видит в выписке 199 ₽. Счёт был на 198,97 — по нему такой
/// платёж не найдётся никогда: этих денег человек не отправлял. Зато он
/// сказал «199», и этого довольно, чтобы не набирать его номер руками.
#[test]
fn a_payment_is_found_by_what_the_person_said_they_sent() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    subscriber(&mut store, 43);

    let _ = store.open_order("rounded", 42, "d30", 30, rub(19_897), NOW);
    let _ = store.open_order("exact", 43, "d30", 30, rub(19_896), NOW);

    // Пока никто ничего не сказал, по 199 не находится ничего.
    assert_eq!(
        expect(store.orders_claiming(rub(19_900), NOW, LIFETIME), "поиск").len(),
        0
    );

    let _ = store.mark_claimed(42, rub(19_900), NOW + 10, LIFETIME);

    assert_eq!(
        expect(
            store.orders_claiming(rub(19_900), NOW + 20, LIFETIME),
            "поиск"
        ),
        vec![("rounded".to_owned(), 42, rub(19_897))],
        "по названной сумме не нашёлся счёт или потерялась выставленная"
    );

    // Сказали то же самое двое — решать должен человек, и оба обязаны быть
    // в ответе. Молча взять первого значило бы продлить не тому, у кого
    // лежат деньги.
    let _ = store.mark_claimed(43, rub(19_900), NOW + 30, LIFETIME);
    let both = expect(
        store.orders_claiming(rub(19_900), NOW + 40, LIFETIME),
        "поиск",
    );
    assert_eq!(both.len(), 2, "второй сказавший потерялся: {both:?}");

    // Оплаченный счёт из поиска уходит: подтверждать его второй раз нечем.
    let _ = store.settle("rounded", "manual", "m-9", rub(19_900), "{}", NOW + 50);
    let rest = expect(
        store.orders_claiming(rub(19_900), NOW + 60, LIFETIME),
        "поиск",
    );
    assert_eq!(rest.len(), 1);
    assert_eq!(rest.first().map(|(id, ..)| id.as_str()), Some("exact"));
}

/// Запасной выход: сумма не сошлась, и счёт ищется по человеку.
///
/// Округлил 198,63 до 200 — совпадения нет, деньги пришли, зачислить их
/// нечему. Тогда владелец закрывает счёт по номеру покупателя.
#[test]
fn an_invoice_can_be_found_by_its_buyer_when_the_amount_does_not_match() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    subscriber(&mut store, 43);

    let _ = store.open_order("older", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.open_order("newer", 42, "d90", 90, rub(49_899), NOW + 60);
    let _ = store.open_order("someone-else", 43, "d30", 30, rub(19_898), NOW);

    // Берётся самый свежий: по нему человек и платил — тот у него на экране.
    assert_eq!(
        store.pending_order_of(42, NOW + 60, LIFETIME).ok(),
        Some(Some(("newer".to_owned(), rub(49_899)))),
        "найден не последний счёт покупателя"
    );

    // У того, кто ничего не выставлял, счёта нет — и выдумывать его нельзя.
    assert_eq!(store.pending_order_of(44, NOW, LIFETIME).ok(), Some(None));

    // Оплаченный счёт больше не открыт.
    let _ = store.settle("newer", "manual", "m-1", rub(50_000), "{}", NOW + 60);
    assert_eq!(
        store.pending_order_of(42, NOW + 60, LIFETIME).ok(),
        Some(Some(("older".to_owned(), rub(19_899)))),
        "закрытый счёт всё ещё считается открытым"
    );

    // Просроченный — тоже: подтверждать его нечем.
    assert_eq!(
        store
            .pending_order_of(42, NOW + LIFETIME + 61, LIFETIME)
            .ok(),
        Some(None)
    );
}

#[test]
fn a_payment_for_an_unknown_order_is_reported() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    assert_eq!(
        store
            .settle("no-such-order", "yookassa", "p-x", rub(19_899), "{}", NOW)
            .ok(),
        Some(Settled::NoSuchOrder)
    );
}

/// Админский экран: владелец видит суммы, по которым узнаёт платежи в
/// уведомлениях банка. Закрытые и просроченные счета там мешают.
#[test]
fn the_admin_screen_lists_only_open_invoices() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);

    let _ = store.open_order("adm-1", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.open_order("adm-2", 42, "d90", 90, rub(49_898), NOW);
    let _ = store.open_order("adm-3", 42, "d30", 30, rub(19_897), NOW);
    let _ = store.settle("adm-3", "manual", "m-1", rub(19_897), "{}", NOW);

    let Ok(pending) = store.pending_orders(NOW, LIFETIME) else {
        return;
    };
    let ids: Vec<&str> = pending.iter().map(|order| order.id.as_str()).collect();
    assert_eq!(ids.len(), 2, "в списке лишние счета: {ids:?}");
    assert!(ids.contains(&"adm-1"));
    assert!(ids.contains(&"adm-2"));
    assert!(!ids.contains(&"adm-3"), "оплаченный счёт остался в списке");

    // Просроченные тоже уходят: подтверждать их поздно.
    let Ok(later) = store.pending_orders(NOW + LIFETIME + 1, LIFETIME) else {
        return;
    };
    assert_eq!(later.len(), 0);
}

/// Сказавший «я оплатил» стоит в списке первым.
///
/// Список читают, когда в выписке лежит перевод, и первым в нём должен быть
/// тот, кто вероятнее всего его и сделал. Особенно если сумма круглая: по
/// ней счёт не находится вовсе, и нажавший кнопку — единственная зацепка.
#[test]
fn whoever_says_they_paid_comes_first() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    subscriber(&mut store, 43);

    let _ = store.open_order("waits-1", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.open_order("waits-2", 43, "d30", 30, rub(19_898), NOW + 10);

    // Пока никто ничего не говорил, первым идёт свежий.
    let quiet = expect(store.pending_orders(NOW + 20, LIFETIME), "список счетов");
    assert_eq!(
        quiet.first().map(|order| order.id.as_str()),
        Some("waits-2")
    );
    assert!(quiet.iter().all(|order| order.claimed.is_none()));

    // Отмечается самый свежий счёт человека — тот же, что нашёл бы
    // запасной выход `/ok <сумма> <номер>`. Названная сумма при этом своя:
    // человек округлил 198,99 до 200, и в выписке будет она.
    assert_eq!(
        expect(
            store.mark_claimed(42, rub(20_000), NOW + 30, LIFETIME),
            "отметка"
        ),
        Some(("waits-1".to_owned(), rub(19_899))),
        "возвращается не наш счёт, а что-то другое"
    );

    let claimed = expect(store.pending_orders(NOW + 40, LIFETIME), "список счетов");
    assert_eq!(
        claimed.first().map(|order| order.id.as_str()),
        Some("waits-1"),
        "нажавший «Я оплатил» не поднялся наверх"
    );
    // Владельцу нужна названная сумма — по ней он ищет в выписке.
    assert_eq!(
        claimed.first().and_then(|order| order.claimed),
        Some(rub(20_000)),
        "названная сумма не дошла до списка"
    );
    assert!(
        claimed.get(1).is_some_and(|order| order.claimed.is_none()),
        "пометка досталась чужому счёту"
    );

    // Отметка не подтверждение: счёт остаётся открытым, подписка не выдана.
    let user = expect(store.ensure_subscriber(42), "покупатель");
    assert_eq!(
        user.expires_at, None,
        "нажатие кнопки выдало подписку — доступ раздаётся по одному нажатию"
    );

    // Ошибся кнопкой — нажал ещё раз. Верно последнее сказанное: иначе
    // исправить оговорку было бы нечем.
    assert_eq!(
        expect(
            store.mark_claimed(42, rub(19_900), NOW + 50, LIFETIME),
            "повторная отметка"
        ),
        Some(("waits-1".to_owned(), rub(19_899)))
    );
    let corrected = expect(store.pending_orders(NOW + 55, LIFETIME), "список счетов");
    assert_eq!(
        corrected.first().and_then(|order| order.claimed),
        Some(rub(19_900)),
        "поправленная сумма не заменила прежнюю"
    );

    // У того, кто ничего не выставлял, отмечать нечего.
    assert_eq!(
        expect(
            store.mark_claimed(44, rub(19_900), NOW + 60, LIFETIME),
            "отметка без счёта"
        ),
        None
    );
}

/// Повторное подтверждение того же счёта не должно продлевать дважды —
/// владелец может нажать /ok второй раз, не заметив, что уже подтвердил.
#[test]
fn confirming_the_same_invoice_twice_changes_nothing() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.open_order("adm-4", 42, "d30", 30, rub(19_899), NOW);

    let reference = "19899-adm-4";
    let first = store
        .settle("adm-4", "manual", reference, rub(19_899), "{}", NOW)
        .ok();
    assert_eq!(
        first,
        Some(Settled::Extended {
            expires_at: NOW + 30 * DAY
        })
    );

    let second = store
        .settle("adm-4", "manual", reference, rub(19_899), "{}", NOW)
        .ok();
    assert_eq!(second, Some(Settled::AlreadyCounted));

    let Ok(user) = store.ensure_subscriber(42) else {
        return;
    };
    assert_eq!(user.expires_at, Some(NOW + 30 * DAY), "срок продлён дважды");
}

// ---------------------------------------------------------------------------
// Очередь согласования с панелью
// ---------------------------------------------------------------------------

/// Пока панель не знает нашей даты, человек стоит в очереди.
#[test]
fn a_person_the_panel_has_not_heard_of_is_queued() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);

    let Ok(work) = store.panel_work(10, NOW, false) else {
        return;
    };
    assert_eq!(work.len(), 1, "человек не попал в очередь");
    let Some(item) = work.first() else {
        return;
    };
    assert_eq!(item.panel_id, 7);
    assert_eq!(item.expires_at, NOW + 3 * DAY);
}

/// Отметились — очередь пуста. Иначе бот вёз бы одну и ту же дату вечно,
/// по запросу в панель на каждом круге цикла.
#[test]
fn a_confirmed_date_leaves_the_queue() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);

    let _ = store.mark_panel_synced(42, NOW + 3 * DAY, "paid");

    let Ok(work) = store.panel_work(10, NOW, false) else {
        return;
    };
    assert!(work.is_empty(), "согласованный остался в очереди: {work:?}");
}

/// Оплата снова ставит человека в очередь: у панели теперь старая дата.
/// Это и есть весь механизм «после оплаты подписка продлевается» — прямого
/// вызова панели после оплаты нет намеренно, он терялся бы при обрыве связи
/// ровно тогда, когда деньги уже взяты.
#[test]
fn a_payment_puts_the_person_back_in_the_queue() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);
    let _ = store.mark_panel_synced(42, NOW + 3 * DAY, "paid");

    let _ = store.open_order("ord-9", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.settle("ord-9", "manual", "19899-ord-9", rub(19_899), "{}", NOW);

    let Ok(work) = store.panel_work(10, NOW, false) else {
        return;
    };
    assert_eq!(work.len(), 1, "продление не встало в очередь");
    let Some(item) = work.first() else {
        return;
    };
    assert_eq!(item.expires_at, NOW + 33 * DAY, "везём не ту дату");
}

/// Между чтением очереди и ответом панели человек мог оплатить ещё раз.
/// Отметка о старой дате не должна объявить согласованной новую — иначе
/// оплата потерялась бы молча, без единой строки в журнале.
#[test]
fn a_late_confirmation_does_not_swallow_a_newer_payment() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);

    // Бот прочитал очередь и ушёл в панель с датой пробы.
    let carried = NOW + 3 * DAY;

    // Пока он ходил, человек оплатил.
    let _ = store.open_order("ord-8", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.settle("ord-8", "manual", "19899-ord-8", rub(19_899), "{}", NOW);

    // Ответ панели пришёл — но он про старую дату.
    let _ = store.mark_panel_synced(42, carried, "paid");

    let Ok(work) = store.panel_work(10, NOW, false) else {
        return;
    };
    assert_eq!(work.len(), 1, "оплата пропала из очереди");
    let Some(item) = work.first() else {
        return;
    };
    assert_eq!(item.expires_at, NOW + 33 * DAY);
}

/// Панель ответила «такого нет» — пользователя удалили там руками. Связь
/// забывается, но **срок остаётся**: он оплачен, и чужая уборка в панели не
/// повод его отнимать. Человек уходит из очереди и ждёт, когда бот заведёт
/// его заново — при первом же его обращении.
#[test]
fn a_person_the_panel_lost_is_forgotten_but_keeps_the_days() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);

    let _ = store.forget_panel_link(42);

    let Ok(work) = store.panel_work(10, NOW, false) else {
        return;
    };
    assert!(work.is_empty(), "везём дату в пустоту: {work:?}");

    let person = store.ensure_subscriber(42);
    assert!(
        person.is_ok(),
        "человек пропал вместе со связью: {person:?}"
    );
    let Ok(person) = person else { return };
    assert_eq!(person.expires_at, Some(NOW + 3 * DAY), "срок отняли");
    assert!(person.subscription_url.is_none(), "адрес остался мёртвым");
}

/// Человека, которого нет в панели, везти некуда: сначала его надо завести.
#[test]
fn a_person_without_a_panel_account_is_not_queued() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.grant_trial(42, 3, NOW);

    let Ok(work) = store.panel_work(10, NOW, false) else {
        return;
    };
    assert!(
        work.is_empty(),
        "везём в панель того, кого там нет: {work:?}"
    );
}

/// Ограничение на круг: накопившаяся очередь не должна превращать один
/// удачный круг в сотни запросов подряд, пока обновления Telegram не читаются.
#[test]
fn the_queue_is_drained_in_portions() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    for id in 1..=5 {
        subscriber(&mut store, id);
        let _ = store.link_to_panel(id, id, &format!("https://panel.example.org/api/sub/{id}"));
        let _ = store.grant_trial(id, 3, NOW);
    }

    let Ok(work) = store.panel_work(2, NOW, false) else {
        return;
    };
    assert_eq!(work.len(), 2);
}

/// Срок правили руками в самой панели. Очередь возит даты только от нас к
/// панели, поэтому обратную правку надо принимать отдельно — иначе кабинет
/// показывает «истекла» человеку, у которого VPN работает.
#[test]
fn a_date_adopted_from_the_panel_replaces_ours() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);

    let Ok(()) = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/AbCdE") else {
        return;
    };
    let Ok(Trial::Granted { .. }) = store.grant_trial(42, 3, NOW) else {
        return;
    };

    let Ok(()) = store.adopt_from_panel(42, NOW + 22 * DAY) else {
        return;
    };

    let Ok(after) = store.ensure_subscriber(42) else {
        return;
    };
    assert_eq!(after.expires_at, Some(NOW + 22 * DAY));

    // И та же дата подтверждённой: иначе строка попала бы в очередь и на
    // следующем круге увезла бы в панель прежнее значение, отменив правку.
    assert_eq!(after.panel_expires_at, Some(NOW + 22 * DAY));
}

/// Принятая дата не должна оставлять работу в очереди. Если оставляет —
/// очередь и сверка тянут одну дату в разные стороны, и она качается между
/// двумя значениями бесконечно.
#[test]
fn an_adopted_date_leaves_the_queue_empty() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);

    let Ok(()) = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/AbCdE") else {
        return;
    };
    let Ok(Trial::Granted { .. }) = store.grant_trial(42, 3, NOW) else {
        return;
    };

    // До принятия работа есть: проба выдана, а панель о ней не знает.
    assert_eq!(
        store.panel_work(10, NOW, false).map(|work| work.len()).ok(),
        Some(1)
    );

    let Ok(()) = store.adopt_from_panel(42, NOW + 22 * DAY) else {
        return;
    };
    // Дата принята — и обратно в панель поедет именно она, а не прежняя.
    // Сама строка в очереди остаётся, пока панель не подтвердит отряды и
    // устройства (`panel_plan`); дату это не качает: везут ту же.
    let work = store.panel_work(10, NOW, false);
    assert!(work.is_ok(), "{work:?}");
    let Ok(work) = work else { return };
    assert!(
        work.iter().all(|item| item.expires_at == NOW + 22 * DAY),
        "очередь везёт не принятую дату: {work:?}"
    );

    let _ = store.mark_panel_synced(42, NOW + 22 * DAY, "paid");
    assert_eq!(
        store.panel_work(10, NOW, false).map(|work| work.len()).ok(),
        Some(0)
    );
}

/// Панель отказывается ставить срок задним числом и отвечает `400`. Такая
/// строка не уедет никогда, а очередь долбится в неё каждые полминуты —
/// ровно это у нас и происходило сутками, с пустым «код 400:» в журнале.
///
/// Терять при этом нечего: просроченного панель гасит сама по своей дате.
#[test]
fn a_date_in_the_past_never_enters_the_queue() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);

    let Ok(()) = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/AbCdE") else {
        return;
    };
    let Ok(Trial::Granted { .. }) = store.grant_trial(42, 3, NOW) else {
        return;
    };

    // Пока срок в будущем — работа есть.
    assert_eq!(
        store.panel_work(10, NOW, false).map(|work| work.len()).ok(),
        Some(1)
    );

    // Тот же срок неделей позже уже в прошлом — и работы нет.
    assert_eq!(
        store
            .panel_work(10, NOW + 7 * DAY, false)
            .map(|work| work.len())
            .ok(),
        Some(0)
    );
}

// ---------------------------------------------------------------------------
// Бесплатный доступ после окончания
// ---------------------------------------------------------------------------

/// Срок прошёл — при включённом бесплатном доступе это работа: человека
/// надо перевести на бесплатные отряды, а не оставить панели гасить его.
#[test]
fn a_lapsed_person_is_queued_for_the_free_plan() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);
    let _ = store.mark_panel_synced(42, NOW + 3 * DAY, "paid");

    let later = NOW + 7 * DAY;
    let Ok(work) = store.panel_work(10, later, true) else {
        return;
    };
    assert_eq!(work.len(), 1, "просроченный не встал в очередь: {work:?}");
    let Some(item) = work.first() else {
        return;
    };
    assert!(item.lapsed, "просроченного везут как платного");
    assert_eq!(item.expires_at, NOW + 3 * DAY, "отметке нужна наша дата");
}

/// Без бесплатного доступа прошедшая дата — по-прежнему не работа: гасит
/// панель, как и до этой правки.
#[test]
fn without_the_free_plan_a_lapsed_person_is_left_to_the_panel() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);
    let _ = store.mark_panel_synced(42, NOW + 3 * DAY, "paid");

    assert_eq!(
        store
            .panel_work(10, NOW + 7 * DAY, false)
            .map(|work| work.len())
            .ok(),
        Some(0)
    );
}

/// Переведённый на бесплатный доступ уходит из очереди. Иначе бот возил бы
/// одни и те же отряды в панель на каждом круге.
#[test]
fn a_person_moved_to_the_free_plan_leaves_the_queue() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);

    let later = NOW + 7 * DAY;
    let far = NOW + 100 * 365 * DAY;
    let _ = store.mark_panel_free(42, NOW + 3 * DAY, far);

    assert_eq!(
        store
            .panel_work(10, later, true)
            .map(|work| work.len())
            .ok(),
        Some(0)
    );

    // Подтверждённой считается далёкая дата панели — иначе сверка приняла
    // бы её за ручное продление.
    let Ok(person) = store.ensure_subscriber(42) else {
        return;
    };
    assert_eq!(person.panel_expires_at, Some(far));
    assert_eq!(person.expires_at, Some(NOW + 3 * DAY), "наш срок подменили");
}

/// Оплата после бесплатного доступа возвращает платные отряды: человек
/// снова в очереди, и уже как платный.
#[test]
fn a_payment_after_the_free_plan_brings_the_paid_plan_back() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);

    let later = NOW + 7 * DAY;
    let _ = store.mark_panel_free(42, NOW + 3 * DAY, NOW + 100 * 365 * DAY);

    let _ = store.open_order("ord-7", 42, "d30", 30, rub(19_899), later);
    let _ = store.settle("ord-7", "manual", "19899-ord-7", rub(19_899), "{}", later);

    let Ok(work) = store.panel_work(10, later, true) else {
        return;
    };
    assert_eq!(work.len(), 1, "оплата не вернула платные отряды");
    let Some(item) = work.first() else {
        return;
    };
    assert!(!item.lapsed);
    assert_eq!(item.expires_at, later + 30 * DAY);
}

/// Пока бот ходил в панель переводить человека на бесплатное, тот оплатил.
/// Отметка о бесплатном не должна съесть оплату.
#[test]
fn a_late_free_mark_does_not_swallow_a_payment() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);

    let later = NOW + 7 * DAY;
    let _ = store.open_order("ord-6", 42, "d30", 30, rub(19_899), later);
    let _ = store.settle("ord-6", "manual", "19899-ord-6", rub(19_899), "{}", later);

    // Ответ панели пришёл — про бесплатный доступ по старой дате.
    let _ = store.mark_panel_free(42, NOW + 3 * DAY, NOW + 100 * 365 * DAY);

    let Ok(work) = store.panel_work(10, later, true) else {
        return;
    };
    assert_eq!(work.len(), 1, "оплата пропала из очереди");
    let Some(item) = work.first() else {
        return;
    };
    assert!(!item.lapsed, "оплатившего везут на бесплатное");
}

/// Отряды, которых панель ещё не подтверждала (`panel_plan` пуст), — работа,
/// даже если даты давно совпали. Так при выкладке тарифов очередь сама
/// отвозит устройства и отряды всем, кто заведён раньше.
#[test]
fn a_person_whose_panel_plan_is_unknown_is_queued_once() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);
    let _ = store.adopt_from_panel(42, NOW + 3 * DAY);

    let Ok(work) = store.panel_work(10, NOW, false) else {
        return;
    };
    assert_eq!(work.len(), 1, "неподтверждённые отряды не встали в очередь");
    assert_eq!(work.first().map(|w| w.kind.as_str()), Some("paid"));

    let _ = store.mark_panel_synced(42, NOW + 3 * DAY, "paid");
    assert_eq!(
        store.panel_work(10, NOW, false).map(|work| work.len()).ok(),
        Some(0)
    );
}

/// Напоминание за три дня — самый дешёвый способ продлить подписку: человек
/// просто забывает. Проверяем, что оно вообще попадает в очередь и что не
/// попадает дважды.
#[test]
fn a_reminder_is_due_once_and_then_marked() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(42, 30, NOW) else {
        return;
    };

    // За трое суток до окончания.
    let moment = expires_at - DAY;
    let Ok(due) = store.due_reminders(moment, 10) else {
        return;
    };
    assert_eq!(due.len(), 1, "ждали одно напоминание, получили {due:?}");
    assert!(
        due.iter()
            .any(|r| r.kind == "day_before" && r.expires_at == expires_at),
        "не то напоминание: {due:?}"
    );

    let Ok(()) = store.mark_reminded(42, "day_before", expires_at) else {
        return;
    };
    assert_eq!(
        store.due_reminders(moment, 10).map(|d| d.len()).ok(),
        Some(0)
    );

    // Повторная отметка не должна падать: два круга могут пересечься.
    assert!(store.mark_reminded(42, "day_before", expires_at).is_ok());
}

/// Продливший подписку получает новый набор напоминаний, а не молчание
/// из-за отметки от прошлого срока. Дата входит в ключ ровно поэтому.
#[test]
fn extending_the_subscription_starts_a_new_set_of_reminders() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(42, 3, NOW) else {
        return;
    };
    let Ok(()) = store.mark_reminded(42, "day_before", expires_at) else {
        return;
    };

    // Оплата продлевает срок — и прежняя отметка к нему уже не относится.
    let Ok(_) = store.open_order("u42-d30-1", 42, "d30", 30, rub(19_899), NOW) else {
        return;
    };
    let Ok(Settled::Extended { expires_at: longer }) =
        store.settle("u42-d30-1", "manual", "ref-1", rub(19_899), "{}", NOW)
    else {
        return;
    };

    let Ok(due) = store.due_reminders(longer - DAY, 10) else {
        return;
    };
    assert!(
        due.iter()
            .any(|r| r.kind == "day_before" && r.expires_at == longer),
        "после продления напоминание не появилось: {due:?}"
    );
}

/// Нижняя граница окон — не мелочь. Без неё первый же круг после выкладки
/// разослал бы «ваша подписка истекла» всем, кто уходил хоть год назад.
#[test]
fn a_long_expired_subscription_is_not_reminded_about() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(42, 3, NOW) else {
        return;
    };

    assert_eq!(
        store
            .due_reminders(expires_at + 30 * DAY, 10)
            .map(|d| d.len())
            .ok(),
        Some(0),
        "напомнили тому, кто ушёл месяц назад"
    );
}

/// Последнее напоминание уходит, **пока подписка ещё действует**. Сообщение
/// после того, как VPN перестал подключаться, рассказывает человеку то, что
/// он и так только что заметил сам.
#[test]
fn the_last_reminder_arrives_before_the_subscription_ends() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(42, 30, NOW) else {
        return;
    };

    // За двенадцать часов до окончания — подписка ещё работает.
    let Ok(due) = store.due_reminders(expires_at - 3600, 10) else {
        return;
    };
    assert!(
        due.iter().any(|r| r.kind == "same_day"),
        "в последний день не напомнили: {due:?}"
    );

    // А сразу после окончания напоминать уже не о чем: следующее — только
    // через три дня.
    let Ok(after) = store.due_reminders(expires_at + 60, 10) else {
        return;
    };
    assert!(
        after.is_empty(),
        "написали человеку сразу после отключения: {after:?}"
    );
}

/// Последнее напоминание — за три часа; если это приходится на ночь по
/// Москве (23:00–9:00), оно уходит накануне в 22:00.
#[test]
fn the_last_reminder_does_not_wake_anyone_at_night() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    // 2 ноября 2026 года, 00:00 UTC (03:00 по Москве).
    const DAY: i64 = 1_793_577_600;
    const HOUR: i64 = 3600;

    // Окончание в 14:00 МСК (11:00 UTC): напоминание в 11:00 МСК, днём.
    subscriber(&mut store, 51);
    let granted = DAY + 11 * HOUR - 2 * 86_400;
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(51, 2, granted) else {
        return;
    };
    let due = |store: &mut Store, at: i64| {
        store
            .due_reminders(at, 10)
            .map(|due| {
                due.iter()
                    .any(|r| r.telegram_id == 51 && r.kind == "same_day")
            })
            .unwrap_or(false)
    };
    assert!(!due(&mut store, expires_at - 3 * HOUR - 60));
    assert!(due(&mut store, expires_at - 3 * HOUR));

    // Окончание в 10:00 МСК (07:00 UTC): «за три часа» — это 07:00 МСК,
    // ночь. Уходит в 22:00 МСК накануне, за двенадцать часов.
    subscriber(&mut store, 52);
    let granted = DAY + 7 * HOUR - 2 * 86_400;
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(52, 2, granted) else {
        return;
    };
    let due = |store: &mut Store, at: i64| {
        store
            .due_reminders(at, 10)
            .map(|due| {
                due.iter()
                    .any(|r| r.telegram_id == 52 && r.kind == "same_day")
            })
            .unwrap_or(false)
    };
    assert!(!due(&mut store, expires_at - 12 * HOUR - 60));
    assert!(due(&mut store, expires_at - 12 * HOUR));
}

/// «За сутки» ночью тоже не будит, но и не уходит за московские сутки —
/// иначе «завтра» стало бы неправдой.
#[test]
fn the_day_before_reminder_does_not_wake_anyone_at_night() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    // 2 ноября 2026 года, 00:00 UTC (03:00 по Москве).
    const DAY: i64 = 1_793_577_600;
    const HOUR: i64 = 3600;

    let due = |store: &mut Store, id: i64, at: i64| {
        store
            .due_reminders(at, 10)
            .map(|due| {
                due.iter()
                    .any(|r| r.telegram_id == id && r.kind == "day_before")
            })
            .unwrap_or(false)
    };

    // Окончание 3 ноября в 14:00 МСК: днём — ровно за сутки.
    subscriber(&mut store, 61);
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(61, 2, DAY + 11 * HOUR - 86_400)
    else {
        return;
    };
    assert!(!due(&mut store, 61, expires_at - 24 * HOUR - 60));
    assert!(due(&mut store, 61, expires_at - 24 * HOUR));

    // Окончание 3 ноября в 03:00 МСК: «за сутки» — 2 ноября в 03:00,
    // ночь. Уходит 2 ноября в 9:00 МСК, а не в три ночи.
    subscriber(&mut store, 62);
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(62, 2, DAY - 86_400) else {
        return;
    };
    assert!(!due(&mut store, 62, expires_at - 24 * HOUR));
    assert!(!due(&mut store, 62, DAY + 6 * HOUR - 60));
    assert!(due(&mut store, 62, DAY + 6 * HOUR));

    // Окончание 3 ноября в 23:30 МСК: «за сутки» — 2 ноября в 23:30.
    // Уходит в 22:00 того же вечера.
    subscriber(&mut store, 63);
    let Ok(Trial::Granted { expires_at }) =
        store.grant_trial(63, 2, DAY + 20 * HOUR + 30 * 60 - 86_400)
    else {
        return;
    };
    assert!(!due(&mut store, 63, DAY + 19 * HOUR - 60));
    assert!(due(&mut store, 63, DAY + 19 * HOUR));
    assert!(!due(&mut store, 63, expires_at - 24 * HOUR + 60 * 60));
}

/// Напоминание знает, что кончается проба, — у неё свой текст. Заплатил —
/// уже не проба.
#[test]
fn a_trial_reminder_is_marked_as_a_trial() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(42, 2, NOW) else {
        return;
    };
    let Ok(due) = store.due_reminders(expires_at - 24 * 3600, 10) else {
        return;
    };
    assert!(
        due.iter().any(|r| r.kind == "day_before" && r.trial),
        "{due:?}"
    );
}

/// Окна не пересекаются: у человека, которому осталось несколько часов, не
/// должно прийти два сообщения подряд — «через три дня» и «меньше суток».
#[test]
fn two_reminders_never_come_due_at_the_same_moment() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let Ok(Trial::Granted { expires_at }) = store.grant_trial(42, 30, NOW) else {
        return;
    };

    for hours_left in [1, 2, 12, 23, 24, 25, 30, 47] {
        let moment = expires_at - hours_left * 3600;
        let Ok(due) = store.due_reminders(moment, 10) else {
            return;
        };
        assert!(
            due.len() <= 1,
            "за {hours_left} ч до конца пришло бы сразу несколько: {due:?}"
        );
    }
}

/// Ответ поддержки находит адресата по процитированному сообщению.
///
/// Владелец отвечает свайпом; Telegram сообщает номер сообщения, а кто за
/// ним стоит — известно только отсюда. Разойдись эта связь, ответ ушёл бы
/// чужому вместе со всем, что в нём написано.
#[test]
fn a_support_reply_finds_its_recipient() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    subscriber(&mut store, 43);

    // Одно обращение переслано двум владельцам. Номера сообщений у каждого
    // свои — потому ключ и составной.
    expect(store.remember_support_message(900, 11, 42), "запись");
    expect(store.remember_support_message(901, 11, 43), "запись");

    assert_eq!(expect(store.support_recipient(900, 11), "поиск"), Some(42));
    assert_eq!(
        expect(store.support_recipient(901, 11), "поиск"),
        Some(43),
        "номер сообщения одного владельца указал на чужого покупателя"
    );

    // Ответ на постороннее сообщение адресата не имеет, и придумывать его
    // нельзя: письмо ушло бы чужому.
    assert_eq!(expect(store.support_recipient(900, 99), "поиск"), None);

    // Повтор не меняет адресата.
    expect(store.remember_support_message(900, 11, 43), "повтор");
    assert_eq!(expect(store.support_recipient(900, 11), "поиск"), Some(42));
}

/// Тема живёт недолго: выбравший её неделю назад пишет уже о другом, и
/// подпись «о чём речь» ввела бы владельца в заблуждение.
#[test]
fn a_support_topic_goes_stale() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    const HOUR: i64 = 3600;

    assert_eq!(expect(store.support_topic(42, NOW, HOUR), "тема"), None);

    expect(store.set_support_topic(42, "pay", NOW), "запись темы");
    assert_eq!(
        expect(store.support_topic(42, NOW + 60, HOUR), "тема"),
        Some("pay".to_owned())
    );

    // Спустя срок — молчание, а не старая тема.
    assert_eq!(
        expect(store.support_topic(42, NOW + HOUR + 1, HOUR), "тема"),
        None
    );

    // Новая заменяет прежнюю целиком.
    expect(store.set_support_topic(42, "slow", NOW + HOUR * 2), "смена");
    assert_eq!(
        expect(store.support_topic(42, NOW + HOUR * 2, HOUR), "тема"),
        Some("slow".to_owned())
    );
}

/// Пока на обращение не ответили, второе до владельца не доходит. Иначе
/// вместо одного обращения он читает шесть — и шесть раз одно и то же.
#[test]
fn a_second_message_waits_for_the_answer() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    const PATIENCE: i64 = DAY;

    assert!(
        expect(store.open_support_request(42, NOW, PATIENCE), "первое"),
        "первое обращение обязано пройти"
    );
    assert!(
        !expect(store.open_support_request(42, NOW + 1, PATIENCE), "второе"),
        "второе обращение прошло, пока первое без ответа"
    );

    // Ответ владельца открывает дорогу следующему.
    expect(store.close_support_request(42), "закрытие");
    assert!(
        expect(store.open_support_request(42, NOW + 2, PATIENCE), "после"),
        "после ответа писать снова нельзя"
    );
}

/// Молчание владельца не запирает человека навсегда: право написать
/// возвращается само. Проглядел обращение — а тот, у кого не работает
/// оплаченный VPN, не может даже напомнить о себе.
#[test]
fn silence_does_not_lock_a_person_out_forever() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    const PATIENCE: i64 = 3600;

    assert!(expect(
        store.open_support_request(42, NOW, PATIENCE),
        "первое"
    ));
    assert!(
        !expect(
            store.open_support_request(42, NOW + PATIENCE - 1, PATIENCE),
            "до срока"
        ),
        "до срока ждём ответа"
    );
    assert!(
        expect(
            store.open_support_request(42, NOW + PATIENCE, PATIENCE),
            "после срока"
        ),
        "после срока молчания писать снова обязано быть можно"
    );
}

/// Обращения разных людей не связаны: молчание по одному не затыкает
/// остальных. Иначе первый написавший закрывал бы поддержку для всех.
#[test]
fn one_persons_wait_does_not_silence_another() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    subscriber(&mut store, 43);
    const PATIENCE: i64 = 3600;

    assert!(expect(
        store.open_support_request(42, NOW, PATIENCE),
        "первый"
    ));
    assert!(
        expect(store.open_support_request(43, NOW, PATIENCE), "второй"),
        "чужое ожидание закрыло поддержку"
    );

    // И закрытие одного не открывает другого.
    expect(store.close_support_request(42), "закрытие");
    assert!(
        !expect(store.open_support_request(43, NOW + 1, PATIENCE), "второй"),
        "ответ одному открыл дорогу другому"
    );
}

// --- приглашения ------------------------------------------------------------

/// Приглашение записывается один раз и первым: иначе «привёл» означало бы
/// «прислал ссылку последним», и чужая работа доставалась бы тому, кто
/// подсуетился позже.
#[test]
fn an_invitation_is_remembered_once_and_by_the_first() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 1);
    subscriber(&mut store, 2);
    subscriber(&mut store, 42);

    assert!(expect(store.remember_invite(42, 1), "первый"));
    assert!(
        !expect(store.remember_invite(42, 2), "второй"),
        "второй пригласивший переписал первого"
    );
}

/// Три отказа, каждый закрывает свою дыру.
#[test]
fn an_invitation_that_makes_no_sense_is_refused() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 1);
    subscriber(&mut store, 42);

    // Сам себя.
    assert!(!expect(store.remember_invite(42, 42), "сам себя"));

    // Пригласившего нет в базе: номер в ссылке пишет кто угодно.
    assert!(!expect(store.remember_invite(42, 999), "выдуманный"));

    // Уже платил — значит пришёл сам, и приводить его задним числом некому.
    let _ = store.open_order("u42-d30", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.settle("u42-d30", "manual", "p-1", rub(19_899), "{}", NOW);
    assert!(
        !expect(store.remember_invite(42, 1), "заплативший"),
        "заплатившего записали приведённым"
    );
}

/// Экран «Друзья» отличает пришедших от платящих.
#[test]
fn the_friends_screen_separates_visitors_from_payers() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 1);
    for friend in [10, 11, 12] {
        subscriber(&mut store, friend);
        let _ = store.remember_invite(friend, 1);
    }

    let stats = expect(store.referral_stats(1), "до оплат");
    assert_eq!((stats.invited, stats.paying), (3, 0));

    let _ = store.open_order("u10", 10, "d30", 30, rub(19_899), NOW);
    let _ = store.settle("u10", "manual", "p-10", rub(19_899), "{}", NOW);

    let stats = expect(store.referral_stats(1), "после оплаты");
    assert_eq!((stats.invited, stats.paying), (3, 1));
}

/// Уведомление о переводе шлётся по номеру счёта, и номер приходит от
/// клиента. Значит счёт обязан принадлежать тому, кто его называет, и быть
/// открытым — иначе чужим номером можно было бы вызвать чужое уведомление.
#[test]
fn a_transfer_notice_is_only_for_the_owner_of_an_open_order() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    subscriber(&mut store, 43);
    let _ = store.open_order("u42-d30", 42, "d30", 30, rub(19_897), NOW);

    // Владельцу открытого счёта — сумма, тариф, бонусы.
    let notice = expect(store.transfer_notice("u42-d30", 42), "свой счёт");
    assert_eq!(notice, Some((rub(19_897), "d30".to_owned())));

    // Чужому — ничего, даже с верным номером.
    assert_eq!(
        expect(store.transfer_notice("u42-d30", 43), "чужой"),
        None,
        "чужой номер вызвал уведомление"
    );

    // Несуществующий номер — ничего.
    assert_eq!(expect(store.transfer_notice("нет-такого", 42), "нет"), None);

    // Оплаченный счёт больше не открыт — уведомлять не о чем.
    let _ = store.settle("u42-d30", "manual", "p-1", rub(19_897), "{}", NOW);
    assert_eq!(
        expect(store.transfer_notice("u42-d30", 42), "закрытый"),
        None,
        "закрытый счёт всё ещё шлёт уведомление"
    );
}

// ---------------------------------------------------------------------------
// Админка
// ---------------------------------------------------------------------------

/// Сводка считает людей по состояниям и деньги — только оплаченные.
#[test]
fn the_summary_counts_people_and_money() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    // Платящий, на пробе, с истёкшей пробой и зашедший без пробы.
    for id in [1, 2, 3, 4] {
        subscriber(&mut store, id);
    }
    let _ = store.grant_trial(1, 3, NOW);
    let _ = store.open_order("ord-1", 1, "d30", 30, rub(19_900), NOW);
    let _ = store.settle("ord-1", "freekassa", "fk-1", rub(19_900), "{}", NOW);
    let _ = store.grant_trial(2, 3, NOW);
    let _ = store.grant_trial(3, 3, NOW - 10 * DAY);

    let summary = store.admin_summary(NOW);
    assert!(summary.is_ok(), "{summary:?}");
    let Ok(summary) = summary else { return };

    assert_eq!(summary.users, 4);
    assert_eq!(summary.active_paid, 1);
    assert_eq!(summary.active_trial, 1);
    assert_eq!(summary.expired, 1);
    assert_eq!(summary.never, 1);
    assert_eq!(summary.revenue_month, 19_900);
    assert_eq!(summary.payments_month, 1);
    assert_eq!(summary.recent.len(), 1);
    assert_eq!(summary.recent.first().map(|p| p.telegram_id), Some(Some(1)));
}

/// Карточку незнакомца админка не заводит: она смотрит, а не создаёт.
#[test]
fn a_card_of_a_stranger_is_absent_and_not_created() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    assert!(matches!(store.admin_card(77), Ok(None)));
    assert_eq!(
        store.admin_summary(NOW).map(|summary| summary.users).ok(),
        Some(0),
        "просмотр завёл человека"
    );
}

/// Ручное продление — по тому же правилу, что оплата, и с записью в журнале.
#[test]
fn a_manual_extension_follows_the_payment_rule_and_is_logged() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.link_to_panel(42, 7, "https://panel.example.org/api/sub/aaa");
    let _ = store.grant_trial(42, 3, NOW);
    let _ = store.mark_panel_synced(42, NOW + 3 * DAY, "paid");

    // Действующая подписка продлевается от своего конца.
    let extended = store.admin_extend(1001, 42, 30, NOW);
    assert_eq!(extended.ok(), Some(Extended::Until(NOW + 33 * DAY)));

    // Продление встаёт в ту же очередь, что и оплата, — панель узнает.
    assert_eq!(
        store.panel_work(10, NOW, true).map(|work| work.len()).ok(),
        Some(1),
        "продление не встало в очередь панели"
    );

    let card = store.admin_card(42);
    assert!(card.is_ok(), "{card:?}");
    let Ok(Some(card)) = card else { return };
    assert_eq!(card.subscriber.expires_at, Some(NOW + 33 * DAY));
    assert_eq!(card.log.len(), 1);
    let Some(entry) = card.log.first() else {
        return;
    };
    assert_eq!(entry.admin_id, 1001);
    assert_eq!(entry.action, "extend");
    assert_eq!(entry.detail, "30");
}

/// Кончившаяся подписка продлевается от сейчас, а не от прошлого.
#[test]
fn a_lapsed_subscription_is_extended_from_now() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.grant_trial(42, 3, NOW - 10 * DAY);

    assert_eq!(
        store.admin_extend(1001, 42, 7, NOW).ok(),
        Some(Extended::Until(NOW + 7 * DAY))
    );
}

/// Лишний ноль в поле «дней» не должен подарить подписку на век.
#[test]
fn an_absurd_number_of_days_is_refused() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    assert!(store.admin_extend(1001, 42, 0, NOW).is_err());
    assert!(store
        .admin_extend(1001, 42, MAX_MANUAL_DAYS + 1, NOW)
        .is_err());

    let Ok(Some(card)) = store.admin_card(42) else {
        return;
    };
    assert!(card.log.is_empty(), "отказ оставил след в журнале");
}

#[test]
fn extending_a_stranger_changes_nothing() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    assert_eq!(
        store.admin_extend(1001, 77, 7, NOW).ok(),
        Some(Extended::NoSuchUser)
    );
}

// ---------------------------------------------------------------------------
// Тарифы и гости
// ---------------------------------------------------------------------------

/// Владелец на тарифе: оплатил заказ `plan` на 30 дней.
fn owner_on(store: &mut Store, id: i64, plan: &str, rubles: u64) {
    subscriber(store, id);
    let order = format!("ord-{id}-{plan}");
    let _ = store.open_order(&order, id, plan, 30, rub(rubles * 100), NOW);
    let settled = store.settle(
        &order,
        "freekassa",
        &format!("fk-{order}"),
        rub(rubles * 100),
        "{}",
        NOW,
    );
    assert!(
        matches!(settled, Ok(Settled::Extended { .. })),
        "{settled:?}"
    );
}

fn tier_of(store: &mut Store, id: i64) -> Option<String> {
    store.ensure_subscriber(id).ok().and_then(|s| s.tier)
}

#[test]
fn a_purchase_sets_the_one_tier() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    owner_on(&mut store, 1, "d30", 199);
    assert_eq!(tier_of(&mut store, 1).as_deref(), Some("personal"));
}

// --- турнир и новости -------------------------------------------------------

/// Настоящее «сейчас»: строки пользователей получают `created_at` от базы,
/// и турнир должен идти в то же время.
fn real_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// Пригласить `friend` от имени `inviter`; `connected` — подключился ли он.
fn invite(store: &mut Store, inviter: i64, friend: i64, connected: bool, at: i64) {
    subscriber(store, friend);
    assert!(expect(
        store.remember_invite(friend, inviter),
        "приглашение"
    ));
    if connected {
        expect(store.mark_connected(friend, at), "подключение");
    }
}

/// Засчитывается только подключившийся: пустой аккаунт очков не даёт.
#[test]
fn only_a_connected_friend_scores() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    let now = real_now();
    let Ok(Started::Started(id)) = store.start_tournament(1, 7, 1, now - 60) else {
        return;
    };
    subscriber(&mut store, 1);
    subscriber(&mut store, 2);
    invite(&mut store, 1, 10, true, now);
    invite(&mut store, 1, 11, false, now);
    invite(&mut store, 2, 20, true, now);
    invite(&mut store, 2, 21, true, now + 5);

    let table = expect(store.standings(id), "таблица");
    let scores: Vec<(i64, i64, i64)> = table
        .iter()
        .map(|s| (s.place, s.telegram_id, s.score))
        .collect();
    assert_eq!(scores, vec![(1, 2, 2), (2, 1, 1)]);
}

/// Второй турнир при идущем не начинается: двое считали бы одних и тех же.
#[test]
fn only_one_tournament_runs_at_a_time() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    let now = real_now();
    assert!(matches!(
        store.start_tournament(1, 7, 3, now),
        Ok(Started::Started(_))
    ));
    assert_eq!(
        expect(store.start_tournament(1, 7, 3, now), "второй"),
        Started::AlreadyRunning
    );
}

/// Призы — только набравшим порог; дни прибавляются к подписке; повторное
/// подведение итогов ничего не выдаёт.
#[test]
fn prizes_go_to_those_above_the_threshold_once() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    let now = real_now();
    let Ok(Started::Started(id)) = store.start_tournament(1, 7, 2, now - 60) else {
        return;
    };
    subscriber(&mut store, 1);
    subscriber(&mut store, 2);
    for friend in [10, 11, 12] {
        invite(&mut store, 1, friend, true, now);
    }
    invite(&mut store, 2, 20, true, now);

    let end = now + 8 * 86_400;
    let prizes = expect(store.finish_tournament(id, end), "итоги").unwrap_or_default();
    assert_eq!(prizes.len(), 1, "{prizes:?}");
    let Some(first) = prizes.first() else {
        return;
    };
    assert_eq!((first.place, first.telegram_id, first.days), (1, 1, 90));
    assert_eq!(first.expires_at, end + 90 * 86_400);

    assert_eq!(expect(store.finish_tournament(id, end), "повтор"), None);
    assert_eq!(expect(store.prizes_of(id), "призы").len(), 1);
}

#[test]
fn prize_days_follow_the_places() {
    assert_eq!(prize_days(1), Some(90));
    assert_eq!(prize_days(2), Some(60));
    assert_eq!(prize_days(3), Some(60));
    assert_eq!(prize_days(4), Some(30));
    assert_eq!(prize_days(10), Some(30));
    assert_eq!(prize_days(11), None);
}

/// Непрочитанное — то, что новее последнего открытия ленты.
#[test]
fn news_are_unread_until_seen() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 5);
    expect(
        store.publish_news(1, "Акция", "Турнир начался", false, NOW),
        "новость",
    );
    assert_eq!(expect(store.unread_news(5), "до"), 1);
    expect(store.mark_news_seen(5, NOW + 1), "прочитал");
    assert_eq!(expect(store.unread_news(5), "после"), 0);

    expect(store.set_news_muted(5, true), "выключил");
    assert!(!expect(store.news_recipients(), "кому").contains(&5));
}

/// Продление сдвигает конец идущего турнира; без турнира — `None`.
#[test]
fn a_tournament_can_be_extended() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    assert_eq!(expect(store.extend_tournament(7), "без турнира"), None);
    let now = real_now();
    let Ok(Started::Started(_)) = store.start_tournament(1, 7, 3, now) else {
        return;
    };
    let ends = expect(store.extend_tournament(5), "продление");
    assert_eq!(ends, Some(now + 12 * 86_400));
}

/// Пауза сохраняет набранное.
#[test]
fn a_paused_tournament_keeps_scores() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    let now = real_now();
    let Ok(Started::Started(id)) = store.start_tournament(1, 7, 1, now - 600) else {
        return;
    };
    subscriber(&mut store, 1);
    invite(&mut store, 1, 10, true, now);

    // Пауза с этой минуты: друг 10 пришёл до неё и остаётся в таблице.
    assert!(expect(store.pause_tournament(now + 60), "пауза"));
    assert!(!expect(store.pause_tournament(now + 61), "вторая пауза"));
    let score = |store: &mut Store| {
        expect(store.standings(id), "таблица")
            .iter()
            .find(|s| s.telegram_id == 1)
            .map_or(0, |s| s.score)
    };
    assert_eq!(score(&mut store), 1);

    expect(store.resume_tournament(now + 120), "снять");
    assert_eq!(score(&mut store), 1, "после паузы очки пропали");
    let open = expect(store.open_tournament(), "турнир");
    assert_eq!(open.map(|t| t.paused_at), Some(None));
}

/// Пришедший во время паузы не засчитывается ни пока она идёт, ни после.
#[test]
fn a_friend_who_came_during_a_pause_never_scores() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    let now = real_now();
    let Ok(Started::Started(id)) = store.start_tournament(1, 7, 1, now - 600) else {
        return;
    };
    subscriber(&mut store, 1);

    // Пауза идёт с прошлого: приглашённый сейчас попадает внутрь неё.
    assert!(expect(store.pause_tournament(now - 5), "пауза"));
    invite(&mut store, 1, 11, true, now);
    assert!(expect(store.standings(id), "на паузе").is_empty());

    // Пауза записана — и после снятия он не засчитывается.
    expect(store.resume_tournament(now + 30), "снять");
    assert!(expect(store.standings(id), "после").is_empty());
}

/// Время на паузе стоит: срок не выходит, а после снятия сдвигается на её
/// длину.
#[test]
fn a_paused_tournament_does_not_run_out() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    let now = real_now();
    let Ok(Started::Started(id)) = store.start_tournament(1, 2, 1, now) else {
        return;
    };
    let ends = now + 2 * 86_400;

    assert!(expect(store.pause_tournament(now + 86_400), "пауза"));
    assert_eq!(
        expect(store.due_tournament(now + 10 * 86_400), "на паузе"),
        None
    );

    // Пауза длиной в пять дней — конец сдвигается на пять дней.
    let resumed = expect(store.resume_tournament(now + 6 * 86_400), "снять");
    assert_eq!(resumed, Some(ends + 5 * 86_400));
    assert_eq!(expect(store.resume_tournament(now), "не на паузе"), None);
    assert_eq!(
        expect(store.due_tournament(ends + 5 * 86_400), "срок"),
        Some(id)
    );
}

/// Выключенный турнир закрыт без призов и итогами не показывается;
/// следующий начинается с нуля.
#[test]
fn a_cancelled_tournament_gives_nothing_and_the_next_starts_clean() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    let now = real_now();
    let Ok(Started::Started(old)) = store.start_tournament(1, 7, 1, now - 600) else {
        return;
    };
    subscriber(&mut store, 1);
    invite(&mut store, 1, 10, true, now);

    assert_eq!(expect(store.cancel_tournament(now), "выключить"), Some(old));
    assert_eq!(expect(store.cancel_tournament(now), "повтор"), None);
    assert_eq!(expect(store.open_tournament(), "идущий"), None);
    assert_eq!(expect(store.last_finished_tournament(), "итоги"), None);
    assert!(expect(store.prizes_of(old), "призы").is_empty());
    assert_eq!(expect(store.finish_tournament(old, now), "итоги"), None);

    // Новый турнир — с нуля: друг, пришедший до него, не считается.
    let started = expect(store.start_tournament(1, 7, 1, now + 1), "новый");
    let Started::Started(new) = started else {
        unreachable!("новый турнир не начался: {started:?}");
    };
    assert!(expect(store.standings(new), "таблица").is_empty());
}
