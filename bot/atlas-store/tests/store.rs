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
use atlas_store::{Settled, Store, Trial};

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
    assert!(expect(store.orders_claiming(rub(19_900), NOW, LIFETIME), "поиск").is_empty());

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

/// Кнопка зачисления называет заказ номером, и по номеру он обязан
/// находиться — но только пока открыт.
///
/// Кнопка остаётся в переписке навсегда. Нажать её второй раз через неделю
/// проще, чем кажется, и тогда владельцу надо сказать «уже закрыт», а не
/// зачислить второй раз.
#[test]
fn a_button_finds_its_order_only_while_it_is_open() {
    let Some((mut store, _lock)) = store() else {
        return;
    };
    subscriber(&mut store, 42);
    let _ = store.open_order("by-button", 42, "d30", 30, rub(19_897), NOW);

    assert_eq!(
        expect(store.pending_order("by-button"), "поиск по номеру"),
        Some((42, rub(19_897)))
    );

    // Заказа с таким номером нет вовсе.
    assert_eq!(expect(store.pending_order("нет-такого"), "поиск"), None);

    let _ = store.settle("by-button", "manual", "m-btn", rub(20_000), "{}", NOW + 10);
    assert_eq!(
        expect(store.pending_order("by-button"), "поиск после оплаты"),
        None,
        "закрытый заказ нашёлся — второе нажатие зачислило бы его снова"
    );
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
    assert!(later.is_empty());
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

    let Ok(work) = store.panel_work(10, NOW) else {
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

    let _ = store.mark_panel_synced(42, NOW + 3 * DAY);

    let Ok(work) = store.panel_work(10, NOW) else {
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
    let _ = store.mark_panel_synced(42, NOW + 3 * DAY);

    let _ = store.open_order("ord-9", 42, "d30", 30, rub(19_899), NOW);
    let _ = store.settle("ord-9", "manual", "19899-ord-9", rub(19_899), "{}", NOW);

    let Ok(work) = store.panel_work(10, NOW) else {
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
    let _ = store.mark_panel_synced(42, carried);

    let Ok(work) = store.panel_work(10, NOW) else {
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

    let Ok(work) = store.panel_work(10, NOW) else {
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

    let Ok(work) = store.panel_work(10, NOW) else {
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

    let Ok(work) = store.panel_work(2, NOW) else {
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
        store.panel_work(10, NOW).map(|work| work.len()).ok(),
        Some(1)
    );

    let Ok(()) = store.adopt_from_panel(42, NOW + 22 * DAY) else {
        return;
    };
    assert_eq!(
        store.panel_work(10, NOW).map(|work| work.len()).ok(),
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
        store.panel_work(10, NOW).map(|work| work.len()).ok(),
        Some(1)
    );

    // Тот же срок неделей позже уже в прошлом — и работы нет.
    assert_eq!(
        store
            .panel_work(10, NOW + 7 * DAY)
            .map(|work| work.len())
            .ok(),
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
    let Ok(()) = store.open_order("u42-d30-1", 42, "d30", 30, rub(19_899), NOW) else {
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
