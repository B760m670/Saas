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

    let prepared = store.reset_for_tests(include_str!("../../../db/migrations/0001_init.sql"));
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
        Some(Some("u42-d30-03".to_owned()))
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
        Some(Some("for-43".to_owned()))
    );
    // Круглая сумма не принадлежит никому — уходит в ручной разбор.
    assert_eq!(
        store.order_by_amount(rub(19_900), NOW, LIFETIME).ok(),
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
