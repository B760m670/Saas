-- Проверка сторожей схемы.
--
-- Ограничение, которое никто не пробовал нарушить, — это комментарий, а не
-- ограничение. Здесь каждое денежное правило проверяется враждебным
-- запросом: он обязан упасть.
--
-- Запуск: psql -v ON_ERROR_STOP=1 -d gloria -f db/tests/invariants.sql
-- Работа идёт в откатываемой транзакции — база остаётся нетронутой.

BEGIN;

-- Сигнал о провале теста помечается своим кодом, иначе он неотличим от
-- исключения, которое поднимает проверяемый сторож.
CREATE OR REPLACE FUNCTION must_fail(statement TEXT, what TEXT) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE statement;
    EXCEPTION
        WHEN SQLSTATE 'GL001' THEN RAISE;
        WHEN OTHERS THEN RETURN;          -- упало, как и требовалось
    END;
    RAISE EXCEPTION 'ПРОВАЛ: прошло то, что не должно было — %', what
        USING ERRCODE = 'GL001';
END;
$$;

-- --- подготовка ------------------------------------------------------------

INSERT INTO users (telegram_id) VALUES (1001), (1002);

INSERT INTO orders (id, telegram_id, plan, days, amount_minor, currency)
VALUES ('order-1', 1001, 'd30', 30, 19900, 'RUB');

-- --- проба выдаётся один раз ----------------------------------------------

UPDATE users SET trial_granted_at = now() WHERE telegram_id = 1001;

-- Второй раз — обязательно другим временем. `now()` внутри транзакции
-- возвращает момент её начала, поэтому повторный `now()` записал бы то же
-- самое значение, строка бы не изменилась, и тест прошёл бы вхолостую,
-- ничего не проверив.
SELECT must_fail(
    $q$UPDATE users SET trial_granted_at = now() + interval '1 day'
       WHERE telegram_id = 1001$q$,
    'повторная выдача пробы');

SELECT must_fail(
    $q$UPDATE users SET trial_granted_at = NULL WHERE telegram_id = 1001$q$,
    'сброс отметки о пробе');

-- --- номер заказа не содержит разделителей --------------------------------

SELECT must_fail(
    $q$INSERT INTO orders (id, telegram_id, plan, days, amount_minor, currency)
       VALUES ('order:2', 1001, 'd30', 30, 19900, 'RUB')$q$,
    'номер заказа с двоеточием');

SELECT must_fail(
    $q$INSERT INTO orders (id, telegram_id, plan, days, amount_minor, currency)
       VALUES ('заказ-2', 1001, 'd30', 30, 19900, 'RUB')$q$,
    'номер заказа кириллицей');

-- --- суммы и валюты --------------------------------------------------------

SELECT must_fail(
    $q$INSERT INTO orders (id, telegram_id, plan, days, amount_minor, currency)
       VALUES ('order-3', 1001, 'd30', 30, 0, 'RUB')$q$,
    'заказ на нулевую сумму');

SELECT must_fail(
    $q$INSERT INTO orders (id, telegram_id, plan, days, amount_minor, currency)
       VALUES ('order-4', 1001, 'd30', 30, 19900, 'EUR')$q$,
    'заказ в неизвестной валюте');

SELECT must_fail(
    $q$INSERT INTO orders (id, telegram_id, plan, days, amount_minor, currency)
       VALUES ('order-5', 1001, 'd30', 0, 19900, 'RUB')$q$,
    'заказ на ноль дней');

-- --- оплаченный заказ знает время оплаты ----------------------------------

SELECT must_fail(
    $q$UPDATE orders SET status = 'paid' WHERE id = 'order-1'$q$,
    'оплата без отметки времени');

SELECT must_fail(
    $q$UPDATE orders SET paid_at = now() WHERE id = 'order-1'$q$,
    'отметка об оплате у неоплаченного заказа');

UPDATE orders SET status = 'paid', paid_at = now() WHERE id = 'order-1';

-- --- одно уведомление учитывается один раз --------------------------------

INSERT INTO payments (provider, provider_ref, order_id, amount_minor, currency, status, payload)
VALUES ('kassa', 'PAY-777', 'order-1', 19900, 'RUB', 'paid', '{}'::jsonb);

SELECT must_fail(
    $q$INSERT INTO payments (provider, provider_ref, order_id, amount_minor, currency, status, payload)
       VALUES ('kassa', 'PAY-777', 'order-1', 19900, 'RUB', 'paid', '{}'::jsonb)$q$,
    'повторная доставка того же уведомления');

-- Тот же номер у другого сервиса — другой платёж, и он обязан пройти.
INSERT INTO payments (provider, provider_ref, order_id, amount_minor, currency, status, payload)
VALUES ('manual', 'PAY-777', 'order-1', 19900, 'RUB', 'paid', '{}'::jsonb);

-- --- приглашение самим собой ----------------------------------------------

SELECT must_fail(
    $q$UPDATE users SET invited_by = 1002 WHERE telegram_id = 1002$q$,
    'приглашение самим собой');

UPDATE users SET invited_by = 1001 WHERE telegram_id = 1002;

-- --- напоминания -----------------------------------------------------------

INSERT INTO reminders_sent (telegram_id, kind, expires_at)
VALUES (1001, 'before_3d', '2026-09-01T00:00:00Z');

SELECT must_fail(
    $q$INSERT INTO reminders_sent (telegram_id, kind, expires_at)
       VALUES (1001, 'before_3d', '2026-09-01T00:00:00Z')$q$,
    'повторная отправка того же напоминания');

-- Главное в этой таблице: после продления тот же вид напоминания обязан
-- отправиться заново — уже к новому сроку.
INSERT INTO reminders_sent (telegram_id, kind, expires_at)
VALUES (1001, 'before_3d', '2026-12-01T00:00:00Z');

-- --- записи не удаляются ---------------------------------------------------

SELECT must_fail(
    $q$DELETE FROM payments WHERE provider = 'manual'$q$,
    'удаление платежа');

SELECT must_fail($q$DELETE FROM orders WHERE id = 'order-1'$q$, 'удаление заказа');
SELECT must_fail($q$DELETE FROM users WHERE telegram_id = 1002$q$, 'удаление пользователя');

-- Осознанное удаление всё же возможно — иначе с базой нельзя работать.
SET LOCAL gloria.allow_delete = 'on';
DELETE FROM reminders_sent WHERE telegram_id = 1001;
DELETE FROM payments WHERE order_id = 'order-1';
SET LOCAL gloria.allow_delete = 'off';

SELECT must_fail($q$DELETE FROM orders WHERE id = 'order-1'$q$,
    'удаление после возврата настройки');

-- --- итог ------------------------------------------------------------------

DO $$ BEGIN RAISE NOTICE 'все сторожа сработали'; END $$;

ROLLBACK;
