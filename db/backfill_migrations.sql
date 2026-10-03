-- ---------------------------------------------------------------------------
-- Учёт миграций задним числом
--
-- Нужен один раз: на базе, где схема стоит с тех времён, когда учёта не
-- было. Дальше `schema_migrations` ведётся сама, и этот файл ничего не
-- меняет — он идемпотентен и безвреден на любой базе.
--
-- # Почему по схеме, а не по отказу
--
-- Сначала «уже применена» определялось по виду отказа: упёрлась в «объект
-- уже есть» — значит применена. На сервере это сломалось сразу:
-- `0003_last_day_reminder.sql` упала не с «уже есть», а с нарушением
-- CHECK. База оказалась **новее** миграции — в ней уже стояла 0004,
-- которая переименовывает виды напоминаний ещё раз, — и повторное
-- применение 0003 пыталось вернуть набор значений, которого в строках
-- больше нет.
--
-- Отказ вообще ничего не говорит о том, применена миграция или нет: он
-- говорит лишь о том, что её нельзя применить сейчас. Признак применённости
-- один — **след в схеме**, и здесь перечислены именно следы.
--
-- Список закрыт. Дополнять его новыми миграциями не нужно: с 0008 учёт
-- ведётся с самого начала, и заднее число больше никому не понадобится.
-- ---------------------------------------------------------------------------

INSERT INTO schema_migrations (name)
SELECT name FROM (VALUES
    ('0001_init.sql', EXISTS (
        SELECT 1 FROM information_schema.tables
         WHERE table_schema = 'public' AND table_name = 'users')),

    ('0002_panel_sync.sql', EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'users' AND column_name = 'panel_expires_at')),

    -- Виды напоминаний переименовывались дважды, и след каждой правки —
    -- в тексте ограничения. `on_expiry` ушёл в 0003; значит его отсутствие
    -- и есть признак, что 0003 применена. Проверять наличие `last_day`
    -- нельзя: 0004 убирает и его.
    ('0003_last_day_reminder.sql', EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'reminders_sent_kind_check'
           AND pg_get_constraintdef(oid) NOT LIKE '%on_expiry%')),

    ('0004_reminder_days.sql', EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'reminders_sent_kind_check'
           AND pg_get_constraintdef(oid) LIKE '%day_before%')),

    ('0005_claimed_orders.sql', EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'orders' AND column_name = 'claimed_at')),

    ('0006_claimed_amount.sql', EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'orders' AND column_name = 'claimed_minor')),

    ('0007_support.sql', EXISTS (
        SELECT 1 FROM information_schema.tables
         WHERE table_schema = 'public' AND table_name = 'support_messages')),

    ('0008_support_one_at_a_time.sql', EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'users' AND column_name = 'support_pending_at'))
) AS m(name, present)
WHERE present
ON CONFLICT (name) DO NOTHING;
