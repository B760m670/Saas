-- ---------------------------------------------------------------------------
-- Сообщения выбранным людям из админки
--
-- Владелец выбирает людей в списке (например, всех, у кого проба кончилась)
-- и пишет им от имени бота. Каждая такая рассылка записывается: кто, когда,
-- что и скольким. Сообщение, ушедшее десятку покупателей, — то же действие
-- владельца, что ручное продление, и следа без него быть не должно.
--
-- Отдельная таблица, а не `admin_log`: там действие всегда над одним
-- человеком (`target_id NOT NULL`), а здесь — над многими сразу.
-- ---------------------------------------------------------------------------

BEGIN;

CREATE TABLE admin_messages (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    admin_id BIGINT NOT NULL CHECK (admin_id > 0),
    body TEXT NOT NULL CHECK (body <> ''),
    -- Скольким ушло. Сами номера не храним: список получателей виден в
    -- момент отправки, а через месяц важнее «сколько и что».
    recipients INTEGER NOT NULL CHECK (recipients > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER admin_messages_are_kept
    BEFORE DELETE ON admin_messages
    FOR EACH ROW EXECUTE FUNCTION gloria_rows_are_kept();

COMMIT;
