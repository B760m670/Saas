-- ---------------------------------------------------------------------------
-- Журнал действий в админке
--
-- Админка меняет состояние руками владельца: продлевает подписку,
-- перевыпускает ссылку. У платежа есть след — запись в `payments`; у
-- ручного продления следа не было бы никакого, и через месяц вопрос «почему
-- у этого человека срок до марта» не имел бы ответа.
--
-- Журнал, а не счётчик и не поле в `users`, по той же причине, что и
-- `bonus_ledger`: запись отвечает, кто, что, кому и когда сделал, а правка
-- поля стирает прошлое.
-- ---------------------------------------------------------------------------

BEGIN;

CREATE TABLE admin_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- Кто сделал: номер в Telegram. Не ссылка на `users`: владелец может и
    -- не быть покупателем.
    admin_id BIGINT NOT NULL CHECK (admin_id > 0),

    -- Что сделал. Набор закрытый: новое действие — новая миграция, а не
    -- произвольная строка, которую потом не сгруппировать.
    action TEXT NOT NULL CHECK (action IN ('extend', 'reissue')),

    -- Кому.
    target_id BIGINT NOT NULL REFERENCES users (telegram_id),

    -- Подробности: для продления — на сколько дней и до какого срока.
    detail TEXT NOT NULL DEFAULT '',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX admin_log_by_target ON admin_log (target_id, created_at DESC);

-- Журнал не правится задним числом — иначе он перестаёт быть журналом.
CREATE TRIGGER admin_log_is_kept
    BEFORE DELETE ON admin_log
    FOR EACH ROW EXECUTE FUNCTION gloria_rows_are_kept();

COMMIT;
