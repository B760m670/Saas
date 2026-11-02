-- ---------------------------------------------------------------------------
-- Вход на сайт через бота
--
-- Кабинет открывается и в обычном браузере, без Telegram. Удостоверения там
-- нет, поэтому вход такой:
--
--   1. сайт просит код (`login_requests`) и показывает ссылку на бота с ним;
--   2. человек открывает бота и **сам** нажимает «Подтвердить вход» — код
--      получает его номер;
--   3. сайт, дождавшись подтверждения, меняет код на сессию
--      (`web_sessions`) — один раз: код после этого погашен.
--
-- Подтверждение кнопкой, а не самим переходом по ссылке, — намеренно. Иначе
-- чужой, подсунув ссылку со своим кодом, вошёл бы в аккаунт того, кто по ней
-- перешёл.
--
-- В базе лежат не сами код и сессия, а их SHA-256: утёкшая таблица не даёт
-- войти ни в один кабинет.
-- ---------------------------------------------------------------------------

BEGIN;

CREATE TABLE login_requests (
    code_hash TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    -- Кто подтвердил в боте. NULL — ещё никто.
    telegram_id BIGINT REFERENCES users (telegram_id),
    confirmed_at TIMESTAMPTZ,
    -- Обменян на сессию. После этого код не работает.
    consumed_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK ((telegram_id IS NULL) = (confirmed_at IS NULL)),
    CHECK (consumed_at IS NULL OR confirmed_at IS NOT NULL)
);

CREATE TABLE web_sessions (
    token_hash TEXT PRIMARY KEY,
    telegram_id BIGINT NOT NULL REFERENCES users (telegram_id),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX web_sessions_by_user ON web_sessions (telegram_id);

COMMIT;
