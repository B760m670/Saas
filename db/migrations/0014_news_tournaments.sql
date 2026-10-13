-- ---------------------------------------------------------------------------
-- Новости и турниры приглашений
--
-- # Новости
--
-- Лента в кабинете: что изменилось, какие акции идут и когда кончатся.
-- Пишет владелец из админки; важное он может разослать и сообщением в бот —
-- тем, кто рассылку не выключил (`users.news_muted`).
--
-- # Турнир
--
-- Временное соревнование: кто за срок приведёт больше людей. Засчитывается
-- приглашённый, который
--
--   - пришёл по ссылке (`users.invited_by`) **во время** турнира
--     (`users.created_at` внутри срока) — старые знакомые задним числом не
--     считаются;
--   - и **подключился к VPN через приложение**: панель увидела его трафик
--     (`users.connected_at`). Пустой аккаунт, заведённый ради счёта, без
--     установленного клиента не засчитывается.
--
-- Призы — дни подписки первым десяти, кто набрал не меньше порога
-- (`tournaments.min_score`). Порог нужен на старте: при трёх участниках
-- без него первое место взял бы приведший одного человека.
-- ---------------------------------------------------------------------------

BEGIN;

-- Имя для таблицы турнира. Берётся из подписанной Telegram строки кабинета,
-- показывается другим только сокращённым («Ал***»).
ALTER TABLE users ADD COLUMN display_name TEXT
    CHECK (char_length(display_name) BETWEEN 1 AND 64);

-- Когда человек последний раз открывал ленту новостей: всё, что новее, —
-- непрочитанное.
ALTER TABLE users ADD COLUMN news_seen_at TIMESTAMPTZ;

-- Не присылать новости сообщением в бот. В кабинете лента видна всё равно.
ALTER TABLE users ADD COLUMN news_muted BOOLEAN NOT NULL DEFAULT false;

-- Когда панель впервые увидела трафик этого человека — то есть он поставил
-- приложение и подключился. NULL — ещё нет или не проверяли.
ALTER TABLE users ADD COLUMN connected_at TIMESTAMPTZ;

CREATE INDEX users_invited ON users (invited_by, created_at) WHERE invited_by IS NOT NULL;

CREATE TABLE news (
    id BIGSERIAL PRIMARY KEY,
    title TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 120),
    body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    author_id BIGINT NOT NULL,
    -- Разослана ли сообщением в бот.
    pushed BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX news_by_time ON news (created_at DESC);

CREATE TABLE tournaments (
    id BIGSERIAL PRIMARY KEY,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    min_score INTEGER NOT NULL DEFAULT 3 CHECK (min_score >= 1),
    created_by BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Итоги подведены, призы выданы. NULL — турнир идёт.
    finished_at TIMESTAMPTZ,
    CHECK (ends_at > starts_at)
);

-- Одновременно идёт не больше одного турнира: два параллельных считали бы
-- одних и тех же приглашённых дважды.
CREATE UNIQUE INDEX tournaments_one_open ON tournaments ((true)) WHERE finished_at IS NULL;

CREATE TABLE tournament_prizes (
    tournament_id BIGINT NOT NULL REFERENCES tournaments (id),
    place INTEGER NOT NULL CHECK (place BETWEEN 1 AND 10),
    telegram_id BIGINT NOT NULL REFERENCES users (telegram_id),
    score INTEGER NOT NULL CHECK (score >= 1),
    days INTEGER NOT NULL CHECK (days BETWEEN 1 AND 365),
    PRIMARY KEY (tournament_id, place),
    UNIQUE (tournament_id, telegram_id)
);

COMMIT;
