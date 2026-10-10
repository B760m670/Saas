-- ---------------------------------------------------------------------------
-- Турнир: пауза и выключение
--
-- # Пауза
--
-- Турнир замирает: время не идёт, новые приглашённые не засчитываются.
-- Набранные очки остаются как были. После снятия паузы срок сдвигается на
-- её длину — турнир продолжается с того места, где остановился.
--
-- Приглашённые, пришедшие во время паузы, не засчитываются и потом: иначе
-- пауза ничего бы не останавливала, а только откладывала подсчёт. Поэтому
-- каждая пауза записывается (`tournament_pauses`), а идущая — в
-- `tournaments.paused_at`.
--
-- # Выключение
--
-- Турнир закрывается без итогов и призов (`cancelled`). Следующий
-- начинается с нуля: очки считаются от его собственного начала, старые на
-- него не переходят. Запись о выключенном остаётся как история, но в
-- кабинете итогами не показывается.
-- ---------------------------------------------------------------------------

BEGIN;

ALTER TABLE tournaments ADD COLUMN paused_at TIMESTAMPTZ;
ALTER TABLE tournaments ADD COLUMN cancelled BOOLEAN NOT NULL DEFAULT false;

-- Выключенный турнир всегда закрыт.
ALTER TABLE tournaments ADD CONSTRAINT tournaments_cancelled_is_closed
    CHECK (NOT cancelled OR finished_at IS NOT NULL);

CREATE TABLE tournament_pauses (
    tournament_id BIGINT NOT NULL REFERENCES tournaments (id),
    from_at TIMESTAMPTZ NOT NULL,
    to_at TIMESTAMPTZ NOT NULL,
    CHECK (to_at >= from_at)
);

CREATE INDEX tournament_pauses_by_tournament ON tournament_pauses (tournament_id);

COMMIT;
