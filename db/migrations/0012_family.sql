-- ---------------------------------------------------------------------------
-- Тарифы «Личный» и «Семья»; гости — близкие, которым владелец дал подписку
--
-- # Почему у гостя своя подписка, а не общая ссылка
--
-- Панель считает трафик по пользователю, а не по устройству. На общей ссылке
-- у всей семьи был бы один счётчик: либо безлимит у всех, либо одни 30 ГБ на
-- всех. Поэтому гость — отдельный пользователь со своей ссылкой: у него свой
-- предел (30 ГБ в месяц), а безлимит остаётся у владельца, который платит.
--
-- # Срок гостя — срок владельца
--
-- Гость не платит. Его срок повторяет срок владельца, и повторяет его база,
-- а не код: триггер ниже переносит новую дату владельца всем его гостям, по
-- какой бы дороге она ни пришла — оплата, ручное продление, правка в
-- панели. Дорога, о которой код забыл, оставила бы гостей с прошлым сроком.
-- ---------------------------------------------------------------------------

BEGIN;

-- Тариф последней покупки. NULL — платил до появления тарифов (у таких
-- остаются прежние 3 устройства) или не платил вовсе.
ALTER TABLE users ADD COLUMN tier TEXT CHECK (tier IN ('personal', 'family'));

-- Чей это гость. NULL — сам себе хозяин.
ALTER TABLE users ADD COLUMN owner_id BIGINT REFERENCES users (telegram_id);
ALTER TABLE users ADD CONSTRAINT users_not_own_guest CHECK (owner_id <> telegram_id);

-- С какого момента гость. Нужно, чтобы при переходе на тариф с меньшим
-- числом мест знать, кто пришёл последним, — его и отключать.
ALTER TABLE users ADD COLUMN guest_since TIMESTAMPTZ;
ALTER TABLE users ADD CONSTRAINT users_guest_has_a_start
    CHECK ((owner_id IS NULL) = (guest_since IS NULL));

CREATE INDEX users_guests ON users (owner_id) WHERE owner_id IS NOT NULL;

-- Что панель о человеке подтвердила. К прежним `paid` и `free` добавились
-- тарифы и гость: от них зависят устройства и трафик, и смена тарифа при той
-- же дате — тоже работа для очереди.
ALTER TABLE users DROP CONSTRAINT users_panel_plan_check;
ALTER TABLE users ADD CONSTRAINT users_panel_plan_check
    CHECK (panel_plan IN ('paid', 'free', 'personal', 'family', 'guest'));

COMMENT ON COLUMN users.panel_plan IS
    'Подтверждённое панелью: paid — прежний платный (3 устройства) или проба, personal/family — тариф, guest — гость, free — только бесплатный отряд. NULL — не отвозили.';

-- Срок гостя следует за сроком владельца.
CREATE OR REPLACE FUNCTION gloria_guests_follow_owner() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE users SET expires_at = NEW.expires_at WHERE owner_id = NEW.telegram_id;
    RETURN NULL;
END;
$$;

-- Только для владельцев (`owner_id IS NULL`): обновление гостя этим же
-- триггером не запускает его снова, и цепочки быть не может.
CREATE TRIGGER guests_follow_owner
    AFTER UPDATE OF expires_at ON users
    FOR EACH ROW
    WHEN (NEW.expires_at IS DISTINCT FROM OLD.expires_at AND NEW.owner_id IS NULL)
    EXECUTE FUNCTION gloria_guests_follow_owner();

-- Приглашения. Одноразовые: одно приглашение — один гость.
CREATE TABLE invites (
    -- Код в ссылке `t.me/<бот>?start=fam_<код>`. Случайный: перебором чужое
    -- приглашение не найти.
    code TEXT PRIMARY KEY CHECK (code ~ '^[A-Za-z0-9]{16,32}$'),
    owner_id BIGINT NOT NULL REFERENCES users (telegram_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_by BIGINT REFERENCES users (telegram_id),
    used_at TIMESTAMPTZ,
    CHECK ((used_by IS NULL) = (used_at IS NULL))
);

CREATE INDEX invites_by_owner ON invites (owner_id, created_at DESC);

COMMIT;
