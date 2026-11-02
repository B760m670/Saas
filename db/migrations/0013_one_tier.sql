-- ---------------------------------------------------------------------------
-- Один тариф: без «Семьи», без гостей и без бонусов
--
-- На старте сервису нужны платящие люди, а не подарки: каждый пользователь
-- оплачивает свою подписку сам. Поэтому:
--
-- - тариф «Семья» и гости (0012) убраны. Гостей отключаем сейчас: их срок
--   кончается, и очередь переведёт их на бесплатный доступ, как после
--   истёкшей подписки. Купившие «Семью» становятся «Личными» — оплаченные
--   дни сохраняются, устройства — по «Личному»;
-- - бонусы за приглашённых (0009) больше не начисляются и не списываются.
--   Журнал `bonus_ledger` и поле `orders.bonus_spent` остаются как история:
--   удалять записи о прошлых деньгах незачем.
-- ---------------------------------------------------------------------------

BEGIN;

-- Гости — без подписки. Срок кончается сейчас, а не стирается: очередь
-- увидит прошедшую дату и отдаст бесплатный доступ.
UPDATE users
   SET expires_at = LEAST(expires_at, now())
 WHERE owner_id IS NOT NULL;

DROP TRIGGER IF EXISTS guests_follow_owner ON users;
DROP FUNCTION IF EXISTS gloria_guests_follow_owner();

DROP TABLE invites;
ALTER TABLE users DROP CONSTRAINT users_guest_has_a_start;
ALTER TABLE users DROP CONSTRAINT users_not_own_guest;
DROP INDEX users_guests;
ALTER TABLE users DROP COLUMN owner_id;
ALTER TABLE users DROP COLUMN guest_since;

-- «Семья» → «Личный».
UPDATE users SET tier = 'personal' WHERE tier = 'family';
ALTER TABLE users DROP CONSTRAINT users_tier_check;
ALTER TABLE users ADD CONSTRAINT users_tier_check CHECK (tier IN ('personal'));

-- Что панель подтвердила. Бывшие «Семья» и гости переотвозятся: у них
-- меняются устройства и трафик.
UPDATE users SET panel_plan = NULL WHERE panel_plan IN ('family', 'guest');
ALTER TABLE users DROP CONSTRAINT users_panel_plan_check;
ALTER TABLE users ADD CONSTRAINT users_panel_plan_check
    CHECK (panel_plan IN ('paid', 'free', 'personal'));

COMMENT ON COLUMN users.panel_plan IS
    'Подтверждённое панелью: paid — прежний платный (3 устройства) или проба, personal — тариф, free — только бесплатный отряд. NULL — не отвозили.';

COMMIT;
