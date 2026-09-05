-- 0001 — начальная схема Gloria VPN.
--
-- Правила, которые здесь закреплены, взяты из docs/14-bot.md. Часть из них
-- можно было бы держать только в коде бота, но они денежные: ошибка в них
-- обнаруживается не тестом, а покупателем, который заплатил дважды или
-- получил год вместо месяца. Поэтому те же правила стоят ограничениями в
-- базе — как второй рубеж, который переживёт правку кода.
--
-- Суммы везде целым числом минорных единиц: копейки для рубля, шесть
-- знаков для USDT. Совпадает с core/atlas-billing/src/money.rs. Плавающая
-- точка запрещена — расхождение в копейку ломает сверку платежа с заказом.

BEGIN;

-- ---------------------------------------------------------------------------
-- Общие сторожа
-- ---------------------------------------------------------------------------

-- Финансовые записи и отметка о пробе не удаляются. Удаление всё же нужно
-- в разработке и при разборе, поэтому оно не запрещено намертво, а сделано
-- намеренным действием: перед DELETE выставляется настройка сеанса.
--
--     SET LOCAL gloria.allow_delete = 'on';
--
-- Забыть эту строку случайно нельзя, а написать её — значит понимать, что
-- делаешь.
CREATE OR REPLACE FUNCTION gloria_rows_are_kept() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('gloria.allow_delete', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION
            'строки таблицы % не удаляются: см. gloria.allow_delete',
            TG_TABLE_NAME;
    END IF;
    RETURN OLD;
END;
$$;

CREATE OR REPLACE FUNCTION gloria_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Пользователи
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    -- Идентификатор Telegram. Он же наш первичный ключ: другого удостоверения
    -- у покупателя нет, а этот стабилен и не переиспользуется.
    telegram_id BIGINT PRIMARY KEY CHECK (telegram_id > 0),

    -- Тот же человек в панели Remnawave. Номер там целочисленный, а не
    -- UUID: сверено с их спецификацией (Remnawave API 3.3.2, поле `id`).
    panel_id BIGINT UNIQUE,

    -- Ссылка на подписку. Выдаётся один раз и живёт всё время, пока человек
    -- с нами, — через оплаты, перерывы и возвраты (docs/14-bot.md §1).
    subscription_url TEXT UNIQUE,

    -- До какого момента ключ рабочий. NULL — подписки не было ни разу.
    expires_at TIMESTAMPTZ,

    -- Когда выдана проба. NULL означает «не выдавалась».
    --
    -- Отметка временем, а не флагом: по ней считается суточный счётчик выдач,
    -- без которого нельзя заметить атаку (docs/14-bot.md §4).
    trial_granted_at TIMESTAMPTZ,

    -- Кто пригласил. Рефералок в первой версии нет, но поле заводится сразу:
    -- добавить его потом означает потерять данные за весь прошедший срок.
    invited_by BIGINT REFERENCES users (telegram_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Приглашение самим собой — признак ошибки в коде, а не выбора человека.
    CONSTRAINT nobody_invites_themselves CHECK (invited_by IS DISTINCT FROM telegram_id)
);

COMMENT ON TABLE users IS 'Покупатели. Строки не удаляются никогда.';

-- Один пробный период на один аккаунт, навсегда.
--
-- Это самое дорогое правило схемы: обойти его — три бесплатных дня, а
-- нечаянно сбросить отметку при правке кода бота проще, чем кажется.
-- Поэтому сброс запрещён на уровне базы.
CREATE OR REPLACE FUNCTION gloria_trial_is_granted_once() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.trial_granted_at IS NOT NULL
       AND NEW.trial_granted_at IS DISTINCT FROM OLD.trial_granted_at THEN
        RAISE EXCEPTION
            'проба уже выдана % и повторно не выдаётся (telegram_id %)',
            OLD.trial_granted_at, OLD.telegram_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trial_is_granted_once
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION gloria_trial_is_granted_once();

CREATE TRIGGER users_touch_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION gloria_touch_updated_at();

CREATE TRIGGER users_are_kept
    BEFORE DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION gloria_rows_are_kept();

-- Обход по срокам для напоминаний: интересны только те, у кого срок есть.
CREATE INDEX users_by_expiry ON users (expires_at) WHERE expires_at IS NOT NULL;

-- Суточный счётчик выданных проб — то, по чему видно атаку.
CREATE INDEX users_by_trial_day ON users (trial_granted_at)
    WHERE trial_granted_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Заказы
-- ---------------------------------------------------------------------------

CREATE TABLE orders (
    -- Номер заказа. Набор символов повторяет OrderId из
    -- core/atlas-billing/src/order.rs: номер уходит в строку подписи, и
    -- разделитель внутри него позволил бы подписать одной подписью два
    -- разных набора полей — сумму в том числе.
    id TEXT PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{1,64}$'),

    telegram_id BIGINT NOT NULL REFERENCES users (telegram_id),

    -- Имя тарифа на момент покупки.
    plan TEXT NOT NULL CHECK (plan <> ''),

    -- Срок и цена запоминаются слепком, а не ссылкой на прайс-лист.
    -- Изменение цен не должно задним числом менять то, что уже продано.
    days INTEGER NOT NULL CHECK (days > 0),
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    currency TEXT NOT NULL CHECK (currency IN ('RUB', 'USDT')),

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'paid', 'failed', 'refunded')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    paid_at TIMESTAMPTZ,

    -- Оплаченный заказ обязан знать, когда именно он оплачен, а
    -- неоплаченный — не имеет права на такую отметку. Без этой связи
    -- появляются заказы, «оплаченные никогда», и разобрать спор по ним
    -- нечем.
    CONSTRAINT paid_orders_know_when CHECK ((status = 'paid') = (paid_at IS NOT NULL))
);

COMMENT ON TABLE orders IS 'Выставленные счета. Не удаляются: по ним разбираются споры.';

CREATE TRIGGER orders_are_kept
    BEFORE DELETE ON orders
    FOR EACH ROW EXECUTE FUNCTION gloria_rows_are_kept();

CREATE INDEX orders_by_user ON orders (telegram_id, created_at DESC);

-- Незакрытые счета — то, что показывается покупателю и то, что подчищается
-- по истечении срока.
CREATE INDEX orders_pending ON orders (created_at) WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- Платежи
-- ---------------------------------------------------------------------------

CREATE TABLE payments (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider <> ''),

    -- Номер платежа у сервиса.
    provider_ref TEXT NOT NULL CHECK (provider_ref <> ''),

    order_id TEXT REFERENCES orders (id),

    amount_minor BIGINT NOT NULL CHECK (amount_minor >= 0),
    currency TEXT NOT NULL CHECK (currency IN ('RUB', 'USDT')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'paid', 'failed', 'refunded')),

    -- Уведомление целиком, как пришло. Когда покупатель напишет «я платил, а
    -- подписки нет», разбираться придётся по этому полю, и «мы это не
    -- сохраняем» — не ответ.
    payload JSONB NOT NULL,

    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Защита от двойного зачисления.
    --
    -- Сервисы повторяют доставку, пока не получат 200, и повторяют её же
    -- после сетевого сбоя. Повтор упирается в это ограничение, обработчик
    -- отвечает 200 и не делает ничего. Без него год превращается в два года
    -- по цене одного (docs/14-bot.md §9).
    CONSTRAINT one_record_per_payment UNIQUE (provider, provider_ref)
);

COMMENT ON TABLE payments IS 'Уведомления платёжных сервисов. Не удаляются.';

CREATE TRIGGER payments_are_kept
    BEFORE DELETE ON payments
    FOR EACH ROW EXECUTE FUNCTION gloria_rows_are_kept();

CREATE INDEX payments_by_order ON payments (order_id);

-- ---------------------------------------------------------------------------
-- Напоминания
-- ---------------------------------------------------------------------------

CREATE TABLE reminders_sent (
    telegram_id BIGINT NOT NULL REFERENCES users (telegram_id),

    kind TEXT NOT NULL CHECK (kind IN ('before_3d', 'on_expiry', 'after_3d')),

    -- К какому именно сроку относится напоминание.
    --
    -- Входит в ключ намеренно. Без него человек, продливший подписку, не
    -- получил бы напоминаний уже никогда: отметка «отправлено» осталась бы
    -- от прошлого срока. С ним новый срок — это новый набор напоминаний.
    expires_at TIMESTAMPTZ NOT NULL,

    sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (telegram_id, kind, expires_at)
);

COMMENT ON TABLE reminders_sent IS 'Что уже отправлено. Защита от повторной рассылки.';

-- ---------------------------------------------------------------------------
-- Настройки, меняемые без выкладки
-- ---------------------------------------------------------------------------

CREATE TABLE settings (
    key TEXT PRIMARY KEY CHECK (key <> ''),
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER settings_touch_updated_at
    BEFORE UPDATE ON settings
    FOR EACH ROW EXECUTE FUNCTION gloria_touch_updated_at();

-- Выдачу проб надо уметь выключить одной настройкой, не выкатывая новую
-- версию, — это единственная защита на случай, когда счётчик выдач вырастет
-- в сто раз (docs/14-bot.md §4).
INSERT INTO settings (key, value) VALUES ('trial_enabled', 'true');

COMMIT;
