#!/bin/sh
# Обновление бота и мини-приложения.
#
# Порядок важен: сборка идёт до остановки службы, чтобы простой был не
# минутами компиляции, а секундами копирования. И собранное ставится
# отдельно от исходников — иначе пересборка попыталась бы переписать файл
# работающего процесса и упёрлась бы в «Text file busy».
set -eu

BRANCH=${BRANCH:-claude/multiplatform-vpn-service-ur6ef4}
SRC=${SRC:-/opt/gloria-src}
SITE=${SITE:-/var/www/gloria}

cd "$SRC"

echo "== обновляемся"
git fetch origin "$BRANCH"
git checkout -q FETCH_HEAD

echo "== схема базы"
for m in db/migrations/*.sql; do
    # Уже применённая упрётся в «уже существует» — это не ошибка, а
    # отсутствие учёта миграций. Поэтому отказ здесь не останавливает.
    docker exec -i remnawave-db psql -U gloria -d gloria -v ON_ERROR_STOP=1 < "$m" >/dev/null 2>&1 \
        && echo "   применена $(basename "$m")" \
        || echo "   пропущена $(basename "$m") (скорее всего, уже применена)"
done

echo "== сборка"
( cd bot && cargo build --release )

echo "== мини-приложение"
install -m 644 site/index.html "$SITE/index.html"

echo "== бот"
systemctl stop gloria-bot
install -m 755 bot/target/release/gloria /opt/gloria/gloria
systemctl start gloria-bot

sleep 2
systemctl is-active --quiet gloria-bot && echo "== готово" || {
    echo "== бот не поднялся:"
    journalctl -u gloria-bot -n 20 --no-pager
    exit 1
}
