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

# Витрина стоит отдельно от кабинета: у неё свой домен без «panel.» в имени,
# и одна папка на двоих означала бы, что личный кабинет открывается по
# публичному адресу, а витрина — по адресу панели.
SITE_PUBLIC=${SITE_PUBLIC:-/var/www/gloria-public}

# Реквизиты, которые публикуются в документах, но не хранятся в репозитории.
# Файл лежит только на сервере и содержит одну строку:
#
#     GLORIA_INN=000000000000
#
# ИНН попадёт на публичную страницу, но история git — другое дело: оттуда
# он уже не исчезнет, а репозиторий может стать открытым.
LEGAL=${LEGAL:-/etc/gloria-legal.env}

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

# Документы выкладываются вместе со страницей: ссылки на них строятся от её
# адреса, и забытая копия оставила бы в кабинете три пункта в никуда. На них
# же ссылается платёжный сервис, а для него неработающая оферта — повод
# отключить приём оплаты.
#
# Имени владельца в документах нет по его решению; ИНН подставляется здесь,
# из файла на сервере.
if [ ! -r "$LEGAL" ]; then
    echo "нет файла $LEGAL — в документах остался бы {{ИНН}} вместо номера" >&2
    exit 1
fi
. "$LEGAL"

if [ -z "${GLORIA_INN:-}" ]; then
    echo "в $LEGAL не задан GLORIA_INN" >&2
    exit 1
fi

# Подстановка при выкладке, а не при сборке: файлы в репозитории остаются
# без реквизитов, и следующий git pull ничего не затирает.
publish_legal() {
    sed "s/{{ИНН}}/$GLORIA_INN/g" "$1" > "$2.tmp"
    if grep -q '{{' "$2.tmp"; then
        echo "в $1 остались неподставленные значения" >&2
        rm -f "$2.tmp"
        exit 1
    fi
    install -m 644 "$2.tmp" "$2"
    rm -f "$2.tmp"
}

install -d -m 755 "$SITE/legal"
for f in site/legal/*.html; do
    publish_legal "$f" "$SITE/legal/$(basename "$f")"
done
install -m 644 site/legal/legal.css "$SITE/legal/legal.css"

# Витрина: то, что видит человек, открывший адрес в обычном браузере, и то,
# что смотрит модератор платёжного сервиса. Без неё по адресу открывается
# личный кабинет, рассчитанный на Telegram, — без подписи он показывает
# прочерки и выглядит как недоделанный сайт.
install -d -m 755 "$SITE_PUBLIC"
publish_legal site/landing/index.html "$SITE_PUBLIC/index.html"

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
