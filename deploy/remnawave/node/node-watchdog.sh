#!/usr/bin/env bash
# Вотчдог узла: перезапускает контейнер, если узел перестал обслуживать.
#
# Зачем он нужен. Контейнер remnawave/node своего healthcheck не объявляет,
# а `restart: always` ловит только падение процесса. Настоящая болячка здесь
# другая: контейнер «жив», но Xray внутри завис или перестал слушать — и узел
# месяцами висит в n/a, пока человек не заметит. Этот скрипт замечает за
# минуту и перезапускает сам.
#
# Проверяем три признака жизни, по возрастанию строгости:
#   1) контейнер запущен;
#   2) процесс xray внутри него существует;
#   3) xray реально слушает TCP-порт на хосте (network_mode: host).
# Если хоть один не выполнен THRESHOLD раз подряд — docker restart.
# Порог, а не мгновенный рестарт, чтобы единичный сбой проверки не дёргал узел.
#
# Ставится на хост узла, запускается раз в минуту через cron. Установка — в
# README, раздел «Надёжность».

set -u

CONTAINER="${NODE_CONTAINER:-remnanode}"
THRESHOLD="${NODE_FAIL_THRESHOLD:-2}"
STATE="/run/node-watchdog.fails"

log() { logger -t node-watchdog "$*" 2>/dev/null || echo "node-watchdog: $*" >&2; }

alive() {
    [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ] || return 1
    docker top "$CONTAINER" 2>/dev/null | grep -qiE '(^|/)xray( |$)' || return 1
    # xray слушает хотя бы один TCP-порт (REALITY-инбаунд). Имя процесса в ss
    # видно, т.к. узел в сети хоста. Если ss без имён — подстрахуемся портами.
    if ss -tlnpH 2>/dev/null | grep -qi 'xray'; then
        return 0
    fi
    ss -tlnH 2>/dev/null | grep -qE ':(443|8443|2053|2083|2087|2096)[[:space:]]' && return 0
    return 1
}

if alive; then
    echo 0 >"$STATE" 2>/dev/null || true
    exit 0
fi

fails=$(( $(cat "$STATE" 2>/dev/null || echo 0) + 1 ))
echo "$fails" >"$STATE" 2>/dev/null || true
log "проверка не прошла ($fails/$THRESHOLD), контейнер=$CONTAINER"

if [ "$fails" -ge "$THRESHOLD" ]; then
    log "перезапуск $CONTAINER после $fails неудач подряд"
    if docker restart "$CONTAINER" >/dev/null 2>&1; then
        echo 0 >"$STATE" 2>/dev/null || true
        log "перезапуск выполнен"
    else
        log "перезапуск НЕ удался — нужен ручной разбор"
    fi
fi
