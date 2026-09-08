#!/bin/sh
# Кто просил подписку и что получил.
#
# Правила ответов пускают Happ и INCY, остальным отвечают 403. Клиент, чью
# строку мы не угадали, получает отказ молча: у человека не обновляется
# подписка, а панель об этом не говорит — она не показывает, кто приходил.
#
# Скрипт отвечает ровно на этот вопрос, читая журнал Caddy.
# Настройка журнала — deploy/caddy/.
set -eu

SINCE=${SINCE:--24h}

journalctl -u caddy --since "$SINCE" --no-pager 2>/dev/null | python3 -c '
import sys, json

seen = {}
for line in sys.stdin:
    # В строке journald перед JSON стоит его собственная шапка.
    start = line.find("{")
    if start < 0:
        continue
    try:
        record = json.loads(line[start:])
    except ValueError:
        continue

    request = record.get("request", {})
    if "/api/sub" not in request.get("uri", ""):
        continue

    agent = request.get("headers", {}).get("User-Agent", ["(нет строки)"])[0]
    key = (agent, record.get("status"))
    seen[key] = seen.get(key, 0) + 1

if not seen:
    print("обращений к подписке за это время не записано. Возможных причин три:")
    print("  1) журнал доступа не включён — см. deploy/caddy/;")
    print("  2) журнал включён только что, и с тех пор никто не обращался;")
    print("  3) запросы до панели не доходят вовсе.")
    print()
    print("Первые две различаются одной проверкой — сделайте запрос сами:")
    # Кавычек вокруг Happ/1.0 здесь нет намеренно. Весь разбор — это
    # аргумент python3, заключённый в одинарные кавычки для оболочки, и
    # любая одинарная кавычка внутри закрыла бы его. Пробелов в значении
    # нет, так что curl примет его и без кавычек.
    print("  curl -s -o /dev/null -A Happ/1.0 https://<домен панели>/api/sub/proverka")
    print("и запустите скрипт снова. Строка появилась — журнал работает.")
    sys.exit()

# Адрес подписки не печатается даже здесь: в журнале он уже вырезан, но
# скрипт не должен зависеть от того, что настройку не забыли применить.
for (agent, status), count in sorted(seen.items(), key=lambda pair: -pair[1]):
    print(f"{count:5}  {status}  {agent}")
'
