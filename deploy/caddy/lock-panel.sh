#!/bin/sh
# Закрыть панель: адрес panel.… отвечает 404 всем, кроме
#   - /api/sub/… — старых ссылок на подписку в приложениях;
#   - браузера, открывшего однажды секретную ссылку ?gate=<секрет>: он
#     получает cookie на 30 дней и дальше видит панель как обычно.
#
# Секрет рождается здесь, на сервере, и печатается один раз. В репозиторий
# и в переписку он не попадает.
#
# Бот ходит в панель по 127.0.0.1:3000 мимо Caddy (bot/README.md), поэтому
# его это не касается. Сценарий это проверяет, прежде чем что-то менять.
#
#   sh lock-panel.sh            закрыть (повторный запуск — новый секрет)
set -eu

CADDYFILE=${CADDYFILE:-/etc/caddy/Caddyfile}
DOMAIN=${DOMAIN:-panel.content-treasure-via.online}
ENVFILE=${ENVFILE:-/etc/gloria.env}

if [ -r "$ENVFILE" ] && grep -q '^GLORIA_PANEL_URL=https://' "$ENVFILE"; then
    echo "Бот ходит в панель через публичный адрес ($ENVFILE)." >&2
    echo "Сначала поставьте GLORIA_PANEL_URL=http://127.0.0.1:3000 и перезапустите бота." >&2
    exit 1
fi

SECRET=$(openssl rand -hex 16)

cp "$CADDYFILE" "$CADDYFILE.bak"

python3 - "$CADDYFILE" "$DOMAIN" "$SECRET" <<'PY'
import re, sys
path, domain, secret = sys.argv[1:]
text = open(path, encoding="utf-8").read()

start = text.find(domain + " {")
if start < 0:
    sys.exit(f"блок {domain} не найден")

# Конец блока — по балансу скобок.
depth, end = 0, None
for i in range(start, len(text)):
    if text[i] == "{":
        depth += 1
    elif text[i] == "}":
        depth -= 1
        if depth == 0:
            end = i
            break
if end is None:
    sys.exit("блок не закрыт")

block = text[start:end + 1]

# Что заменяем: прежний пропуск, если сценарий уже запускался, — иначе
# исходный `handle { reverse_proxy 127.0.0.1:3000 }`.
previous = re.search(r"[ \t]*# gloria-gate-begin.*?# gloria-gate-end\n", block, flags=re.S)
original = re.search(r"[ \t]*handle \{\s*reverse_proxy 127\.0\.0\.1:3000\s*\}\n", block)
target = previous or original
if target is None:
    sys.exit("в блоке нет ожидаемого `handle { reverse_proxy 127.0.0.1:3000 }`")

gate = f"""\t# gloria-gate-begin
\t@sub path /api/sub/*
\thandle @sub {{
\t\treverse_proxy 127.0.0.1:3000
\t}}

\t@login query gate={secret}
\thandle @login {{
\t\theader Set-Cookie "gloria_gate={secret}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"
\t\tredir / 302
\t}}

\t@admin header_regexp Cookie "(^|;\\s*)gloria_gate={secret}(;|$)"
\thandle @admin {{
\t\treverse_proxy 127.0.0.1:3000
\t}}

\thandle {{
\t\trespond 404
\t}}
\t# gloria-gate-end
"""
block = block[:target.start()] + gate + block[target.end():]
open(path, "w", encoding="utf-8").write(text[:start] + block + text[end + 1:])
PY

if caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1 && systemctl reload caddy; then
    echo
    echo "Панель закрыта. Вход — только по этой ссылке (сохраните её, больше она не покажется):"
    echo
    echo "    https://$DOMAIN/?gate=$SECRET"
    echo
else
    cp "$CADDYFILE.bak" "$CADDYFILE"
    systemctl reload caddy || true
    echo "Caddy не принял конфиг — вернул прежний. Ничего не изменилось." >&2
    exit 1
fi
