#!/bin/sh
# Проверка RU-узла до того, как на него придут люди. См. docs/18-ru-node.md.
#
#   sh check.sh                         адрес, список, порт, отрезанное
#   sh check.sh NL_АДРЕС ИМЯ_ПРИКРЫТИЯ  то же плюс путь до NL-узла
#
# Ничего не ставит и не меняет: только спрашивает и печатает. Вывод можно
# переслать целиком — секретов в нём нет, а адрес машины вы и так знаете.
set -u

NL_ADDR=${1:-}
NL_SNI=${2:-}

# Общественный перечень адресов, живых при ограничениях. Собирается
# сканированием, а не выдаётся государством, — поэтому «есть» здесь довод,
# а не доказательство.
LIST_URL=https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt

echo "== адрес машины"
IP=$(curl -4 -sm10 https://api.ipify.org || true)
if [ -z "$IP" ]; then
    echo "не удалось узнать: нет выхода наружу?"
else
    echo "$IP"
fi

echo
echo "== общественный белый список"
if [ -n "$IP" ]; then
    LIST=$(mktemp)
    if curl -sSLm30 -o "$LIST" "$LIST_URL"; then
        # Сверка подсетями, а не строкой: адрес обычно лежит внутри
        # перечисленной сети, а не записан сам.
        python3 - "$IP" "$LIST" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
hits = []
total = 0
for line in open(sys.argv[2]):
    line = line.strip()
    try:
        net = ipaddress.ip_network(line, strict=False)
    except ValueError:
        continue
    total += 1
    if net.version == ip.version and ip in net:
        hits.append(str(net))
print(f"сетей в перечне: {total}")
if hits:
    print("ЕСТЬ, в " + ", ".join(hits))
    print("это довод, не доказательство: проверьте с телефона при ограничениях")
else:
    print("НЕТ: при белом списке этот адрес, скорее всего, недоступен")
    print("против отрезания зарубежных хостингов узел полезен всё равно")
PY
    else
        echo "перечень не скачался — проверить не удалось"
    fi
    rm -f "$LIST"
fi

echo
echo "== порт 443"
# Узлу нужен именно 443: нестандартный порт заметен до содержимого и при
# мягких ограничениях не проходит (deploy/remnawave/node/README.md).
if ss -tlnH 'sport = :443' 2>/dev/null | grep -q .; then
    echo "ЗАНЯТ:"
    ss -tlnp 'sport = :443'
else
    echo "свободен"
fi

echo
echo "== что отрезано на канале хостера"
# Код 000 — соединение не состоялось. Это и есть то, что узел должен
# возить через Нидерланды, а не отдавать напрямую.
for url in https://www.google.com https://www.youtube.com \
           https://api.telegram.org https://www.instagram.com \
           https://ya.ru https://www.gosuslugi.ru; do
    printf '%-28s ' "$url"
    # При отказе curl сам печатает 000 через -w; ненулевой код здесь —
    # результат проверки, а не повод остановиться.
    curl -so /dev/null -m8 -w '%{http_code}  %{time_total} с\n' "$url" || true
done

if [ -n "$NL_ADDR" ]; then
    echo
    echo "== путь до NL-узла"
    # Ответ сертификатом сайта прикрытия означает: Xray на NL жив, и
    # канал между машинами его пропускает.
    if [ -z "$NL_SNI" ]; then
        echo "имя прикрытия не задано — проверяю только TCP"
        # /dev/tcp — свойство bash, а не sh: в dash его нет.
        if timeout 5 bash -c "</dev/tcp/$NL_ADDR/443" 2>/dev/null; then
            echo "443 открыт"
        else
            echo "443 НЕ ОТВЕЧАЕТ"
        fi
    else
        subject=$(openssl s_client -connect "$NL_ADDR:443" -servername "$NL_SNI" \
                      -tls1_3 </dev/null 2>/dev/null | grep -m1 '^subject=')
        if [ -n "$subject" ]; then
            echo "рукопожатие прошло: $subject"
        else
            echo "рукопожатия НЕТ: узел не отвечает или канал режется"
        fi
    fi
fi
