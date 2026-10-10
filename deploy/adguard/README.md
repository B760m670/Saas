# DNS-фильтр для опции «Без рекламы»

AdGuard Home на узле VPN. Режет рекламу, трекеры и опасные сайты у тех,
кто подключён к серверам со значком 🛡.

## Как это устроено

```text
телефон ─VLESS─▶ узел, вход VLESS-ADBLOCK
                   │  Xray узнаёт имя сайта из самого соединения (sniffing)
                   │  и спрашивает его адрес у AdGuard Home на 127.0.0.1:5353
                   ▼
           реклама → NXDOMAIN → соединение не открывается
           остальное → адрес → соединение идёт как обычно
```

- Работает в любом клиенте: настройки DNS в телефоне ни при чём.
- Только на своём входе (`VLESS-ADBLOCK`): выход `DIRECT` у остальных
  спрашивает системный резолвер, и фильтра у них нет.
- Вход выдаётся отрядом «adblock» (`GLORIA_ADBLOCK_SQUADS`), пока у
  человека идёт опция (`users.adblock_until`), — бот кладёт и убирает его.
- Чего DNS-фильтр не уберёт: рекламу, которая приходит с тех же адресов,
  что и сам сайт (часть рекламы Яндекса, YouTube, ленты ВК).
- Если шаблон клиента пускает какие-то сайты мимо VPN (русские — напрямую),
  их реклама до фильтра не доходит.

## Установка на узел — только через SSH

```sh
mkdir -p /opt/adguard && cd /opt/adguard
cp /opt/gloria-src/deploy/adguard/compose.yml .   # или содержимое руками
docker compose up -d

# Первичная настройка без браузера: пароль — в файле рядом.
PASS=$(openssl rand -hex 12); echo "$PASS" > admin-password; chmod 600 admin-password
curl -s -X POST http://127.0.0.1:3000/control/install/configure \
  -H 'Content-Type: application/json' \
  -d "{\"web\":{\"ip\":\"0.0.0.0\",\"port\":3000},\"dns\":{\"ip\":\"0.0.0.0\",\"port\":53},\"username\":\"admin\",\"password\":\"$PASS\"}"

A="admin:$PASS"; U=http://127.0.0.1:3000/control
curl -s -u "$A" -X POST $U/dns_config -H 'Content-Type: application/json' \
  -d '{"upstream_dns":["https://dns.cloudflare.com/dns-query","https://dns.google/dns-query"],"upstream_mode":"parallel","ratelimit":0,"blocking_mode":"nxdomain"}'
curl -s -u "$A" -X POST $U/filtering/add_url -H 'Content-Type: application/json' \
  -d '{"name":"HaGeZi Pro","url":"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt","whitelist":false}'
curl -s -u "$A" -X POST $U/filtering/add_url -H 'Content-Type: application/json' \
  -d '{"name":"Phishing","url":"https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt","whitelist":false}'
```

Обязательно:

- **режим блокировки — NXDOMAIN**, не `0.0.0.0`: получив `0.0.0.0`, узел
  открыл бы соединение к самому себе;
- **ограничение запросов — 0**: все запросы приходят с одного адреса.

## Профиль узла

```jsonc
// верхний уровень: DNS, которым пользуется только выход ADBLOCK
"dns": { "servers": [{ "address": "127.0.0.1", "port": 5353 }], "queryStrategy": "UseIPv4" }

// inbounds: REALITY, как остальные, свой порт и shortId
{ "tag": "VLESS-ADBLOCK", "port": <порт>, ... }

// outbounds: прямой выход, который узнаёт адрес через DNS выше
{ "tag": "ADBLOCK", "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4" } }

// routing.rules, после bittorrent
{ "type": "field", "inboundTag": ["VLESS-ADBLOCK"], "outboundTag": "ADBLOCK" }
```

## Проверка

На узле — фильтр сам по себе:

```sh
dig +short -p 5353 @127.0.0.1 doubleclick.net   # пусто
dig +short -p 5353 @127.0.0.1 google.com        # адреса
```

Через VPN: подключиться к серверу 🛡, открыть несколько сайтов и на узле
посмотреть счётчики — оба больше нуля, значит запросы идут через фильтр:

```sh
A="admin:$(cat /opt/adguard/admin-password)"
curl -s -u "$A" http://127.0.0.1:3000/control/stats \
  | grep -o '"num_dns_queries":[0-9]*\|"num_blocked_filtering":[0-9]*'
```
