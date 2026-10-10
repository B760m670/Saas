# DNS-фильтр для опции «Без рекламы»

AdGuard Home на главном сервере. Режет рекламу, трекеры и опасные сайты у
тех, кто подключён к серверам со значком 🛡.

## Как это устроено

Фильтр стоит не у человека в телефоне, а на нашем узле:

```text
телефон ─VLESS─▶ узел NL, вход VLESS-ADBLOCK
                   │  Xray узнаёт имя сайта из TLS (sniffing)
                   │  и спрашивает его адрес у AdGuard Home
                   ▼
           AdGuard Home на главном сервере
             реклама → NXDOMAIN → соединение не открывается
             остальное → адрес → соединение идёт как обычно
```

Поэтому:

- работает в любом клиенте и на любом устройстве: настройки DNS в телефоне
  ни при чём, имя берётся из самого соединения;
- работает только на своём входе (`VLESS-ADBLOCK`): у остальных Xray
  ходит в обычный DNS, и фильтра у них нет;
- вход выдаётся отрядом «adblock» (`GLORIA_ADBLOCK_SQUADS`) тем, у кого
  идёт опция (`users.adblock_until`), — бот кладёт и убирает его сам.

## Обязательные настройки AdGuard Home

- **Режим блокировки — NXDOMAIN.** Не `0.0.0.0`: узел, получив `0.0.0.0`,
  открыл бы соединение к самому себе — к своим же внутренним портам.
- **Ограничение запросов — 0.** Все запросы приходят с одного адреса —
  узла; ограничение «на клиента» душило бы всех сразу.
- **Доступ — только адрес узла** (Настройки DNS → Разрешённые клиенты), и
  то же в firewall.

## Установка

На главном сервере, `NODE_IP` — адрес узла NL:

```sh
mkdir -p /opt/adguard && cd /opt/adguard
cp /opt/gloria-src/deploy/adguard/compose.yml .
echo "PUBLIC_IP=$(curl -4s https://ifconfig.me)" > .env
docker compose up -d
ufw allow from NODE_IP to any port 53 proto udp
ufw allow from NODE_IP to any port 53 proto tcp
```

Первичная настройка — через туннель с компьютера:
`ssh -L 3000:127.0.0.1:3000 root@<главный сервер>`, затем
`http://localhost:3000` в браузере. Списки (Фильтры → Чёрные списки DNS →
Добавить → Выбрать из списка): AdGuard DNS filter, HaGeZi's Pro
Blocklist, Dandelion Sprout's Anti-Malware List, Phishing URL Blocklist.

## Узел: что добавить в профиль

В профиль узла NL — вход, исходящий, DNS и правило:

```jsonc
// inbounds: как VLESS-REALITY-2, но свой порт и shortId
{ "tag": "VLESS-ADBLOCK", "port": <порт>, ... }

// outbounds: прямой выход, который сам узнаёт адрес — через DNS ниже
{ "tag": "ADBLOCK", "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4" } }

// верхний уровень: DNS, которым пользуется только ADBLOCK
"dns": { "servers": ["<адрес главного сервера>"], "queryStrategy": "UseIPv4" }

// routing.rules: после правила для bittorrent
{ "type": "field", "inboundTag": ["VLESS-ADBLOCK"], "outboundTag": "ADBLOCK" }
```

`DIRECT` остаётся с `AsIs` — он спрашивает системный резолвер и `dns` выше
не трогает. Поэтому у остальных входов всё как было.

## Проверка

```sh
dig +short @<адрес главного сервера> doubleclick.net   # пусто (NXDOMAIN)
dig +short @<адрес главного сервера> google.com        # адреса
```

С телефона: подключиться к серверу 🛡 и открыть
`https://d3ward.github.io/toolz/adblock` — процент заблокированного.
