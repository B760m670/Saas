#!/bin/sh
# Сборка профиля RU-узла из подписки служебного пользователя.
#
#   sh make-profile.sh 'ССЫЛКА_ПОДПИСКИ' ИМЯ_ПРИКРЫТИЯ_RU [АДРЕС_NL]
#
# Зачем: профиль — это два десятка значений из трёх мест панели, и набирать
# их на телефоне руками — верный способ ошибиться в одном символе ключа.
# Узел с такой ошибкой выглядит рабочим и не возит ничего.
#
# Откуда что берётся:
#   - выход в NL — из подписки служебного пользователя: там уже лежат
#     адрес, порт, UUID, поток, имя прикрытия, открытый ключ и shortId
#     ровно в том виде, в каком их видит любой клиент;
#   - ключи входа RU — порождаются здесь же, openssl;
#   - остальное — шаблон profile.json рядом.
#
# Итог — /root/ru-profile.json. В нём закрытый ключ и UUID: его вставляют в
# панель и никуда не пересылают.
set -eu

SUB=${1:?нужна ссылка подписки служебного пользователя}
SNI=${2:?нужно имя прикрытия, например www.kinopoisk.ru}
NL=${3:-}
OUT=${OUT:-/root/ru-profile.json}
HERE=$(cd "$(dirname "$0")" && pwd)
TEMPLATE=${TEMPLATE:-$HERE/profile.json}

[ -r "$TEMPLATE" ] || {
    echo "нет шаблона $TEMPLATE — положите profile.json рядом" >&2
    exit 1
}

# Правила ответов панели отдают адреса только Happ и INCY; представляемся
# Happ — тогда приходит Xray JSON со всеми полями выхода.
RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
curl -fsS -m20 -A 'Happ/1.0' "$SUB" -o "$RAW" || {
    echo "подписка не скачалась: проверьте ссылку" >&2
    exit 1
}

# Пара X25519 для входа. Из DER берутся последние 32 байта — это и есть
# сырой ключ; Xray ждёт его в base64url без выравнивания.
PRIV_DER=$(mktemp)
openssl genpkey -algorithm X25519 -outform DER -out "$PRIV_DER"
b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
PRIV=$(tail -c 32 "$PRIV_DER" | b64url)
PUB=$(openssl pkey -inform DER -in "$PRIV_DER" -pubout -outform DER | tail -c 32 | b64url)
rm -f "$PRIV_DER"
SID=$(openssl rand -hex 8)

python3 - "$RAW" "$TEMPLATE" "$OUT" "$SNI" "$NL" "$PRIV" "$SID" <<'PY'
import json, sys

raw, template, out, sni, want_addr, priv, sid = sys.argv[1:8]

try:
    data = json.load(open(raw))
except ValueError:
    sys.exit("подписка пришла не в Xray JSON: проверьте шаблон подписки "
             "и правила ответов (Happ должен получать JSON)")

# Подписка — список конфигов, по одному на хост. Ищем в нём все выходы
# VLESS + REALITY, где бы они ни лежали.
found = []
def walk(node):
    if isinstance(node, dict):
        vnext = node.get("settings", {}).get("vnext") if node.get("protocol") == "vless" else None
        stream = node.get("streamSettings", {})
        if vnext and stream.get("security") == "reality":
            found.append(node)
        for v in node.values():
            walk(v)
    elif isinstance(node, list):
        for v in node:
            walk(v)
walk(data)

def describe(o):
    v = o["settings"]["vnext"][0]
    return f'{v["address"]}:{v["port"]}'

if want_addr:
    found = [o for o in found if o["settings"]["vnext"][0]["address"] == want_addr]
# Основной вход NL — на 443; запасной на 8443 каскаду не нужен.
on443 = [o for o in found if o["settings"]["vnext"][0]["port"] == 443]
found = on443 or found
if not found:
    sys.exit("в подписке нет выхода VLESS + REALITY"
             + (f" на {want_addr}" if want_addr else "")
             + ": служебный пользователь в отряде с NL-входом?")
if len(found) > 1:
    sys.exit("подходящих выходов несколько: "
             + ", ".join(describe(o) for o in found)
             + " — укажите адрес NL третьим доводом")

nl = found[0]
v = nl["settings"]["vnext"][0]
user = v["users"][0]
rs = nl["streamSettings"]["realitySettings"]

profile = json.load(open(template))
entry = profile["inbounds"][0]["streamSettings"]["realitySettings"]
entry["target"] = f"{sni}:443"
entry["serverNames"] = [sni]
entry["privateKey"] = priv
entry["shortIds"] = [sid]

to_nl = next(o for o in profile["outbounds"] if o["tag"] == "TO_NL")
tv = to_nl["settings"]["vnext"][0]
tv["address"] = v["address"]
tv["port"] = v["port"]
tv["users"][0]["id"] = user["id"]
# Поток берётся тот, что у NL-входа: Vision с одной стороны и без него с
# другой не договорятся.
if user.get("flow"):
    tv["users"][0]["flow"] = user["flow"]
else:
    tv["users"][0].pop("flow", None)
trs = to_nl["streamSettings"]["realitySettings"]
trs["serverName"] = rs.get("serverName", "")
trs["publicKey"] = rs.get("publicKey") or rs.get("password", "")
trs["shortId"] = rs.get("shortId", "")
trs["fingerprint"] = rs.get("fingerprint", "chrome")
# Транспорт NL-входа переносится как есть: если там не TCP, а XHTTP,
# каскад обязан говорить так же.
net = nl["streamSettings"].get("network", "tcp")
to_nl["streamSettings"]["network"] = net
for k in ("xhttpSettings", "grpcSettings", "tcpSettings"):
    if k in nl["streamSettings"]:
        to_nl["streamSettings"][k] = nl["streamSettings"][k]

missing = [k for k, val in (("serverName", trs["serverName"]),
                            ("publicKey", trs["publicKey"]),
                            ("shortId", trs["shortId"])) if not val]
if missing:
    sys.exit("в подписке не хватает полей: " + ", ".join(missing))

with open(out, "w") as f:
    json.dump(profile, f, ensure_ascii=False, indent=2)

print(f"выход: {describe(nl)}, транспорт {net}, поток {user.get('flow') or 'нет'}, "
      f"прикрытие NL {trs['serverName']}")
print(f"вход:  443, прикрытие RU {sni}")
PY

chmod 600 "$OUT"
echo
echo "Готово: $OUT"
echo "Открытый ключ входа (для сверки с хостом в панели): $PUB"
echo "Вставить в панель: cat $OUT — и скопировать целиком."
echo "Никуда не пересылать: внутри закрытый ключ и UUID."
