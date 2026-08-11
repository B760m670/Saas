// Проверки разбора VLESS и обрамления UDP.
//
// Гоняются обычным узлом: `node --test clients/worker/tests/`. Ни
// Cloudflare, ни сети, ни единого пакета из npm — иначе в цепочку
// поставки инструмента обхода цензуры пришлось бы добавить десятки
// чужих зависимостей ради проверки арифметики над байтами.
//
// Почему это вообще стало возможно: разбор вынесен из `worker.js` в
// `vless.js`. Пока он жил рядом с `import ... from "cloudflare:sockets"`,
// файл нельзя было даже загрузить, и единственным способом проверить
// разбор было развернуть край и посмотреть, открылся ли сайт.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
    asksWhere,
    COMMAND_TCP,
    COMMAND_UDP,
    decodeEarlyData,
    frameUdp,
    parseProxies,
    parseSecret,
    parseUuid,
    parseVless,
    resolveDns,
    UdpFramer,
} from "../src/vless.js";

const UUID = Uint8Array.from(
    "550e8400e29b41d4a716446655440000".match(/../g),
    (b) => parseInt(b, 16),
);

/** Собрать запрос VLESS с заданным назначением. */
function request({
    uuid = UUID,
    version = 0,
    addons = new Uint8Array(0),
    command = COMMAND_TCP,
    port = 443,
    kind = 2,
    host = "example.org",
    payload = new Uint8Array(0),
} = {}) {
    const out = [version, ...uuid, addons.length, ...addons, command, port >> 8, port & 0xff, kind];
    if (kind === 1) {
        out.push(...host.split(".").map(Number));
    } else if (kind === 2) {
        const name = new TextEncoder().encode(host);
        out.push(name.length, ...name);
    } else if (kind === 3) {
        for (const group of host) {
            out.push(group >> 8, group & 0xff);
        }
    }
    out.push(...payload);
    return new Uint8Array(out);
}

test("обычный запрос TCP разбирается целиком", () => {
    const payload = new Uint8Array([1, 2, 3, 4]);
    const parsed = parseVless(request({ payload }), UUID);

    assert.equal(parsed.version, 0);
    assert.equal(parsed.host, "example.org");
    assert.equal(parsed.port, 443);
    assert.equal(parsed.isUdp, false);
    assert.deepEqual(parsed.rest, payload, "остаток обязан быть началом данных");
});

test("адреса всех трёх видов разбираются", () => {
    assert.equal(parseVless(request({ kind: 1, host: "93.184.216.34" }), UUID).host, "93.184.216.34");
    assert.equal(parseVless(request({ kind: 2, host: "claude.ai" }), UUID).host, "claude.ai");
    assert.equal(
        parseVless(request({ kind: 3, host: [0x2606, 0x4700, 0, 0, 0, 0, 0, 1] }), UUID).host,
        "[2606:4700:0:0:0:0:0:1]",
    );
});

test("добавка ненулевой длины не сбивает разбор", () => {
    // Поле есть в протоколе и у части клиентов непусто. Разбор,
    // считающий его всегда пустым, уехал бы на несколько байт и
    // соединился бы не туда, куда просили.
    const parsed = parseVless(
        request({ addons: new Uint8Array([9, 9, 9]), host: "example.net" }),
        UUID,
    );
    assert.equal(parsed.host, "example.net");
});

test("чужой идентификатор пользователя отвергается", () => {
    const stranger = new Uint8Array(16).fill(0xaa);
    assert.throws(() => parseVless(request({ uuid: stranger }), UUID), /чужой идентификатор/);
});

// Главное свойство разбора. `Uint8Array.slice` за пределами массива
// молча отдаёт короткий кусок, поэтому без явной проверки обрезанный
// запрос превращался бы не в отказ, а в соединение с адресом, которого
// клиент не называл. Проверяется каждая длина, а не одна выбранная.
test("обрезанный запрос отвергается на любой длине, а не разбирается наполовину", () => {
    const whole = request({ host: "example.org", payload: new Uint8Array([7, 7]) });
    for (let len = 0; len < whole.length - 2; len += 1) {
        assert.throws(
            () => parseVless(whole.slice(0, len), UUID),
            /обрезан|чужой идентификатор/,
            `запрос длиной ${len} байт разобрался, хотя он неполон`,
        );
    }
});

test("UDP принимается только для DNS", () => {
    const dns = parseVless(request({ command: COMMAND_UDP, port: 53 }), UUID);
    assert.equal(dns.isUdp, true);
    assert.equal(dns.port, 53);

    assert.throws(
        () => parseVless(request({ command: COMMAND_UDP, port: 443 }), UUID),
        /только для DNS/,
        "UDP на произвольный порт отправить нечем: connect() даёт только TCP",
    );
});

test("неизвестные команда и тип адреса отвергаются", () => {
    assert.throws(() => parseVless(request({ command: 3 }), UUID), /команда 3/);
    assert.throws(() => parseVless(request({ kind: 9 }), UUID), /тип адреса 9/);
});

test("пустое имя назначения отвергается", () => {
    assert.throws(() => parseVless(request({ kind: 2, host: "" }), UUID), /пустое имя/);
});

// Границы сообщений WebSocket не совпадают с границами датаграмм
// никак. Сборщик, работающий только когда они совпали, — это сборщик,
// который сломается на первом же длинном ответе DNS.
test("датаграммы собираются при любой нарезке потока", () => {
    const first = Uint8Array.from([1, 2, 3]);
    const second = Uint8Array.from([4, 5, 6, 7, 8]);
    const stream = new Uint8Array([...frameUdp(first), ...frameUdp(second)]);

    for (let cut = 0; cut <= stream.length; cut += 1) {
        const framer = new UdpFramer();
        framer.push(stream.slice(0, cut));
        const early = framer.drain();
        framer.push(stream.slice(cut));
        const got = [...early, ...framer.drain()];

        assert.equal(got.length, 2, `нарезка на ${cut}-м байте потеряла датаграмму`);
        assert.deepEqual(got[0], first);
        assert.deepEqual(got[1], second);
    }
});

test("неполная датаграмма не выдаётся за целую", () => {
    const framer = new UdpFramer();
    framer.push(frameUdp(Uint8Array.from([1, 2, 3, 4])).slice(0, 4));
    assert.deepEqual(framer.drain(), [], "выдана датаграмма, которая ещё не пришла");
});

test("датаграмма длиннее 65535 байт отвергается, а не обрезается", () => {
    assert.throws(() => frameUdp(new Uint8Array(65_536)), /длиннее/);
});

test("данные из заголовка рукопожатия разбираются, а мусор не роняет", () => {
    const bytes = decodeEarlyData("AQID");
    assert.deepEqual(bytes, Uint8Array.from([1, 2, 3]));

    // Base64url: те же байты, но алфавит другой.
    assert.deepEqual(decodeEarlyData("-_8"), decodeEarlyData("+/8"));

    // Там может оказаться и обычное имя подпротокола — это не повод
    // отказывать в соединении.
    assert.equal(decodeEarlyData(""), null);
    assert.equal(decodeEarlyData(null), null);
    assert.equal(decodeEarlyData("не base64!!"), null);
});

test("настройки проверяются на входе, а не при первом соединении", () => {
    assert.throws(() => parseSecret(undefined), /не задан/);
    assert.throws(() => parseSecret("короткий"), /32 байта|не разбирается/);
    assert.equal(parseSecret(Buffer.alloc(32).toString("base64url")).length, 32);

    assert.throws(() => parseUuid("не uuid"), /шестнадцатью байтами/);
    assert.throws(() => parseUuid(undefined), /не задан/);
    assert.deepEqual(parseUuid("550e8400-e29b-41d4-a716-446655440000"), UUID);
    assert.deepEqual(parseUuid("550e8400e29b41d4a716446655440000"), UUID, "дефисы необязательны");
});

// Путь «где ты» обязан открываться только по идентификатору. Иначе он
// становится маяком: достаточно обойти поддомены и спросить, чтобы
// перечислить все края разом.
test("о расположении рассказывают только по идентификатору", () => {
    const uuid = "550e8400-e29b-41d4-a716-446655440000";

    assert.equal(asksWhere(`/${uuid}/where`, UUID), true);
    assert.equal(asksWhere(`/${uuid.replaceAll("-", "")}/where`, UUID), true, "дефисы необязательны");
    assert.equal(asksWhere(`/${uuid.toUpperCase()}/where`, UUID), true, "регистр hex не важен");

    // Всё, что не предъявило идентификатор, обязано выглядеть как
    // обычный несуществующий путь.
    for (const bad of [
        "/where",
        "/",
        "/e",
        "/00000000-0000-0000-0000-000000000000/where",
        `/${uuid}`,
        `/${uuid}/`,
        `/${uuid}/whereabouts`,
        `/prefix/${uuid}/where`,
        "",
        null,
    ]) {
        assert.equal(asksWhere(bad, UUID), false, `путь ${JSON.stringify(bad)} не должен отвечать`);
    }
});

test("список посредников разбирается, а пустая настройка даёт пустой список", () => {
    // Порт по умолчанию — порт назначения: посредник выбирает зону по
    // имени в ClientHello, а не по адресу, поэтому 443 у него тот же.
    assert.deepEqual(parseProxies("1.2.3.4", 443), [{ hostname: "1.2.3.4", port: 443 }]);
    assert.deepEqual(parseProxies("1.2.3.4:8443", 443), [{ hostname: "1.2.3.4", port: 8443 }]);

    // Разделители — и запятая, и пробел: человек напишет по-разному.
    assert.deepEqual(parseProxies("a.example, b.example c.example:99", 443), [
        { hostname: "a.example", port: 443 },
        { hostname: "b.example", port: 443 },
        { hostname: "c.example", port: 99 },
    ]);

    // IPv6 без скобок неотличим от «имя:порт» — отсюда скобки.
    assert.deepEqual(parseProxies("[2606:4700::1]:443", 80), [
        { hostname: "2606:4700::1", port: 443 },
    ]);
    assert.deepEqual(parseProxies("[2606:4700::1]", 80), [{ hostname: "2606:4700::1", port: 80 }]);

    // Пусто — значит запасного пути нет, и это законное состояние:
    // умолчания здесь нет намеренно.
    assert.deepEqual(parseProxies("", 443), []);
    assert.deepEqual(parseProxies(undefined, 443), []);
    assert.deepEqual(parseProxies("   ", 443), []);
});

test("запрос DNS уходит как dns-message, а отказ не выдаётся за ответ", async () => {
    const query = Uint8Array.from([0xab, 0xcd]);
    let seen = null;

    const reply = await resolveDns(query, "https://example.invalid/dns-query", async (url, init) => {
        seen = { url, init };
        return {
            ok: true,
            arrayBuffer: async () => Uint8Array.from([1, 2, 3]).buffer,
        };
    });

    assert.equal(seen.url, "https://example.invalid/dns-query");
    assert.equal(seen.init.method, "POST");
    assert.equal(seen.init.headers["content-type"], "application/dns-message");
    assert.deepEqual(seen.init.body, query);
    assert.deepEqual(reply, Uint8Array.from([1, 2, 3]));

    await assert.rejects(
        () => resolveDns(query, "https://example.invalid/dns-query", async () => ({ ok: false, status: 502 })),
        /502/,
        "отказ DoH обязан быть отказом, а не пустым ответом",
    );
});
