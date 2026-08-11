// Проверки обрамления датаграмм DNS.
//
// Гоняются обычным узлом: `node --test 'clients/worker/tests/*.test.mjs'`.
// Ни Cloudflare, ни сети, ни единого пакета из npm.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
    Datagrams,
    DNS_PORT,
    frameDatagram,
    resolveOverHttps,
} from "../src/udp.js";

test("порт DNS тот, что ожидает клиент", () => {
    assert.equal(DNS_PORT, 53);
});

// Границы сообщений WebSocket не совпадают с границами датаграмм никак.
// Сборщик, работающий только когда они совпали, развалится на первом же
// длинном ответе DNS — а длинные ответы это норма, не редкость.
test("датаграммы собираются при любой нарезке потока", () => {
    const first = Uint8Array.from([1, 2, 3]);
    const second = Uint8Array.from([4, 5, 6, 7, 8]);
    const stream = new Uint8Array([...frameDatagram(first), ...frameDatagram(second)]);

    for (let cut = 0; cut <= stream.length; cut += 1) {
        const framer = new Datagrams();
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
    const framer = new Datagrams();
    framer.push(frameDatagram(Uint8Array.from([1, 2, 3, 4])).slice(0, 4));
    assert.deepEqual(framer.drain(), [], "выдана датаграмма, которая ещё не пришла");
});

test("несколько датаграмм в одном куске разбираются все", () => {
    const framer = new Datagrams();
    framer.push(
        new Uint8Array([
            ...frameDatagram(Uint8Array.from([9])),
            ...frameDatagram(Uint8Array.from([8, 7])),
            ...frameDatagram(Uint8Array.from([6, 5, 4])),
        ]),
    );
    assert.deepEqual(
        framer.drain().map((d) => [...d]),
        [[9], [8, 7], [6, 5, 4]],
    );
});

test("длина пишется двумя байтами, старший впереди", () => {
    const packet = new Uint8Array(300);
    const framed = frameDatagram(packet);
    assert.equal(framed[0], 300 >> 8);
    assert.equal(framed[1], 300 & 0xff);
    assert.equal(framed.length, 302);
});

test("датаграмма длиннее 65535 байт отвергается, а не обрезается", () => {
    assert.throws(() => frameDatagram(new Uint8Array(65_536)), /длиннее/);
});

test("запрос уходит как dns-message, а отказ не выдаётся за ответ", async () => {
    const query = Uint8Array.from([0xab, 0xcd]);
    let seen = null;

    const reply = await resolveOverHttps(query, "https://example.invalid/dns-query", async (url, init) => {
        seen = { url, init };
        return { ok: true, arrayBuffer: async () => Uint8Array.from([1, 2, 3]).buffer };
    });

    assert.equal(seen.url, "https://example.invalid/dns-query");
    assert.equal(seen.init.method, "POST");
    assert.equal(seen.init.headers["content-type"], "application/dns-message");
    assert.deepEqual(seen.init.body, query);
    assert.deepEqual(reply, Uint8Array.from([1, 2, 3]));

    // Отказ DoH обязан быть отказом: иначе клиент получит пустой ответ
    // и будет считать, что имени не существует.
    await assert.rejects(
        () =>
            resolveOverHttps(query, "https://example.invalid/dns-query", async () => ({
                ok: false,
                status: 502,
            })),
        /502/,
    );
});
