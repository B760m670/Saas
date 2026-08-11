// Точка выхода ATLAS на Cloudflare Workers.
//
// # Зачем
//
// Всё остальное в проекте упирается в машину с публичным адресом, а
// машина — в карту зарубежного банка. Здесь этого нет: бесплатный тариф
// Workers заводится по почте, живёт бессрочно и стоит ноль.
//
// # Как это выглядит для наблюдателя
//
// Обычное соединение с Cloudflare: настоящий сертификат, настоящее имя,
// переход на WebSocket. Заблокировать адреса Cloudflare целиком нельзя —
// за ними стоит заметная часть интернета.
//
// # Чего этот код не делает и обещать не может
//
// Он **не прячет назначение от Cloudflare**. Край обязан знать, куда
// соединяться, иначе он не соединится. Сквозной канал (`edge.js`)
// закрывает посредника между телефоном и Cloudflare — то есть ТСПУ, —
// но не саму площадку.
//
// # Развёртывание
//
// ```
// npx wrangler deploy
// npx wrangler secret put ATLAS_SECRET   # 32 байта, base64url без выравнивания
// ```
//
// Секрет — тот же, что в ключе доступа у клиента. Кто им владеет, тот
// пользуется вашим краем.

// Исходящий TCP из Worker. Именно эта возможность и делает всю затею
// осуществимой: без неё край мог бы только ходить по HTTP.
import { connect } from "cloudflare:sockets";

import { respond, MAX_RECORD, CLIENT_HELLO_LEN } from "./edge.js";
import {
    Datagrams,
    DEFAULT_DOH,
    DNS_PORT,
    frameDatagram,
    resolveOverHttps,
} from "./udp.js";

/// Сколько ждать соединения с адресом назначения.
const CONNECT_TIMEOUT_MS = 15_000;

/**
 * Разобрать секрет из base64url без выравнивания.
 *
 * Отсутствие или неверная длина — отказ на старте, а не при первом
 * соединении: край без секрета не край, и выяснять это в момент, когда
 * человек уже нажал «Включить», незачем.
 */
function parseSecret(text) {
    if (typeof text !== "string" || text.length === 0) {
        throw new Error("ATLAS_SECRET не задан");
    }
    const padded = text.replaceAll("-", "+").replaceAll("_", "/");
    const raw = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    if (raw.length !== 32) {
        throw new Error(`ATLAS_SECRET обязан быть 32 байта, а он ${raw.length}`);
    }
    return raw;
}

/**
 * Разобрать запрос VLESS.
 *
 * Формат: версия, идентификатор пользователя, длина добавки, команда,
 * порт, тип адреса, адрес. Возвращает адрес назначения и остаток —
 * первые байты полезных данных, приклеенные к заголовку.
 */
function parseVless(data, uuid) {
    if (data.length < 24) {
        throw new Error("запрос VLESS обрезан");
    }
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

    const version = data[0];
    for (let i = 0; i < 16; i += 1) {
        if (data[1 + i] !== uuid[i]) {
            throw new Error("чужой идентификатор пользователя");
        }
    }

    const addonLen = data[17];
    let at = 18 + addonLen;

    const command = data[at];
    at += 1;
    // 1 — TCP, 2 — UDP. Датаграммы наружу край послать не может —
    // `connect()` даёт только TCP, — но для DNS этого и не нужно:
    // запрос уходит по HTTPS. Поэтому UDP принимается, а порт
    // проверяется ниже, когда он уже прочитан.
    if (command !== 1 && command !== 2) {
        throw new Error(`команда ${command} не поддерживается`);
    }

    const port = view.getUint16(at, false);
    at += 2;

    if (command === 2 && port !== DNS_PORT) {
        throw new Error(`UDP через край доступен только для DNS, а порт ${port}`);
    }

    const kind = data[at];
    at += 1;
    let host;
    if (kind === 1) {
        host = Array.from(data.slice(at, at + 4)).join(".");
        at += 4;
    } else if (kind === 2) {
        const len = data[at];
        at += 1;
        host = new TextDecoder().decode(data.slice(at, at + len));
        at += len;
    } else if (kind === 3) {
        const parts = [];
        for (let i = 0; i < 8; i += 1) {
            parts.push(view.getUint16(at + i * 2, false).toString(16));
        }
        host = `[${parts.join(":")}]`;
        at += 16;
    } else {
        throw new Error(`тип адреса ${kind} неизвестен`);
    }

    return { version, host, port, isUdp: command === 2, rest: data.slice(at) };
}

/**
 * Отвечать на запросы DNS, пришедшие в туннель.
 *
 * Живёт отдельно от перекачки TCP, потому что это другой протокол: там
 * поток, здесь датаграммы с длиной впереди. Смешивать их в одном цикле
 * значило бы получить разбор, который верен ровно наполовину.
 *
 * Цикл завершается сам, когда клиент закрывает соединение: `readRecord`
 * бросает, и это штатный конец, а не отказ.
 */
async function relayDns(socket, reader, session, request, greeting, dohUrl) {
    const datagrams = new Datagrams();
    let header = greeting;

    const answer = async (packet) => {
        const reply = await resolveOverHttps(packet, dohUrl);
        const framed = frameDatagram(reply);
        // Заголовок ответа VLESS уходит вместе с первой датаграммой.
        const payload = header ? merge2(header, framed) : framed;
        header = null;
        socket.send(session ? await session.seal(payload) : payload);
    };

    datagrams.push(request.rest);
    for (const packet of datagrams.drain()) {
        await answer(packet);
    }

    for (;;) {
        datagrams.push(await readRecord(reader, session));
        for (const packet of datagrams.drain()) {
            await answer(packet);
        }
    }
}

/** Склеить два куска. */
function merge2(left, right) {
    const out = new Uint8Array(left.length + right.length);
    out.set(left, 0);
    out.set(right, left.length);
    return out;
}

/**
 * Читатель поверх WebSocket: события превращаются в ожидаемые куски.
 *
 * Границы сообщений WebSocket не совпадают с границами записей
 * сквозного канала, поэтому нужен буфер и ожидание нужной длины, а не
 * «одно сообщение — одна запись».
 */
class Reader {
    constructor(socket) {
        this.chunks = [];
        this.length = 0;
        this.waiting = null;
        this.closed = false;

        socket.addEventListener("message", (event) => {
            const data =
                event.data instanceof ArrayBuffer
                    ? new Uint8Array(event.data)
                    : new TextEncoder().encode(event.data);
            this.chunks.push(data);
            this.length += data.length;
            this.#wake();
        });
        const finish = () => {
            this.closed = true;
            this.#wake();
        };
        socket.addEventListener("close", finish);
        socket.addEventListener("error", finish);
    }

    #wake() {
        if (this.waiting) {
            const resolve = this.waiting;
            this.waiting = null;
            resolve();
        }
    }

    /** Забрать то, что пришло, дождавшись хотя бы чего-нибудь. */
    async some() {
        while (this.length === 0) {
            if (this.closed) {
                throw new Error("соединение закрыто");
            }
            await new Promise((resolve) => {
                this.waiting = resolve;
            });
        }
        return this.exact(this.length);
    }

    /** Забрать ровно `want` байт, дождавшись их появления. */
    async exact(want) {
        while (this.length < want) {
            if (this.closed) {
                throw new Error("соединение закрыто до конца записи");
            }
            await new Promise((resolve) => {
                this.waiting = resolve;
            });
        }
        const out = new Uint8Array(want);
        let filled = 0;
        while (filled < want) {
            const head = this.chunks[0];
            const take = Math.min(head.length, want - filled);
            out.set(head.subarray(0, take), filled);
            filled += take;
            if (take === head.length) {
                this.chunks.shift();
            } else {
                this.chunks[0] = head.subarray(take);
            }
        }
        this.length -= want;
        return out;
    }
}

/**
 * Прочитать порцию данных.
 *
 * В обычном режиме записей нет вовсе: что пришло сообщением WebSocket,
 * то и есть данные.
 */
async function readRecord(reader, session) {
    if (!session) {
        return reader.some();
    }
    const header = await reader.exact(2);
    const len = (header[0] << 8) | header[1];
    if (len > MAX_RECORD) {
        throw new Error("запись длиннее допустимого");
    }
    // Тег имитовставки идёт следом за нагрузкой.
    const sealed = await reader.exact(len + 16);
    return session.open(header, sealed);
}

/**
 * Обслужить одно соединение целиком.
 *
 * # Два режима, и это не украшение
 *
 * `sealed` — наш сквозной канал: он закрывает посредника между
 * телефоном и Cloudflare, но требует нашего же клиента. Чужие клиенты
 * такого рукопожатия не умеют и не научатся.
 *
 * Обычный режим — голый VLESS поверх WebSocket, как его понимают Happ,
 * Hiddify, v2rayNG и все прочие. Скрытность в нём держится только на
 * TLS самого Cloudflare, зато работает он с тем, что человек уже
 * поставил из App Store.
 *
 * Выбор делается по пути, а не угадыванием: угадывать по первым байтам
 * значит однажды принять чужое приветствие за своё.
 */
async function serve(socket, secret, uuid, sealed, doh) {
    socket.accept();
    const reader = new Reader(socket);

    let session = null;
    if (sealed) {
        const hello = await reader.exact(CLIENT_HELLO_LEN);
        const now = Math.floor(Date.now() / 1000);
        const agreed = await respond(secret, hello, now);
        session = agreed.session;
        socket.send(agreed.response);
    }

    // Первая запись несёт заголовок VLESS и, как правило, начало данных.
    const first = await readRecord(reader, session);
    const request = parseVless(first, uuid);
    const { version, host, port, rest } = request;

    // Запрос имени идёт другим путём: датаграммы наружу отправить нечем,
    // но по HTTPS их разрешить можно.
    if (request.isUdp) {
        try {
            await relayDns(socket, reader, session, request, new Uint8Array([version, 0]), doh);
        } finally {
            socket.close(1000);
        }
        return;
    }

    const upstream = await Promise.race([
        connect({ hostname: host, port }),
        new Promise((_, reject) =>
            setTimeout(
                () => reject(new Error("адрес назначения не отвечает")),
                CONNECT_TIMEOUT_MS,
            ),
        ),
    ]);

    // Ответ VLESS: версия и нулевая длина добавки. Уходит вместе с
    // первым куском данных, чтобы не тратить лишний обмен.
    const writer = upstream.writable.getWriter();
    if (rest.length > 0) {
        await writer.write(rest);
    }
    const greeting = new Uint8Array([version, 0]);
    socket.send(session ? await session.seal(greeting) : greeting);

    // Назначение → клиент.
    const downstream = (async () => {
        const source = upstream.readable.getReader();
        for (;;) {
            const { value, done } = await source.read();
            if (done) {
                break;
            }
            for (let at = 0; at < value.length; at += MAX_RECORD) {
                const piece = value.subarray(at, at + MAX_RECORD);
            socket.send(session ? await session.seal(piece) : piece);
            }
        }
    })();

    // Клиент → назначение.
    const upstreamPump = (async () => {
        for (;;) {
            const chunk = await readRecord(reader, session);
            await writer.write(chunk);
        }
    })();

    try {
        await Promise.race([downstream, upstreamPump]);
    } finally {
        try {
            await writer.close();
        } catch {
            // Закрывать уже закрытое — не ошибка, о которой стоит знать.
        }
        socket.close(1000);
    }
}

export default {
    async fetch(request, env) {
        // Посторонний, попавший сюда браузером, обязан увидеть обычный
        // ответ, а не признак прокси. Худшее, что можно сделать, — вернуть
        // что-то своё и опознаваемое.
        if (request.headers.get("Upgrade") !== "websocket") {
            return new Response("Not Found", { status: 404 });
        }

        let secret;
        let uuid;
        try {
            secret = parseSecret(env.ATLAS_SECRET);
            uuid = Uint8Array.from(
                env.ATLAS_UUID.replaceAll("-", "").match(/../g),
                (b) => parseInt(b, 16),
            );
            if (uuid.length !== 16) {
                throw new Error("ATLAS_UUID обязан быть 16 байт");
            }
        } catch (error) {
            // Настройка не сошлась — это наша беда, а не гостя. Наружу
            // всё равно уходит обычная ошибка сервера без подробностей.
            console.error(error.message);
            return new Response("Internal Server Error", { status: 500 });
        }

        // Путь решает, каким протоколом говорить. `/e` — наш сквозной
        // канал, всё остальное — обычный VLESS для чужих клиентов.
        const sealed = new URL(request.url).pathname.endsWith("/e");

        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);

        serve(server, secret, uuid, sealed, env.ATLAS_DOH || DEFAULT_DOH).catch((error) => {
            console.error(error.message);
            try {
                server.close(1011);
            } catch {
                // Уже закрыт.
            }
        });

        return new Response(null, { status: 101, webSocket: client });
    },
};
