// ATLAS — точка выхода на Cloudflare Workers, одним файлом.
//
// СОБРАНО АВТОМАТИЧЕСКИ. Не правьте здесь: правки затрёт следующая
// сборка. Исходники — `src/edge.js` и `src/worker.js`, сборщик —
// `bundle.py`, а согласие с частью на Rust проверяет
// `core/atlas-transport/tests/interop.rs`.
//
// # Что с этим делать
//
// 1. В панели Cloudflare: Compute (Workers) → Workers & Pages →
//    Create → Start with Hello World → Deploy.
// 2. Edit code → выделить всё, вставить этот файл → Deploy.
// 3. Settings → Variables and Secrets → добавить два секрета:
//    ATLAS_SECRET (32 байта в base64url) и ATLAS_UUID.
//
// Ноутбук для этого не нужен: всё делается в браузере, в том числе на
// телефоне.

// ── ЧАСТЬ 1: сквозной канал до края ──
//
// Ровно то же, что `core/atlas-transport/src/edge.rs`, только на
// JavaScript. Два описания одного протокола — это всегда риск, что они
// разойдутся, поэтому согласие проверяется настоящим прогоном:
// `core/atlas-transport/tests/interop.rs` гоняет этот файл узлом и
// сверяет байты. Правка здесь без правки там уронит сборку — так и
// задумано.
//
// Почему такой набор примитивов: здесь есть только WebCrypto. Отсюда
// SHA-256 вместо blake3, которым пользуется остальной проект, и
// AES-256-GCM вместо ChaCha20-Poly1305, которого в WebCrypto нет.

const SECRET_LEN = 32;
const SHARE_LEN = 32;
const MAC_LEN = 16;
const TIME_LEN = 8;
const CLIENT_HELLO_LEN = SHARE_LEN + TIME_LEN + MAC_LEN;
const SERVER_HELLO_LEN = SHARE_LEN + MAC_LEN;
const MAX_RECORD = 16 * 1024;
const CLOCK_SKEW_SECS = 300;

const CLIENT_LABEL = new TextEncoder().encode("atlas-edge-client-v1");
const SERVER_LABEL = new TextEncoder().encode("atlas-edge-server-v1");
const KDF_INFO = new TextEncoder().encode("atlas-edge-v1");

/** Склеить несколько кусков в один. */
function join(...parts) {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let at = 0;
    for (const part of parts) {
        out.set(part, at);
        at += part.length;
    }
    return out;
}

/**
 * Сравнение за постоянное время.
 *
 * Обычное `===` по байтам выходило бы раньше на первом различии, и по
 * времени ответа отпечаток можно было бы подобрать побайтно.
 */
function equalConstantTime(left, right) {
    if (left.length !== right.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < left.length; i += 1) {
        diff |= left[i] ^ right[i];
    }
    return diff === 0;
}

/** Отпечаток над частями, привязанный к общему секрету. */
async function mac(secret, label, parts) {
    const key = await crypto.subtle.importKey(
        "raw",
        secret,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    const full = new Uint8Array(
        await crypto.subtle.sign("HMAC", key, join(label, ...parts)),
    );
    return full.slice(0, MAC_LEN);
}

/**
 * Ключи направлений.
 *
 * Секрет идёт солью, а материалом — общий результат ECDH. Так знание
 * одного лишь секрета, без эфемерных долей, не даёт ключей сессии.
 */
async function derive(shared, secret, clientShare, serverShare) {
    const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
        "deriveBits",
    ]);
    const prefix = join(KDF_INFO, clientShare, serverShare);

    const expand = async (tag) => {
        const bits = await crypto.subtle.deriveBits(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: secret,
                info: join(prefix, new Uint8Array([tag])),
            },
            base,
            256,
        );
        return new Uint8Array(bits);
    };

    return { toEdge: await expand(0), toClient: await expand(1) };
}

/** Одноразовое число из счётчика: четыре нуля и восемь байт номера. */
function nonce(counter) {
    const raw = new Uint8Array(12);
    new DataView(raw.buffer).setBigUint64(4, BigInt(counter), false);
    return raw;
}

/** Согласованная сессия: шифрует и расшифровывает записи. */
class Session {
    constructor(sendingKey, receivingKey) {
        this.sendingKey = sendingKey;
        this.receivingKey = receivingKey;
        this.sent = 0;
        this.received = 0;
    }

    static async create(sending, receiving) {
        const load = (raw, use) =>
            crypto.subtle.importKey("raw", raw, "AES-GCM", false, [use]);
        return new Session(
            await load(sending, "encrypt"),
            await load(receiving, "decrypt"),
        );
    }

    /** Зашифровать запись целиком, вместе с длиной. */
    async seal(plain) {
        if (plain.length > MAX_RECORD) {
            throw new Error("запись длиннее допустимого");
        }
        const header = new Uint8Array(2);
        new DataView(header.buffer).setUint16(0, plain.length, false);

        // Длина идёт в связанные данные: иначе посредник переписал бы
        // её, не тронув шифртекст.
        const sealed = new Uint8Array(
            await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: nonce(this.sent),
                    additionalData: header,
                    tagLength: 128,
                },
                this.sendingKey,
                plain,
            ),
        );
        this.sent += 1;
        return join(header, sealed);
    }

    /** Расшифровать запись с уже прочитанным заголовком. */
    async open(header, sealed) {
        const plain = new Uint8Array(
            await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: nonce(this.received),
                    additionalData: header,
                    tagLength: 128,
                },
                this.receivingKey,
                sealed,
            ),
        );
        this.received += 1;
        return plain;
    }
}

/**
 * Ответить на приветствие клиента.
 *
 * `now` — секунды эпохи Unix. Передаётся снаружи, чтобы проверки не
 * зависели от настоящих часов.
 */
async function respond(secret, hello, now) {
    if (hello.length < CLIENT_HELLO_LEN) {
        throw new Error("сообщение обрезано");
    }
    const clientShare = hello.slice(0, SHARE_LEN);
    const timeBytes = hello.slice(SHARE_LEN, SHARE_LEN + TIME_LEN);
    const tag = hello.slice(SHARE_LEN + TIME_LEN, CLIENT_HELLO_LEN);

    // Отпечаток проверяется до метки времени: иначе разница в ответах
    // на «неверный секрет» и «верный секрет, старое время» давала бы
    // постороннему способ проверять секреты.
    const expected = await mac(secret, CLIENT_LABEL, [clientShare, timeBytes]);
    if (!equalConstantTime(expected, tag)) {
        throw new Error("отпечаток не сошёлся");
    }

    const claimed = new DataView(
        timeBytes.buffer,
        timeBytes.byteOffset,
        TIME_LEN,
    ).getBigUint64(0, false);
    const skew =
        claimed > BigInt(now) ? claimed - BigInt(now) : BigInt(now) - claimed;
    if (skew > BigInt(CLOCK_SKEW_SECS)) {
        throw new Error("метка времени вне окна");
    }

    const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, [
        "deriveBits",
    ]);
    const serverShare = new Uint8Array(
        await crypto.subtle.exportKey("raw", pair.publicKey),
    );
    const peer = await crypto.subtle.importKey(
        "raw",
        clientShare,
        { name: "X25519" },
        false,
        [],
    );
    const shared = new Uint8Array(
        await crypto.subtle.deriveBits(
            { name: "X25519", public: peer },
            pair.privateKey,
            256,
        ),
    );

    const replyTag = await mac(secret, SERVER_LABEL, [clientShare, serverShare]);
    const { toEdge, toClient } = await derive(
        shared,
        secret,
        clientShare,
        serverShare,
    );

    return {
        response: join(serverShare, replyTag),
        // У края направления зеркальны: он читает то, что клиент пишет.
        session: await Session.create(toClient, toEdge),
    };
}


// ── ЧАСТЬ 2: сама точка выхода ──
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
    // 1 — TCP. UDP через этот край не идёт: `connect()` даёт только TCP.
    if (command !== 1) {
        throw new Error(`команда ${command} не поддерживается`);
    }

    const port = view.getUint16(at, false);
    at += 2;

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

    return { version, host, port, rest: data.slice(at) };
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

/** Прочитать одну запись сквозного канала. */
async function readRecord(reader, session) {
    const header = await reader.exact(2);
    const len = (header[0] << 8) | header[1];
    if (len > MAX_RECORD) {
        throw new Error("запись длиннее допустимого");
    }
    // Тег имитовставки идёт следом за нагрузкой.
    const sealed = await reader.exact(len + 16);
    return session.open(header, sealed);
}

/** Обслужить одно соединение целиком. */
async function serve(socket, secret, uuid) {
    socket.accept();
    const reader = new Reader(socket);

    const hello = await reader.exact(CLIENT_HELLO_LEN);
    const now = Math.floor(Date.now() / 1000);
    const { response, session } = await respond(secret, hello, now);
    socket.send(response);

    // Первая запись несёт заголовок VLESS и, как правило, начало данных.
    const first = await readRecord(reader, session);
    const { version, host, port, rest } = parseVless(first, uuid);

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
    await socket.send(await session.seal(new Uint8Array([version, 0])));

    // Назначение → клиент.
    const downstream = (async () => {
        const source = upstream.readable.getReader();
        for (;;) {
            const { value, done } = await source.read();
            if (done) {
                break;
            }
            for (let at = 0; at < value.length; at += MAX_RECORD) {
                socket.send(await session.seal(value.subarray(at, at + MAX_RECORD)));
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

        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);

        serve(server, secret, uuid).catch((error) => {
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
