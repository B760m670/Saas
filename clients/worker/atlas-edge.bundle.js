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


// ── ЧАСТЬ 2: разбор VLESS и обрамление UDP ──
//
// # Почему это отдельный файл
//
// `worker.js` начинается с `import { connect } from "cloudflare:sockets"`.
// Этого модуля нет нигде, кроме самой Cloudflare, поэтому файл целиком
// невозможно даже загрузить обычным узлом. Пока разбор запроса жил там,
// проверить его можно было ровно одним способом: развернуть край и
// посмотреть, открылся ли сайт. Ошибка в разборе при этом выглядела бы
// как «клиент не подключается» — то есть как что угодно.
//
// Здесь нет ничего, кроме арифметики над байтами и одного `fetch`,
// поэтому набор проверок гоняется `node --test`, без Cloudflare и без
// сети.
//
// # Про имена
//
// Все имена верхнего уровня во всех трёх файлах края обязаны быть
// разными: `bundle.py` склеивает их в один файл для вставки в панель, и
// два одинаковых объявления дали бы синтаксическую ошибку прямо при
// развёртывании. Отсюда `concat` вместо `join` и `sameBytes` вместо
// `equalConstantTime` — в `edge.js` эти имена уже заняты.

/** Команда «соединиться по TCP». */
const COMMAND_TCP = 1;

/** Команда «переслать датаграммы UDP». */
const COMMAND_UDP = 2;

/** Порт DNS — единственный, для которого мы принимаем UDP. */
const DNS_PORT = 53;

/**
 * Куда уходят запросы DNS, пришедшие в туннель.
 *
 * Это `fetch`, а не `connect`, поэтому запрет на исходящие соединения к
 * адресам самой Cloudflare здесь ни при чём.
 */
const DEFAULT_DOH = "https://cloudflare-dns.com/dns-query";

/** Наибольшая длина датаграммы, помещающаяся в двухбайтовый префикс. */
const MAX_DATAGRAM = 0xffff;

/** Склеить куски в один массив. */
function concat(...parts) {
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
 * Идентификатор пользователя — это и есть пропуск на край. Обычное
 * сравнение выходило бы на первом различии, и по времени ответа его
 * можно было бы подобрать побайтно: 16 попыток на байт вместо перебора
 * всех значений.
 */
function sameBytes(left, right) {
    if (left.length !== right.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < left.length; i += 1) {
        diff |= left[i] ^ right[i];
    }
    return diff === 0;
}

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
    let raw;
    try {
        raw = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    } catch {
        throw new Error("ATLAS_SECRET не разбирается как base64url");
    }
    if (raw.length !== 32) {
        throw new Error(`ATLAS_SECRET обязан быть 32 байта, а он ${raw.length}`);
    }
    return raw;
}

/** Разобрать идентификатор пользователя в шестнадцать байт. */
function parseUuid(text) {
    if (typeof text !== "string") {
        throw new Error("ATLAS_UUID не задан");
    }
    const digits = text.replaceAll("-", "");
    if (!/^[0-9a-fA-F]{32}$/.test(digits)) {
        throw new Error("ATLAS_UUID обязан быть шестнадцатью байтами в hex");
    }
    return Uint8Array.from(digits.match(/../g), (b) => parseInt(b, 16));
}

/**
 * Разобрать запрос VLESS.
 *
 * Раскладка: версия (1), идентификатор пользователя (16), длина добавки
 * (1), добавка, команда (1), порт (2), тип адреса (1), адрес.
 *
 * # Почему каждое поле проверяется на обрезание
 *
 * Первое сообщение WebSocket приходит от постороннего и может быть
 * любым. `Uint8Array.slice` за пределами массива молча отдаёт короткий
 * кусок, поэтому без явной проверки обрезанный запрос превращался бы не
 * в отказ, а в соединение с адресом, которого клиент не называл.
 */
function parseVless(data, uuid) {
    const end = (at, len, what) => {
        const to = at + len;
        if (to > data.length) {
            throw new Error(`запрос VLESS обрезан на поле «${what}»`);
        }
        return to;
    };

    let at = end(0, 1, "версия");
    const version = data[0];

    const uuidEnd = end(at, 16, "идентификатор пользователя");
    if (!sameBytes(data.slice(at, uuidEnd), uuid)) {
        throw new Error("чужой идентификатор пользователя");
    }
    at = uuidEnd;

    at = end(at, 1, "длина добавки");
    const addonLen = data[at - 1];
    at = end(at, addonLen, "добавка");

    at = end(at, 1, "команда");
    const command = data[at - 1];

    at = end(at, 2, "порт");
    const port = (data[at - 2] << 8) | data[at - 1];

    at = end(at, 1, "тип адреса");
    const kind = data[at - 1];

    let host;
    if (kind === 1) {
        const to = end(at, 4, "адрес IPv4");
        host = Array.from(data.slice(at, to)).join(".");
        at = to;
    } else if (kind === 2) {
        at = end(at, 1, "длина имени");
        const len = data[at - 1];
        if (len === 0) {
            throw new Error("пустое имя назначения");
        }
        const to = end(at, len, "имя назначения");
        host = new TextDecoder().decode(data.slice(at, to));
        at = to;
    } else if (kind === 3) {
        const to = end(at, 16, "адрес IPv6");
        const parts = [];
        for (let i = 0; i < 8; i += 1) {
            parts.push(((data[at + i * 2] << 8) | data[at + i * 2 + 1]).toString(16));
        }
        host = `[${parts.join(":")}]`;
        at = to;
    } else {
        throw new Error(`тип адреса ${kind} неизвестен`);
    }

    if (command !== COMMAND_TCP && command !== COMMAND_UDP) {
        throw new Error(`команда ${command} не поддерживается`);
    }
    // UDP через край идёт только для DNS: `connect()` даёт лишь TCP, а
    // датаграммы наружу отправить нечем. Для имён этого достаточно, и
    // без этого клиент в режиме системного VPN не резолвит ничего.
    if (command === COMMAND_UDP && port !== DNS_PORT) {
        throw new Error(`UDP через край доступен только для DNS, а порт ${port}`);
    }

    return {
        version,
        command,
        isUdp: command === COMMAND_UDP,
        host,
        port,
        rest: data.slice(at),
    };
}

/**
 * Разобрать данные, приехавшие в заголовке `Sec-WebSocket-Protocol`.
 *
 * # Что это вообще такое
 *
 * Клиент с `?ed=…` в пути кладёт **первые байты потока** прямо в
 * заголовок рукопожатия WebSocket, не дожидаясь его завершения. Так
 * экономится целый оборот до края. Клиенты, которые так умеют, делают
 * это молча — сервер, который заголовок не читает, ждёт первого
 * сообщения, а оно уже пришло и больше не придёт.
 *
 * Возвращает `null`, если заголовка нет или он не разбирается: там
 * может оказаться и обычное имя подпротокола, и это не повод отказывать.
 */
function decodeEarlyData(header) {
    if (typeof header !== "string" || header.length === 0) {
        return null;
    }
    const padded = header.trim().replaceAll("-", "+").replaceAll("_", "/");
    try {
        const raw = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
        return raw.length > 0 ? raw : null;
    } catch {
        return null;
    }
}

/**
 * Сборщик датаграмм из потока.
 *
 * UDP внутри VLESS едет по потоку, и каждая датаграмма несёт свою длину
 * двумя байтами впереди. Границы сообщений WebSocket с этими границами
 * не совпадают никак, поэтому нужен именно сборщик, а не разбор
 * «одно сообщение — одна датаграмма».
 */
class UdpFramer {
    constructor() {
        this.pending = new Uint8Array(0);
    }

    /** Добавить пришедший кусок. */
    push(chunk) {
        this.pending = concat(this.pending, chunk);
    }

    /** Забрать все датаграммы, пришедшие целиком. */
    drain() {
        const out = [];
        for (;;) {
            if (this.pending.length < 2) {
                break;
            }
            const len = (this.pending[0] << 8) | this.pending[1];
            if (this.pending.length < 2 + len) {
                break;
            }
            out.push(this.pending.slice(2, 2 + len));
            this.pending = this.pending.slice(2 + len);
        }
        return out;
    }
}

/** Обрамить датаграмму длиной для отправки в поток. */
function frameUdp(packet) {
    if (packet.length > MAX_DATAGRAM) {
        throw new Error("датаграмма длиннее 65535 байт");
    }
    const header = new Uint8Array([packet.length >> 8, packet.length & 0xff]);
    return concat(header, packet);
}

/**
 * Разрешить имя, отправив запрос DNS по HTTPS.
 *
 * `fetchImpl` подставляется в проверках: настоящий `fetch` тянул бы за
 * собой сеть, а проверять надо разбор и обрамление.
 */
async function resolveDns(packet, dohUrl = DEFAULT_DOH, fetchImpl = fetch) {
    const answer = await fetchImpl(dohUrl, {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: packet,
    });
    if (!answer.ok) {
        throw new Error(`DoH ответил ${answer.status}`);
    }
    return new Uint8Array(await answer.arrayBuffer());
}


// ── ЧАСТЬ 3: сама точка выхода ──
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
// npx wrangler secret put ATLAS_UUID
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
 * Открыть исходящее соединение, узнав об отказе сразу.
 *
 * `connect()` ленив: он возвращает сокет немедленно, а отказ всплывает
 * только при первом чтении или записи. Полагаться на это нельзя —
 * запасной путь включался бы тогда по признаку «данных не пришло», то
 * есть после полного ожидания. `opened` даёт узнать об отказе сразу.
 */
async function dial(hostname, port) {
    const socket = connect({ hostname, port });
    if (socket.opened) {
        await Promise.race([
            socket.opened,
            new Promise((_, reject) =>
                setTimeout(
                    () => reject(new Error("адрес назначения не отвечает")),
                    CONNECT_TIMEOUT_MS,
                ),
            ),
        ]);
    }
    return socket;
}

/**
 * Разобрать `ATLAS_PROXY_IP`.
 *
 * Допускается `адрес` и `адрес:порт`. Без порта берётся порт самого
 * назначения — так и задумано: посредник здесь обычно другой узел
 * Cloudflare, и на 443 он раздаёт тот же сайт, что и любой другой,
 * потому что выбор зоны идёт по имени в `ClientHello`, а не по адресу.
 */
function parseProxyIp(text, fallbackPort) {
    if (typeof text !== "string" || text.trim().length === 0) {
        return null;
    }
    const value = text.trim();
    // IPv6 в скобках: `[2606:4700::1]:443`.
    const bracketed = value.match(/^\[(.+)\](?::(\d+))?$/);
    if (bracketed) {
        return {
            hostname: bracketed[1],
            port: bracketed[2] ? Number(bracketed[2]) : fallbackPort,
        };
    }
    const at = value.lastIndexOf(":");
    if (at > 0 && !value.slice(at + 1).includes(":")) {
        const port = Number(value.slice(at + 1));
        if (Number.isInteger(port) && port > 0 && port < 65536) {
            return { hostname: value.slice(0, at), port };
        }
    }
    return { hostname: value, port: fallbackPort };
}

/**
 * Соединиться с назначением, при отказе — через посредника.
 *
 * # Зачем здесь вообще запасной путь
 *
 * Cloudflare запрещает Worker'у открывать соединение на адрес самой
 * Cloudflare: для платформы это петля. А за Cloudflare стоит немалая
 * часть интернета, и для пользователя это выглядит так, что часть
 * сайтов просто не открывается, притом что туннель заведомо жив и
 * быстр. Диагноз при этом не подсказывает ничего: обрыв неотличим от
 * обрыва по любой другой причине.
 *
 * Посредник — узел, до которого Worker'у ходить не запрещено. Он
 * пересылает байты как есть, поэтому TLS остаётся сквозным от
 * устройства до назначения: посреднику видно имя в `ClientHello` и
 * объём, но не содержимое.
 *
 * Умолчания нет и не будет. Зашитый в код чужой адрес означал бы, что
 * трафик пользователей молча идёт через узел, которого они не выбирали.
 */
async function openUpstream(host, port, proxy) {
    try {
        return await dial(host, port);
    } catch (error) {
        if (!proxy) {
            throw new Error(
                `${host}:${port} недостижим (${error.message}). ` +
                    "Если сайт за Cloudflare, это запрет платформы на петлю: " +
                    "задайте ATLAS_PROXY_IP.",
            );
        }
        return dial(proxy.hostname, proxy.port);
    }
}

/**
 * Читатель поверх WebSocket: события превращаются в ожидаемые куски.
 *
 * Границы сообщений WebSocket не совпадают с границами записей
 * сквозного канала, поэтому нужен буфер и ожидание нужной длины, а не
 * «одно сообщение — одна запись».
 */
class Reader {
    constructor(socket, earlyData) {
        this.chunks = [];
        this.length = 0;
        this.waiting = null;
        this.closed = false;

        // Данные из заголовка рукопожатия — это начало потока, и они
        // обязаны лечь перед всем, что придёт сообщениями.
        if (earlyData && earlyData.length > 0) {
            this.chunks.push(earlyData);
            this.length += earlyData.length;
        }

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

/** Отправить порцию клиенту, запечатав её, если канал сквозной. */
async function sendPayload(socket, session, payload) {
    socket.send(session ? await session.seal(payload) : payload);
}

/**
 * Перекачка TCP между клиентом и адресом назначения.
 *
 * # Про заголовок ответа
 *
 * Ответ VLESS — версия и нулевая длина добавки — уходит **приклеенным к
 * первому куску данных**, а не отдельным сообщением. Для потока разницы
 * нет, но сообщение WebSocket — это не поток: разборщик, который ждёт
 * заголовок и данные в одном кадре, на отдельном кадре встаёт. Клиенты
 * на этот счёт расходятся, и дешевле вести себя как эталонные
 * реализации, чем выяснять, какой именно клиент у пользователя.
 */
async function relayTcp(socket, reader, session, request, greeting, proxy) {
    const upstream = await openUpstream(request.host, request.port, proxy);
    const writer = upstream.writable.getWriter();
    if (request.rest.length > 0) {
        await writer.write(request.rest);
    }

    let header = greeting;

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
                const payload = header ? concat(header, piece) : piece;
                header = null;
                await sendPayload(socket, session, payload);
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
    }
}

/**
 * Ответы на запросы DNS, пришедшие в туннель.
 *
 * # Почему без этого не работал целый класс клиентов
 *
 * Клиент в режиме системного VPN забирает весь трафик, включая запросы
 * имён, и шлёт их сюда командой UDP. Край, отвечавший на команду 2
 * отказом, рвал соединение на первом же запросе DNS — то есть до
 * первого обращения к любому сайту. Снаружи это выглядит как «профиль
 * подключился, но ничего не грузится», и на туннель не указывает ничем.
 *
 * Датаграмм наружу край послать не может — `connect()` даёт только TCP.
 * Но для DNS этого и не нужно: запрос уходит по HTTPS, а `fetch` под
 * запрет на петлю не подпадает.
 */
async function relayDns(socket, reader, session, request, greeting, doh) {
    const framer = new UdpFramer();
    let header = greeting;

    const answer = async (packet) => {
        const reply = await resolveDns(packet, doh);
        const framed = frameUdp(reply);
        const payload = header ? concat(header, framed) : framed;
        header = null;
        await sendPayload(socket, session, payload);
    };

    framer.push(request.rest);
    for (const packet of framer.drain()) {
        await answer(packet);
    }

    for (;;) {
        framer.push(await readRecord(reader, session));
        for (const packet of framer.drain()) {
            await answer(packet);
        }
    }
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
async function serve(socket, config, sealed, earlyData) {
    socket.accept();
    const reader = new Reader(socket, earlyData);

    let session = null;
    if (sealed) {
        const hello = await reader.exact(CLIENT_HELLO_LEN);
        const now = Math.floor(Date.now() / 1000);
        const agreed = await respond(config.secret, hello, now);
        session = agreed.session;
        socket.send(agreed.response);
    }

    // Первая запись несёт заголовок VLESS и, как правило, начало данных.
    const first = await readRecord(reader, session);
    const request = parseVless(first, config.uuid);

    // Ответ VLESS: версия и нулевая длина добавки.
    const greeting = new Uint8Array([request.version, 0]);

    try {
        if (request.isUdp) {
            await relayDns(socket, reader, session, request, greeting, config.doh);
        } else {
            await relayTcp(socket, reader, session, request, greeting, config.proxy);
        }
    } finally {
        socket.close(1000);
    }
}

export default {
    async fetch(request, env) {
        // Посторонний, попавший сюда браузером, обязан увидеть обычный
        // ответ, а не признак прокси. Худшее, что можно сделать, — вернуть
        // что-то своё и опознаваемое.
        //
        // Значение заголовка сравнивается без учёта регистра: по RFC 6455
        // оно нечувствительно к нему, и клиенты этим пользуются
        // по-разному. Строгое сравнение отсекало бы часть из них с
        // ответом «404», то есть выглядело бы как «ключ не работает
        // именно в этом приложении».
        const upgrade = request.headers.get("Upgrade");
        if (upgrade?.toLowerCase() !== "websocket") {
            return new Response("Not Found", { status: 404 });
        }

        let config;
        try {
            config = {
                secret: parseSecret(env.ATLAS_SECRET),
                uuid: parseUuid(env.ATLAS_UUID),
                doh: env.ATLAS_DOH || DEFAULT_DOH,
                proxy: parseProxyIp(env.ATLAS_PROXY_IP, 443),
            };
        } catch (error) {
            // Настройка не сошлась — это наша беда, а не гостя. Наружу
            // всё равно уходит обычная ошибка сервера без подробностей.
            console.error(error.message);
            return new Response("Internal Server Error", { status: 500 });
        }

        // Путь решает, каким протоколом говорить. `/e` — наш сквозной
        // канал, всё остальное — обычный VLESS для чужих клиентов.
        const sealed = new URL(request.url).pathname.endsWith("/e");

        // Клиент с `?ed=…` в пути кладёт первые байты потока прямо в
        // заголовок рукопожатия, экономя оборот до края.
        const protocol = request.headers.get("Sec-WebSocket-Protocol");
        const earlyData = decodeEarlyData(protocol);

        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);

        serve(server, config, sealed, earlyData).catch((error) => {
            console.error(error.message);
            try {
                server.close(1011);
            } catch {
                // Уже закрыт.
            }
        });

        // Подпротокол возвращается обратно. По RFC 6455 сервер обязан
        // выбрать его из предложенного клиентом, и часть клиентов на
        // отсутствие выбора отвечает обрывом рукопожатия — то есть
        // отказом, который выглядит как неработающий ключ.
        const headers = {};
        if (protocol) {
            headers["Sec-WebSocket-Protocol"] = protocol;
        }

        return new Response(null, { status: 101, webSocket: client, headers });
    },
};
