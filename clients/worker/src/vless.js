// Разбор VLESS и обрамление UDP — та часть края, где нет площадки.
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
export const COMMAND_TCP = 1;

/** Команда «переслать датаграммы UDP». */
export const COMMAND_UDP = 2;

/** Порт DNS — единственный, для которого мы принимаем UDP. */
export const DNS_PORT = 53;

/**
 * Куда уходят запросы DNS, пришедшие в туннель.
 *
 * Это `fetch`, а не `connect`, поэтому запрет на исходящие соединения к
 * адресам самой Cloudflare здесь ни при чём.
 */
export const DEFAULT_DOH = "https://cloudflare-dns.com/dns-query";

/** Наибольшая длина датаграммы, помещающаяся в двухбайтовый префикс. */
export const MAX_DATAGRAM = 0xffff;

/** Склеить куски в один массив. */
export function concat(...parts) {
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
export function parseSecret(text) {
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
export function parseUuid(text) {
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
export function parseVless(data, uuid) {
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
export function decodeEarlyData(header) {
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
export class UdpFramer {
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
export function frameUdp(packet) {
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
export async function resolveDns(packet, dohUrl = DEFAULT_DOH, fetchImpl = fetch) {
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
