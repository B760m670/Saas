// Датаграммы DNS внутри потока VLESS.
//
// # Зачем это понадобилось
//
// Клиент в режиме системного VPN забирает весь трафик, включая запросы
// имён, и отправляет их на край **командой 2** — «доставь как UDP».
// Край отвечал на неё отказом и рвал соединение, а в журнале оставалась
// строка `команда 2 не поддерживается`. Снято с живого края, на трафике
// пользователя: такая ошибка приходится на каждый запрос имени.
//
// Снаружи это выглядит как «подключился, но ничего не грузится»: без
// разрешения имён не открывается ничего, даже когда сам туннель цел.
//
// # Почему только порт 53
//
// Отправить датаграмму наружу край не может вовсе — `connect()` даёт
// только TCP. Но для DNS это и не нужно: запрос уходит по HTTPS, а
// `fetch` под запрет на соединение с адресами самой Cloudflare не
// подпадает. Для всех прочих портов отказ остаётся, и это не упущение:
// отправить такой пакет нечем.
//
// # Почему отдельный файл
//
// `worker.js` начинается с `import { connect } from "cloudflare:sockets"`,
// а этого модуля нет нигде, кроме самой площадки, — файл невозможно
// даже загрузить обычным узлом. Здесь нет ничего, кроме арифметики над
// байтами, поэтому проверки гоняются `node --test`, без Cloudflare и без
// сети.
//
// Имена верхнего уровня во всех файлах края обязаны быть разными:
// `bundle.py` склеивает их в один файл, и два одинаковых объявления
// дали бы синтаксическую ошибку прямо при развёртывании.

/** Порт DNS — единственный, для которого принимается UDP. */
export const DNS_PORT = 53;

/** Куда уходят запросы DNS, пришедшие в туннель. */
export const DEFAULT_DOH = "https://cloudflare-dns.com/dns-query";

/** Наибольшая длина датаграммы, помещающаяся в двухбайтовый префикс. */
export const MAX_DATAGRAM = 0xffff;

/** Склеить куски в один массив. */
function merge(left, right) {
    const out = new Uint8Array(left.length + right.length);
    out.set(left, 0);
    out.set(right, left.length);
    return out;
}

/**
 * Сборщик датаграмм из потока.
 *
 * UDP внутри VLESS едет по потоку, и каждая датаграмма несёт свою длину
 * двумя байтами впереди. Границы сообщений WebSocket с этими границами
 * не совпадают никак, поэтому нужен именно сборщик, а не разбор
 * «одно сообщение — одна датаграмма»: на первом же длинном ответе такой
 * разбор развалился бы.
 */
export class Datagrams {
    constructor() {
        this.pending = new Uint8Array(0);
    }

    /** Добавить пришедший кусок. */
    push(chunk) {
        this.pending = merge(this.pending, chunk);
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
export function frameDatagram(packet) {
    if (packet.length > MAX_DATAGRAM) {
        throw new Error("датаграмма длиннее 65535 байт");
    }
    return merge(new Uint8Array([packet.length >> 8, packet.length & 0xff]), packet);
}

/**
 * Разрешить имя, отправив запрос DNS по HTTPS.
 *
 * `fetchImpl` подставляется в проверках: настоящий `fetch` тянул бы за
 * собой сеть, а проверять надо разбор и обрамление.
 */
export async function resolveOverHttps(packet, dohUrl = DEFAULT_DOH, fetchImpl = fetch) {
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
