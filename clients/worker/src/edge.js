// Сквозной канал до края — сторона края.
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

export const SECRET_LEN = 32;
export const SHARE_LEN = 32;
export const MAC_LEN = 16;
export const TIME_LEN = 8;
export const CLIENT_HELLO_LEN = SHARE_LEN + TIME_LEN + MAC_LEN;
export const SERVER_HELLO_LEN = SHARE_LEN + MAC_LEN;
export const MAX_RECORD = 16 * 1024;
export const CLOCK_SKEW_SECS = 300;

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
export class Session {
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
export async function respond(secret, hello, now) {
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
