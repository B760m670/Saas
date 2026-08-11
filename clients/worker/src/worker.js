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
// npx wrangler secret put ATLAS_UUID
// ```
//
// Секрет — тот же, что в ключе доступа у клиента. Кто им владеет, тот
// пользуется вашим краем.

// Исходящий TCP из Worker. Именно эта возможность и делает всю затею
// осуществимой: без неё край мог бы только ходить по HTTP.
import { connect } from "cloudflare:sockets";

import { respond, MAX_RECORD, CLIENT_HELLO_LEN } from "./edge.js";
import {
    asksWhere,
    concat,
    decodeEarlyData,
    frameUdp,
    parseSecret,
    parseUuid,
    parseProxies,
    parseVless,
    resolveDns,
    UdpFramer,
    DEFAULT_DOH,
} from "./vless.js";

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
 * Соединиться с назначением, при отказе — через посредников по очереди.
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
 * Посредник — узел, до которого Worker'у ходить не запрещено и который
 * пересылает байты как есть. Тогда TLS остаётся сквозным от устройства
 * до назначения: посреднику видно имя в `ClientHello` и объём, но не
 * содержимое.
 *
 * # Почему их несколько и почему этого всё равно мало
 *
 * Годный посредник обязан быть **прозрачным**. Проверено на живом узле,
 * что бывает иначе: `cdn.xn--b6gac.eu.org` сам завершает рукопожатие
 * своим просроченным сертификатом, и клиент получает не сайт, а ошибку
 * проверки имени. Соединение при этом формально устанавливается,
 * поэтому отличить негодного посредника от годного на уровне `connect()`
 * нельзя — отказ виден только клиенту, и только по сертификату.
 *
 * Отсюда список: перебор даёт шанс дойти до прозрачного узла. Но
 * гарантии он не даёт, и обещать её здесь было бы неправдой.
 *
 * Умолчания нет и не будет. Зашитый в код чужой адрес означал бы, что
 * трафик пользователей молча идёт через узел, которого они не выбирали.
 */
async function openUpstream(host, port, proxies) {
    let last;
    try {
        return await dial(host, port);
    } catch (error) {
        last = error;
    }

    for (const proxy of proxies) {
        try {
            return await dial(proxy.hostname, proxy.port);
        } catch (error) {
            last = error;
        }
    }

    const hint = proxies.length
        ? `ни один из ${proxies.length} посредников не ответил`
        : "если сайт за Cloudflare, это запрет платформы на петлю: задайте ATLAS_PROXY_IP";
    throw new Error(`${host}:${port} недостижим (${last?.message ?? "?"}). ${hint}`);
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
async function relayTcp(socket, reader, session, request, greeting, proxies) {
    const upstream = await openUpstream(request.host, request.port, proxies);
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
            await relayTcp(socket, reader, session, request, greeting, config.proxies);
        }
    } finally {
        socket.close(1000);
    }
}

/**
 * Узнать, каким адресом край выходит в интернет.
 *
 * # Почему замер идёт через `connect()`, а не через `fetch`
 *
 * У площадки это два разных пути наружу, и адреса у них могут не
 * совпадать. Нас интересует тот, которым идёт трафик пользователя, а он
 * идёт через `connect()`. Замер, сделанный удобным способом вместо
 * верного, показывал бы чужую цифру с убедительным видом.
 *
 * Служба опрошена по обычному HTTP: `ip-api.com` не за Cloudflare,
 * поэтому запрет на петлю здесь ни при чём, а TLS ради публичного факта
 * о собственном адресе не нужен.
 */
async function measureExit() {
    const socket = await dial("ip-api.com", 80);
    const writer = socket.writable.getWriter();
    await writer.write(
        new TextEncoder().encode(
            "GET /json/?fields=query,country,countryCode,city,as HTTP/1.1\r\n" +
                "Host: ip-api.com\r\nConnection: close\r\n\r\n",
        ),
    );

    const reader = socket.readable.getReader();
    let text = "";
    for (;;) {
        const { value, done } = await reader.read();
        if (done || text.length > 8192) {
            break;
        }
        text += new TextDecoder().decode(value);
    }
    const body = text.split("\r\n\r\n")[1] ?? "";
    return JSON.parse(body);
}

/**
 * Ответить, где край находится.
 *
 * # Что здесь два разных факта, и путать их нельзя
 *
 * `colo` — дата-центр, **принявший** запрос. Он определяется тем, где
 * находится пользователь, и меняется вместе с ним.
 *
 * `exit` — адрес, которым край **выходит** наружу. Именно его видит сайт
 * назначения, и именно он решает, что показать по стране.
 *
 * Обычно они рядом, но совпадение не гарантировано, поэтому отдаются оба
 * и по отдельности. Подписывать ключ страной надо по `exit`.
 */
async function whereAmI(request) {
    const colo = request.cf?.colo ?? null;
    let exit = null;
    let failure = null;
    try {
        exit = await measureExit();
    } catch (error) {
        // Замер — сведения, а не работа края. Его отказ не повод молчать
        // о том, что известно и так.
        failure = error.message;
    }

    return new Response(JSON.stringify({ colo, exit, failure }, null, 2), {
        status: 200,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
        },
    });
}

export default {
    async fetch(request, env) {
        const path = new URL(request.url).pathname;

        // Значение заголовка сравнивается без учёта регистра: по RFC 6455
        // оно нечувствительно к нему, и клиенты этим пользуются
        // по-разному. Строгое сравнение отсекало бы часть из них с
        // ответом «404», то есть выглядело бы как «ключ не работает
        // именно в этом приложении».
        const upgrade = request.headers.get("Upgrade");
        const wants_websocket = upgrade?.toLowerCase() === "websocket";

        let config;
        try {
            config = {
                secret: parseSecret(env.ATLAS_SECRET),
                uuid: parseUuid(env.ATLAS_UUID),
                doh: env.ATLAS_DOH || DEFAULT_DOH,
                proxies: parseProxies(env.ATLAS_PROXY_IP, 443),
            };
        } catch (error) {
            // Настройка не сошлась — это наша беда, а не гостя. Наружу
            // всё равно уходит обычная ошибка сервера без подробностей.
            //
            // Постороннему при этом по-прежнему полагается `404`: иначе
            // сломанная настройка отвечала бы `500` там, где исправная
            // отвечает `404`, и одно это отличало бы наш край от пустого
            // места.
            console.error(error.message);
            return wants_websocket
                ? new Response("Internal Server Error", { status: 500 })
                : new Response("Not Found", { status: 404 });
        }

        // Где край находится. Путь несёт идентификатор, поэтому для
        // постороннего он неотличим от любого другого несуществующего.
        if (!wants_websocket && asksWhere(path, config.uuid)) {
            return whereAmI(request);
        }

        // Посторонний, попавший сюда браузером, обязан увидеть обычный
        // ответ, а не признак прокси. Худшее, что можно сделать, — вернуть
        // что-то своё и опознаваемое.
        if (!wants_websocket) {
            return new Response("Not Found", { status: 404 });
        }

        // Путь решает, каким протоколом говорить. `/e` — наш сквозной
        // канал, всё остальное — обычный VLESS для чужих клиентов.
        const sealed = path.endsWith("/e");

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
