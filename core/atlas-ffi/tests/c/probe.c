/* Проверка границы C: настоящая программа на C против нашей библиотеки.
 *
 * Смысл именно в отдельной программе, а не в вызове тех же функций из
 * Rust: из Rust вызов проверил бы сигнатуры так, как их видит Rust.
 * Здесь же они видны так, как их видит сторонний компилятор, читающий
 * сгенерированный заголовок, — то есть ровно так, как их увидит Swift
 * или Kotlin.
 *
 * Доводы: ключ доступа и адрес назначения. Выводит строки, которые
 * сверяет вызывающий тест.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "atlas.h"

static int fail(const char *what) {
    char *why = atlas_last_error();
    fprintf(stderr, "%s: %s\n", what, why ? why : "(причина не сообщена)");
    atlas_string_free(why);
    return 1;
}

/* Пройти сквозь поднятый прокси до назначения и вернуться с ответом.
 *
 * Тот же путь, каким пойдёт настоящий клиент: CONNECT в локальный
 * прокси, дальше туннель, точка выхода и назначение.
 */
static int through_proxy(const char *proxy_address, const char *destination) {
    char host[64];
    int port = 0;
    const char *colon = strrchr(proxy_address, ':');
    if (colon == NULL || (size_t)(colon - proxy_address) >= sizeof(host)) return -1;
    memcpy(host, proxy_address, (size_t)(colon - proxy_address));
    host[colon - proxy_address] = '\0';
    port = atoi(colon + 1);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in where;
    memset(&where, 0, sizeof(where));
    where.sin_family = AF_INET;
    where.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &where.sin_addr) != 1) { close(sock); return -1; }
    if (connect(sock, (struct sockaddr *)&where, sizeof(where)) != 0) { close(sock); return -1; }

    char request[256];
    int written = snprintf(request, sizeof(request),
                           "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
                           destination, destination);
    if (written <= 0 || send(sock, request, (size_t)written, 0) != written) { close(sock); return -1; }

    /* Ответ прокси: достаточно первой строки. */
    char answer[512];
    ssize_t got = recv(sock, answer, sizeof(answer) - 1, 0);
    if (got <= 0) { close(sock); return -1; }
    answer[got] = '\0';
    if (strstr(answer, "200") == NULL) {
        fprintf(stderr, "прокси отказал: %.*s\n", (int)got, answer);
        close(sock);
        return -1;
    }

    if (send(sock, "ping", 4, 0) != 4) { close(sock); return -1; }
    got = recv(sock, answer, sizeof(answer) - 1, 0);
    close(sock);
    if (got <= 0) return -1;
    answer[got] = '\0';
    printf("skvoz=%s\n", answer);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "нужен ключ доступа\n");
        return 2;
    }
    const char *key = argv[1];

    printf("version=%s\n", atlas_version());

    /* Отказ обязан сообщать причину, а не молчать. */
    if (atlas_key_describe("не-ключ") != NULL) {
        fprintf(stderr, "испорченный ключ принят\n");
        return 1;
    }
    char *why = atlas_last_error();
    if (why == NULL) {
        fprintf(stderr, "отказ без причины\n");
        return 1;
    }
    printf("otkaz=%s\n", why);
    atlas_string_free(why);

    /* Причина обнуляется при чтении. */
    if (atlas_last_error() != NULL) {
        fprintf(stderr, "причина не обнулилась\n");
        return 1;
    }

    /* Нулевой указатель не должен ронять процесс. */
    if (atlas_key_describe(NULL) != NULL) {
        fprintf(stderr, "ноль принят за ключ\n");
        return 1;
    }
    atlas_string_free(atlas_last_error());
    atlas_string_free(NULL);

    char *described = atlas_key_describe(key);
    if (described == NULL) return fail("описание ключа");
    printf("opisanie=%s\n", described);
    if (strstr(described, "uuid") != NULL) {
        fprintf(stderr, "в описании оказались учётные данные\n");
        return 1;
    }
    atlas_string_free(described);

    struct AtlasOptions options;
    options.ech = 0;
    options.connect_timeout_ms = 5000;
    options.read_timeout_ms = 10000;

    /* Испорченные правила обязаны быть отвергнуты с объяснением. */
    if (atlas_proxy_start(key, "127.0.0.1:0", &options, "{\"direct\": 5}") != NULL) {
        fprintf(stderr, "испорченные правила приняты\n");
        return 1;
    }
    atlas_string_free(atlas_last_error());

    AtlasProxy *proxy = atlas_proxy_start(key, "127.0.0.1:0", &options,
                                          "{\"direct\":[\"gosuslugi.ru\"]}");
    if (proxy == NULL) return fail("запуск прокси");

    char *address = atlas_proxy_address(proxy);
    if (address == NULL) return fail("адрес прокси");
    printf("adres=%s\n", address);
    atlas_string_free(address);

    char *pac = atlas_proxy_pac(proxy);
    if (pac == NULL) return fail("скрипт правил");
    if (strstr(pac, "gosuslugi.ru") == NULL) {
        fprintf(stderr, "правила не дошли до скрипта\n");
        return 1;
    }
    printf("pac_dlina=%zu\n", strlen(pac));
    atlas_string_free(pac);

    char *where2 = atlas_proxy_address(proxy);
    if (where2 == NULL) return fail("адрес для профиля");
    char *profile = atlas_mobileconfig("Дом", where2, 1, NULL);
    if (profile == NULL) return fail("профиль");
    if (strstr(profile, "com.apple.wifi.managed") == NULL ||
        strstr(profile, "/proxy.pac") == NULL) {
        fprintf(stderr, "профиль неполный\n");
        return 1;
    }
    printf("profil_dlina=%zu\n", strlen(profile));
    atlas_string_free(profile);

    /* Защищённая сеть без пароля обязана быть отвергнута. */
    char *broken = atlas_mobileconfig("", where2, 1, NULL);
    if (broken != NULL) {
        fprintf(stderr, "пустое имя сети принято\n");
        return 1;
    }
    atlas_string_free(atlas_last_error());
    atlas_string_free(where2);

    char *stats = atlas_proxy_stats(proxy);
    if (stats == NULL) return fail("счётчики");
    printf("schetchiki=%s\n", stats);
    atlas_string_free(stats);

    if (argc >= 3) {
        char *where = atlas_proxy_address(proxy);
        if (where == NULL) return fail("адрес прокси");
        int passed = through_proxy(where, argv[2]);
        atlas_string_free(where);
        if (passed != 0) {
            fprintf(stderr, "сквозь прокси пройти не удалось\n");
            atlas_proxy_stop(proxy);
            return 1;
        }
        char *after = atlas_proxy_stats(proxy);
        if (after == NULL) return fail("счётчики после");
        printf("posle=%s\n", after);
        atlas_string_free(after);
    }

    atlas_proxy_stop(proxy);
    atlas_proxy_stop(NULL);

    printf("gotovo\n");
    return 0;
}
