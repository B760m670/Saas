/* Сгенерировано cbindgen — правки вносятся в atlas-ffi/src/lib.rs.
 *
 * Обновить:  cbindgen --config cbindgen.toml --crate atlas-ffi \
 *                     --output include/atlas.h
 * Проверить: cargo test -p atlas-ffi --test abi
 */

#ifndef ATLAS_H
#define ATLAS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Запущенный прокси со стороны C.
 *
 * Устройство наружу не раскрывается: за границей это просто указатель.
 */
typedef struct AtlasProxy AtlasProxy;

/**
 * Настройки соединения для стороны C.
 *
 * Нулевой указатель вместо структуры означает «взять умолчания».
 * Нулевое поле времени означает то же самое для этого поля в
 * отдельности: так C-вызывающему не нужно знать наши константы.
 */
typedef struct AtlasOptions {
  /**
   * Отправлять ли расширение ECH. Ноль — не отправлять.
   *
   * Обычно его надо отправлять: так делает браузер. Но встречаются
   * сети, где приветствие с ECH рвут — см. `docs/09-lab.md`.
   */
  unsigned int ech;
  /**
   * Предел ожидания TCP, миллисекунды. Ноль — умолчание.
   */
  unsigned int connect_timeout_ms;
  /**
   * Предел ожидания чтения, миллисекунды. Ноль — умолчание.
   */
  unsigned int read_timeout_ms;
} AtlasOptions;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Версия ядра.
 *
 * Строка статическая: освобождать её нельзя.
 */
const char *atlas_version(void);

/**
 * Забрать причину последнего отказа в этом потоке.
 *
 * Возвращает ноль, если отказов не было. Строку освобождает
 * вызывающий; повторный вызов вернёт ноль, пока не случится новый
 * отказ.
 */
char *atlas_last_error(void);

/**
 * Освободить строку, выданную этой библиотекой.
 *
 * Ноль допустим и ничего не делает.
 *
 * # Safety
 *
 * `text` получен от этой библиотеки и ещё не освобождался.
 */
void atlas_string_free(char *text);

/**
 * Разобрать ключ доступа и описать его в JSON.
 *
 * Служит проверкой годности ключа перед тем, как его сохранять:
 * клиенту нужно показать пользователю, куда он собрался соединяться, и
 * отказать по-человечески, если ключ испорчен.
 *
 * **Учётных данных в описании нет намеренно.** Описание уходит в
 * интерфейс и в журналы, а UUID — секрет, дающий доступ к точке
 * выхода.
 *
 * # Safety
 *
 * `uri` — годная строка C.
 */
char *atlas_key_describe(const char *uri);

/**
 * Поднять локальный прокси и начать обслуживание.
 *
 * `listen` — адрес вида `127.0.0.1:1080`; порт `0` означает «любой
 * свободный», и тогда занятый адрес узнаётся через
 * [`atlas_proxy_address`]. `options` может быть нулём — тогда берутся
 * умолчания.
 *
 * `rules` — правила маршрутизации в JSON, либо ноль для умолчания
 * («всё через туннель, кроме локального»):
 *
 * ```json
 * {"direct": ["gosuslugi.ru"], "blocked": ["ads.example.com"]}
 * ```
 *
 * Списками, а не строкой со списком, — потому что имена приходят от
 * пользователя и попадают в исполняемый скрипт; разбор JSON снимает
 * вопрос о разделителях, а проверка имён происходит уже в ядре.
 *
 * Возвращает ноль при отказе; причина — в [`atlas_last_error`].
 *
 * # Safety
 *
 * `uri` и `listen` — годные строки C; `options` — либо ноль, либо
 * годный указатель на [`AtlasOptions`]; `rules` — либо ноль, либо
 * годная строка C.
 */
struct AtlasProxy *atlas_proxy_start(const char *uri,
                                     const char *listen,
                                     const struct AtlasOptions *options,
                                     const char *rules);

/**
 * Скрипт правил, который прокси отдаёт по `/proxy.pac`.
 *
 * Нужен клиенту, чтобы показать пользователю, что именно пойдёт мимо
 * туннеля: правила, которых не видно, — это правила, которым нельзя
 * доверять.
 *
 * # Safety
 *
 * `proxy` получен от [`atlas_proxy_start`] и ещё не остановлен.
 */
char *atlas_proxy_pac(const struct AtlasProxy *proxy);

/**
 * Собрать профиль конфигурации iOS для сети Wi-Fi.
 *
 * `ssid` — имя сети; `proxy_address` — занятый прокси адрес, обычно
 * из [`atlas_proxy_address`]. Ненулевой `automatic` означает профиль
 * с PAC-скриптом (правила берутся у прокси по сети), нулевой — один
 * адрес прокси на всё.
 *
 * `wifi_password` — пароль сети либо ноль для открытой. Для сети с
 * защитой пароль **обязателен**: профиль описывает сеть целиком, и без
 * пароля устройство может перестать к ней подключаться.
 *
 * # Safety
 *
 * `ssid` и `proxy_address` — годные строки C; `wifi_password` — либо
 * ноль, либо годная строка C.
 */
char *atlas_mobileconfig(const char *ssid,
                         const char *proxy_address,
                         unsigned int automatic,
                         const char *wifi_password);

/**
 * Занятый прокси адрес.
 *
 * # Safety
 *
 * `proxy` получен от [`atlas_proxy_start`] и ещё не остановлен.
 */
char *atlas_proxy_address(const struct AtlasProxy *proxy);

/**
 * Показания счётчиков в JSON.
 *
 * # Safety
 *
 * `proxy` получен от [`atlas_proxy_start`] и ещё не остановлен.
 */
char *atlas_proxy_stats(const struct AtlasProxy *proxy);

/**
 * Остановить прокси и освободить дескриптор.
 *
 * Новые соединения перестают приниматься; уже открытые доживают своё.
 * Ноль допустим и ничего не делает.
 *
 * # Safety
 *
 * `proxy` получен от [`atlas_proxy_start`] и останавливается ровно
 * один раз.
 */
void atlas_proxy_stop(struct AtlasProxy *proxy);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* ATLAS_H */
