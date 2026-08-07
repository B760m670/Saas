//
//  Затыкание известных путей утечки в WebKit.
//
//  # Зачем это вообще нужно
//
//  `WKWebsiteDataStore.proxyConfigurations` (iOS 17+) уводит через
//  прокси **почти** весь трафик страницы. Почти — потому что три пути
//  идут мимо и раскрывают настоящий адрес устройства:
//
//  | Что | С какой версии |
//  |---|---|
//  | Подсказки предзагрузки DNS (`dns-prefetch`, `preconnect`) | iOS 26.0 |
//  | Проверка WebAuthn (`.well-known/webauthn`) | iOS 18.0 |
//  | WebTransport поверх QUIC | iOS 26.4 |
//
//  Для браузера, которым пользуются ради сокрытия адреса, это не мелочь:
//  одна такая утечка сводит на нет весь туннель.
//
//  # Как это закрывается и насколько надёжно
//
//  Публичных переключателей у Apple нет ни для одного из трёх. Поэтому
//  подход другой: **если возможности нет у страницы, WebKit её и не
//  задействует**. Скрипт ниже убирает соответствующие API до того, как
//  на странице выполнится хоть одна её собственная строка.
//
//  Надёжность у мер разная, и смешивать их нельзя:
//
//  - **WebRTC, WebAuthn, WebTransport** — надёжно. Это точки входа в
//    JavaScript; нет свойства — нет и вызова, а значит нет и запроса,
//    который шёл бы мимо прокси. Свойства переопределяются
//    неконфигурируемыми, поэтому вернуть их страница не может.
//  - **Подсказки предзагрузки** — по мере сил. Они задаются разметкой, а
//    не вызовом, поэтому убираются наблюдателем за деревом. Между
//    появлением элемента и его удалением есть окно, и запрос может
//    успеть уйти. Это **не гарантия**, и в интерфейсе так и написано.
//
//  # Чего эти меры стоят
//
//  Сайты, вход на которые устроен через ключи доступа (passkeys), в
//  таком браузере войти не дадут. Видеозвонки в вебе не заработают.
//  Это осознанный размен: возможность, работающая мимо туннеля, для
//  инструмента обхода цензуры хуже, чем отсутствующая.
//

import WebKit

enum Hardening {

    /// Меры, применённые к сеансу, — для показа пользователю.
    struct Applied: Equatable {
        /// Трафик страницы уходит в туннель.
        var proxied: Bool
        /// Точки входа, убранные надёжно.
        var removed: [String]
        /// Меры, работающие по мере сил.
        var bestEffort: [String]
    }

    /// Что именно убирается и по какой причине.
    ///
    /// Список держится здесь, а не в теле скрипта, чтобы то же самое
    /// можно было показать на экране: пользователь вправе знать, чем за
    /// сокрытие адреса заплачено.
    static let removedFeatures = [
        "RTCPeerConnection",
        "webkitRTCPeerConnection",
        "RTCDataChannel",
        "navigator.credentials",
        "WebTransport",
    ]

    static let bestEffortMeasures = [
        "подсказки предзагрузки DNS",
        "предварительные соединения",
    ]

    /// Скрипт, выполняемый до собственных скриптов страницы.
    static let script = """
        (function () {
            'use strict';

            // Убрать точку входа так, чтобы её нельзя было вернуть.
            //
            // Простого `delete` мало: страница вправе восстановить
            // свойство из прототипа или из другого окна. Свойство
            // объявляется неконфигурируемым и неизменяемым.
            // Неудачи копятся, а не проглатываются. Молчащий `catch`
            // однажды уже спрятал настоящую поломку: возможность
            // осталась доступной странице, а узнали мы об этом от
            // проверки, которой нечего было сказать о причине.
            window.__atlasSealFailures = [];

            function seal(target, name) {
                if (!target) return;

                // Свойство может лежать не на самом объекте, а на его
                // прототипе. Тогда собственное свойство его заслоняет —
                // но снимать надо и то, и другое: страница доберётся до
                // прототипа напрямую.
                var targets = [target];
                var proto = Object.getPrototypeOf(target);
                if (proto && proto !== Object.prototype) targets.push(proto);

                for (var i = 0; i < targets.length; i += 1) {
                    var where = targets[i];
                    if (!Object.prototype.hasOwnProperty.call(where, name)) continue;

                    // Сначала снять, потом объявить заново. Объявление
                    // поверх существующего неконфигурируемого свойства
                    // бросает исключение — а снятое место свободно.
                    try { delete where[name]; } catch (ignored) {}

                    try {
                        Object.defineProperty(where, name, {
                            get: function () { return undefined; },
                            set: function () {},
                            configurable: false,
                            enumerable: false
                        });
                    } catch (error) {
                        window.__atlasSealFailures.push(name + ': ' + error);
                    }
                }

                // Последняя попытка: если свойство всё ещё отвечает,
                // объявить его на самом объекте поверх прототипа.
                if (typeof target[name] !== 'undefined') {
                    try {
                        Object.defineProperty(target, name, {
                            get: function () { return undefined; },
                            set: function () {},
                            configurable: false,
                            enumerable: false
                        });
                    } catch (error) {
                        window.__atlasSealFailures.push(name + ' (поверх): ' + error);
                    }
                }

                if (typeof target[name] !== 'undefined') {
                    window.__atlasSealFailures.push(name + ': осталась доступной');
                }
            }

            // WebRTC: классический путь раскрытия настоящего адреса.
            // Он ходит мимо любого прокси HTTP по самому своему
            // устройству — соединения устанавливаются напрямую.
            seal(window, 'RTCPeerConnection');
            seal(window, 'webkitRTCPeerConnection');
            seal(window, 'RTCDataChannel');
            seal(window, 'webkitRTCDataChannel');

            // WebAuthn: обращение к `.well-known/webauthn` уходит мимо
            // прокси начиная с iOS 18.
            if (window.navigator) {
                seal(window.navigator, 'credentials');
            }
            seal(window, 'PublicKeyCredential');

            // WebTransport: работает поверх QUIC, который прокси HTTP не
            // переносит вовсе.
            seal(window, 'WebTransport');

            // Подсказки предзагрузки задаются разметкой, поэтому их
            // приходится вычищать из дерева. Это мера по мере сил:
            // между появлением элемента и удалением есть окно.
            var UNSAFE_RELS = ['dns-prefetch', 'preconnect', 'prefetch', 'prerender'];

            function strip(node) {
                if (!node || node.nodeType !== 1 || node.tagName !== 'LINK') return;
                var rel = (node.getAttribute('rel') || '').toLowerCase();
                for (var i = 0; i < UNSAFE_RELS.length; i++) {
                    if (rel.indexOf(UNSAFE_RELS[i]) !== -1) {
                        node.parentNode && node.parentNode.removeChild(node);
                        return;
                    }
                }
            }

            function sweep(root) {
                var links = root.querySelectorAll ? root.querySelectorAll('link[rel]') : [];
                for (var i = 0; i < links.length; i++) strip(links[i]);
            }

            // Подсказка самому движку, если он её понимает.
            function hint() {
                if (!document.head) return;
                var meta = document.createElement('meta');
                meta.httpEquiv = 'x-dns-prefetch-control';
                meta.content = 'off';
                document.head.insertBefore(meta, document.head.firstChild);
            }

            if (document.documentElement) {
                new MutationObserver(function (records) {
                    for (var i = 0; i < records.length; i++) {
                        var added = records[i].addedNodes;
                        for (var j = 0; j < added.length; j++) {
                            strip(added[j]);
                            if (added[j].querySelectorAll) sweep(added[j]);
                        }
                    }
                }).observe(document.documentElement, { childList: true, subtree: true });
            }

            document.addEventListener('DOMContentLoaded', function () {
                hint();
                sweep(document);
            });
            sweep(document);
            hint();
        })();
        """

    /// Пользовательский скрипт для настройки веб-представления.
    static func userScript() -> WKUserScript {
        WKUserScript(
            source: script,
            injectionTime: .atDocumentStart,
            // Только в основном мире: в изолированном подмена свойств
            // страницу бы не затронула, а именно её и надо ограничить.
            forMainFrameOnly: false
        )
    }
}
