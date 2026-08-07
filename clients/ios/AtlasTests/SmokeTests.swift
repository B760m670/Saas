//
//  Проверка в симуляторе: приложение не просто собирается, а работает.
//
//  # Зачем это отдельно от тестов на Linux
//
//  Шестнадцать тестов `AtlasCore` идут на Linux и доказывают, что
//  граница C верна, а состояние переходит правильно. Они ничего не
//  говорят про iOS: там другой компоновщик, другой рантайм, другая
//  песочница и другие правила для сокетов.
//
//  Здесь проверяется ровно то, что могло сломаться **только** на iOS:
//
//  1. Статический архив Rust действительно подключился и исполняется.
//  2. Приложению позволено слушать порт на петле. Это не очевидно:
//     песочница iOS ограничивает сеть, и весь замысел сборки `lite`
//     держится на том, что локальный прокси поднимается.
//  3. Экран строится и раскладывается без падения. Компилятор про это
//     молчит — вызов, которого нет в этой версии iOS, падает в момент
//     обращения, а не при сборке.
//
//  # Почему набор размещён в приложении
//
//  `testHost` — само приложение, поэтому оно по-настоящему
//  запускается. Падение при старте роняет проверку, и это главное, чего
//  нельзя увидеть сборкой.
//

import SwiftUI
import UIKit
import WebKit
import XCTest

// `AtlasCore` приходит вместе с модулем приложения: оно его
// переэкспортирует. Отдельно импортировать нельзя — набор исполняется
// внутри процесса приложения, и вторая компоновка статического продукта
// отвергается Xcode.
@testable import Atlas

/// Ключ, годный по форме. Точки выхода за ним нет и не требуется.
private let sampleKey = """
    vless://11111111-2222-3333-4444-555555555555@127.0.0.1:8443\
    ?type=tcp&security=reality&sni=www.microsoft.com\
    &pbk=gJlCetp4vTHnF1QNWPaer9qTEuFPln_LskAsPGzMXnI&sid=dead\
    &fp=chrome&flow=xtls-rprx-vision#проба
    """

final class SmokeTests: XCTestCase {

    /// Приложение вообще запустилось.
    ///
    /// Проверка выглядит пустой, но именно она ловит падение при старте:
    /// набор размещён в приложении, и до этой строки исполнение доходит,
    /// только если приложение поднялось.
    @MainActor
    func testTheApplicationIsAlive() {
        // Обращение к `UIApplication.shared` возможно только внутри
        // живого приложения — этого и достаточно.
        XCTAssertNotEqual(UIApplication.shared.applicationState, .background)
        XCTAssertEqual(Bundle.main.bundleIdentifier, "org.atlas.client")
    }

    /// Статический архив Rust подключился и исполняется под iOS.
    func testTheRustCoreRunsOnThisPlatform() {
        let version = Atlas.version
        XCTAssertFalse(version.isEmpty)
        XCTAssertNotEqual(version, "неизвестна", "ядро не отозвалось")
    }

    /// Разбор ключа работает и в рантайме iOS.
    ///
    /// Заодно проверяется, что кодировка переживает границу: метка
    /// написана кириллицей, и потеря UTF-8 здесь была бы видна.
    func testKeyDescriptionSurvivesTheBoundary() throws {
        let described = try Atlas.describe(key: sampleKey)
        XCTAssertEqual(described.host, "127.0.0.1")
        XCTAssertEqual(described.port, 8443)
        XCTAssertEqual(described.tag, "проба")
        XCTAssertTrue(described.reality)
    }

    /// Песочница iOS позволяет приложению слушать порт на петле.
    ///
    /// Весь замысел сборки `lite` держится на этом: без локального
    /// прокси профиль конфигурации указывать некуда. Проверить это можно
    /// только на настоящем iOS — ни сборка, ни тесты на Linux ответа не
    /// дают.
    func testTheProxyCanBindOnIOS() throws {
        let proxy = try AtlasProxy(key: sampleKey)
        defer { proxy.stop() }

        let address = try proxy.address
        XCTAssertTrue(address.hasPrefix("127.0.0.1:"), "не тот адрес: \(address)")
        XCTAssertFalse(address.hasSuffix(":0"), "порт не занят: \(address)")
    }

    /// Прокси принимает соединение и разбирает `CONNECT`.
    ///
    /// Точки выхода за ключом нет, поэтому правильный ответ — `502`.
    /// Именно он и доказывает больше всего: соединение принято, запрос
    /// разобран, попытка поднять туннель сделана и честно провалилась.
    /// Молчание или отказ в соединении означали бы, что слушающий сокет
    /// на iOS не работает.
    func testTheProxyAnswersAConnectRequest() throws {
        let proxy = try AtlasProxy(
            key: sampleKey,
            options: ConnectionOptions(connectTimeout: 2, readTimeout: 2)
        )
        defer { proxy.stop() }

        let address = try proxy.address
        guard let port = UInt16(address.split(separator: ":").last ?? "") else {
            return XCTFail("порт не разбирается: \(address)")
        }

        let answer = try askProxy(port: port)
        XCTAssertTrue(
            answer.hasPrefix("HTTP/1.1 502"),
            "ожидался отказ шлюза, получено: \(answer.prefix(60))"
        )

        let stats = try proxy.stats()
        XCTAssertEqual(stats.accepted, 1, "соединение не сосчитано")
    }

    /// Профиль конфигурации собирается на устройстве.
    func testTheProfileIsBuiltOnDevice() throws {
        let proxy = try AtlasProxy(key: sampleKey)
        defer { proxy.stop() }

        let profile = try proxy.mobileconfig(ssid: "Дом")
        XCTAssertTrue(profile.contains("com.apple.wifi.managed"))
        XCTAssertTrue(profile.contains("/proxy.pac"))

        // Профиль обязан разбираться средствами самой системы: если его
        // не понимает `PropertyListSerialization`, не поймёт и iOS.
        let data = Data(profile.utf8)
        let parsed = try PropertyListSerialization.propertyList(
            from: data, options: [], format: nil
        )
        XCTAssertTrue(parsed is [String: Any], "профиль не разбирается системой")
    }

    /// Экран строится, раскладывается и рисуется без падения.
    ///
    /// Это то, чего не ловит сборка. Вызов, которого нет в целевой
    /// версии iOS, падает в момент обращения — здесь он и обратится.
    ///
    /// Экран обязательно помещается в настоящее окно. Первая редакция
    /// этого не делала, и `subviews` оказался пуст: SwiftUI строит
    /// иерархию лениво и вне окна её просто не создаёт. Проверка тогда
    /// падала не потому, что экран сломан, а потому, что была написана
    /// неверно.
    ///
    /// Настоящее доказательство — проход отрисовки: `render(in:)`
    /// заставляет систему пройти по всему дереву, и недоступный вызов
    /// уронил бы процесс именно здесь.
    @MainActor
    func testTheMainScreenRendersWithoutCrashing() {
        let size = CGSize(width: 390, height: 844)
        let model = AppModel()
        let host = UIHostingController(rootView: MainScreen().environmentObject(model))

        let window = UIWindow(frame: CGRect(origin: .zero, size: size))
        window.rootViewController = host
        window.makeKeyAndVisible()

        host.view.setNeedsLayout()
        host.view.layoutIfNeeded()

        let renderer = UIGraphicsImageRenderer(bounds: host.view.bounds)
        let picture = renderer.image { context in
            host.view.layer.render(in: context.cgContext)
        }

        XCTAssertEqual(picture.size.width, size.width, accuracy: 1, "отрисовка не прошла")
        XCTAssertFalse(host.view.subviews.isEmpty, "иерархия представлений пуста")
    }

    /// Ввод ключа доводит до состояния, в котором можно включать.
    ///
    /// Проверяется связка «модель — ядро», а не разметка: пользователь
    /// вставил ключ, приложение его разобрало и готово подключаться.
    @MainActor
    func testEnteringAKeyMakesItConnectable() {
        let model = AppModel()
        XCTAssertNil(model.described)

        model.key = sampleKey
        model.refreshDescription()

        XCTAssertEqual(model.described?.host, "127.0.0.1")
        XCTAssertEqual(model.described?.sni, "www.microsoft.com")
    }
}

/// Отправить прокси запрос `CONNECT` и вернуть первую строку ответа.
private func askProxy(port: UInt16) throws -> String {
    let handle = socket(AF_INET, SOCK_STREAM, 0)
    guard handle >= 0 else { throw Failure.socket }
    defer { close(handle) }

    var target = sockaddr_in()
    target.sin_family = sa_family_t(AF_INET)
    target.sin_port = port.bigEndian
    target.sin_addr.s_addr = inet_addr("127.0.0.1")

    let connected = withUnsafePointer(to: &target) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
            connect(handle, address, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 else { throw Failure.connect }

    let request = "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n"
    let sent = Array(request.utf8).withUnsafeBufferPointer { buffer in
        send(handle, buffer.baseAddress, buffer.count, 0)
    }
    guard sent > 0 else { throw Failure.send }

    var buffer = [UInt8](repeating: 0, count: 256)
    let read = recv(handle, &buffer, buffer.count, 0)
    guard read > 0 else { throw Failure.receive }
    return String(decoding: buffer[..<read], as: UTF8.self)
}

private enum Failure: Error {
    case socket, connect, send, receive
}

/// Браузер: проверяется то, ради чего он и написан.
///
/// Не «открывается ли окно», а **уходит ли трафик в туннель** и
/// **убраны ли пути утечки**. Первое проверяется наличием настройки
/// прокси, второе — исполнением скрипта затыкания в настоящем движке.
@MainActor
final class BrowserTests: XCTestCase {

    /// Адрес прокси разбирается в точку подключения.
    func testTheProxyAddressBecomesAnEndpoint() {
        XCTAssertNotNil(WebView.endpoint(from: "127.0.0.1:1080"))
        XCTAssertNil(WebView.endpoint(from: "127.0.0.1"), "адрес без порта не годится")
        XCTAssertNil(WebView.endpoint(from: ":1080"), "адрес без узла не годится")
        XCTAssertNil(WebView.endpoint(from: "127.0.0.1:не-порт"))
    }

    /// Введённое без схемы считается адресом, а не поисковым запросом.
    ///
    /// Отправлять напечатанное в поисковую службу значило бы отдавать ей
    /// всё, что человек набирает, — включая то, ради сокрытия чего он и
    /// включил туннель.
    func testTypedTextBecomesAnAddressNotASearch() {
        XCTAssertEqual(
            WebView.url(from: "example.org")?.absoluteString,
            "https://example.org"
        )
        XCTAssertEqual(
            WebView.url(from: "https://example.org/путь")?.scheme,
            "https"
        )
        XCTAssertNil(WebView.url(from: "   "))
    }


    /// Дождаться, пока скрипт затыкания доказуемо отработал.
    ///
    /// `settle(view)` говорит только о том, что навигация завершилась.
    /// Между этим и исполнением скрипта, объявленного «в начале
    /// документа», есть окно, и проверки то попадали в него, то нет —
    /// отсюда плавающие отказы, каждый раз в другом месте.
    ///
    /// Ожидание не маскирует поломку, а разделяет две разные: если
    /// скрипт не исполнится вовсе, ожидание истечёт и скажет об этом
    /// прямо. Защита, срабатывающая три раза из четырёх, течёт один раз
    /// из четырёх — и знать об этом надо от проверки, а не от
    /// пользователя.
    private func awaitHardening(_ view: WKWebView, file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<50 {
            let ready = try? await view.evaluateJavaScript(
                "typeof window.__atlasSealFailures !== 'undefined'"
            )
            if (ready as? Bool) == true { return }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTFail("скрипт затыкания не исполнился за отведённое время", file: file, line: line)
    }

    /// Скрипт затыкания действительно убирает точки входа.
    ///
    /// Проверяется исполнением в настоящем `WKWebView`: скрипт
    /// объявляется, страница загружается из строки, и у неё же
    /// спрашивается, что осталось. Проверять текст скрипта глазами
    /// бессмысленно — важно поведение движка.
    func testHardeningRemovesTheLeakingEntryPoints() async throws {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.userContentController.addUserScript(Hardening.userScript())

        let view = WKWebView(frame: .zero, configuration: configuration)
        view.loadHTMLString("<html><head></head><body>проба</body></html>", baseURL: nil)
        try await settle(view)
        try await awaitHardening(view)

        // Скрипт копит причины неудач вместо того, чтобы их глотать.
        // Без них отказ сообщает только «осталась доступной» — и
        // разбираться приходится вслепую, без движка под рукой.
        let failures =
            (try? await view.evaluateJavaScript(
                "(window.__atlasSealFailures || ['список недоступен']).join(' | ')"
            )) as? String ?? "скрипт не исполнился"

        for name in ["window.RTCPeerConnection", "window.WebTransport", "window.PublicKeyCredential"] {
            let answer = try await view.evaluateJavaScript("typeof \(name)")
            XCTAssertEqual(
                answer as? String, "undefined",
                "\(name) осталась доступной странице. Причины: \(failures)"
            )
        }
        let credentials = try await view.evaluateJavaScript("typeof navigator.credentials")
        XCTAssertEqual(credentials as? String, "undefined", "WebAuthn остался доступен")
    }

    /// Убранное нельзя вернуть со стороны страницы.
    ///
    /// Свойства объявлены неконфигурируемыми именно ради этого: иначе
    /// достаточно одной строки скрипта на странице, чтобы утечка
    /// вернулась.
    func testTheRemovedEntryPointsCannotBeRestored() async throws {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.userContentController.addUserScript(Hardening.userScript())

        let view = WKWebView(frame: .zero, configuration: configuration)
        view.loadHTMLString("<html><body></body></html>", baseURL: nil)
        try await settle(view)
        try await awaitHardening(view)

        let attempt = """
            (function () {
                try { window.RTCPeerConnection = function () {}; } catch (e) {}
                try {
                    Object.defineProperty(window, 'WebTransport', { value: function () {} });
                } catch (e) {}
                return typeof window.RTCPeerConnection + ',' + typeof window.WebTransport;
            })();
            """
        // Тот же приём, что и в соседних проверках: без диагностики
        // отказ не отличает «затыкание не сработало» от «скрипт вообще
        // не исполнялся». Разница здесь решающая — второе означало бы,
        // что защиты нет ни в проверке, ни у пользователя.
        let ran =
            (try? await view.evaluateJavaScript(
                "typeof window.__atlasSealFailures === 'undefined' "
                    + "? 'скрипт не исполнялся' "
                    + ": ('исполнялся, неудачи: ' + (window.__atlasSealFailures.join(' | ') || 'нет'))"
            )) as? String ?? "опрос не удался"

        let answer = try await view.evaluateJavaScript(attempt)
        XCTAssertEqual(
            answer as? String, "undefined,undefined",
            "страница вернула себе убранную возможность. Скрипт: \(ran)"
        )
    }

    /// Подсказки предзагрузки вычищаются из дерева.
    func testPrefetchHintsAreStripped() async throws {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.userContentController.addUserScript(Hardening.userScript())

        let view = WKWebView(frame: .zero, configuration: configuration)
        view.loadHTMLString(
            """
            <html><head>
            <link rel="dns-prefetch" href="//tracker.example.com">
            <link rel="preconnect" href="//cdn.example.com">
            <link rel="stylesheet" href="data:text/css,">
            </head><body></body></html>
            """,
            baseURL: nil
        )
        try await settle(view)
        try await awaitHardening(view)

        let left = try await view.evaluateJavaScript(
            "document.querySelectorAll('link[rel*=prefetch], link[rel*=preconnect]').length"
        )
        XCTAssertEqual(left as? Int, 0, "подсказка предзагрузки осталась в дереве")

        // Безобидная ссылка обязана уцелеть: вычищать всё подряд —
        // значит сломать страницы без нужды.
        // Что именно осталось в дереве — единственный способ отличить
        // «вычистили лишнее» от «движок сам не создал элемент».
        // Догадываться об этом, не имея движка под рукой, бесполезно:
        // прошлый раз причина оказалась не той, что казалась.
        let survivors =
            (try? await view.evaluateJavaScript(
                "Array.from(document.querySelectorAll('link'))"
                    + ".map(function (l) { return l.outerHTML; }).join(' | ') || 'ни одной ссылки'"
            )) as? String ?? "опрос не удался"
        let failures =
            (try? await view.evaluateJavaScript(
                "(window.__atlasSealFailures || []).join(' | ') || 'нет'"
            )) as? String ?? "опрос не удался"

        let kept = try await view.evaluateJavaScript(
            "document.querySelectorAll('link[rel=stylesheet]').length"
        )
        XCTAssertEqual(
            kept as? Int, 1,
            "вычищено лишнее. Осталось: \(survivors). Неудачи затыкания: \(failures)"
        )
    }

    /// Дать движку дойти до конца загрузки.
    private func settle(_ view: WKWebView) async throws {
        for _ in 0..<200 where view.isLoading {
            try await Task.sleep(nanoseconds: 25_000_000)
        }
        // Наблюдателю за деревом нужен ещё один оборот цикла.
        try await Task.sleep(nanoseconds: 150_000_000)
    }
}
