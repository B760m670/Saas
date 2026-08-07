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

import AtlasCore
import SwiftUI
import UIKit
import XCTest

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

    /// Экран строится и раскладывается без падения.
    ///
    /// Это то, чего не ловит сборка. Вызов, которого нет в целевой
    /// версии iOS, падает в момент обращения — здесь он и обратится.
    @MainActor
    func testTheMainScreenLaysOutWithoutCrashing() {
        let model = AppModel()
        let host = UIHostingController(rootView: MainScreen().environmentObject(model))

        host.loadViewIfNeeded()
        host.view.frame = CGRect(x: 0, y: 0, width: 390, height: 844)
        host.view.setNeedsLayout()
        host.view.layoutIfNeeded()

        XCTAssertFalse(host.view.subviews.isEmpty, "экран не построился")
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
