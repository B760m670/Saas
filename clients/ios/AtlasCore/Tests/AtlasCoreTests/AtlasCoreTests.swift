//
//  Проверка обёртки над границей C.
//
//  Проверяется ровно то, ради чего обёртка существует: что ошибиться
//  теперь нельзя. Строки освобождаются, причина отказа доходит,
//  остановленный прокси отвечает отказом, а не порчей памяти.
//
//  Тесты идут на Linux, рядом с ядром. Ни UIKit, ни устройства для
//  этого не нужно — и это осознанное свойство пакета: то, что можно
//  проверить без iPhone, проверяется без iPhone.
//

import XCTest

@testable import AtlasCore

/// Ключ, годный по форме. Соединяться по нему тесты не просят.
private let sampleKey = """
    vless://11111111-2222-3333-4444-555555555555@127.0.0.1:8443\
    ?type=tcp&security=reality&sni=www.microsoft.com\
    &pbk=gJlCetp4vTHnF1QNWPaer9qTEuFPln_LskAsPGzMXnI&sid=dead\
    &fp=chrome&flow=xtls-rprx-vision#проба
    """

final class AtlasCoreTests: XCTestCase {

    func testVersionIsReported() {
        XCTAssertFalse(Atlas.version.isEmpty)
        XCTAssertNotEqual(Atlas.version, "неизвестна")
    }

    func testKeyIsDescribedWithoutCredentials() throws {
        let described = try Atlas.describe(key: sampleKey)

        XCTAssertEqual(described.host, "127.0.0.1")
        XCTAssertEqual(described.port, 8443)
        XCTAssertEqual(described.sni, "www.microsoft.com")
        XCTAssertEqual(described.tag, "проба")
        XCTAssertTrue(described.reality)

        // Учётные данные не должны попадать в описание: оно уходит на
        // экран и в журналы.
        let mirror = String(describing: described)
        XCTAssertFalse(mirror.contains("11111111"), "в описании оказался UUID: \(mirror)")
    }

    func testABrokenKeyExplainsItself() {
        XCTAssertThrowsError(try Atlas.describe(key: "не-ключ")) { error in
            guard let error = error as? AtlasError else {
                return XCTFail("не тот тип ошибки: \(error)")
            }
            XCTAssertTrue(
                error.reason.contains("разбирается"),
                "отказ без внятной причины: \(error.reason)"
            )
        }
    }

    /// Отказ обязан объясняться и после успешных вызовов.
    ///
    /// Причина живёт в памяти потока и обнуляется при чтении. Если
    /// обёртка забудет её забрать, следующий отказ покажет чужую старую
    /// причину — худший вид диагностики.
    func testAnErrorDoesNotLeakIntoTheNextOne() {
        XCTAssertThrowsError(try Atlas.describe(key: "первый мусор"))
        XCTAssertNoThrow(try Atlas.describe(key: sampleKey))
        XCTAssertThrowsError(try Atlas.describe(key: "второй мусор")) { error in
            let reason = (error as? AtlasError)?.reason ?? ""
            XCTAssertTrue(reason.contains("разбирается"), "причина протухла: \(reason)")
        }
    }

    func testProxyReportsTheAddressItActuallyTook() throws {
        let proxy = try AtlasProxy(key: sampleKey)
        defer { proxy.stop() }

        let address = try proxy.address
        XCTAssertTrue(address.hasPrefix("127.0.0.1:"), "не тот адрес: \(address)")
        XCTAssertFalse(address.hasSuffix(":0"), "порт не сообщён: \(address)")
        XCTAssertTrue(proxy.isRunning)
    }

    func testRulesReachTheScript() throws {
        let rules = RoutingRules(direct: ["gosuslugi.ru"], blocked: ["ads.example.com"])
        let proxy = try AtlasProxy(key: sampleKey, rules: rules)
        defer { proxy.stop() }

        let script = try proxy.pacScript
        XCTAssertTrue(script.contains("gosuslugi.ru"), "правило не дошло: \(script)")
        XCTAssertTrue(script.contains("ads.example.com"), "правило не дошло: \(script)")
        XCTAssertTrue(script.contains("FindProxyForURL"))
    }

    /// Имя, которое сломало бы скрипт, обязано быть отвергнуто ядром.
    func testAHostileRuleIsRefused() {
        let rules = RoutingRules(direct: ["example.org\" ; return \"DIRECT"])
        XCTAssertThrowsError(try AtlasProxy(key: sampleKey, rules: rules))
    }

    func testTheProfilePointsAtThisVeryProxy() throws {
        let proxy = try AtlasProxy(key: sampleKey)
        defer { proxy.stop() }

        let profile = try proxy.mobileconfig(ssid: "Дом")
        let expected = try proxy.pacURL.absoluteString

        XCTAssertTrue(profile.contains("com.apple.wifi.managed"))
        XCTAssertTrue(profile.contains(expected), "профиль указывает не сюда: \(expected)")
        // Молчаливый уход мимо туннеля обязан быть запрещён.
        XCTAssertTrue(profile.contains("ProxyPACFallbackAllowed"))
    }

    func testAStoppedProxyRefusesInsteadOfCrashing() throws {
        let proxy = try AtlasProxy(key: sampleKey)
        XCTAssertNoThrow(try proxy.address)

        proxy.stop()
        XCTAssertFalse(proxy.isRunning)
        // Второй раз — тоже без последствий.
        proxy.stop()

        XCTAssertThrowsError(try proxy.address) { error in
            let reason = (error as? AtlasError)?.reason ?? ""
            XCTAssertTrue(reason.contains("остановлен"), "не тот отказ: \(reason)")
        }
        XCTAssertThrowsError(try proxy.stats())
        XCTAssertThrowsError(try proxy.pacScript)
    }

    /// Счётчики обязаны считать то, что прошло через прокси.
    ///
    /// Проверка не косметическая: она заодно доказывает, что обёртка
    /// разбирает JSON ядра теми же именами полей, которыми ядро их
    /// выдаёт. Расхождение здесь молча вернуло бы нули.
    func testStatsCountWhatWentThrough() throws {
        let proxy = try AtlasProxy(key: sampleKey)
        defer { proxy.stop() }

        let before = try proxy.stats()
        XCTAssertEqual(before.accepted, 0)
        XCTAssertEqual(before.active, 0)

        // Соединение, которому некуда идти: точки выхода за ключом нет.
        // Прокси обязан его принять и записать отказ.
        let address = try proxy.address
        let parts = address.split(separator: ":")
        let port = UInt16(parts[1]) ?? 0
        try? probeConnect(port: port)

        // Обслуживание идёт в своих потоках; дать им дойти до конца.
        var after = try proxy.stats()
        for _ in 0..<100 where after.accepted == 0 {
            Thread.sleep(forTimeInterval: 0.05)
            after = try proxy.stats()
        }
        XCTAssertEqual(after.accepted, 1, "принятое соединение не сосчитано")
    }

    /// Обращение из нескольких потоков не должно ломать дескриптор.
    func testConcurrentUseIsSafe() throws {
        let proxy = try AtlasProxy(key: sampleKey)
        defer { proxy.stop() }

        let group = DispatchGroup()
        for _ in 0..<16 {
            DispatchQueue.global().async(group: group) {
                _ = try? proxy.address
                _ = try? proxy.stats()
                _ = try? proxy.pacScript
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 10), .success)
        XCTAssertTrue(proxy.isRunning)
    }
}

/// Постучаться в прокси и уйти.
private func probeConnect(port: UInt16) throws {
    let socket = FileHandle(fileDescriptor: try openSocket(port: port), closeOnDealloc: true)
    let request = "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n"
    socket.write(Data(request.utf8))
    _ = try? socket.read(upToCount: 64)
}

/// Открыть соединение с локальным портом.
private func openSocket(port: UInt16) throws -> Int32 {
    let handle = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
    guard handle >= 0 else { throw AtlasError(reason: "сокет не открылся") }

    var where_ = sockaddr_in()
    where_.sin_family = sa_family_t(AF_INET)
    where_.sin_port = port.bigEndian
    where_.sin_addr.s_addr = inet_addr("127.0.0.1")

    let connected = withUnsafePointer(to: &where_) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
            connect(handle, address, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 else {
        close(handle)
        throw AtlasError(reason: "соединение не установилось")
    }
    return handle
}

/// Переходы состояния подключения.
///
/// Проверяются здесь, а не на устройстве, именно поэтому логика и
/// вынесена из SwiftUI: представление осталось тонким, а всё, что может
/// сломаться, — проверяемым.
final class ProxyControllerTests: XCTestCase {

    func testStartAndStopAreReported() throws {
        let observed = Observed()
        let controller = ProxyController { state in observed.append(state) }

        let started = controller.start(key: sampleKey)
        XCTAssertTrue(started.isRunning, "не включилось: \(started)")
        XCTAssertTrue(controller.current.isRunning)

        controller.stop()
        XCTAssertEqual(controller.current, .idle)

        XCTAssertEqual(observed.states.count, 2, "извещений не столько: \(observed.states)")
        XCTAssertEqual(observed.states.last, .idle)
    }

    func testStoppingTwiceDoesNotReportTwice() {
        let observed = Observed()
        let controller = ProxyController { state in observed.append(state) }

        controller.start(key: sampleKey)
        controller.stop()
        controller.stop()
        controller.stop()

        // Состояние не менялось — извещать не о чем.
        XCTAssertEqual(observed.states.filter { $0 == .idle }.count, 1)
    }

    func testABrokenKeyLeavesAnExplainedFailure() {
        let controller = ProxyController()
        let outcome = controller.start(key: "не-ключ")

        guard case .failed(let reason) = outcome else {
            return XCTFail("отказ обязан объясняться: \(outcome)")
        }
        XCTAssertTrue(reason.contains("разбирается"), "невнятная причина: \(reason)")
        XCTAssertEqual(controller.current, outcome)
    }

    /// Повторное включение перезапускает, а не молчит.
    func testStartingAgainRebinds() throws {
        let controller = ProxyController()
        defer { controller.stop() }

        guard case .running(let first) = controller.start(key: sampleKey) else {
            return XCTFail("первый запуск не удался")
        }
        guard case .running(let second) = controller.start(key: sampleKey) else {
            return XCTFail("второй запуск не удался")
        }
        XCTAssertNotEqual(first, second, "перезапуск обязан занять другой порт")
    }

    /// Пока выключено, профиля не бывает.
    func testNoProfileWhileStopped() {
        let controller = ProxyController()
        XCTAssertNil(controller.mobileconfig(ssid: "Дом"))
        XCTAssertNil(controller.pacScript())
        XCTAssertNil(controller.stats())

        controller.start(key: sampleKey)
        XCTAssertNotNil(controller.mobileconfig(ssid: "Дом"))
        XCTAssertNotNil(controller.pacScript())
        controller.stop()
        XCTAssertNil(controller.mobileconfig(ssid: "Дом"))
    }
}

/// Собиратель извещений.
private final class Observed: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [ConnectionState] = []

    var states: [ConnectionState] {
        lock.lock()
        defer { lock.unlock() }
        return seen
    }

    func append(_ state: ConnectionState) {
        lock.lock()
        seen.append(state)
        lock.unlock()
    }
}
