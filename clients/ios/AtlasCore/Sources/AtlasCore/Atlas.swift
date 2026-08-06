//
//  Обёртка над границей C ядра ATLAS.
//
//  Задача обёртки — не «сделать удобнее», а **не дать ошибиться**.
//  Граница C прощает три вещи, которые в Swift обязаны быть
//  невозможными: забыть освободить строку, прочитать причину отказа не
//  в том потоке и обратиться к уже остановленному прокси. Всё три
//  закрыты здесь, и ничего сверх этого обёртка не делает: логика живёт
//  в ядре, иначе поведение клиента разойдётся с поведением
//  `atlas-proxy`.
//

import CAtlas
import Foundation

/// Отказ ядра.
public struct AtlasError: Error, CustomStringConvertible {
    /// Причина, как её сообщило ядро.
    public let reason: String

    public var description: String { reason }
}

/// Забрать причину последнего отказа.
///
/// Читается **сразу** и в том же потоке, где случился отказ: причина
/// хранится в памяти потока, как `errno`. Отложить чтение — значит
/// потерять диагностику.
private func lastError(_ fallback: String) -> AtlasError {
    guard let raw = atlas_last_error() else {
        return AtlasError(reason: fallback)
    }
    defer { atlas_string_free(raw) }
    return AtlasError(reason: String(cString: raw))
}

/// Забрать строку, выданную ядром, освободив её.
///
/// Единственное место, где владение строкой пересекает границу.
/// Все остальные вызовы идут через него, поэтому забыть
/// `atlas_string_free` попросту негде.
private func takeString(_ raw: UnsafeMutablePointer<CChar>?, _ what: String) throws -> String {
    guard let raw else { throw lastError(what) }
    defer { atlas_string_free(raw) }
    return String(cString: raw)
}

/// Описание ключа доступа.
///
/// Учётных данных здесь нет намеренно: описание уходит на экран и в
/// журналы, а UUID даёт доступ к точке выхода.
public struct KeyDescription: Decodable, Sendable, Equatable {
    /// Прокси-протокол.
    public let proto: String
    /// Узел точки выхода.
    public let host: String
    /// Порт точки выхода.
    public let port: UInt16
    /// Имя точки для показа пользователю.
    public let tag: String
    /// Режим потока XTLS.
    public let flow: String
    /// Вид маскировки.
    public let security: String
    /// Домен сайта прикрытия.
    public let sni: String?
    /// Предлагаемые протоколы прикладного уровня.
    public let alpn: [String]
    /// Используется ли REALITY.
    public let reality: Bool

    private enum CodingKeys: String, CodingKey {
        // `protocol` — ключевое слово Swift, отсюда переименование.
        case proto = "protocol"
        case host, port, tag, flow, security, sni, alpn, reality
    }
}

/// Правила маршрутизации.
public struct RoutingRules: Sendable, Equatable {
    /// Домены, идущие мимо туннеля.
    ///
    /// Каждое исключение — осознанное решение показать оператору связи,
    /// что пользователь ходит на этот сайт. Пустой список по умолчанию
    /// выбран поэтому.
    public var direct: [String]
    /// Домены, которым отказано в соединении.
    public var blocked: [String]

    public init(direct: [String] = [], blocked: [String] = []) {
        self.direct = direct
        self.blocked = blocked
    }

    /// Правила в том виде, в каком их ждёт ядро.
    func json() throws -> String {
        let payload = ["direct": direct, "blocked": blocked]
        let data = try JSONSerialization.data(withJSONObject: payload)
        guard let text = String(data: data, encoding: .utf8) else {
            throw AtlasError(reason: "правила не кодируются")
        }
        return text
    }
}

/// Настройки соединения.
public struct ConnectionOptions: Sendable, Equatable {
    /// Отправлять ли расширение ECH.
    ///
    /// Обычно да: так делает браузер. Но встречаются сети, где
    /// приветствие с ECH рвут, — тогда это выключается.
    public var sendECH: Bool
    /// Предел ожидания TCP.
    public var connectTimeout: TimeInterval?
    /// Предел ожидания чтения.
    public var readTimeout: TimeInterval?

    public init(
        sendECH: Bool = true,
        connectTimeout: TimeInterval? = nil,
        readTimeout: TimeInterval? = nil
    ) {
        self.sendECH = sendECH
        self.connectTimeout = connectTimeout
        self.readTimeout = readTimeout
    }

    /// Перевести в структуру, понятную границе C.
    ///
    /// Ноль в поле времени означает «взять умолчание ядра»: так клиенту
    /// не нужно знать наши константы.
    func asC() -> AtlasOptions {
        AtlasOptions(
            ech: sendECH ? 1 : 0,
            connect_timeout_ms: milliseconds(connectTimeout),
            read_timeout_ms: milliseconds(readTimeout)
        )
    }

    private func milliseconds(_ interval: TimeInterval?) -> CUnsignedInt {
        guard let interval, interval > 0 else { return 0 }
        return CUnsignedInt(min(interval * 1000, Double(CUnsignedInt.max)))
    }
}

/// Показания счётчиков прокси.
public struct ProxyStats: Decodable, Sendable, Equatable {
    /// Сколько соединений принято всего.
    public let accepted: UInt64
    /// Сколько обслуживается прямо сейчас.
    public let active: UInt64
    /// Сколько не удалось довести до туннеля.
    public let failed: UInt64
    /// Байт от клиента к назначению.
    public let toTarget: UInt64
    /// Байт от назначения к клиенту.
    public let fromTarget: UInt64

    private enum CodingKeys: String, CodingKey {
        case accepted, active, failed
        case toTarget = "to_target"
        case fromTarget = "from_target"
    }
}

/// Общие сведения о ядре.
public enum Atlas {
    /// Версия ядра.
    public static var version: String {
        guard let raw = atlas_version() else { return "неизвестна" }
        // Строка статическая — освобождать её нельзя.
        return String(cString: raw)
    }

    /// Разобрать и описать ключ доступа.
    ///
    /// Годится как проверка перед сохранением: пользователю надо
    /// показать, куда он собрался соединяться, и отказать по-человечески,
    /// если ключ испорчен.
    public static func describe(key: String) throws -> KeyDescription {
        let text = try takeString(atlas_key_describe(key), "ключ не разбирается")
        guard let data = text.data(using: .utf8) else {
            throw AtlasError(reason: "описание ключа не в UTF-8")
        }
        return try JSONDecoder().decode(KeyDescription.self, from: data)
    }
}

/// Запущенный локальный прокси.
///
/// Останавливается явным ``stop()`` либо при уничтожении. Обращение к
/// остановленному прокси даёт отказ, а не порчу памяти: указатель
/// обнуляется под замком, и вернуть его назад невозможно.
public final class AtlasProxy: @unchecked Sendable {
    // `@unchecked Sendable` — потому что безопасность здесь
    // обеспечивает замок, а не система типов: `handle` меняется только
    // под ним, а сам прокси в ядре рассчитан на обращения из разных
    // потоков.
    private let lock = NSLock()
    private var handle: OpaquePointer?

    /// Поднять прокси и начать обслуживание.
    ///
    /// Порт `0` в `listen` означает «любой свободный»; занятый адрес
    /// узнаётся из ``address``. Для приложения это существенно:
    /// заданный порт может оказаться занят, а объяснить такую ошибку
    /// пользователю нечем.
    public init(
        key: String,
        listen: String = "127.0.0.1:0",
        options: ConnectionOptions = ConnectionOptions(),
        rules: RoutingRules = RoutingRules()
    ) throws {
        var settings = options.asC()
        let rulesJSON = try rules.json()

        let started = withUnsafePointer(to: &settings) { pointer in
            atlas_proxy_start(key, listen, pointer, rulesJSON)
        }
        guard let started else { throw lastError("прокси не поднялся") }
        handle = started
    }

    deinit {
        stop()
    }

    /// Занятый адрес вида `127.0.0.1:53017`.
    public var address: String {
        get throws {
            try withHandle { try takeString(atlas_proxy_address($0), "адрес недоступен") }
        }
    }

    /// Скрипт правил, который прокси отдаёт по `/proxy.pac`.
    ///
    /// Нужен, чтобы правила можно было **показать**: правила
    /// маршрутизации, которых не видно, — это правила, которым нельзя
    /// доверять.
    public var pacScript: String {
        get throws {
            try withHandle { try takeString(atlas_proxy_pac($0), "скрипт правил недоступен") }
        }
    }

    /// Адрес, по которому лежит скрипт правил.
    public var pacURL: URL {
        get throws {
            guard let url = URL(string: "http://\(try address)/proxy.pac") else {
                throw AtlasError(reason: "адрес скрипта не собирается")
            }
            return url
        }
    }

    /// Показания счётчиков.
    public func stats() throws -> ProxyStats {
        let text = try withHandle {
            try takeString(atlas_proxy_stats($0), "счётчики недоступны")
        }
        guard let data = text.data(using: .utf8) else {
            throw AtlasError(reason: "счётчики не в UTF-8")
        }
        return try JSONDecoder().decode(ProxyStats.self, from: data)
    }

    /// Собрать профиль конфигурации для сети Wi-Fi.
    ///
    /// `automatic` означает профиль с PAC-скриптом: правила берутся у
    /// прокси по сети и меняются без переустановки профиля. Иначе —
    /// один адрес прокси на всё.
    ///
    /// Для сети с защитой пароль **обязателен**: профиль описывает сеть
    /// целиком, и без пароля устройство может перестать к ней
    /// подключаться.
    public func mobileconfig(
        ssid: String,
        automatic: Bool = true,
        wifiPassword: String? = nil
    ) throws -> String {
        let at = try address
        return try takeString(
            atlas_mobileconfig(ssid, at, automatic ? 1 : 0, wifiPassword),
            "профиль не собрался"
        )
    }

    /// Перестать принимать новые соединения.
    ///
    /// Уже открытые доживают своё: обрывать чужую загрузку на полуслове
    /// потому, что нажали «выключить», — худшее из поведений. Повторный
    /// вызов ничего не делает.
    public func stop() {
        lock.lock()
        let taken = handle
        handle = nil
        lock.unlock()
        if let taken {
            atlas_proxy_stop(taken)
        }
    }

    /// Работает ли прокси.
    public var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return handle != nil
    }

    /// Выполнить действие с живым дескриптором.
    private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else {
            throw AtlasError(reason: "прокси уже остановлен")
        }
        return try body(handle)
    }
}
