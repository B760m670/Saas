//
//  Состояние подключения, отделённое от интерфейса.
//
//  Логика «включить — выключить — показать ошибку» живёт здесь, а не в
//  SwiftUI, по одной причине: здесь её можно проверить тестами, а в
//  представлении — нет. На Linux, рядом с ядром, без устройства и без
//  Xcode.
//
//  Представление поверх этого получается тонким: подписаться на
//  изменение состояния и нарисовать его.
//

import Foundation

/// Состояние подключения.
public enum ConnectionState: Sendable, Equatable {
    /// Выключено.
    case idle
    /// Работает; адрес — занятый прокси.
    case running(address: String)
    /// Отказ с объяснением.
    case failed(reason: String)

    /// Работает ли прокси прямо сейчас.
    public var isRunning: Bool {
        if case .running = self { return true }
        return false
    }
}

/// Управление подключением.
///
/// Класс намеренно не знает ни про экран, ни про хранилище ключей:
/// первое — дело представления, второе — дело платформы (Keychain на
/// Apple, Keystore на Android). Здесь только переходы состояния.
public final class ProxyController: @unchecked Sendable {
    private let lock = NSLock()
    private var proxy: AtlasProxy?
    private var state: ConnectionState = .idle

    /// Кого извещать об изменении состояния.
    ///
    /// Вызывается **вне** замка: обработчик почти наверняка захочет
    /// обновить экран, а держать замок во время чужого кода — верный
    /// способ получить взаимную блокировку.
    private let onChange: @Sendable (ConnectionState) -> Void

    public init(onChange: @escaping @Sendable (ConnectionState) -> Void = { _ in }) {
        self.onChange = onChange
    }

    /// Текущее состояние.
    public var current: ConnectionState {
        lock.lock()
        defer { lock.unlock() }
        return state
    }

    /// Проверить ключ, не подключаясь.
    ///
    /// Отдельно от ``start(key:options:rules:)``, потому что показать
    /// пользователю «куда он собрался» надо **до** того, как он нажмёт
    /// «включить».
    public func inspect(key: String) throws -> KeyDescription {
        try Atlas.describe(key: key)
    }

    /// Включить.
    ///
    /// Повторный вызов при работающем прокси перезапускает его с новыми
    /// настройками: пользователь, поменявший ключ и нажавший «включить»,
    /// ожидает именно этого, а не молчаливого игнорирования.
    @discardableResult
    /// Запустить **без ключа** — ярус T0.
    ///
    /// Ни точки выхода, ни аккаунта, ни ключа. Обход достигается
    /// нарезкой приветствия TLS по дороге к настоящему сайту.
    @discardableResult
    public func startDirect(options: ConnectionOptions = ConnectionOptions()) -> ConnectionState {
        stop()
        let outcome: ConnectionState
        do {
            let started = try AtlasProxy(directListen: "127.0.0.1:0", options: options)
            let address = try started.address
            lock.lock()
            proxy = started
            state = .running(address: address)
            lock.unlock()
            outcome = .running(address: address)
        } catch {
            let reason = (error as? AtlasError)?.reason ?? "\(error)"
            lock.lock()
            state = .failed(reason: reason)
            lock.unlock()
            outcome = .failed(reason: reason)
        }
        onChange(outcome)
        return outcome
    }

    public func start(
        key: String,
        options: ConnectionOptions = ConnectionOptions(),
        rules: RoutingRules = RoutingRules()
    ) -> ConnectionState {
        stop()
        let outcome: ConnectionState
        do {
            let started = try AtlasProxy(key: key, options: options, rules: rules)
            let address = try started.address
            lock.lock()
            proxy = started
            state = .running(address: address)
            lock.unlock()
            outcome = .running(address: address)
        } catch {
            let reason = (error as? AtlasError)?.reason ?? "\(error)"
            lock.lock()
            proxy = nil
            state = .failed(reason: reason)
            lock.unlock()
            outcome = .failed(reason: reason)
        }
        onChange(outcome)
        return outcome
    }

    /// Выключить.
    ///
    /// Ничего не делает, если уже выключено, и **не сообщает** об
    /// изменении: состояние не менялось, а лишнее извещение заставило бы
    /// экран моргать на пустом месте.
    public func stop() {
        lock.lock()
        let taken = proxy
        proxy = nil
        let changed = state != .idle
        state = .idle
        lock.unlock()

        taken?.stop()
        if changed {
            onChange(.idle)
        }
    }

    /// Показания счётчиков, если прокси работает.
    public func stats() -> ProxyStats? {
        lock.lock()
        let running = proxy
        lock.unlock()
        return try? running?.stats()
    }

    /// Профиль конфигурации для сети Wi-Fi.
    ///
    /// Возвращает `nil`, если прокси не работает: профиль указывает на
    /// занятый им адрес, и выдавать профиль, ведущий в пустоту, хуже,
    /// чем не выдавать никакого.
    public func mobileconfig(ssid: String, wifiPassword: String? = nil) -> String? {
        lock.lock()
        let running = proxy
        lock.unlock()
        return try? running?.mobileconfig(ssid: ssid, wifiPassword: wifiPassword)
    }

    /// Скрипт правил — чтобы его можно было показать.
    public func pacScript() -> String? {
        lock.lock()
        let running = proxy
        lock.unlock()
        return try? running?.pacScript
    }
}
