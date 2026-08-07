//
//  Мостик между состоянием подключения и SwiftUI.
//
//  Здесь намеренно почти ничего нет: вся логика в `ProxyController`,
//  который проверяется тестами на Linux. Задача этого файла — перевести
//  извещения в `@Published` и уйти с дороги.
//

import AtlasCore
import Combine
import Foundation

@MainActor
final class AppModel: ObservableObject {
    /// Ключ доступа, введённый пользователем.
    @Published var key: String = ""
    /// Что показать про ключ, пока он не включён.
    @Published var described: KeyDescription?
    /// Состояние подключения.
    @Published private(set) var state: ConnectionState = .idle
    /// Счётчики, обновляемые пока прокси работает.
    @Published private(set) var stats: ProxyStats?
    /// Домены, идущие мимо туннеля.
    @Published var directDomains: [String] = []

    private var controller: ProxyController?
    private var ticker: AnyCancellable?

    /// Ключ хранится в связке ключей, а не в `UserDefaults`.
    ///
    /// `UserDefaults` — это обычный plist в песочнице приложения,
    /// попадающий в резервные копии. Ключ доступа даёт вход в точку
    /// выхода, и обращаться с ним как с настройкой громкости нельзя.
    private let storage = KeychainStorage(account: "atlas.access.key")

    init() {
        key = storage.load() ?? ""
        let controller = ProxyController { [weak self] state in
            Task { @MainActor in self?.state = state }
        }
        self.controller = controller
        refreshDescription()
    }

    /// Разобрать введённый ключ и показать, куда он ведёт.
    func refreshDescription() {
        described = try? controller?.inspect(key: key)
    }

    /// Включить или выключить.
    func toggle() {
        guard let controller else { return }
        if state.isRunning {
            controller.stop()
            stopTicking()
        } else if described == nil {
            // Ключа нет — включаемся ярусом T0. Это не запасной путь и
            // не полумера: большинству ничего другого и не нужно.
            controller.startDirect()
            startTicking()
        } else {
            storage.save(key)
            controller.start(key: key, rules: RoutingRules(direct: directDomains))
            startTicking()
        }
    }

    /// Профиль конфигурации для текущей сети.
    func mobileconfig(ssid: String, password: String?) -> String? {
        controller?.mobileconfig(ssid: ssid, wifiPassword: password)
    }

    /// Скрипт правил — чтобы пользователь видел, что идёт мимо туннеля.
    func pacScript() -> String? {
        controller?.pacScript()
    }

    private func startTicking() {
        ticker = Timer.publish(every: 1, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self else { return }
                self.stats = self.controller?.stats()
            }
    }

    private func stopTicking() {
        ticker?.cancel()
        ticker = nil
        stats = nil
    }
}
