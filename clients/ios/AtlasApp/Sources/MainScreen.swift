//
//  Главный экран: одна кнопка и честный ответ на вопрос «работает?».
//
//  Принцип из docs/05-clients.md: пользователю не нужно знать слова
//  «VLESS», «REALITY» и «PAC», чтобы включить обход. Но всё, что
//  происходит, он обязан иметь возможность увидеть — отсюда экран
//  правил и показ адреса.
//

import AtlasCore
import SwiftUI

struct MainScreen: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingProfile = false
    @State private var showingRules = false
    @State private var ssid = ""

    var body: some View {
        NavigationView {
            Form {
                keySection
                switchSection
                if model.state.isRunning {
                    runningSection
                }
                aboutSection
            }
            .navigationTitle("ATLAS")
        }
        .navigationViewStyle(.stack)
        .sheet(isPresented: $showingRules) {
            RulesScreen(script: model.pacScript() ?? "правила недоступны")
        }
    }

    private var keySection: some View {
        Section("Ключ доступа") {
            TextField("vless://…", text: $model.key)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .onChange(of: model.key) { _ in model.refreshDescription() }
                .disabled(model.state.isRunning)

            if let described = model.described {
                LabeledContent("Точка выхода", value: "\(described.host):\(described.port)")
                LabeledContent("Сайт прикрытия", value: described.sni ?? "—")
                if described.reality {
                    Label("REALITY", systemImage: "checkmark.shield")
                        .foregroundStyle(.secondary)
                }
            } else if !model.key.isEmpty {
                Label("Ключ не разбирается", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
        }
    }

    private var switchSection: some View {
        Section {
            Button(action: model.toggle) {
                HStack {
                    Image(systemName: model.state.isRunning ? "stop.circle" : "play.circle")
                    Text(model.state.isRunning ? "Выключить" : "Включить")
                }
            }
            .disabled(model.described == nil)

            if case .failed(let reason) = model.state {
                // Причина показывается как есть: догадываться, что
                // означает «не удалось подключиться», пользователь не
                // обязан.
                Text(reason)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
    }

    private var runningSection: some View {
        Section("Работает") {
            if case .running(let address) = model.state {
                LabeledContent("Прокси", value: address)
            }
            if let stats = model.stats {
                LabeledContent("Соединений", value: "\(stats.accepted)")
                LabeledContent("Передано", value: format(stats.toTarget))
                LabeledContent("Принято", value: format(stats.fromTarget))
            }

            TextField("Имя сети Wi-Fi", text: $ssid)
                .autocorrectionDisabled()
            Button("Настроить эту сеть Wi-Fi") { showingProfile = true }
                .disabled(ssid.isEmpty)

            Button("Показать правила маршрутизации") { showingRules = true }
        }
        .sheet(isPresented: $showingProfile) {
            ProfileScreen(xml: model.mobileconfig(ssid: ssid, password: nil))
        }
    }

    private var aboutSection: some View {
        Section {
            LabeledContent("Версия ядра", value: Atlas.version)
            Text(
                "На мобильном интернете системная настройка прокси недоступна — "
                    + "там работает только встроенный браузер. На Wi-Fi профиль "
                    + "уводит через ядро весь системный трафик."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    private func format(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }
}

/// Показ правил: то, что идёт мимо туннеля, обязано быть видно.
struct RulesScreen: View {
    let script: String

    var body: some View {
        NavigationView {
            ScrollView {
                Text(script)
                    .font(.system(.footnote, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .navigationTitle("Правила")
        }
    }
}
