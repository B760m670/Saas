//
//  Главный экран: одна кнопка и честный ответ на вопрос «работает?».
//
//  Принцип из docs/05-clients.md: пользователю не нужно знать слова
//  «VLESS», «REALITY» и «PAC», чтобы включить обход. Но всё, что
//  происходит, он обязан иметь возможность увидеть — отсюда экран
//  правил и показ адреса.
//
//  # Почему здесь старые вызовы SwiftUI
//
//  Нижняя граница — iOS 14: это минимум, поддерживаемый самим
//  LiveContainer, а именно под ним живёт сборка `lite`. Поэтому здесь
//  нет ни `LabeledContent` (iOS 16), ни `Section("строка")`,
//  `.foregroundStyle`, `.autocorrectionDisabled`,
//  `.textInputAutocapitalization` (все iOS 15). Всё это выглядит
//  современнее и молча отрезало бы часть тех, ради кого сборка `lite`
//  и существует.
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
            .navigationBarTitle("ATLAS")
        }
        .navigationViewStyle(StackNavigationViewStyle())
        .sheet(isPresented: $showingRules) {
            RulesScreen(script: model.pacScript() ?? "правила недоступны")
        }
    }

    private var keySection: some View {
        Section(header: Text("Ключ доступа")) {
            TextField("vless://…", text: $model.key)
                .disableAutocorrection(true)
                .autocapitalization(.none)
                .onChange(of: model.key) { _ in model.refreshDescription() }
                .disabled(model.state.isRunning)

            if let described = model.described {
                Row(title: "Точка выхода", value: "\(described.host):\(described.port)")
                Row(title: "Сайт прикрытия", value: described.sni ?? "—")
                if described.reality {
                    Label("REALITY", systemImage: "checkmark.shield")
                        .foregroundColor(.secondary)
                }
            } else if !model.key.isEmpty {
                Label("Ключ не разбирается", systemImage: "exclamationmark.triangle")
                    .foregroundColor(.orange)
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
                    .foregroundColor(.red)
            }
        }
    }

    private var runningSection: some View {
        Section(header: Text("Работает")) {
            if case .running(let address) = model.state {
                Row(title: "Прокси", value: address)
            }
            if let stats = model.stats {
                Row(title: "Соединений", value: "\(stats.accepted)")
                Row(title: "Передано", value: format(stats.toTarget))
                Row(title: "Принято", value: format(stats.fromTarget))
            }

            TextField("Имя сети Wi-Fi", text: $ssid)
                .disableAutocorrection(true)
            Button("Настроить эту сеть Wi-Fi") { showingProfile = true }
                .disabled(ssid.isEmpty)

            Button("Показать правила маршрутизации") { showingRules = true }
        }
        .sheet(isPresented: $showingProfile) {
            ProfileScreen(xml: model.mobileconfig(ssid: ssid, password: nil))
        }
    }

    private var aboutSection: some View {
        Section(
            footer: Text(
                "На мобильном интернете системная настройка прокси недоступна — "
                    + "там работает только встроенный браузер. На Wi-Fi профиль "
                    + "уводит через ядро весь системный трафик."
            )
        ) {
            Row(title: "Версия ядра", value: Atlas.version)
        }
    }

    private func format(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }
}

/// Строка «название — значение».
///
/// Своя, потому что `LabeledContent` появился только в iOS 16, а
/// нижняя граница здесь — iOS 14.
private struct Row: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title)
            Spacer(minLength: 12)
            Text(value)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
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
            .navigationBarTitle("Правила")
        }
    }
}
