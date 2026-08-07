//
//  Главный экран: одна кнопка и честный ответ на вопрос «работает?».
//
//  Принцип из docs/05-clients.md: пользователю не нужно знать слова
//  «VLESS», «REALITY» и «PAC», чтобы включить обход. Но всё, что
//  происходит, он обязан иметь возможность увидеть — отсюда экран
//  правил и показ адреса.
//
//  # Про нижнюю границу
//
//  iOS 16. Основной способ установки — подпись своим сертификатом, а не
//  LiveContainer, поэтому его требование (15+) перестало определять
//  порог. Отсюда `NavigationStack` вместо устаревшего `NavigationView`
//  и `LabeledContent` вместо самодельной строки.
//

import AtlasCore
import SwiftUI

struct MainScreen: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingProfile = false
    @State private var showingRules = false
    @State private var showingBrowser = false
    @State private var ssid = ""

    var body: some View {
        NavigationStack {
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

    /// Что написать на кнопке.
    ///
    /// Без ключа приложение делает другое дело, и называть это тем же
    /// словом «Включить» значило бы скрывать разницу.
    private var title: String {
        if model.state.isRunning { return "Выключить" }
        return model.described == nil ? "Включить без ключа" : "Включить"
    }

    private var switchSection: some View {
        Section {
            // Кнопка живая всегда: без ключа приложение включается ярусом
            // T0 — обход без точки выхода вовсе. Неактивная кнопка
            // здесь означала бы, что без ключа сделать нельзя ничего,
            // а это неправда.
            Button(action: model.toggle) {
                HStack {
                    Image(systemName: model.state.isRunning ? "stop.circle" : "play.circle")
                    Text(title)
                }
            }

            if case .failed(let reason) = model.state {
                // Причина показывается как есть: догадываться, что
                // означает «не удалось подключиться», пользователь не
                // обязан.
                Text(reason)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } footer: {
            if model.described == nil {
                Text(
                    "Без ключа работает обход без точки выхода: трафик идёт "
                        + "напрямую к сайту, но приветствие нарезается так, что "
                        + "цензор не разбирает имя. Это открывает заблокированные "
                        + "сайты, но **не меняет ваш адрес** — ограничения по "
                        + "стране останутся. Для них нужен ключ."
                )
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

            // Браузер стоит первым: он работает везде, включая
            // сотовую связь, а профиль — только в названной сети Wi-Fi.
            Button {
                showingBrowser = true
            } label: {
                Label("Открыть браузер", systemImage: "safari")
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
        .sheet(isPresented: $showingBrowser) {
            if case .running(let address) = model.state {
                BrowserScreen(proxy: address)
            }
        }
    }

    private var aboutSection: some View {
        Section {
            // Две разные версии, и путать их нельзя.
            //
            // Версия ядра вкомпилирована в Rust и не меняется от сборки
            // к сборке — по ней нельзя понять, свежее ли приложение.
            // Версия сборки растёт с каждым изменением основной ветки, и
            // именно её надо называть, сообщая о неполадке.
            LabeledContent("Версия сборки", value: Bundle.main.atlasVersion)
            LabeledContent("Версия ядра", value: Atlas.version)
        } footer: {
            Text(
                "На мобильном интернете системная настройка прокси недоступна — "
                    + "там работает только встроенный браузер. На Wi-Fi профиль "
                    + "уводит через ядро весь системный трафик."
            )
        }
    }

    private func format(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }
}

extension Bundle {
    /// Версия сборки в виде `0.1.7 (7)`.
    ///
    /// Отсутствие полей не считается ошибкой: под LiveContainer и в
    /// наборе тестов пакет не тот, что на устройстве, и падать из-за
    /// справочной строки было бы несоразмерно.
    var atlasVersion: String {
        let short = object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        let build = object(forInfoDictionaryKey: "CFBundleVersion") as? String
        switch (short, build) {
        case let (.some(short), .some(build)) where short != build:
            return "\(short) (\(build))"
        case let (.some(short), _):
            return short
        case let (_, .some(build)):
            return build
        default:
            return "неизвестна"
        }
    }
}

/// Показ правил: то, что идёт мимо туннеля, обязано быть видно.
struct RulesScreen: View {
    let script: String

    var body: some View {
        NavigationStack {
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
