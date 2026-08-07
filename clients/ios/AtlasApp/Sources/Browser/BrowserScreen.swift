//
//  Встроенный браузер.
//
//  Без расширения сети это единственный способ пользоваться туннелем на
//  мобильном интернете: профиль конфигурации привязан к сети Wi-Fi, а
//  здесь трафик уходит в прокси независимо от того, чем подключён
//  телефон.
//
//  # Что на экране сказано прямо
//
//  Браузер закрывает три известных пути утечки (см. `Hardening`), но
//  один из них — подсказки предзагрузки — закрывается **по мере сил**, а
//  не наверняка. Умолчать об этом нельзя: человек, считающий себя
//  защищённым полностью, рискует иначе, чем знающий про остаток. Отсюда
//  раздел «Что защищено», доступный прямо из строки адреса.
//

import SwiftUI

struct BrowserScreen: View {
    /// Адрес локального прокси, `хост:порт`.
    let proxy: String

    @State private var state = BrowserState()
    @State private var command: BrowserCommand?
    @State private var input = ""
    @State private var showingProtection = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                addressBar
                if state.loading {
                    ProgressView(value: state.progress)
                        .progressViewStyle(.linear)
                }
                if let failure = state.failure {
                    failureBar(failure)
                }
                WebView(proxy: proxy, state: $state, command: $command)
            }
            .navigationTitle(state.title.isEmpty ? "Браузер" : state.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Закрыть") { dismiss() }
                }
                ToolbarItemGroup(placement: .bottomBar) {
                    Button { command = .back } label: {
                        Image(systemName: "chevron.left")
                    }
                    .disabled(!state.canGoBack)

                    Button { command = .forward } label: {
                        Image(systemName: "chevron.right")
                    }
                    .disabled(!state.canGoForward)

                    Spacer()

                    Button { command = state.loading ? .stop : .reload } label: {
                        Image(systemName: state.loading ? "xmark" : "arrow.clockwise")
                    }

                    Spacer()

                    Button { showingProtection = true } label: {
                        Label("Защита", systemImage: shieldName)
                    }
                }
            }
            .sheet(isPresented: $showingProtection) {
                ProtectionScreen(applied: state.hardening)
            }
        }
    }

    private var shieldName: String {
        state.hardening?.proxied == true ? "lock.shield" : "exclamationmark.shield"
    }

    private var addressBar: some View {
        HStack(spacing: 8) {
            Image(systemName: shieldName)
                .foregroundStyle(state.hardening?.proxied == true ? .green : .red)

            TextField("адрес", text: $input)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                .submitLabel(.go)
                .onSubmit { command = .load(input) }
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .onChange(of: state.address) { address in
            // Строка обновляется вслед за переходами, но не мешает
            // печатать: пока поле в работе, его никто не трогает.
            if !address.isEmpty { input = address }
        }
    }

    private func failureBar(_ text: String) -> some View {
        Text(text)
            .font(.footnote)
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(.red)
    }
}

/// Что защищено, а что нет — без умолчаний.
struct ProtectionScreen: View {
    let applied: Hardening.Applied?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if applied?.proxied == true {
                        Label("Трафик страниц идёт через туннель", systemImage: "checkmark.circle")
                            .foregroundStyle(.green)
                    } else {
                        Label(
                            "Прокси недоступен — страницы не загружаются",
                            systemImage: "xmark.circle"
                        )
                        .foregroundStyle(.red)
                    }
                } footer: {
                    Text(
                        "Настройка прокси для веб-представления появилась в iOS 17. "
                            + "Без неё браузер загружал бы страницы напрямую, поэтому "
                            + "он не загружает их вовсе."
                    )
                }

                Section {
                    ForEach(applied?.removed ?? [], id: \.self) { name in
                        Label(name, systemImage: "checkmark")
                            .font(.system(.body, design: .monospaced))
                    }
                } header: {
                    Text("Отключено надёжно")
                } footer: {
                    Text(
                        "Эти возможности ходят в сеть мимо прокси. Они убраны до "
                            + "того, как страница выполнит первую строку, и вернуть их "
                            + "она не может. Цена: не сработают вход по ключам доступа "
                            + "(passkeys) и видеозвонки в браузере."
                    )
                }

                Section {
                    ForEach(applied?.bestEffort ?? [], id: \.self) { name in
                        Label(name, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                } header: {
                    Text("Закрыто по мере сил")
                } footer: {
                    Text(
                        "Задаются разметкой страницы и вычищаются наблюдателем. "
                            + "Между появлением такой подсказки и её удалением есть "
                            + "окно, в которое запрос имени может успеть уйти мимо "
                            + "туннеля. Это ограничение WebKit, а не недоделка: "
                            + "публичного способа выключить их нет."
                    )
                }
            }
            .navigationTitle("Что защищено")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Закрыть") { dismiss() }
                }
            }
        }
    }
}
