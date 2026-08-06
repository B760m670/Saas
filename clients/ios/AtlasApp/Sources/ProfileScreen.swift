//
//  Установка профиля конфигурации.
//
//  iOS ставит `.mobileconfig` только через Safari: файл надо отдать по
//  ссылке, которую откроет система. Отсюда крошечный сервер на петле —
//  он живёт ровно столько, сколько открыт этот экран.
//

import SwiftUI
import UIKit

struct ProfileScreen: View {
    let xml: String?
    @Environment(\.dismiss) private var dismiss
    @State private var server: ProfileServer?

    var body: some View {
        NavigationView {
            Form {
                if let xml {
                    Section {
                        Text(
                            "Профиль настроит прокси для выбранной сети Wi-Fi. "
                                + "Весь системный трафик этой сети пойдёт через ядро."
                        )
                        Text(
                            "Снять профиль можно в Настройках → Основные → "
                                + "VPN и управление устройством."
                        )
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    }

                    Section {
                        Button("Открыть и установить") {
                            let running = ProfileServer(xml: xml)
                            server = running
                            running.start { url in
                                UIApplication.shared.open(url)
                            }
                        }
                    } footer: {
                        Text(
                            "Откроется Safari и предложит установить профиль. "
                                + "Это ожидаемо: другого способа поставить "
                                + "профиль на iOS нет."
                        )
                    }
                } else {
                    Text("Профиль недоступен: прокси не работает.")
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Профиль Wi-Fi")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Закрыть") { dismiss() }
                }
            }
        }
        .onDisappear { server?.stop() }
    }
}
