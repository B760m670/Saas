//
//  Установка профиля конфигурации.
//
//  iOS ставит `.mobileconfig` только через Safari: файл надо отдать по
//  ссылке, которую откроет система. Отсюда крошечный сервер на петле —
//  он живёт ровно столько, сколько открыт этот экран.
//
//  Вызовы намеренно старые: нижняя граница — iOS 14, см. `MainScreen`.
//

import SwiftUI
import UIKit

struct ProfileScreen: View {
    let xml: String?
    // `@Environment(\.dismiss)` появился в iOS 15; здесь нужен способ,
    // работающий с iOS 14.
    @Environment(\.presentationMode) private var presentation
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
                        .foregroundColor(.secondary)
                    }

                    Section(
                        footer: Text(
                            "Откроется Safari и предложит установить профиль. "
                                + "Это ожидаемо: другого способа поставить "
                                + "профиль на iOS нет."
                        )
                    ) {
                        Button("Открыть и установить") {
                            let running = ProfileServer(xml: xml)
                            server = running
                            running.start { url in
                                UIApplication.shared.open(url)
                            }
                        }
                    }
                } else {
                    Text("Профиль недоступен: прокси не работает.")
                        .foregroundColor(.secondary)
                }
            }
            .navigationBarTitle("Профиль Wi-Fi", displayMode: .inline)
            .navigationBarItems(
                leading: Button("Закрыть") {
                    presentation.wrappedValue.dismiss()
                }
            )
        }
        .onDisappear { server?.stop() }
    }
}
