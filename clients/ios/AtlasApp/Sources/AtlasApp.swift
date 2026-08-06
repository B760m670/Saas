//
//  Точка входа приложения.
//
//  Сборка `lite`: без расширения, значит работает под LiveContainer и
//  с бесплатным Apple ID. Весь захват трафика — через локальный прокси
//  и профиль конфигурации, см. docs/05-clients.md.
//

import SwiftUI

@main
struct AtlasApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            MainScreen()
                .environmentObject(model)
        }
    }
}
