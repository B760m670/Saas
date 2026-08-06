//
//  Хранение ключа доступа в связке ключей.
//
//  Не `UserDefaults`: это обычный plist в песочнице, попадающий в
//  резервные копии. Ключ доступа даёт вход в точку выхода.
//
//  `ThisDeviceOnly` выбрано намеренно: ключ не должен переезжать на
//  другое устройство через резервную копию iCloud.
//

import Foundation
import Security

struct KeychainStorage {
    let account: String

    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "org.atlas.client",
            kSecAttrAccount as String: account,
        ]
    }

    func save(_ value: String) {
        guard let data = value.data(using: .utf8) else { return }
        SecItemDelete(query as CFDictionary)
        guard !value.isEmpty else { return }

        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    func load() -> String? {
        var item = query
        item[kSecReturnData as String] = true
        item[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        guard SecItemCopyMatching(item as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data
        else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
