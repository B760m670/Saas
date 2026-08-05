# 05 — Клиенты по платформам

---

## 1. iOS — начинаем отсюда, и здесь есть проблема

### 1.1 Как вообще устроен VPN на iOS

Есть ровно три способа увести трафик приложения/системы:

| Способ | Что нужно | Custom-протокол |
|---|---|---|
| **Personal VPN** (`NEVPNManager`) | entitlement `com.apple.developer.networking.vpn.api` | ❌ только встроенные IKEv2/IPsec |
| **Packet Tunnel Provider** (`NEPacketTunnelProvider`) | entitlement `com.apple.developer.networking.networkextension` + **отдельный таргет app extension** | ✅ любой |
| **Локальный прокси в самом приложении** | ничего | ✅, но только свой трафик или трафик через системную настройку прокси |

Для VLESS/REALITY нужен **Packet Tunnel Provider**. Это не библиотека внутри приложения — это **отдельный процесс-расширение**, который система запускает по своим правилам, регистрируя его через установленный бандл.

### 1.2 Проблема с LiveContainer — прямо

> **LiveContainer не поддерживает app extensions. Вообще.**

Причины архитектурные, а не временные:
- LiveContainer запускает гостевое приложение **внутри своего процесса**, подменяя окружение. Расширение — это отдельный процесс, который порождает **система** (SpringBoard/`pkd`).
- SpringBoard не знает о приложениях внутри LiveContainer — они не зарегистрированы в базе установленных приложений. Зарегистрировать расширение невозможно.
- **Entitlements гостевого приложения не применяются** — гостевое приложение работает с entitlements хоста (LiveContainer), а у него нет `networkextension`.
- Каждое расширение требует отдельный App ID — а лимит App ID у бесплатного Apple ID это как раз то, что LiveContainer обходит.

**Вывод: полноценный VPN-туннель через LiveContainer технически невозможен.** Это не то, что можно «доделать» — это следует из модели процессов iOS.

### 1.3 Что делать — три реальных пути

#### Путь A. **LiveContainer-совместимая сборка: локальный прокси** (работает у всех, бесплатно)

Приложение внутри себя поднимает ядро с локальным inbound `127.0.0.1:1080` (SOCKS5) и `127.0.0.1:1087` (HTTP). Дальше:

- **Wi-Fi**: в настройках сети вручную (или через `.mobileconfig`-профиль, который приложение сгенерирует) прописывается HTTP-прокси `127.0.0.1:1087`. **Весь системный трафик, уважающий прокси, идёт через ядро.** Это Safari и подавляющее большинство приложений на `URLSession`.
- **PAC-файл**: iOS нативно поддерживает Proxy Auto-Config — можно раздавать правила маршрутизации (что напрямую, что через туннель) без всякого VPN.
- **Встроенный браузер** в приложении — гарантированно работает через ядро, без каких-либо системных настроек.

Ограничения — честно:
- ❌ **Не работает на мобильном интернете** (в настройках сотовой сети нет поля прокси без supervised-профиля).
- ❌ Не покрывает приложения, игнорирующие системный прокси, и не покрывает UDP/QUIC (частично лечится запретом QUIC в PAC).
- ✅ Зато **не нужен ни платный аккаунт, ни особые entitlements** — работает ровно в той схеме, что у тебя уже есть.

#### Путь B. **TrollStore** (бесплатно, но только на уязвимых версиях iOS)

TrollStore подписывает IPA с **произвольными entitlements**, включая `networkextension`, постоянно и без 7-дневного истечения. Работает на iOS 14.0–16.6.1 и 17.0 (зависит от устройства/эксплойта). На современных iOS 17.1+ — нет.

Если целевая аудитория сидит на старых прошивках — это полноценный бесплатный VPN. Собираем **тот же** IPA, что и для пути C.

#### Путь C. **Платный Apple Developer ($99/год) + SideStore/AltStore или свой source** (полноценно, всегда)

Единственный путь к настоящему `NEPacketTunnelProvider` на актуальных iOS. С платным аккаунтом entitlement выдаётся self-serve, галочкой в Xcode. Дальше IPA раздаётся:
- через **AltStore/SideStore source JSON** (то, что ты и планировал — только сам IPA должен быть подписан твоим сертификатом),
- либо через TestFlight (до 10 000 тестеров, но нужна ревью Apple).

### 1.4 Рекомендация

**Делаем пути A и C одной кодовой базой.** Один и тот же Rust- core, одно и то же UI, две схемы сборки:

```
clients/ios/
  AtlasCore/          Swift-обёртка над atlas-ffi (общая)
  AtlasUI/            SwiftUI, общий интерфейс
  AtlasApp/           основное приложение
  AtlasTunnel/        NEPacketTunnelProvider  ← только в сборке "full"
  Configs/
    Atlas-lite.xcconfig   ← без extension, для LiveContainer/бесплатного аккаунта
    Atlas-full.xcconfig   ← с extension, для TrollStore/платного аккаунта
```

CI выпускает **два IPA**: `Atlas-lite.ipa` (LiveContainer, локальный прокси) и `Atlas-full.ipa` (полный туннель), оба публикуются в один **source JSON**, где пользователь выбирает подходящую версию.

Начинаем с **lite** — он работает сразу, без денег и без ожидания.

### 1.5 Технические ограничения iOS, которые надо держать в голове
- **Лимит памяти Network Extension — 50 МБ** (15 МБ на старых устройствах). Превышение = мгновенный kill. Это главный аргумент за Rust-ядро.
- Расширение может быть выгружено системой в любой момент → нужен быстрый (< 300 мс) холодный старт и восстановление состояния.
- Фоновая работа основного приложения жёстко ограничена → всё, что должно работать всегда, живёт в расширении.
- `NEDNSSettings`, `includedRoutes`/`excludedRoutes` — основной инструмент split-tunneling; per-app routing на iOS доступен только через MDM.

---

## 2. Android

Самая свободная платформа. `VpnService` даёт TUN-интерфейс без каких-либо особых разрешений и без root.

```
clients/android/
  app/            Kotlin + Jetpack Compose
  core/           JNI-мост к atlas-ffi (Rust, cargo-ndk)
  service/        AtlasVpnService : VpnService
```

Возможности, которых нет на iOS:
- **Per-app routing из коробки**: `addAllowedApplication()` / `addDisallowedApplication()` по имени пакета. Это прямо закрывает твою задачу «блокировки на отдельные приложения».
- **Режим без VpnService**: локальный SOCKS5 + DPI-десинхронизация (как ByeDPI) — трафик не покидает устройство, максимум скрытности.
- **Always-on VPN** + block-connections-without-VPN = встроенный kill switch.
- **QUIC/UDP** полностью доступен.

Сборка: `.apk` (universal + per-ABI splits) в GitHub Actions, подпись keystore из секретов репозитория.

---

## 3. Windows

```
clients/windows/
  atlas-tray/     Tauri (Rust + web UI)
  atlas-svc/      Windows Service (ядро, работает от SYSTEM)
  drivers/        WinTun (туннель) + WinDivert (desync-режим)
```

Два режима:
1. **Desync** — через WinDivert, как GoodbyeDPI: перехват и модификация исходящих пакетов, **без туннеля**. Мгновенно, ничего не замедляет.
2. **Full tunnel** — WinTun-адаптер + маршруты + kill switch через WFP (Windows Filtering Platform).

Артефакты: portable `.exe` (без установки, важно) + MSI. Подпись — по возможности; без сертификата будет SmartScreen-предупреждение, это надо честно писать в README.

---

## 4. macOS

```
clients/macos/
  AtlasMac/            SwiftUI menu-bar app
  AtlasSysExtension/   NETransparentProxyProvider / NEPacketTunnelProvider
```

Особенности:
- System Extension требует нотаризации Apple для распространения вне App Store; без неё — только с отключённым SIP или через ручное разрешение в Настройках.
- Альтернатива без entitlements: `utun`-интерфейс + `pfctl` из helper-процесса с правами (как делает большинство OSS-клиентов).
- Universal binary (arm64 + x86_64), артефакт `.dmg`.

**Про отсутствие MacBook:** это решаемо. GitHub Actions даёт бесплатные macOS-раннеры (`macos-14`, arm64) для публичных репозиториев. Там можно не только собирать, но и **запускать** — юнит-тесты, интеграционные тесты ядра, скриншот-тесты UI через XCUITest в headless-режиме. Полноценно проверить System Extension в CI не выйдет (нужны права и перезагрузка), но собрать, протестировать ядро и убедиться, что приложение стартует — вполне. Это же относится и к iOS: симулятор в CI прогоняет UI-тесты.

---

## 5. Linux

```
clients/linux/
  atlas-cli/      основной бинарь, headless
  atlas-gui/      Tauri
  packaging/      .deb, .rpm, AppImage, systemd unit
```

- TUN через `/dev/net/tun`, маршрутизация через `netlink`, политика через `nftables`.
- Desync-режим через `nfqueue` (как zapret) — системно, без туннеля.
- Отдельная сборка под **OpenWrt** (ipk, mips/arm) — один роутер закрывает всю квартиру. Это очень сильный сценарий: настроил один раз, работают все устройства, включая телевизор и приставку.

---

## 6. Общий UI/UX — принципы

1. **Одна кнопка.** Главный экран — большая кнопка и статус. Всё остальное — за «Дополнительно».
2. **Никогда не показывать пользователю слово «VLESS»** на первом экране. Он не должен знать про протоколы. Приложение выбирает само.
3. **Честный статус**: не «Подключено», а «Подключено · 42 Мбит/с · через свою точку (Cloudflare)». Пользователь должен понимать, что происходит.
4. **Режим помощи** — отдельный экран с полным объяснением рисков, выключен по умолчанию.
5. **Импорт чужих ключей** — обязателен. Пользователь придёт со своими `vless://`, и это должно просто работать (вставка, QR, файл подписки).
6. **Экспорт своей точки** в виде ключа/QR — чтобы поделиться с родственниками.
7. **Полная локализация** ru/en с первого дня.

---

## 7. Матрица возможностей

| Возможность | iOS lite | iOS full | Android | Windows | macOS | Linux |
|---|---|---|---|---|---|---|
| Системный туннель | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Прокси только Wi-Fi | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DPI-desync без сервера | частично | ✅ | ✅ | ✅ | ✅ | ✅ |
| Per-app маршрутизация | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| UDP / QUIC | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Волонтёрский релей (отдача) | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Автодеплой своей точки | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Работает без платного аккаунта | ✅ | только TrollStore | ✅ | ✅ | ✅ | ✅ |

---

### Источники
- [LiveContainer — README (ограничения, app extensions)](https://github.com/LiveContainer/LiveContainer)
- [Apple — Network Extension entitlement, порядок получения](https://newly.app/how-to/network-extension-entitlement)
- [iOS Network Extensions and Personal VPN: A Developer's Guide](https://antongubarenko.substack.com/p/ios-personal-vpn-and-network-extensions)
- [Проксирование в iOS-приложении без VPN (connectionProxyDictionary)](https://medium.com/@stevjun7/forget-vpns-a-simpler-way-to-proxy-your-ios-app-c64ec1c8a1b9)
- [SideStore + LiveContainer, unlimited sideload 2026](https://fr0stb1rd.gitlab.io/posts/ios-26-unlimited-sideload-sidestore-livecontainer/)
- [ByeDPI / Zapret / GoodbyeDPI — сравнение](https://bypasscore.com/blog/zapret-vs-goodbyedpi-vs-byedpi-comparison)
