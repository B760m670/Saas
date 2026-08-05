# 06 — Сборка и дистрибуция через GitHub Actions

---

## 1. Общая схема

```
push / tag / workflow_dispatch
        │
        ├── core-test        (Linux)      cargo test / clippy / fuzz-smoke
        ├── core-build       (matrix)     статические либы под 8 триплетов
        │        │
        │        ├── aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-darwin, aarch64-apple-darwin
        │        ├── aarch64-linux-android, armv7-linux-androideabi, x86_64-linux-android
        │        └── x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu
        │
        ├── ios-build        (macos-14)   → Atlas-lite.ipa, Atlas-full.ipa
        ├── android-build    (ubuntu)     → .apk (splits + universal)
        ├── windows-build    (windows)    → .exe portable + .msi
        ├── macos-build      (macos-14)   → .dmg (universal)
        ├── linux-build      (ubuntu)     → AppImage, .deb, .rpm, OpenWrt .ipk
        │
        └── release          создаёт GitHub Release + обновляет source JSON на Pages
```

**Ограничения бесплатного тарифа:** для публичных репозиториев минуты Actions не тарифицируются, включая macOS-раннеры. Это и есть наш бесплатный CI, в том числе для сборки под Mac, которого нет физически.

---

## 2. iOS: source JSON для AltStore / SideStore / LiveContainer

Ты просил «json-ссылку на источник приложения». Это формат **AltStore Source** — его понимают AltStore, SideStore и совместимые.

Файл публикуется на **GitHub Pages** по постоянному адресу:
```
https://<user>.github.io/<repo>/source.json
```

### 2.1 Структура

```json
{
  "name": "ATLAS",
  "identifier": "dev.atlas.source",
  "subtitle": "Adaptive transport",
  "description": "…",
  "iconURL": "https://…/icon.png",
  "website": "https://github.com/…",
  "tintColor": "#1B6AC9",
  "apps": [
    {
      "name": "ATLAS",
      "bundleIdentifier": "dev.atlas.app",
      "developerName": "ATLAS Project",
      "subtitle": "Локальный прокси-режим (LiveContainer)",
      "localizedDescription": "…",
      "iconURL": "https://…/icon.png",
      "tintColor": "#1B6AC9",
      "category": "utilities",
      "screenshots": ["https://…/1.png"],
      "versions": [
        {
          "version": "0.1.0",
          "buildVersion": "1",
          "date": "2026-08-05T00:00:00Z",
          "localizedDescription": "Первый релиз",
          "downloadURL": "https://github.com/…/releases/download/v0.1.0/Atlas-lite.ipa",
          "size": 12345678,
          "sha256": "…",
          "minOSVersion": "15.0"
        }
      ],
      "appPermissions": { "entitlements": [], "privacy": {} }
    },
    {
      "name": "ATLAS Full",
      "bundleIdentifier": "dev.atlas.app.full",
      "subtitle": "Полный туннель (TrollStore / платный аккаунт)",
      "versions": [ /* … Atlas-full.ipa … */ ]
    }
  ],
  "news": []
}
```

Ключевые моменты:
- `versions[]` — массив, **новая версия добавляется в начало**; старые остаются доступными (важно для отката).
- `sha256` и `size` вычисляются в CI автоматически — руками этот файл не редактируется никогда.
- Два приложения с разными `bundleIdentifier`: lite и full могут стоять одновременно.
- `downloadURL` указывает на ассет GitHub Release — трафик и хранение бесплатны.

### 2.2 Резервные зеркала source JSON
GitHub Pages может быть недоступен. Тот же файл дублируется на:
- Cloudflare Pages (бесплатно),
- IPFS (по CID),
- в репозиторий как `raw.githubusercontent.com`.

Приложение при обновлении опрашивает все зеркала.

### 2.3 Подпись IPA
- **lite** — собирается **неподписанным** (`CODE_SIGNING_ALLOWED=NO`), подпись делает SideStore/AltStore/LiveContainer сертификатом самого пользователя. Секреты в CI не нужны.
- **full** — либо неподписанный (для TrollStore, он сам подпишет с нужными entitlements), либо подписанный сертификатом разработчика из секретов репозитория (`IOS_CERT_P12`, `IOS_CERT_PASSWORD`, `IOS_PROFILE`).

---

## 3. Android

- Сборка `.apk` со сплитами по ABI + universal.
- Подпись: keystore в секретах (`ANDROID_KEYSTORE_B64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`).
- Публикация в GitHub Release + **F-Droid-совместимый репозиторий** на Pages (для тех, кто не хочет ставить APK вручную).
- Reproducible builds — желательно с самого начала: это аргумент доверия для проекта такого рода.

---

## 4. Windows / macOS / Linux

| Платформа | Артефакты | Нюансы |
|---|---|---|
| Windows | `Atlas-portable.exe`, `Atlas-setup.msi` | без code signing будет SmartScreen; портативная версия важнее установщика |
| macOS | `Atlas.dmg` (universal) | без нотаризации — Gatekeeper потребует ручного разрешения; инструкция в README |
| Linux | `.AppImage`, `.deb`, `.rpm`, `.ipk` (OpenWrt) | AppImage — основной, работает везде |

---

## 5. Что делаем в CI без Mac и без устройств

Раз физического MacBook нет, компенсируем автоматикой:
- `macos-14` раннер: сборка + `xcodebuild test` (юнит-тесты ядра и Swift-обёртки) + UI-тесты в симуляторе iOS/tvOS.
- Скриншот-тесты в симуляторе → артефакты в Release → **можно глазами посмотреть, что получилось**, не имея устройства.
- Интеграционные тесты транспортов против поднятого в том же job'е Xray-сервера (проверяем реальный REALITY-хэндшейк).
- Проверка отпечатка: свой эхо-сервер в CI считает JA4 нашего ClientHello и сравнивает с эталоном Chrome. **Регрессия отпечатка = красный билд.** Это важнее большинства функциональных тестов.

---

## 6. Безопасность цепочки поставки

Для проекта, который люди используют, чтобы обходить государственную цензуру, компрометация сборки = катастрофа. Поэтому с первого дня:

- Все зависимости зафиксированы (`Cargo.lock`, `Package.resolved`, `gradle/verification-metadata.xml`).
- `cargo-deny` / `cargo-audit` в CI — блокирующие.
- Артефакты подписываются **Sigstore/cosign** (keyless, бесплатно) + публикуется **SLSA provenance**.
- В Release публикуется `SHA256SUMS`, подписанный ключом проекта.
- Ветка `main` — защищена, обязательный ревью, запрет force-push.
- **Reproducible builds** как цель: любой должен уметь собрать байт-в-байт тот же артефакт.
- Секреты — только через GitHub Secrets, никаких токенов в коде; `run_secret_scanning` в CI.
