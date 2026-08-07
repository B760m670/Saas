// swift-tools-version: 5.9
//
// Обёртка над границей C ядра ATLAS.
//
// Пакет намеренно не зависит ни от UIKit, ни от SwiftUI: так он
// собирается и проверяется тестами не только на macOS, но и на Linux —
// то есть в том же месте, где живёт само ядро. Интерфейс лежит рядом,
// в отдельной цели.
//
// Где искать библиотеку и заголовок, задаёт `ATLAS_LIB_DIR`; по
// умолчанию — сборка ядра в этом же дереве.

import PackageDescription
import Foundation

let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()   // AtlasCore
    .deletingLastPathComponent()   // ios
    .deletingLastPathComponent()   // clients
    .deletingLastPathComponent()   // корень дерева

let libraryDirectory = ProcessInfo.processInfo.environment["ATLAS_LIB_DIR"]
    ?? root.appendingPathComponent("core/target/debug").path
let includeDirectory = ProcessInfo.processInfo.environment["ATLAS_INCLUDE_DIR"]
    ?? root.appendingPathComponent("core/atlas-ffi/include").path

// Кто подключает ядро — зависит от того, кто собирает.
//
// В приложении под iOS архив даёт проект Xcode: он собран под нужный
// триплет и лежит не там, где сборка для этой машины. Пакет в этом
// случае обязан **не** трогать компоновку вовсе, иначе притянет чужой
// архив и сборка развалится на непонятной ошибке.
//
// При самостоятельной проверке (`swift test`) проекта Xcode нет, и
// подключать некому — тогда это делает пакет. Признак — переменная
// `ATLAS_LINK_LOCAL`.
//
// Подключается динамическая библиотека, а не архив, и причина внешняя:
// шаг `swift-autolink-extract` есть только в сборке ELF, он читает
// секции биткода в архиве, а собран с LLVM другой версии, чем `rustc`.
// Архив Rust он открыть не может. На Apple этого шага нет вовсе.
let linkage: [LinkerSetting] =
    ProcessInfo.processInfo.environment["ATLAS_LINK_LOCAL"] == nil
    ? []
    : [
        .unsafeFlags(["-L\(libraryDirectory)"]),
        .linkedLibrary("atlas_ffi"),
    ]

let package = Package(
    name: "AtlasCore",
    // Нижняя граница — та же, что у приложения. Объявлено явно, чтобы
    // расхождение с целью сборки ловил компилятор, а не устройство.
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        // Именно `.static`, и это не мелочь.
        //
        // Без указания вида Xcode вправе собрать продукт динамическим, а
        // динамическому продукту компоновщик обязан разрешить все
        // символы **на его собственном шаге** — то есть найти
        // `libatlas_ffi.a` там, где о ней знает только цель приложения.
        // Отсюда «Undefined symbols: _atlas_version …» при сборке
        // продукта, а не приложения.
        //
        // Статический продукт откладывает разрешение до компоновки
        // приложения, где архив и подставляется. Заодно это верно по
        // существу: ядро статическое, и динамических библиотек на iOS не
        // бывает.
        .library(name: "AtlasCore", type: .static, targets: ["AtlasCore"])
    ],
    targets: [
        .target(
            name: "CAtlas",
            cSettings: [.unsafeFlags(["-I\(includeDirectory)"])]
        ),
        .target(
            name: "AtlasCore",
            dependencies: ["CAtlas"],
            swiftSettings: [.unsafeFlags(["-I\(includeDirectory)"])],
            linkerSettings: linkage
        ),
        .testTarget(name: "AtlasCoreTests", dependencies: ["AtlasCore"]),
    ]
)
