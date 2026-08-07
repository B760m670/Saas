//
//  Веб-представление, настроенное ходить только через туннель.
//
//  # Главное правило: не загружать, если не через прокси
//
//  Настройка прокси для `WKWebView` появилась в iOS 17
//  (`WKWebsiteDataStore.proxyConfigurations`). До неё увести трафик
//  веб-представления штатными средствами нельзя вовсе.
//
//  Отсюда решение, которое стоит назвать прямо: **если прокси
//  подставить не удалось, страница не загружается**. Показать страницу
//  напрямую было бы худшим из возможных поведений — пользователь
//  открыл браузер в приложении для обхода цензуры и вправе считать, что
//  защищён. Молчаливый обход туннеля превращает средство защиты в
//  средство разоблачения.
//

import Network
import SwiftUI
import WebKit

/// Что случилось с загрузкой — для показа на экране.
struct BrowserState: Equatable {
    var address: String = ""
    var title: String = ""
    var loading: Bool = false
    var progress: Double = 0
    var canGoBack: Bool = false
    var canGoForward: Bool = false
    var failure: String?
    /// Меры, применённые к сеансу.
    var hardening: Hardening.Applied?
}

/// Команда представлению извне.
enum BrowserCommand: Equatable {
    case load(String)
    case back
    case forward
    case reload
    case stop
}

struct WebView: UIViewRepresentable {
    /// Адрес локального прокси, `хост:порт`.
    let proxy: String
    @Binding var state: BrowserState
    @Binding var command: BrowserCommand?

    func makeCoordinator() -> Coordinator {
        Coordinator(state: $state)
    }

    func makeUIView(context: Context) -> WKWebView {
        let view = WKWebView(frame: .zero, configuration: configuration())
        view.navigationDelegate = context.coordinator
        view.uiDelegate = context.coordinator
        view.allowsBackForwardNavigationGestures = true
        // Предпросмотр по долгому нажатию заранее ходит по ссылке —
        // то есть загружает то, чего пользователь не открывал.
        view.allowsLinkPreview = false
        context.coordinator.observe(view)
        return view
    }

    func updateUIView(_ view: WKWebView, context: Context) {
        guard let command else { return }
        // Команда исполняется один раз: сбрасываем её, не вызывая
        // повторной перерисовки внутри текущей.
        DispatchQueue.main.async { self.command = nil }

        switch command {
        case .load(let text):
            guard let url = Self.url(from: text) else {
                state.failure = "адрес не разбирается"
                return
            }
            view.load(URLRequest(url: url))
        case .back: view.goBack()
        case .forward: view.goForward()
        case .reload: view.reload()
        case .stop: view.stopLoading()
        }
    }

    /// Собрать настройки: прокси, ограничения, скрипт затыкания.
    private func configuration() -> WKWebViewConfiguration {
        let configuration = WKWebViewConfiguration()

        // Хранилище **непостоянное**: ни печенья, ни кэш, ни хранилище
        // страниц не переживают закрытие. Для инструмента обхода
        // цензуры это не роскошь — следы на устройстве выдают не хуже
        // трафика.
        let store = WKWebsiteDataStore.nonPersistent()

        var proxied = false
        if #available(iOS 17.0, *),
           let endpoint = Self.endpoint(from: proxy) {
            store.proxyConfigurations = [ProxyConfiguration(httpCONNECTProxy: endpoint)]
            proxied = true
        }
        configuration.websiteDataStore = store

        // Предупреждение о мошеннических сайтах сверяется со сторонней
        // службой, то есть отправляет туда адреса. Выключено: для нас
        // это утечка ровно того, что мы прячем.
        configuration.preferences.isFraudulentWebsiteWarningEnabled = false

        // Ничего не воспроизводится само: автозапуск порождает
        // обращения к сети, которых пользователь не запрашивал.
        configuration.mediaTypesRequiringUserActionForPlayback = .all
        configuration.allowsInlineMediaPlayback = true

        configuration.userContentController.addUserScript(Hardening.userScript())

        // Состояние мер запоминается заранее, чтобы экран мог о них
        // сказать, не гадая.
        DispatchQueue.main.async {
            state.hardening = Hardening.Applied(
                proxied: proxied,
                removed: Hardening.removedFeatures,
                bestEffort: Hardening.bestEffortMeasures
            )
        }
        return configuration
    }

    /// Разобрать `хост:порт` в точку подключения.
    static func endpoint(from address: String) -> NWEndpoint? {
        guard let separator = address.lastIndex(of: ":"),
              let port = NWEndpoint.Port(String(address[address.index(after: separator)...]))
        else { return nil }
        let host = String(address[..<separator])
        guard !host.isEmpty else { return nil }
        return .hostPort(host: NWEndpoint.Host(host), port: port)
    }

    /// Превратить введённое пользователем в адрес.
    ///
    /// Строка без схемы считается адресом, а не поисковым запросом:
    /// отправлять введённое в поисковую службу значило бы отдавать ей
    /// всё, что человек печатает.
    static func url(from text: String) -> URL? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if let url = URL(string: trimmed), url.scheme != nil {
            return url
        }
        return URL(string: "https://" + trimmed)
    }

    /// Наблюдение за загрузкой и запрет всего, что мимо туннеля.
    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        @Binding private var state: BrowserState
        private var watchers: [NSKeyValueObservation] = []

        init(state: Binding<BrowserState>) {
            _state = state
        }

        func observe(_ view: WKWebView) {
            watchers = [
                view.observe(\.estimatedProgress, options: .new) { [weak self] view, _ in
                    self?.state.progress = view.estimatedProgress
                },
                view.observe(\.title, options: .new) { [weak self] view, _ in
                    self?.state.title = view.title ?? ""
                },
                view.observe(\.url, options: .new) { [weak self] view, _ in
                    self?.state.address = view.url?.absoluteString ?? ""
                },
                view.observe(\.canGoBack, options: .new) { [weak self] view, _ in
                    self?.state.canGoBack = view.canGoBack
                },
                view.observe(\.canGoForward, options: .new) { [weak self] view, _ in
                    self?.state.canGoForward = view.canGoForward
                },
            ]
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor action: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            // Без прокси не загружается ничего. Это главное правило
            // экрана, и нарушать его нельзя даже ради удобства.
            guard state.hardening?.proxied == true else {
                state.failure = "прокси недоступен — загрузка отменена"
                return decisionHandler(.cancel)
            }

            // Схемы, уводящие наружу, обрываются здесь: переход в другое
            // приложение вынес бы запрос из туннеля.
            let scheme = action.request.url?.scheme?.lowercased() ?? ""
            guard ["http", "https", "about", "data"].contains(scheme) else {
                state.failure = "ссылка ведёт мимо туннеля: \(scheme)"
                return decisionHandler(.cancel)
            }
            decisionHandler(.allow)
        }

        func webView(_ webView: WKWebView, didStartProvisionalNavigation: WKNavigation!) {
            state.loading = true
            state.failure = nil
        }

        func webView(_ webView: WKWebView, didFinish: WKNavigation!) {
            state.loading = false
        }

        func webView(
            _ webView: WKWebView,
            didFail navigation: WKNavigation!,
            withError error: Error
        ) {
            state.loading = false
            state.failure = error.localizedDescription
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            state.loading = false
            state.failure = error.localizedDescription
        }

        /// Запрос местоположения отклоняется молча и всегда.
        @available(iOS 15.0, *)
        func webView(
            _ webView: WKWebView,
            requestMediaCapturePermissionFor origin: WKSecurityOrigin,
            initiatedByFrame frame: WKFrameInfo,
            type: WKMediaCaptureType,
            decisionHandler: @escaping (WKPermissionDecision) -> Void
        ) {
            decisionHandler(.deny)
        }
    }
}
