//
//  Крошечный сервер, отдающий профиль один раз.
//
//  Существует потому, что iOS ставит `.mobileconfig` только по ссылке,
//  открытой в Safari: ни из файла, ни из буфера обмена профиль не
//  устанавливается.
//
//  Живёт ровно столько, сколько нужно. Долгоживущий сервер на
//  устройстве — лишняя поверхность, даже на петле.
//

import Foundation
import Network

final class ProfileServer {
    private let xml: String
    private var listener: NWListener?

    init(xml: String) {
        self.xml = xml
    }

    /// Занять порт и позвать обработчик с готовым адресом.
    func start(_ ready: @escaping (URL) -> Void) {
        guard let listener = try? NWListener(using: .tcp) else { return }
        self.listener = listener

        listener.newConnectionHandler = { [weak self] connection in
            self?.serve(connection)
        }
        listener.stateUpdateHandler = { state in
            guard case .ready = state,
                  let port = listener.port?.rawValue,
                  let url = URL(string: "http://127.0.0.1:\(port)/atlas.mobileconfig")
            else { return }
            DispatchQueue.main.async { ready(url) }
        }
        listener.start(queue: .global())
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    private func serve(_ connection: NWConnection) {
        connection.start(queue: .global())
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) {
            [weak self] _, _, _, _ in
            guard let self else { return }
            let body = Data(self.xml.utf8)
            // Тип содержимого обязателен: без него Safari покажет
            // профиль текстом вместо предложения установить.
            let head = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: application/x-apple-aspen-config\r\n"
                + "Content-Length: \(body.count)\r\n"
                + "Connection: close\r\n\r\n"
            var answer = Data(head.utf8)
            answer.append(body)
            connection.send(
                content: answer,
                completion: .contentProcessed { _ in connection.cancel() }
            )
        }
    }
}
