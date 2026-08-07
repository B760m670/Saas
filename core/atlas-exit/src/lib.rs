//! Точка выхода: та сторона, которую пользователь разворачивает у себя.
//!
//! # Главное здесь — не то, что она делает для своих
//!
//! Обслужить своего клиента несложно: открыть метку, поднять TLS,
//! принять VLESS, соединиться с адресом назначения. Всё это ниже есть.
//!
//! Но точка выхода стоит на порту 443 в интернете, и к ней постоянно
//! приходят посторонние: сканеры портов, поисковые роботы, зонды
//! цензора, случайные браузеры. От того, **как она отвечает им**,
//! зависит всё остальное. Оборвать соединение — значит выдать себя:
//! настоящий сайт так не поступает, и разница видна сразу.
//!
//! Поэтому посторонний не отвергается, а **проксируется на сайт
//! прикрытия целиком и без изменений**, вместе с теми байтами, которые
//! мы уже успели прочитать. Он видит настоящий чужой сайт, с настоящим
//! сертификатом и настоящим содержимым, — потому что он и правда с ним
//! разговаривает. Отличить нас от сайта прикрытия для него невозможно:
//! отличать не от чего.
//!
//! ```text
//!                       ┌── метка открылась ──► VLESS ──► адрес назначения
//! входящее соединение ──┤
//!                       └── не открылась ────► сайт прикрытия, байт в байт
//! ```
//!
//! # Что здесь сознательно просто
//!
//! Поток на соединение и блокирующий ввод-вывод. Для точки выхода на
//! бесплатном тарифе, где счёт соединений идёт на десятки, этого более
//! чем достаточно, а асинхронная переработка потребовала бы тащить
//! исполнитель в ядро, которому он больше нигде не нужен.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use atlas_reality::{Certificates, Server};
use atlas_tls::server::{CertificateSource, Pending, ServerConfig, ServerConnection};
use atlas_tls::ClientHello;
use atlas_vless::session::ServerSession;
use atlas_vless::{Address, Endpoint};

pub mod link;

/// Сколько байт читать за раз.
const CHUNK: usize = 16 * 1024;

/// Сколько ждать первого приветствия, прежде чем счесть соединение
/// брошенным.
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);

/// Сколько ждать соединения с адресом назначения.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);

/// Настройки точки выхода.
#[derive(Debug)]
pub struct ExitConfig {
    /// Серверная сторона REALITY: приватный ключ и разрешённые `shortId`.
    pub reality: Server,
    /// Адрес сайта прикрытия, куда уходят посторонние.
    ///
    /// Обычно `домен:443` того же сайта, чьё имя стоит в SNI у клиентов.
    pub cover: String,
    /// Имя в выпускаемом сертификате — как правило, домен прикрытия.
    pub common_name: String,
    /// Протоколы прикладного уровня в порядке предпочтения.
    pub alpn: Vec<String>,
    /// Куда точке выхода позволено соединяться.
    pub policy: Policy,
}

/// Ограничения на адрес назначения.
///
/// # Зачем это обязательно
///
/// Клиент вправе назвать любой адрес. Для точки, которую человек
/// развернул себе одному, это безобидно. Для точки, которой он
/// поделился, — открытая дверь: `127.0.0.1` ведёт к службам самого
/// узла, `169.254.169.254` у большинства облачных провайдеров отдаёт
/// учётные данные виртуальной машины, а частные диапазоны — во
/// внутреннюю сеть хостера.
///
/// Поэтому по умолчанию закрыто, и проверка идёт **по разрешённому
/// адресу**, а не по имени: `localhost` и любое доменное имя,
/// указывающее внутрь, обязаны отсекаться одинаково.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Разрешить петлю, частные диапазоны и служебные адреса.
    ///
    /// По умолчанию выключено — то есть закрыто. Включать только на
    /// точке, которой никто не пользуется, кроме самого хозяина, и в
    /// тестах.
    pub allow_private: bool,
    /// Разрешённые порты назначения. Пусто — любые.
    pub allowed_ports: Vec<u16>,
}

impl Policy {
    /// Разрешено ли соединяться по этому адресу.
    #[must_use]
    pub fn permits(&self, address: SocketAddr) -> bool {
        if !self.allowed_ports.is_empty() && !self.allowed_ports.contains(&address.port()) {
            return false;
        }
        self.allow_private || is_public(address.ip())
    }
}

/// Ведёт ли адрес наружу, а не внутрь узла или его сети.
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // Общий диапазон операторов, 100.64.0.0/10.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Уникальные локальные, fc00::/7.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Локальные для канала, fe80::/10.
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

impl ExitConfig {
    /// Настройки с указанным ключом и сайтом прикрытия.
    #[must_use]
    pub fn new(reality: Server, cover: impl Into<String>) -> Self {
        let cover = cover.into();
        let common_name = cover
            .rsplit_once(':')
            .map_or_else(|| cover.clone(), |(host, _)| host.to_owned());
        Self {
            reality,
            cover,
            common_name,
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            policy: Policy::default(),
        }
    }

    /// Задать ограничения на адрес назначения.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Задать имя в сертификате.
    #[must_use]
    pub fn with_common_name(mut self, name: impl Into<String>) -> Self {
        self.common_name = name.into();
        self
    }
}

/// Что делать с сообщением о событии.
///
/// Точка выхода стоит без присмотра, и молчащая служба неотлаживаема.
/// Но и болтливая опасна: в журнале не должно оказаться ничего, что
/// связывает пользователя с адресом назначения. Поэтому наружу идут
/// только события, а решение, писать ли их, принимает вызывающий.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// Точка выхода, готовая принимать соединения.
#[derive(Clone)]
pub struct ExitPoint {
    certificates: Arc<Certificates>,
    cover: String,
    alpn: Vec<String>,
    policy: Policy,
    log: Option<Log>,
}

impl core::fmt::Debug for ExitPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ExitPoint {{ cover: {:?} }}", self.cover)
    }
}

impl ExitPoint {
    /// Собрать точку выхода из настроек.
    #[must_use]
    pub fn new(config: ExitConfig) -> Self {
        let certificates = Arc::new(Certificates::new(config.reality, config.common_name));
        Self {
            certificates,
            cover: config.cover,
            alpn: config.alpn,
            policy: config.policy,
            log: None,
        }
    }

    /// Куда писать сообщения о событиях.
    #[must_use]
    pub fn with_log(mut self, log: Log) -> Self {
        self.log = Some(log);
        self
    }

    fn say(&self, message: &str) {
        if let Some(log) = self.log.as_ref() {
            log(message);
        }
    }

    /// Принимать соединения, пока слушающий сокет жив.
    ///
    /// Каждое обслуживается в своём потоке. Ошибки отдельного соединения
    /// не должны останавливать точку: упавший клиент — обычное дело.
    ///
    /// # Errors
    ///
    /// Отказ самого слушающего сокета.
    pub fn serve(self: &Arc<Self>, listener: &TcpListener) -> io::Result<()> {
        for incoming in listener.incoming() {
            let socket = incoming?;
            let point = Arc::clone(self);
            // Результат намеренно отбрасывается: единственный разумный
            // ответ на отказ соединения — забыть о нём.
            let _ = std::thread::Builder::new()
                .name("atlas-exit".to_owned())
                .spawn(move || {
                    if let Err(error) = point.handle(socket) {
                        point.say(&format!("соединение: {error}"));
                    }
                });
        }
        Ok(())
    }

    /// Обслужить одно соединение.
    ///
    /// # Errors
    ///
    /// Отказ сети. Незнакомый клиент ошибкой **не** является: он уходит
    /// на сайт прикрытия, и это штатный исход.
    pub fn handle(&self, socket: TcpStream) -> io::Result<()> {
        socket.set_read_timeout(Some(HELLO_TIMEOUT))?;
        socket.set_nodelay(true)?;

        // Первая запись читается целиком и **сохраняется**: если клиент
        // окажется посторонним, эти же байты уйдут на сайт прикрытия
        // без единого изменения.
        let (hello_record, socket) = read_first_record(socket)?;

        let config =
            ServerConfig::new(Box::new(SharedCertificates(Arc::clone(&self.certificates))))
                .with_alpn(self.alpn.clone());
        let mut connection = ServerConnection::new(config);

        if connection.read_tls(&hello_record).is_err() || connection.process().is_err() {
            self.say("посторонний — уводим на сайт прикрытия");
            return self.forward_to_cover(socket, &hello_record);
        }
        self.say("свой клиент — рукопожатие");

        // Метка открылась. Дальше — обычное рукопожатие и VLESS.
        socket.set_read_timeout(None)?;
        let mut stream = ServerStream {
            socket,
            connection,
            pending: Vec::new(),
            consumed: 0,
        };
        stream.finish_handshake()?;

        let accepted = ServerSession::accept(stream)?;
        self.say(&format!(
            "назначение {} ({:?})",
            to_socket_string(&accepted.destination),
            accepted.session.flow()
        ));
        let upstream = self.connect_upstream(&accepted.destination)?;
        let outcome = relay(accepted.session, upstream, self.log.clone());
        if let Err(error) = &outcome {
            self.say(&format!("перекачка окончена: {error}"));
        }
        outcome
    }

    /// Соединиться с адресом назначения, соблюдая ограничения.
    ///
    /// Проверка идёт по **разрешённому** адресу, а не по имени: иначе
    /// `localhost` и любой домен, указывающий внутрь, прошли бы мимо
    /// неё. Резолвер здесь — граница доверия, и полагаться на то, что
    /// клиент прислал внешне безобидное имя, нельзя.
    fn connect_upstream(&self, endpoint: &Endpoint) -> io::Result<TcpStream> {
        if endpoint.port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "нулевой порт назначения",
            ));
        }

        let target = to_socket_string(endpoint);
        let resolved: Vec<SocketAddr> = target.to_socket_addrs()?.collect();
        if resolved.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "имя назначения не разрешается",
            ));
        }

        let mut last = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "все адреса назначения запрещены настройками",
        );
        for address in resolved {
            if !self.policy.permits(address) {
                continue;
            }
            match TcpStream::connect_timeout(&address, UPSTREAM_TIMEOUT) {
                Ok(socket) => {
                    socket.set_nodelay(true)?;
                    return Ok(socket);
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Увести соединение на сайт прикрытия.
    ///
    /// Прочитанные байты дописываются первыми: для сайта прикрытия
    /// соединение обязано выглядеть так, будто мы его вообще не трогали.
    fn forward_to_cover(&self, socket: TcpStream, already_read: &[u8]) -> io::Result<()> {
        socket.set_read_timeout(None)?;
        let mut cover = TcpStream::connect(&self.cover)?;
        cover.set_nodelay(true)?;
        cover.write_all(already_read)?;
        cover.flush()?;
        splice(socket, cover)
    }
}

/// Общий источник сертификатов на все соединения.
///
/// Окно повторов и список разрешённых `shortId` у точки выхода одни на
/// всех, поэтому источник разделяется, а не создаётся заново.
#[derive(Debug)]
struct SharedCertificates(Arc<Certificates>);

impl CertificateSource for SharedCertificates {
    fn accept(&self, hello: &ClientHello, raw: &[u8]) -> atlas_tls::Result<Box<dyn Pending>> {
        self.0.accept(hello, raw)
    }
}

/// Прочитать первую запись TLS целиком, сохранив её байты.
fn read_first_record(mut socket: TcpStream) -> io::Result<(Vec<u8>, TcpStream)> {
    /// Приветствие длиннее этого не бывает даже с постквантовой долей.
    const MAX_HELLO: usize = 1 << 15;

    let mut raw = Vec::new();
    let mut buf = vec![0_u8; CHUNK];

    loop {
        if let Some([_, _, _, hi, lo]) = raw.get(..5) {
            let declared = usize::from(u16::from_be_bytes([*hi, *lo]));
            if raw.len() >= 5 + declared {
                return Ok((raw, socket));
            }
            if 5 + declared > MAX_HELLO {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "первая запись неправдоподобной длины",
                ));
            }
        }
        if raw.len() > MAX_HELLO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "приветствие не пришло целиком",
            ));
        }

        let read = socket.read(&mut buf)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "соединение закрыто до приветствия",
            ));
        }
        raw.extend_from_slice(buf.get(..read).unwrap_or_default());
    }
}

/// Адрес назначения в виде, пригодном для `TcpStream::connect`.
fn to_socket_string(endpoint: &Endpoint) -> String {
    match &endpoint.address {
        Address::Domain(name) => format!("{name}:{}", endpoint.port),
        Address::Ipv4(octets) => format!(
            "{}.{}.{}.{}:{}",
            octets[0], octets[1], octets[2], octets[3], endpoint.port
        ),
        Address::Ipv6(octets) => {
            let groups: Vec<String> = octets
                .chunks_exact(2)
                .map(|pair| match pair {
                    [hi, lo] => format!("{:x}", u16::from_be_bytes([*hi, *lo])),
                    _ => String::new(),
                })
                .collect();
            format!("[{}]:{}", groups.join(":"), endpoint.port)
        }
    }
}

/// Принять обычное соединение TLS на уже открытом сокете.
///
/// Точке выхода сама по себе не нужна — у неё соединения идут через
/// REALITY. Нужна тому, кто ставит рядом обычный сервер TLS: например,
/// узлу назначения в сквозных проверках.
///
/// # Errors
///
/// Отказ сокета либо нарушение протокола клиентом.
pub fn accept_tls(socket: TcpStream, config: ServerConfig) -> io::Result<ServerStream> {
    socket.set_nodelay(true)?;
    let mut stream = ServerStream {
        socket,
        connection: ServerConnection::new(config),
        pending: Vec::new(),
        consumed: 0,
    };
    stream.finish_handshake()?;
    Ok(stream)
}

/// Поток TLS со стороны сервера.
#[derive(Debug)]
pub struct ServerStream {
    socket: TcpStream,
    connection: ServerConnection,
    pending: Vec<u8>,
    consumed: usize,
}

impl ServerStream {
    /// Довести рукопожатие до конца.
    fn finish_handshake(&mut self) -> io::Result<()> {
        let mut buf = vec![0_u8; CHUNK];
        loop {
            self.flush_output()?;
            if !self.connection.is_handshaking() {
                return Ok(());
            }
            let read = self.socket.read(&mut buf)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "клиент ушёл во время рукопожатия",
                ));
            }
            self.connection
                .read_tls(buf.get(..read).unwrap_or_default())
                .map_err(to_io)?;
            self.connection.process().map_err(to_io)?;
            self.pending.extend(self.connection.take_plaintext());
        }
    }

    fn flush_output(&mut self) -> io::Result<()> {
        if self.connection.wants_write() {
            let out = self.connection.take_output();
            self.socket.write_all(&out)?;
            self.socket.flush()?;
        }
        Ok(())
    }
}

impl Read for ServerStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut buf = vec![0_u8; CHUNK];
        loop {
            if let Some(rest) = self.pending.get(self.consumed..) {
                if !rest.is_empty() {
                    let take = rest.len().min(out.len());
                    if let (Some(dst), Some(src)) = (out.get_mut(..take), rest.get(..take)) {
                        dst.copy_from_slice(src);
                    }
                    self.consumed += take;
                    return Ok(take);
                }
            }
            self.pending.clear();
            self.consumed = 0;

            if self.connection.peer_closed() {
                return Ok(0);
            }
            let read = self.socket.read(&mut buf)?;
            if read == 0 {
                return Ok(0);
            }
            self.connection
                .read_tls(buf.get(..read).unwrap_or_default())
                .map_err(to_io)?;
            self.connection.process().map_err(to_io)?;
            self.flush_output()?;
            self.pending = self.connection.take_plaintext();
        }
    }
}

impl Write for ServerStream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.connection.send(data).map_err(to_io)?;
        self.flush_output()?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_output()
    }
}

/// Гонять байты между туннелем и адресом назначения, пока живы оба.
///
/// Соединение разъято на две независимые половины: у чтения и записи в
/// TLS свои ключи и свои счётчики, а обрамление Vision в разных
/// направлениях тоже не делит состояния. Поэтому потоки работают без
/// замка — а замок здесь был бы источником взаимной блокировки, потому
/// что чтение из сокета блокирующее.
#[allow(clippy::too_many_lines)]
fn relay(
    session: ServerSession<ServerStream>,
    upstream: TcpStream,
    log: Option<Log>,
) -> io::Result<()> {
    let parts = session.into_parts();
    let ServerStream {
        socket,
        connection,
        pending,
        consumed,
    } = parts.stream;

    // Всё, что успело прийти до разъятия, обязано дойти до назначения.
    let leftover = {
        let mut out = parts.buffered;
        out.extend_from_slice(pending.get(consumed..).unwrap_or_default());
        out
    };

    let (mut reader, mut writer) = connection.into_halves().map_err(to_io)?;
    let mut unpadder = parts.unpadder;
    let mut padder = parts.padder;
    let response = parts.response;

    let mut client_read = socket.try_clone()?;
    let mut client_write = socket;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream;

    let say = move |message: String| {
        if let Some(log) = log.as_ref() {
            log(&message);
        }
    };
    let say_in = say.clone();

    // Клиент → назначение.
    let inbound = std::thread::spawn(move || -> io::Result<()> {
        let mut sent = 0_usize;
        if !leftover.is_empty() {
            upstream_write.write_all(&leftover)?;
        }
        let mut buf = vec![0_u8; CHUNK];
        loop {
            let read = client_read.read(&mut buf)?;
            if read == 0 {
                break;
            }
            let plain = reader
                .decrypt(buf.get(..read).unwrap_or_default())
                .map_err(to_io)?;
            let content = match unpadder.as_mut() {
                None => plain,
                Some(unpadder) => {
                    unpadder.push(&plain);
                    unpadder.drain().map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?
                }
            };
            if !content.is_empty() {
                upstream_write.write_all(&content)?;
                sent += content.len();
            }
            if reader.peer_closed() {
                break;
            }
        }
        say_in(format!("клиент → назначение: {sent} байт"));
        let _ = upstream_write.shutdown(std::net::Shutdown::Write);
        Ok(())
    });

    // Назначение → клиент.
    let outbound = (|| -> io::Result<()> {
        let mut prefix = response;
        let mut back = 0_usize;
        let mut buf = vec![0_u8; CHUNK];
        loop {
            let read = upstream_read.read(&mut buf)?;
            if read == 0 {
                break;
            }
            let payload = buf.get(..read).unwrap_or_default();

            let framed = match padder.as_mut() {
                Some(padder) if !padder.is_finished() => {
                    let mut out = Vec::new();
                    // Ответ назначения обрамляется, пока идёт его
                    // рукопожатие: именно длины этих записей и выдают
                    // TLS-in-TLS.
                    for chunk in payload.chunks(MAX_VISION_CONTENT) {
                        let block = padder
                            .wrap(chunk, atlas_vless::vision::Command::Continue, true)
                            .map_err(|error| {
                                io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                            })?;
                        out.extend_from_slice(&block);
                    }
                    out
                }
                _ => payload.to_vec(),
            };

            let mut plain = prefix.take().unwrap_or_default();
            plain.extend_from_slice(&framed);
            let records = writer.encrypt(&plain).map_err(to_io)?;
            client_write.write_all(&records)?;
            back += read;
        }
        say(format!("назначение → клиент: {back} байт"));
        if let Ok(bye) = writer.close_notify() {
            let _ = client_write.write_all(&bye);
        }
        let _ = client_write.shutdown(std::net::Shutdown::Write);
        Ok(())
    })();

    let _ = inbound.join();
    outbound
}

/// Наибольший размер содержимого блока Vision.
const MAX_VISION_CONTENT: usize = atlas_vless::vision::MAX_BLOCK
    - atlas_vless::vision::HEADER_LEN
    - atlas_vless::vision::UUID_LEN;

/// Гонять байты между двумя сокетами в обе стороны.
fn splice(a: TcpStream, b: TcpStream) -> io::Result<()> {
    let (mut a_read, mut a_write) = (a.try_clone()?, a);
    let (mut b_read, mut b_write) = (b.try_clone()?, b);

    let forward = std::thread::spawn(move || {
        let _ = io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(std::net::Shutdown::Write);
    });
    let _ = io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown(std::net::Shutdown::Write);
    let _ = forward.join();
    Ok(())
}

/// Перевести ошибку протокола в ошибку ввода-вывода.
fn to_io(error: atlas_tls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
