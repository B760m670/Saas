//! Локальный прокси, уводящий трафик в туннель.
//!
//! Слушает HTTP-прокси с методом `CONNECT`. Выбор не случайный: именно
//! этот способ понимает iOS через `.mobileconfig` с PAC — то есть
//! единственный, каким сборка `lite` под `LiveContainer` сможет забрать
//! системный трафик, не имея права на `NEPacketTunnelProvider`
//! (см. `docs/05-clients.md`). Заодно его понимают `curl`, браузеры и
//! почти всё остальное.
//!
//! Каждое соединение поднимает **свой** туннель. Так дороже по
//! рукопожатиям, но зато у наблюдателя нет одного долгоживущего потока,
//! в который сходится вся активность пользователя.
//!
//! Модуль, а не только двоичный файл, потому что тот же прокси нужен
//! клиентам через `atlas-ffi`: держать две копии одной перекачки —
//! верный способ починить ошибку в одной и оставить в другой.

use std::io::{self, BufRead as _, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use atlas_types::ProxyKey;

use crate::desync::{self, Strategy};
use crate::pac;
use crate::{dial_with, DialOptions, Target};

/// Сколько ждать между проверками, не пора ли останавливаться.
///
/// Слушающий сокет переведён в неблокирующий режим: иначе поток навсегда
/// застревает в `accept`, и остановить прокси можно было бы только
/// соединением с самим собой.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Размер буфера перекачки.
const CHUNK: usize = 16 * 1024;

/// Счётчики работы прокси.
#[derive(Debug, Default)]
struct Counters {
    /// Подобранный приём обхода, общий на всё время работы прокси.
    ///
    /// Хранится числом, потому что делится между потоками без
    /// блокировки: приём подбирается редко, читается постоянно.
    strategy: AtomicU64,
    accepted: AtomicU64,
    active: AtomicU64,
    failed: AtomicU64,
    to_target: AtomicU64,
    from_target: AtomicU64,
}

/// Мгновенный снимок счётчиков.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Сколько соединений принято всего.
    pub accepted: u64,
    /// Сколько обслуживается прямо сейчас.
    pub active: u64,
    /// Сколько не удалось довести до туннеля.
    pub failed: u64,
    /// Байт от клиента к назначению.
    pub to_target: u64,
    /// Байт от назначения к клиенту.
    pub from_target: u64,
}

/// Запущенный локальный прокси.
///
/// Останавливается явным [`Proxy::stop`] либо при уничтожении.
#[derive(Debug)]
pub struct Proxy {
    address: SocketAddr,
    counters: Arc<Counters>,
    running: Arc<AtomicBool>,
    script: Arc<String>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Proxy {
    /// Занять адрес и начать обслуживание.
    ///
    /// `listen` — обычный адрес вида `127.0.0.1:1080`; порт `0` означает
    /// «любой свободный», и тогда занятый адрес узнаётся из
    /// [`Proxy::address`].
    ///
    /// # Errors
    ///
    /// Ошибки занятия адреса.
    pub fn start(key: ProxyKey, listen: &str, options: DialOptions) -> io::Result<Self> {
        Self::start_with_rules(key, listen, options, None)
    }

    /// То же, но с заданными правилами маршрутизации.
    ///
    /// Правила отдаются по [`pac::URL_PATH`] тем же слушающим сокетом:
    /// профиль конфигурации iOS указывает на этот адрес, и правила
    /// меняются без переустановки профиля.
    ///
    /// `None` означает умолчание — всё через туннель, кроме локального.
    /// Собрать его заранее нельзя: в правилах стоит занятый адрес, а он
    /// известен только после привязки сокета.
    ///
    /// # Errors
    ///
    /// Ошибки занятия адреса и негодные правила.
    pub fn start_with_rules(
        key: ProxyKey,
        listen: &str,
        options: DialOptions,
        rules: Option<pac::Rules>,
    ) -> io::Result<Self> {
        Self::start_inner(Some(key), listen, options, rules)
    }

    /// Запустить прокси **без ключа** — ярус T0.
    ///
    /// Точки выхода нет вовсе: соединения идут напрямую к настоящим
    /// сайтам, а обход достигается нарезкой приветствия TLS. Ни
    /// аккаунта, ни ключа, ни узла за границей.
    ///
    /// # Errors
    ///
    /// Не удалось занять адрес.
    pub fn start_direct(listen: &str, options: DialOptions) -> io::Result<Self> {
        Self::start_inner(None, listen, options, None)
    }

    fn start_inner(
        key: Option<ProxyKey>,
        listen: &str,
        options: DialOptions,
        rules: Option<pac::Rules>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(listen)?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let rules = rules.unwrap_or_else(|| pac::Rules::new(address.to_string()));
        let script =
            Arc::new(pac::script(&rules).map_err(|error| io::Error::other(error.to_string()))?);

        let counters = Arc::new(Counters::default());
        let running = Arc::new(AtomicBool::new(true));

        let thread = {
            let counters = Arc::clone(&counters);
            let running = Arc::clone(&running);
            let key = Arc::new(key);
            let options = Arc::new(options);
            let script = Arc::clone(&script);
            std::thread::Builder::new()
                .name("atlas-proxy".to_owned())
                .spawn(move || {
                    accept_loop(&listener, &key, &options, &counters, &running, &script);
                })?
        };

        Ok(Self {
            address,
            counters,
            running,
            script,
            thread: Some(thread),
        })
    }

    /// Скрипт PAC, который отдаётся по [`pac::URL_PATH`].
    #[must_use]
    pub fn pac_script(&self) -> &str {
        &self.script
    }

    /// Занятый адрес.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Снять показания счётчиков.
    #[must_use]
    pub fn stats(&self) -> Stats {
        Stats {
            accepted: self.counters.accepted.load(Ordering::Relaxed),
            active: self.counters.active.load(Ordering::Relaxed),
            failed: self.counters.failed.load(Ordering::Relaxed),
            to_target: self.counters.to_target.load(Ordering::Relaxed),
            from_target: self.counters.from_target.load(Ordering::Relaxed),
        }
    }

    /// Перестать принимать новые соединения и дождаться слушателя.
    ///
    /// Уже открытые соединения не рвутся: их потоки доживают своё сами.
    /// Обрывать чужую загрузку на полуслове только потому, что
    /// пользователь нажал «выключить», — худшее из поведений.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Принимать соединения, пока не попросят остановиться.
fn accept_loop(
    listener: &TcpListener,
    key: &Arc<Option<ProxyKey>>,
    options: &Arc<DialOptions>,
    counters: &Arc<Counters>,
    running: &Arc<AtomicBool>,
    script: &Arc<String>,
) {
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((socket, _)) => {
                counters.accepted.fetch_add(1, Ordering::Relaxed);
                counters.active.fetch_add(1, Ordering::Relaxed);
                let key = Arc::clone(key);
                let options = Arc::clone(options);
                let owned = Arc::clone(counters);
                let script = Arc::clone(script);
                let spawned = std::thread::Builder::new()
                    .name("atlas-proxy-conn".to_owned())
                    .spawn(move || {
                        if serve(socket, key.as_ref().as_ref(), &options, &owned, &script).is_err()
                        {
                            owned.failed.fetch_add(1, Ordering::Relaxed);
                        }
                        owned.active.fetch_sub(1, Ordering::Relaxed);
                    });
                if spawned.is_err() {
                    counters.active.fetch_sub(1, Ordering::Relaxed);
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(_) => break,
        }
    }
}

/// Что просит локальный клиент.
#[derive(Debug)]
enum Request {
    /// Туннель до `хост:порт`.
    Connect(String, u16),
    /// Скрипт правил маршрутизации.
    Pac,
}

/// Обслужить одно соединение прокси.
fn serve(
    mut socket: TcpStream,
    key: Option<&ProxyKey>,
    options: &DialOptions,
    counters: &Counters,
    script: &str,
) -> io::Result<()> {
    socket.set_nodelay(true)?;

    let (host, port) = match read_request(&mut socket)? {
        Request::Pac => {
            // Профиль конфигурации iOS указывает сюда же: правила
            // меняются вместе с настройками, не требуя переустановки
            // профиля.
            let head = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/x-ns-proxy-autoconfig\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-store\r\n\
                 Connection: close\r\n\r\n",
                script.len()
            );
            socket.write_all(head.as_bytes())?;
            socket.write_all(script.as_bytes())?;
            return socket.flush();
        }
        Request::Connect(host, port) => (host, port),
    };

    // Ключа нет — идём ярусом T0: прямо к настоящему сайту, но с
    // нарезкой приветствия. Ни узла, ни аккаунта здесь не участвует.
    let Some(key) = key else {
        return serve_direct(socket, &host, port, options, counters);
    };

    let tunnel = match dial_with(key, &Target::domain(host, port), options) {
        Ok(tunnel) => tunnel,
        Err(error) => {
            // Причину видит только локальный клиент; наружу она не идёт.
            let _ = socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return Err(io::Error::other(error.to_string()));
        }
    };

    socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    socket.flush()?;
    splice(socket, tunnel, counters)
}

/// Прочитать первую строку запроса и заголовки до пустой строки.
fn read_request(socket: &mut TcpStream) -> io::Result<Request> {
    let mut reader = BufReader::new(socket.try_clone()?);
    let mut request = String::new();
    reader.read_line(&mut request)?;

    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default().to_owned();

    // Остаток заголовков дочитывается и отбрасывается: в туннель они не
    // идут, там уже начинается TLS клиента.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
    }

    if method.eq_ignore_ascii_case("GET") {
        // Путь может прийти и целым адресом: так делают некоторые
        // клиенты, считая нас обычным прокси.
        if target == pac::URL_PATH || target.ends_with(pac::URL_PATH) {
            return Ok(Request::Pac);
        }
        let _ = socket.write_all("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".as_bytes());
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("нет такого пути: {target}"),
        ));
    }

    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = socket.write_all(
            "HTTP/1.1 405 Method Not Allowed\r\n\r\nПоддерживается только CONNECT.\n".as_bytes(),
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("метод {method} не поддерживается"),
        ));
    }

    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "нет порта в цели CONNECT"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "порт не число"))?;
    Ok(Request::Connect(host.to_owned(), port))
}

/// Гонять байты между локальным клиентом и туннелем.
///
/// Оба направления независимы и живут каждое в своём потоке. Ни
/// очереди, ни общего состояния: очередь здесь однажды уже стоила
/// работоспособности — насос разбирал её только между блокирующими
/// чтениями туннеля, и клиент, заговоривший первым после паузы, ждал
/// ответа до предела чтения, а потом получал обрыв. Через `curl` это
/// выживало случайно, потому что пачка сервера приходит несколькими
/// сегментами. Разбор — в `docs/09-lab.md`, раздел 11.
fn splice(socket: TcpStream, tunnel: crate::Tunnel, counters: &Counters) -> io::Result<()> {
    let (tunnel_read, tunnel_write) =
        crate::split(tunnel).map_err(|error| io::Error::other(error.to_string()))?;
    pump(socket, tunnel_read, tunnel_write, counters)
}

/// То же для прямого соединения — когда туннеля нет вовсе.
///
/// Ярус T0 ходит к настоящему сайту напрямую, поэтому «та сторона» —
/// обычный сокет, а не туннель. Перекачка при этом та же самая, и
/// повторять её вторым телом нельзя: два одинаковых цикла разъедутся.
fn splice_direct(socket: TcpStream, remote: TcpStream, counters: &Counters) -> io::Result<()> {
    let remote_read = remote.try_clone()?;
    pump(socket, remote_read, remote, counters)
}

/// Перекачка в обе стороны между локальным клиентом и той стороной.
fn pump<R, W>(
    socket: TcpStream,
    mut tunnel_read: R,
    mut tunnel_write: W,
    counters: &Counters,
) -> io::Result<()>
where
    R: Read + Send,
    W: Write + Send,
{
    let mut local_read = socket.try_clone()?;
    let mut local_write = socket;

    std::thread::scope(|scope| {
        scope.spawn(|| {
            // Из туннеля — локальному клиенту.
            let mut buf = vec![0_u8; CHUNK];
            loop {
                match tunnel_read.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        counters
                            .from_target
                            .fetch_add(read as u64, Ordering::Relaxed);
                        if local_write
                            .write_all(buf.get(..read).unwrap_or_default())
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = local_write.shutdown(std::net::Shutdown::Write);
        });

        // От локального клиента — в туннель.
        let mut buf = vec![0_u8; CHUNK];
        loop {
            match local_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    counters.to_target.fetch_add(read as u64, Ordering::Relaxed);
                    if tunnel_write
                        .write_all(buf.get(..read).unwrap_or_default())
                        .is_err()
                        || tunnel_write.flush().is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = local_read.shutdown(std::net::Shutdown::Read);
    });
    Ok(())
}

impl Counters {
    /// Какой приём обхода применять сейчас.
    fn strategy(&self) -> Strategy {
        match self.strategy.load(Ordering::Relaxed) {
            0 => Strategy::None,
            2 => Strategy::Records,
            3 => Strategy::Disorder,
            _ => Strategy::Split,
        }
    }
}

/// Прямое соединение с нарезкой приветствия — ярус T0.
///
/// # Почему первые байты идут особым путём
///
/// Всё, что решает, начинается в первом же пакете: ТСПУ ищет имя сайта
/// в приветствии TLS. Дальше поток шифрован и цензору неинтересен,
/// поэтому нарезается только начало, а остальное перекачивается как
/// есть.
///
/// # Почему приём подбирается, а не задаётся
///
/// У разных операторов работает разное, и узнать это можно только
/// попыткой. Подобранный приём запоминается на всё время работы
/// прокси: перебирать на каждом соединении — значит платить неудачными
/// попытками за каждую вкладку.
fn serve_direct(
    mut socket: TcpStream,
    host: &str,
    port: u16,
    options: &DialOptions,
    counters: &Counters,
) -> io::Result<()> {
    let mut remote = match connect_direct(host, port, options) {
        Ok(remote) => remote,
        Err(error) => {
            let _ = socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return Err(error);
        }
    };

    socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    socket.flush()?;

    // Первый кусок от клиента — то самое приветствие TLS.
    let mut first = vec![0_u8; 8 * 1024];
    let read = socket.read(&mut first)?;
    if read == 0 {
        return Ok(());
    }
    counters.to_target.fetch_add(read as u64, Ordering::Relaxed);

    let strategy = counters.strategy();
    desync::send_first(&mut remote, first.get(..read).unwrap_or_default(), strategy)?;

    splice_direct(socket, remote, counters)
}

/// Открыть прямое соединение с настоящим сайтом.
fn connect_direct(host: &str, port: u16, options: &DialOptions) -> io::Result<TcpStream> {
    use std::net::ToSocketAddrs as _;

    let address = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("адрес не разрешается"))?;
    let socket = TcpStream::connect_timeout(&address, options.connect_timeout)?;
    socket.set_read_timeout(options.read_timeout)?;
    // Без этого система склеит куски обратно, и вся нарезка пропадёт.
    socket.set_nodelay(true)?;
    Ok(socket)
}
