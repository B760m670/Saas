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
        let listener = TcpListener::bind(listen)?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let counters = Arc::new(Counters::default());
        let running = Arc::new(AtomicBool::new(true));

        let thread = {
            let counters = Arc::clone(&counters);
            let running = Arc::clone(&running);
            let key = Arc::new(key);
            let options = Arc::new(options);
            std::thread::Builder::new()
                .name("atlas-proxy".to_owned())
                .spawn(move || accept_loop(&listener, &key, &options, &counters, &running))?
        };

        Ok(Self {
            address,
            counters,
            running,
            thread: Some(thread),
        })
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
    key: &Arc<ProxyKey>,
    options: &Arc<DialOptions>,
    counters: &Arc<Counters>,
    running: &Arc<AtomicBool>,
) {
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((socket, _)) => {
                counters.accepted.fetch_add(1, Ordering::Relaxed);
                counters.active.fetch_add(1, Ordering::Relaxed);
                let key = Arc::clone(key);
                let options = Arc::clone(options);
                let owned = Arc::clone(counters);
                let spawned = std::thread::Builder::new()
                    .name("atlas-proxy-conn".to_owned())
                    .spawn(move || {
                        if serve(socket, &key, &options, &owned).is_err() {
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

/// Обслужить одно соединение прокси.
fn serve(
    mut socket: TcpStream,
    key: &ProxyKey,
    options: &DialOptions,
    counters: &Counters,
) -> io::Result<()> {
    socket.set_nodelay(true)?;
    let (host, port) = read_connect(&mut socket)?;

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

/// Прочитать запрос `CONNECT host:port` и заголовки до пустой строки.
fn read_connect(socket: &mut TcpStream) -> io::Result<(String, u16)> {
    let mut reader = BufReader::new(socket.try_clone()?);
    let mut request = String::new();
    reader.read_line(&mut request)?;

    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default().to_owned();

    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = socket.write_all(
            "HTTP/1.1 405 Method Not Allowed\r\n\r\nПоддерживается только CONNECT.\n".as_bytes(),
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("метод {method} не поддерживается"),
        ));
    }

    // Остаток заголовков дочитывается и отбрасывается: в туннель они не
    // идут, там уже начинается TLS клиента.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
    }

    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "нет порта в цели CONNECT"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "порт не число"))?;
    Ok((host.to_owned(), port))
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
    let (mut tunnel_read, mut tunnel_write) =
        crate::split(tunnel).map_err(|error| io::Error::other(error.to_string()))?;
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
