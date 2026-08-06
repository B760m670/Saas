//! Связывание клиента с настоящим сокетом.
//!
//! Весь ввод-вывод собран здесь и только здесь. [`Connection`] о нём не
//! знает: это позволяет тому же автомату работать поверх TCP на
//! десктопе, поверх пакетного туннеля на iOS и поверх чего угодно ещё,
//! что умеет передавать байты.
//!
//! Адаптер намеренно блокирующий и минимальный. Асинхронная обёртка,
//! когда понадобится, ляжет рядом и будет пользоваться тем же
//! [`Connection`].

use std::io::{self, Read, Write};

use crate::client::{ClientConfig, Connection};
use crate::error::Error;

/// Сколько байт читать за один заход у сокета.
const CHUNK: usize = 16 * 1024;

/// Поток TLS поверх произвольного двунаправленного канала.
#[derive(Debug)]
pub struct TlsStream<S> {
    socket: S,
    connection: Connection,
    /// Расшифрованное, но ещё не отданное вызывающему.
    pending: Vec<u8>,
    /// Сколько байт из `pending` уже отдано.
    consumed: usize,
}

impl<S: Read + Write> TlsStream<S> {
    /// Провести рукопожатие и вернуть готовый к работе поток.
    ///
    /// # Errors
    ///
    /// Ошибки сокета и ошибки протокола; последние приходят как
    /// [`io::ErrorKind::InvalidData`] с исходным текстом.
    pub fn connect(socket: S, config: ClientConfig) -> io::Result<Self> {
        let connection = Connection::new(config).map_err(to_io)?;
        let mut stream = Self {
            socket,
            connection,
            pending: Vec::new(),
            consumed: 0,
        };
        stream.handshake()?;
        Ok(stream)
    }

    fn handshake(&mut self) -> io::Result<()> {
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
                    "соединение закрыто во время рукопожатия",
                ));
            }
            self.connection
                .read_tls(buf.get(..read).unwrap_or_default())
                .map_err(to_io)?;
            self.connection.process().map_err(to_io)?;
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

    /// Согласованный ALPN.
    #[must_use]
    pub fn alpn(&self) -> Option<&str> {
        self.connection.alpn()
    }

    /// Доступ к автомату — нужен для снятия отпечатка и диагностики.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Разобрать соединение обратно на части.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.socket
    }

    /// Отправить `close_notify`, если соединение ещё живо.
    ///
    /// # Errors
    ///
    /// Ошибки сокета.
    pub fn close(&mut self) -> io::Result<()> {
        self.connection.send_close_notify().map_err(to_io)?;
        self.flush_output()
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut buf = vec![0_u8; CHUNK];
        loop {
            // Сначала отдать то, что уже расшифровано.
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
                // Обрыв без close_notify. Для нас это не ошибка данных,
                // а обычное поведение большинства серверов.
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

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.connection.send(data).map_err(to_io)?;
        self.flush_output()?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_output()
    }
}

/// Перевести ошибку протокола в ошибку ввода-вывода, не теряя текста.
fn to_io(error: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
