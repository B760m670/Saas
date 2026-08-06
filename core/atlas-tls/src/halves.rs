//! Половины установленного соединения.
//!
//! После рукопожатия направления TLS независимы: у каждого свой ключ и
//! свой счётчик записей. Разъятие соединения надвое — не украшение, а
//! необходимость: перекачка байт в обе стороны иначе требует либо
//! замка, либо очереди, и то и другое приводит к взаимной блокировке,
//! потому что чтение из сокета блокирующее.
//!
//! Ровно на этом проект уже обжёгся: локальный прокси гонял оба
//! направления через один канал и поток-насос, который разбирал очередь
//! на отправку **между** блокирующими чтениями. Клиент, заговоривший
//! первым после паузы, ждал ответа до предела чтения (тридцать секунд)
//! и получал обрыв. Через `curl` это выживало случайно — пачка сервера
//! приходит несколькими сегментами, и насос успевал слить очередь между
//! ними. Разбор — в `docs/09-lab.md`, раздел 11.
//!
//! Половины одинаковы для клиента и сервера: в TLS 1.3 после
//! рукопожатия стороны различаются только ключами.

use crate::error::{Error, Result};
use crate::record::{ContentType, Protection, HEADER_LEN, MAX_PLAINTEXT};

/// Половина установленного соединения, отвечающая за чтение.
///
/// После рукопожатия направления независимы: у каждого свой ключ и свой
/// счётчик записей. Это позволяет развести их по потокам без замка —
/// а замок здесь был бы не просто накладным расходом, а источником
/// взаимной блокировки, потому что чтение из сокета блокирующее.
#[derive(Debug)]
pub struct RecordReader {
    pub(crate) protection: Protection,
    pub(crate) buffer: Vec<u8>,
    pub(crate) closed: bool,
}

impl RecordReader {
    /// Скормить сырые байты и забрать расшифрованное.
    ///
    /// # Errors
    ///
    /// [`Error::Aead`] при неудачной проверке подлинности,
    /// [`Error::Alert`] при фатальном предупреждении.
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        let mut out = Vec::new();

        while let Some(header) = self.buffer.get(..HEADER_LEN) {
            let declared = match header {
                [_, _, _, hi, lo] => usize::from(u16::from_be_bytes([*hi, *lo])),
                _ => break,
            };
            let Some(total) = HEADER_LEN.checked_add(declared) else {
                return Err(Error::Malformed("длина записи переполнена"));
            };
            if self.buffer.len() < total {
                break;
            }
            let record = self.buffer.get(..total).unwrap_or_default().to_vec();
            self.buffer.drain(..total);

            let outer = ContentType::from_code(*record.first().unwrap_or(&0))?;
            if outer == ContentType::ChangeCipherSpec {
                continue;
            }
            let (content_type, body) = self.protection.decrypt(&record)?;
            match content_type {
                ContentType::ApplicationData => out.extend_from_slice(&body),
                // Сообщения после рукопожатия — билеты и смена ключей.
                // Первых мы не выдаём, вторые в перекачке не встречаются;
                // `change_cipher_spec` внутри шифрования не бывает вовсе.
                ContentType::Handshake | ContentType::ChangeCipherSpec => {}
                ContentType::Alert => match body.as_slice() {
                    [_, 0] => self.closed = true,
                    [_, code] => return Err(Error::Alert(*code)),
                    _ => return Err(Error::Malformed("предупреждение неверной длины")),
                },
            }
        }
        Ok(out)
    }

    /// Закрыл ли собеседник свою сторону.
    #[must_use]
    pub const fn peer_closed(&self) -> bool {
        self.closed
    }
}

/// Половина установленного соединения, отвечающая за запись.
#[derive(Debug)]
pub struct RecordWriter {
    pub(crate) protection: Protection,
}

impl RecordWriter {
    /// Зашифровать прикладные данные в готовые записи.
    ///
    /// # Errors
    ///
    /// Отказ шифрования либо переполнение счётчика записей.
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for chunk in data.chunks(MAX_PLAINTEXT - 1) {
            let record = self
                .protection
                .encrypt(ContentType::ApplicationData, chunk, 0)?;
            out.extend_from_slice(&record);
        }
        Ok(out)
    }

    /// Записать `close_notify`.
    ///
    /// # Errors
    ///
    /// Отказ шифрования.
    pub fn close_notify(&mut self) -> Result<Vec<u8>> {
        self.protection
            .encrypt(ContentType::Alert, &[0x01, 0x00], 0)
    }
}
