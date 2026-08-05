//! Обрамление датаграмм UDP внутри потока VLESS.
//!
//! Поток TCP границ сообщений не сохраняет, поэтому каждая датаграмма
//! предваряется двухбайтовой длиной. Приёмник обязан собирать из потока,
//! а не считать, что одно чтение из сокета — это ровно одна датаграмма:
//! иначе на границах TLS-записей пакеты начнут склеиваться и биться.

use crate::error::{Error, Result};

/// Максимальный размер датаграммы, помещающийся в двухбайтовую длину.
pub const MAX_DATAGRAM: usize = u16::MAX as usize;

/// Закодировать датаграмму.
///
/// # Errors
///
/// [`Error::TooLong`], если размер превышает [`MAX_DATAGRAM`].
pub fn encode(payload: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(payload.len())
        .map_err(|_| Error::TooLong("датаграмма длиннее 65535 байт"))?;
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Сборщик датаграмм из потока байт.
#[derive(Debug, Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    /// Создать пустой сборщик.
    #[must_use]
    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Добавить очередной кусок, прочитанный из потока.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    /// Извлечь следующую полную датаграмму, если она уже собралась.
    #[must_use]
    pub fn next_datagram(&mut self) -> Option<Vec<u8>> {
        let (hi, lo) = match self.buffer.as_slice() {
            [hi, lo, ..] => (*hi, *lo),
            _ => return None,
        };
        let len = u16::from_be_bytes([hi, lo]) as usize;

        if self.buffer.len() < 2 + len {
            return None;
        }

        let rest = self.buffer.split_off(2 + len);
        let mut datagram = core::mem::replace(&mut self.buffer, rest);
        datagram.drain(..2);
        Some(datagram)
    }

    /// Сколько байт ещё лежит в буфере, не составив целой датаграммы.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn single_datagram_round_trips() {
        let mut decoder = Decoder::new();
        decoder.push(&encode(b"hello").unwrap());
        assert_eq!(decoder.next_datagram().as_deref(), Some(&b"hello"[..]));
        assert_eq!(decoder.next_datagram(), None);
    }

    #[test]
    fn reassembles_across_arbitrary_chunk_boundaries() {
        // Главное свойство: границы чтений из потока не совпадают
        // с границами датаграмм.
        let mut wire = Vec::new();
        for payload in [&b"first"[..], b"second", b"third"] {
            wire.extend_from_slice(&encode(payload).unwrap());
        }

        for chunk_size in 1..=wire.len() {
            let mut decoder = Decoder::new();
            let mut received = Vec::new();
            for chunk in wire.chunks(chunk_size) {
                decoder.push(chunk);
                while let Some(datagram) = decoder.next_datagram() {
                    received.push(datagram);
                }
            }
            assert_eq!(
                received,
                vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
                "разбиение по {chunk_size} байт"
            );
            assert_eq!(decoder.pending(), 0);
        }
    }

    #[test]
    fn empty_datagram_is_preserved() {
        // Пустая датаграмма UDP допустима и не должна теряться.
        let mut decoder = Decoder::new();
        decoder.push(&encode(b"").unwrap());
        assert_eq!(decoder.next_datagram(), Some(Vec::new()));
    }

    #[test]
    fn partial_input_yields_nothing_and_is_kept() {
        let mut decoder = Decoder::new();
        decoder.push(&[0x00, 0x05, b'a', b'b']);
        assert_eq!(decoder.next_datagram(), None);
        assert_eq!(decoder.pending(), 4);

        decoder.push(b"cde");
        assert_eq!(decoder.next_datagram().as_deref(), Some(&b"abcde"[..]));
    }

    #[test]
    fn rejects_oversized_payload() {
        let payload = vec![0_u8; MAX_DATAGRAM + 1];
        assert!(matches!(encode(&payload), Err(Error::TooLong(_))));
    }

    #[test]
    fn maximum_size_is_accepted() {
        let payload = vec![0_u8; MAX_DATAGRAM];
        let mut decoder = Decoder::new();
        decoder.push(&encode(&payload).unwrap());
        assert_eq!(decoder.next_datagram().map(|d| d.len()), Some(MAX_DATAGRAM));
    }
}
