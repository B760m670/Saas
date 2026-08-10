//! Кадры WebSocket (RFC 6455).
//!
//! Раскладка кадра:
//!
//! ```text
//!  0               1               2               3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//! |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//! |N|V|V|V|       |S|             |   (если len == 126 или 127)   |
//! | |1|2|3|       |K|             |                               |
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |                     Masking-key (4 байта, если MASK)          |
//! +---------------------------------------------------------------+
//! |                          Payload                              |
//! +---------------------------------------------------------------+
//! ```
//!
//! Важное правило протокола: **клиент обязан маскировать каждый кадр
//! свежим случайным ключом, сервер — обязан не маскировать**. Нарушение
//! в любую сторону — повод для промежуточного узла разорвать соединение,
//! а для наблюдателя — признак самодельной реализации.

use atlas_crypto::rng::OsRng;

use crate::error::{Error, Result};

/// Длина ключа маскирования.
pub const MASK_LEN: usize = 4;

/// Тип кадра.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// Продолжение фрагментированного сообщения.
    Continuation,
    /// Текстовые данные (UTF-8).
    Text,
    /// Двоичные данные. Прокси-трафик идёт только так.
    Binary,
    /// Закрытие соединения.
    Close,
    /// Проверка живости.
    Ping,
    /// Ответ на проверку живости.
    Pong,
}

impl Opcode {
    /// Числовой код.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xa,
        }
    }

    /// Разобрать числовой код.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] для зарезервированных кодов.
    pub const fn from_code(code: u8) -> Result<Self> {
        match code {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xa => Ok(Self::Pong),
            _ => Err(Error::Protocol("зарезервированный код кадра")),
        }
    }

    /// Управляющий ли это кадр.
    ///
    /// Управляющие кадры нельзя фрагментировать, и их длина не может
    /// превышать 125 байт.
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// Кадр WebSocket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Последний ли это фрагмент сообщения.
    pub fin: bool,
    /// Тип кадра.
    pub opcode: Opcode,
    /// Полезная нагрузка в открытом виде.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Двоичный кадр с данными.
    #[must_use]
    pub const fn binary(payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: Opcode::Binary,
            payload,
        }
    }

    /// Кадр проверки живости.
    #[must_use]
    pub const fn ping(payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: Opcode::Ping,
            payload,
        }
    }

    /// Ответ на проверку живости.
    #[must_use]
    pub const fn pong(payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: Opcode::Pong,
            payload,
        }
    }

    /// Закодировать кадр как клиент — с обязательным маскированием.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`], если управляющий кадр длиннее 125 байт.
    pub fn encode_masked(&self) -> Result<Vec<u8>> {
        self.encode(Some(OsRng::bytes::<MASK_LEN>()))
    }

    /// Закодировать кадр как сервер — без маскирования.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`], если управляющий кадр длиннее 125 байт.
    pub fn encode_unmasked(&self) -> Result<Vec<u8>> {
        self.encode(None)
    }

    fn encode(&self, mask: Option<[u8; MASK_LEN]>) -> Result<Vec<u8>> {
        if self.opcode.is_control() {
            if self.payload.len() > 125 {
                return Err(Error::Protocol("управляющий кадр длиннее 125 байт"));
            }
            if !self.fin {
                return Err(Error::Protocol("управляющий кадр не может быть фрагментом"));
            }
        }

        let mut out = Vec::with_capacity(self.payload.len() + 14);
        out.push(if self.fin { 0x80 } else { 0x00 } | self.opcode.code());

        let mask_bit = if mask.is_some() { 0x80 } else { 0x00 };
        let len = self.payload.len();
        if len < 126 {
            out.push(mask_bit | u8::try_from(len).unwrap_or(0));
        } else if let Ok(short) = u16::try_from(len) {
            out.push(mask_bit | 0x7e);
            out.extend_from_slice(&short.to_be_bytes());
        } else {
            out.push(mask_bit | 0x7f);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }

        match mask {
            Some(key) => {
                out.extend_from_slice(&key);
                out.extend(
                    self.payload
                        .iter()
                        .zip(key.iter().cycle())
                        .map(|(byte, k)| byte ^ k),
                );
            }
            None => out.extend_from_slice(&self.payload),
        }

        Ok(out)
    }
}

/// Сборщик кадров из потока байт.
///
/// Границы чтений из сокета не совпадают с границами кадров, поэтому
/// собирать обязательно, а не считать одно чтение одним кадром.
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

    /// Добавить прочитанный кусок.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    /// Сколько байт лежит в буфере, не составив целого кадра.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// Извлечь следующий полный кадр.
    ///
    /// Возвращает `Ok(None)`, если кадр ещё не собрался целиком.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] при нарушении правил протокола: выставленные
    /// биты RSV, зарезервированный код, слишком длинный управляющий кадр.
    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        let (first, second) = match self.buffer.as_slice() {
            [first, second, ..] => (*first, *second),
            _ => return Ok(None),
        };

        // Биты RSV используются только расширениями, которых мы не
        // согласовывали. Выставленный бит — либо чужое расширение, либо
        // повреждение; в обоих случаях продолжать нельзя.
        if first & 0x70 != 0 {
            return Err(Error::Protocol("выставлены биты RSV без расширений"));
        }

        let fin = first & 0x80 != 0;
        let opcode = Opcode::from_code(first & 0x0f)?;
        let masked = second & 0x80 != 0;
        let short_len = usize::from(second & 0x7f);

        let (payload_len, len_bytes) = match short_len {
            126 => match self.buffer.get(2..4) {
                Some([hi, lo]) => (usize::from(u16::from_be_bytes([*hi, *lo])), 2),
                _ => return Ok(None),
            },
            127 => match self
                .buffer
                .get(2..10)
                .and_then(|s| <[u8; 8]>::try_from(s).ok())
            {
                Some(raw) => {
                    let len = u64::from_be_bytes(raw);
                    // Старший бит длины обязан быть нулём по RFC 6455.
                    if len & 0x8000_0000_0000_0000 != 0 {
                        return Err(Error::Protocol("недопустимая длина кадра"));
                    }
                    match usize::try_from(len) {
                        Ok(len) => (len, 8),
                        Err(_) => return Err(Error::Protocol("длина кадра не помещается в usize")),
                    }
                }
                None => return Ok(None),
            },
            len => (len, 0),
        };

        if opcode.is_control() && payload_len > 125 {
            return Err(Error::Protocol("управляющий кадр длиннее 125 байт"));
        }

        let mask_bytes = if masked { MASK_LEN } else { 0 };
        let header_len = 2 + len_bytes + mask_bytes;
        let total = header_len + payload_len;
        if self.buffer.len() < total {
            return Ok(None);
        }

        let mask: Option<[u8; MASK_LEN]> = if masked {
            self.buffer
                .get(2 + len_bytes..2 + len_bytes + MASK_LEN)
                .and_then(|s| <[u8; MASK_LEN]>::try_from(s).ok())
        } else {
            None
        };

        let mut payload = self
            .buffer
            .get(header_len..total)
            .ok_or(Error::Protocol("нарушен учёт длины кадра"))?
            .to_vec();

        if let Some(key) = mask {
            for (byte, k) in payload.iter_mut().zip(key.iter().cycle()) {
                *byte ^= k;
            }
        }

        self.buffer.drain(..total);
        Ok(Some(Frame {
            fin,
            opcode,
            payload,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn decode_one(bytes: &[u8]) -> Frame {
        let mut decoder = Decoder::new();
        decoder.push(bytes);
        decoder.next_frame().unwrap().unwrap()
    }

    #[test]
    fn masked_frame_round_trips() {
        let frame = Frame::binary(b"vless payload".to_vec());
        let wire = frame.encode_masked().unwrap();
        assert_eq!(decode_one(&wire), frame);
    }

    #[test]
    fn client_frames_are_always_masked() {
        let wire = Frame::binary(b"x".to_vec()).encode_masked().unwrap();
        assert_eq!(
            wire.get(1).map(|b| b & 0x80),
            Some(0x80),
            "бит MASK обязателен"
        );

        // Нагрузка снимается тем же ключом, что лежит на проводе.
        //
        // Сравнивать замаскированный байт с открытым на неравенство
        // нельзя, хотя соблазн велик: маскирование — это XOR со
        // случайным ключом, и один раз из 256 первый байт ключа
        // оказывается нулём. Тогда байт совпадает с открытым, маска при
        // этом наложена правильно, а проверка падает. Так и случилось:
        // `left: Some(120), right: Some(120)` — то есть `x` и `x`.
        //
        // Проверять надо то, что действительно требуется от отправителя:
        // что ключ на проводе снимает нагрузку обратно.
        let first_key_byte = wire.get(2).copied().unwrap();
        let masked = wire.get(6).copied().unwrap();
        assert_eq!(
            masked ^ first_key_byte,
            b'x',
            "ключ с провода не снимает маску обратно"
        );
    }

    #[test]
    fn server_frames_are_never_masked() {
        let wire = Frame::binary(b"x".to_vec()).encode_unmasked().unwrap();
        assert_eq!(wire.get(1).map(|b| b & 0x80), Some(0x00));
        assert_eq!(wire.get(2), Some(&b'x'));
    }

    #[test]
    fn every_frame_gets_a_fresh_mask() {
        // Повтор ключа маскирования — уязвимость и признак реализации.
        let masks: std::collections::HashSet<Vec<u8>> = (0..64)
            .map(|_| {
                let wire = Frame::binary(vec![0; 8]).encode_masked().unwrap();
                wire.get(2..6).unwrap_or_default().to_vec()
            })
            .collect();
        assert!(masks.len() > 60, "ключи маскирования повторяются");
    }

    #[test]
    fn all_three_length_encodings_work() {
        for len in [0_usize, 1, 125, 126, 127, 65535, 65536, 70000] {
            let frame = Frame::binary(vec![0xab; len]);
            let wire = frame.encode_masked().unwrap();
            assert_eq!(decode_one(&wire), frame, "длина {len}");
        }
    }

    #[test]
    fn length_encoding_is_minimal() {
        // Использование длинной формы там, где хватает короткой, —
        // отклонение от того, что делают обычные библиотеки.
        assert_eq!(
            Frame::binary(vec![0; 125]).encode_masked().unwrap().get(1),
            Some(&(0x80_u8 | 0x7d))
        );
        assert_eq!(
            Frame::binary(vec![0; 126]).encode_masked().unwrap().get(1),
            Some(&(0x80_u8 | 0x7e))
        );
        assert_eq!(
            Frame::binary(vec![0; 65536])
                .encode_masked()
                .unwrap()
                .get(1),
            Some(&(0x80_u8 | 0x7f))
        );
    }

    #[test]
    fn reassembles_across_arbitrary_chunk_boundaries() {
        let mut wire = Vec::new();
        for payload in [&b"first"[..], b"second", b"third"] {
            wire.extend(Frame::binary(payload.to_vec()).encode_masked().unwrap());
        }

        for chunk_size in 1..=wire.len().min(40) {
            let mut decoder = Decoder::new();
            let mut received = Vec::new();
            for chunk in wire.chunks(chunk_size) {
                decoder.push(chunk);
                while let Some(frame) = decoder.next_frame().unwrap() {
                    received.push(frame.payload);
                }
            }
            assert_eq!(
                received,
                vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
                "куски по {chunk_size} байт"
            );
            assert_eq!(decoder.pending(), 0);
        }
    }

    #[test]
    fn fragmented_message_preserves_fin_and_opcode() {
        let first = Frame {
            fin: false,
            opcode: Opcode::Binary,
            payload: b"part".to_vec(),
        };
        let rest = Frame {
            fin: true,
            opcode: Opcode::Continuation,
            payload: b"ition".to_vec(),
        };

        let mut decoder = Decoder::new();
        decoder.push(&first.encode_masked().unwrap());
        decoder.push(&rest.encode_masked().unwrap());

        assert_eq!(decoder.next_frame().unwrap(), Some(first));
        assert_eq!(decoder.next_frame().unwrap(), Some(rest));
    }

    #[test]
    fn control_frames_are_bounded() {
        assert!(Frame::ping(vec![0; 125]).encode_masked().is_ok());
        assert!(matches!(
            Frame::ping(vec![0; 126]).encode_masked(),
            Err(Error::Protocol(_))
        ));

        let fragmented_control = Frame {
            fin: false,
            opcode: Opcode::Close,
            payload: Vec::new(),
        };
        assert!(matches!(
            fragmented_control.encode_masked(),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn rejects_reserved_bits_and_opcodes() {
        let mut decoder = Decoder::new();
        // RSV1 выставлен.
        decoder.push(&[0xc0, 0x00]);
        assert!(matches!(decoder.next_frame(), Err(Error::Protocol(_))));

        let mut decoder = Decoder::new();
        // Код 0x3 зарезервирован.
        decoder.push(&[0x83, 0x00]);
        assert!(matches!(decoder.next_frame(), Err(Error::Protocol(_))));
    }

    #[test]
    fn partial_frame_is_kept_not_consumed() {
        let wire = Frame::binary(b"hello".to_vec()).encode_masked().unwrap();
        let mut decoder = Decoder::new();
        decoder.push(wire.get(..4).unwrap_or_default());
        assert_eq!(decoder.next_frame().unwrap(), None);
        assert_eq!(decoder.pending(), 4);

        decoder.push(wire.get(4..).unwrap_or_default());
        assert!(decoder.next_frame().unwrap().is_some());
    }

    #[test]
    fn survives_arbitrary_garbage() {
        for seed in 0_u8..=255 {
            let mut decoder = Decoder::new();
            let noise: Vec<u8> = (0..seed).map(|i| i.wrapping_mul(seed) ^ 0x5f).collect();
            decoder.push(&noise);
            let _ = decoder.next_frame();
        }
    }
}
