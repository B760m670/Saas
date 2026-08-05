//! Поле `addons` — protobuf-сообщение внутри заголовка VLESS.
//!
//! ```proto
//! message Addons {
//!   string Flow = 1;
//!   bytes  Seed = 2;
//! }
//! ```
//!
//! Полноценная библиотека protobuf ради двух полей не нужна, а лишняя
//! зависимость в коде, разбирающем сетевой ввод, — это лишняя поверхность
//! атаки. Реализация здесь минимальная, но соблюдает главное правило
//! protobuf: **неизвестные поля пропускаются, а не считаются ошибкой**.
//! Без этого клиент сломается на первом же расширении протокола.

use crate::error::{Error, Result};

/// Номер поля `Flow`.
const FIELD_FLOW: u64 = 1;
/// Номер поля `Seed`.
const FIELD_SEED: u64 = 2;

/// Тип провода: значение переменной длины (varint).
const WIRE_VARINT: u64 = 0;
/// Тип провода: 64 бита.
const WIRE_FIXED64: u64 = 1;
/// Тип провода: длина, затем байты.
const WIRE_DELIMITED: u64 = 2;
/// Тип провода: 32 бита.
const WIRE_FIXED32: u64 = 5;

/// Содержимое поля `addons`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addons {
    /// Режим потока XTLS, например `xtls-rprx-vision`.
    pub flow: Option<String>,
    /// Дополнительный материал, используемый некоторыми режимами.
    pub seed: Option<Vec<u8>>,
}

impl Addons {
    /// Пустые addons — их кодирование даёт ноль байт.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            flow: None,
            seed: None,
        }
    }

    /// Addons с указанным режимом потока.
    #[must_use]
    pub fn with_flow(flow: impl Into<String>) -> Self {
        Self {
            flow: Some(flow.into()),
            seed: None,
        }
    }

    /// Нет ли в addons ни одного заданного поля.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.flow.is_none() && self.seed.is_none()
    }

    /// Закодировать в байты protobuf.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(flow) = &self.flow {
            // Пустая строка — не то же самое, что отсутствие поля, но
            // кодировать её бессмысленно: сервер трактует их одинаково.
            if !flow.is_empty() {
                write_delimited(&mut out, FIELD_FLOW, flow.as_bytes());
            }
        }
        if let Some(seed) = &self.seed {
            if !seed.is_empty() {
                write_delimited(&mut out, FIELD_SEED, seed);
            }
        }
        out
    }

    /// Разобрать байты protobuf.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при обрыве, [`Error::Malformed`] при нарушении
    /// кодирования varint или неизвестном типе провода.
    pub fn decode(mut input: &[u8]) -> Result<Self> {
        let mut out = Self::empty();

        while !input.is_empty() {
            let (tag, rest) = read_varint(input)?;
            input = rest;

            let field = tag >> 3;
            let wire = tag & 0b111;

            match (field, wire) {
                (FIELD_FLOW, WIRE_DELIMITED) => {
                    let (bytes, rest) = read_delimited(input)?;
                    input = rest;
                    out.flow = Some(
                        core::str::from_utf8(bytes)
                            .map_err(|_| Error::Malformed("flow не в UTF-8"))?
                            .to_owned(),
                    );
                }
                (FIELD_SEED, WIRE_DELIMITED) => {
                    let (bytes, rest) = read_delimited(input)?;
                    input = rest;
                    out.seed = Some(bytes.to_vec());
                }
                // Неизвестное поле — пропускаем, как требует protobuf.
                _ => input = skip_field(input, wire)?,
            }
        }

        Ok(out)
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn write_delimited(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    write_varint(out, (field << 3) | WIRE_DELIMITED);
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn read_varint(input: &[u8]) -> Result<(u64, &[u8])> {
    let mut value: u64 = 0;
    for (index, byte) in input.iter().enumerate() {
        // Больше десяти байт в 64-битном varint быть не может; без этой
        // проверки враждебный ввод крутил бы цикл бесконечно.
        if index >= 10 {
            return Err(Error::Malformed("varint длиннее десяти байт"));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            let rest = input.get(index + 1..).unwrap_or_default();
            return Ok((value, rest));
        }
    }
    Err(Error::Truncated)
}

fn read_delimited(input: &[u8]) -> Result<(&[u8], &[u8])> {
    let (len, rest) = read_varint(input)?;
    let len = usize::try_from(len).map_err(|_| Error::Malformed("длина поля не помещается"))?;
    rest.split_at_checked(len).ok_or(Error::Truncated)
}

fn skip_field(input: &[u8], wire: u64) -> Result<&[u8]> {
    match wire {
        WIRE_VARINT => read_varint(input).map(|(_, rest)| rest),
        WIRE_FIXED64 => input
            .split_at_checked(8)
            .map(|(_, r)| r)
            .ok_or(Error::Truncated),
        WIRE_DELIMITED => read_delimited(input).map(|(_, rest)| rest),
        WIRE_FIXED32 => input
            .split_at_checked(4)
            .map(|(_, r)| r)
            .ok_or(Error::Truncated),
        _ => Err(Error::Malformed("неизвестный тип провода protobuf")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_addons_encode_to_nothing() {
        assert!(Addons::empty().encode().is_empty());
        assert_eq!(Addons::decode(&[]).unwrap(), Addons::empty());
    }

    #[test]
    fn vision_flow_matches_expected_bytes() {
        let encoded = Addons::with_flow("xtls-rprx-vision").encode();
        let mut expected = vec![0x0a, 16];
        expected.extend_from_slice(b"xtls-rprx-vision");
        assert_eq!(encoded, expected);
    }

    #[test]
    fn round_trips_both_fields() {
        let addons = Addons {
            flow: Some("xtls-rprx-vision".into()),
            seed: Some(vec![1, 2, 3]),
        };
        assert_eq!(Addons::decode(&addons.encode()).unwrap(), addons);
    }

    #[test]
    fn unknown_fields_are_skipped() {
        // Поле 15 каждого типа провода вперемешку с известным полем Flow.
        let mut input = Vec::new();
        write_varint(&mut input, (15 << 3) | WIRE_VARINT);
        write_varint(&mut input, 300);
        write_delimited(&mut input, FIELD_FLOW, b"xtls-rprx-vision");
        write_varint(&mut input, (16 << 3) | WIRE_FIXED32);
        input.extend_from_slice(&[0, 0, 0, 0]);
        write_varint(&mut input, (17 << 3) | WIRE_FIXED64);
        input.extend_from_slice(&[0; 8]);
        write_delimited(&mut input, 18, "неизвестно".as_bytes());

        let parsed = Addons::decode(&input).unwrap();
        assert_eq!(parsed.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn multi_byte_varint_round_trips() {
        let mut buf = Vec::new();
        for value in [0_u64, 1, 127, 128, 300, 16_384, u64::from(u32::MAX)] {
            buf.clear();
            write_varint(&mut buf, value);
            assert_eq!(read_varint(&buf).unwrap().0, value, "значение {value}");
        }
    }

    #[test]
    fn rejects_runaway_varint() {
        // Непрерывный поток байт с установленным старшим битом.
        assert!(Addons::decode(&[0xff; 32]).is_err());
    }

    #[test]
    fn rejects_length_beyond_input() {
        // Поле Flow объявляет 100 байт, а их нет.
        assert_eq!(Addons::decode(&[0x0a, 100, 1, 2]), Err(Error::Truncated));
    }

    #[test]
    fn survives_arbitrary_garbage() {
        for seed in 0_u8..=255 {
            let noise: Vec<u8> = (0..seed)
                .map(|i| i.wrapping_mul(seed).wrapping_add(7))
                .collect();
            let _ = Addons::decode(&noise);
        }
    }
}
