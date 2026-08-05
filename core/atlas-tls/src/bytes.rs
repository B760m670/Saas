//! Чтение и запись примитивов проводного формата TLS.
//!
//! TLS кодирует переменные поля как длина-затем-значение, где длина занимает
//! один, два или три байта. Отдельный слой для этого нужен потому, что все
//! ошибки разбора чужого ввода должны быть возвращаемыми: разбирается
//! враждебный ввод, паника недопустима.

use crate::error::{Error, Result};

/// Курсор по байтовому срезу.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Создать курсор.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Остались ли непрочитанные байты.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Непрочитанный остаток.
    #[must_use]
    pub const fn rest(&self) -> &'a [u8] {
        self.buf
    }

    /// Прочитать ровно `n` байт.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`], если байтов меньше требуемого.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, tail) = self.buf.split_at_checked(n).ok_or(Error::Truncated)?;
        self.buf = tail;
        Ok(head)
    }

    /// Прочитать один байт.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при исчерпании ввода.
    pub fn u8(&mut self) -> Result<u8> {
        match self.take(1)? {
            [byte] => Ok(*byte),
            _ => Err(Error::Truncated),
        }
    }

    /// Прочитать 16-битное число (big-endian).
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при исчерпании ввода.
    pub fn u16(&mut self) -> Result<u16> {
        match self.take(2)? {
            [hi, lo] => Ok(u16::from_be_bytes([*hi, *lo])),
            _ => Err(Error::Truncated),
        }
    }

    /// Прочитать 24-битное число (big-endian) — длина handshake-сообщения.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при исчерпании ввода.
    pub fn u24(&mut self) -> Result<u32> {
        match self.take(3)? {
            [a, b, c] => Ok(u32::from_be_bytes([0, *a, *b, *c])),
            _ => Err(Error::Truncated),
        }
    }

    /// Прочитать вектор с однобайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при исчерпании ввода.
    pub fn vec_u8(&mut self) -> Result<&'a [u8]> {
        let len = self.u8()? as usize;
        self.take(len)
    }

    /// Прочитать вектор с двухбайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при исчерпании ввода.
    pub fn vec_u16(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    /// Прочитать список 16-битных значений из вектора с двухбайтовой длиной.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] при исчерпании ввода,
    /// [`Error::Malformed`], если длина не кратна двум.
    pub fn list_u16(&mut self) -> Result<Vec<u16>> {
        let body = self.vec_u16()?;
        if body.len() % 2 != 0 {
            return Err(Error::Malformed("список 16-битных значений нечётной длины"));
        }
        Ok(body
            .chunks_exact(2)
            .map(|pair| match pair {
                [hi, lo] => u16::from_be_bytes([*hi, *lo]),
                _ => 0,
            })
            .collect())
    }
}

/// Накопитель байт с поддержкой полей переменной длины.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Создать пустой накопитель.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Забрать накопленные байты.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Текущая длина.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Пуст ли накопитель.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Записать байт.
    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Записать 16-битное число (big-endian).
    pub fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Записать срез как есть.
    pub fn bytes(&mut self, value: &[u8]) {
        self.buf.extend_from_slice(value);
    }

    /// Записать список 16-битных значений.
    pub fn list_u16(&mut self, values: &[u16]) {
        for value in values {
            self.u16(*value);
        }
    }

    /// Записать вложенный блок с однобайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`], если тело не помещается в 255 байт.
    pub fn nested_u8(&mut self, body: impl FnOnce(&mut Self)) -> Result<()> {
        self.nested(1, body)
    }

    /// Записать вложенный блок с двухбайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`], если тело не помещается в 65535 байт.
    pub fn nested_u16(&mut self, body: impl FnOnce(&mut Self)) -> Result<()> {
        self.nested(2, body)
    }

    /// Записать вложенный блок с трёхбайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`], если тело не помещается в 2^24-1 байт.
    pub fn nested_u24(&mut self, body: impl FnOnce(&mut Self)) -> Result<()> {
        self.nested(3, body)
    }

    /// Общая реализация вложенного блока: резервируем место под длину,
    /// пишем тело, затем проставляем длину задним числом.
    fn nested(&mut self, width: usize, body: impl FnOnce(&mut Self)) -> Result<()> {
        let placeholder = self.buf.len();
        self.buf.extend(core::iter::repeat_n(0_u8, width));

        body(self);

        let len = self
            .buf
            .len()
            .checked_sub(placeholder + width)
            .ok_or(Error::Malformed("нарушен учёт длины вложенного блока"))?;

        let max = if width >= 4 {
            usize::MAX
        } else {
            (1_usize << (width * 8)) - 1
        };
        if len > max {
            return Err(Error::TooLong);
        }

        let encoded = len.to_be_bytes();
        let start = encoded.len().saturating_sub(width);
        let src = encoded.get(start..).ok_or(Error::TooLong)?;
        let dst = self
            .buf
            .get_mut(placeholder..placeholder + width)
            .ok_or(Error::Malformed("нарушен учёт длины вложенного блока"))?;
        dst.copy_from_slice(src);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn nested_lengths_are_patched() {
        let mut w = Writer::new();
        w.nested_u16(|inner| {
            inner.u16(0x1301);
            inner.u16(0x1302);
        })
        .unwrap();
        assert_eq!(w.finish(), vec![0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
    }

    #[test]
    fn nested_blocks_compose() {
        let mut w = Writer::new();
        w.nested_u24(|outer| {
            let _ = outer.nested_u8(|inner| inner.bytes(b"ab"));
        })
        .unwrap();
        assert_eq!(w.finish(), vec![0x00, 0x00, 0x03, 0x02, b'a', b'b']);
    }

    #[test]
    fn reader_round_trips_writer() {
        let mut w = Writer::new();
        w.u8(1);
        w.u16(0x0303);
        w.nested_u16(|inner| inner.list_u16(&[0x1301, 0x1302]))
            .unwrap();
        let bytes = w.finish();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 0x0303);
        assert_eq!(r.list_u16().unwrap(), vec![0x1301, 0x1302]);
        assert!(r.is_empty());
    }

    #[test]
    fn reader_reports_truncation_instead_of_panicking() {
        let mut r = Reader::new(&[0x00]);
        assert_eq!(r.u16(), Err(Error::Truncated));

        let mut r = Reader::new(&[0x00, 0x05, 0x01]);
        assert_eq!(r.vec_u16(), Err(Error::Truncated));
    }

    #[test]
    fn rejects_odd_length_u16_list() {
        let mut r = Reader::new(&[0x00, 0x03, 0x01, 0x02, 0x03]);
        assert!(matches!(r.list_u16(), Err(Error::Malformed(_))));
    }

    #[test]
    fn rejects_oversized_nested_block() {
        let mut w = Writer::new();
        let result = w.nested_u8(|inner| inner.bytes(&[0_u8; 256]));
        assert_eq!(result, Err(Error::TooLong));
    }
}
