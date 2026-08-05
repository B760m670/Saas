//! Метка, которую клиент прячет в поле `session_id`.
//!
//! Шестнадцать байт открытого текста, раскладка разобрана по исходнику Xray
//! (см. `docs/01-protocols.md`, раздел 3.5):
//!
//! ```text
//! +---------+----------+-------------+-----------+
//! | Version | Reserved | Timestamp   | ShortId   |
//! | 3 байта | 1 байт   | 4 байта, BE | 8 байт    |
//! +---------+----------+-------------+-----------+
//! ```
//!
//! После шифрования получается 32 байта — ровно столько, сколько браузер
//! кладёт в `session_id`, и снаружи неотличимых от случайных.

use crate::error::{Error, Result};

/// Длина открытого текста метки.
pub const PLAINTEXT_LEN: usize = 16;
/// Длина `shortId`.
pub const SHORT_ID_LEN: usize = 8;

/// Содержимое метки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    /// Версия клиента: три числа.
    ///
    /// Сервер её не проверяет, но она попадает в аутентифицируемые данные,
    /// поэтому подменить её незаметно нельзя.
    pub version: [u8; 3],
    /// Момент отправки, секунды Unix.
    ///
    /// Сервер отбраковывает метки со слишком большим расхождением, что
    /// закрывает повтор записанного `ClientHello`.
    pub timestamp: u32,
    /// Короткий идентификатор, дополненный нулями до восьми байт.
    pub short_id: [u8; SHORT_ID_LEN],
}

impl Marker {
    /// Собрать метку.
    ///
    /// `short_id` короче восьми байт дополняется нулями — так же поступает
    /// эталонная реализация.
    ///
    /// # Errors
    ///
    /// [`Error::ShortIdTooLong`], если идентификатор длиннее восьми байт.
    pub fn new(version: [u8; 3], timestamp: u32, short_id: &[u8]) -> Result<Self> {
        if short_id.len() > SHORT_ID_LEN {
            return Err(Error::ShortIdTooLong(short_id.len()));
        }
        let mut padded = [0_u8; SHORT_ID_LEN];
        if let Some(slot) = padded.get_mut(..short_id.len()) {
            slot.copy_from_slice(short_id);
        }
        Ok(Self {
            version,
            timestamp,
            short_id: padded,
        })
    }

    /// Разложить метку в шестнадцать байт открытого текста.
    #[must_use]
    pub fn to_plaintext(self) -> [u8; PLAINTEXT_LEN] {
        let mut out = [0_u8; PLAINTEXT_LEN];
        if let Some(slot) = out.get_mut(..3) {
            slot.copy_from_slice(&self.version);
        }
        // Байт 3 остаётся нулевым — зарезервирован.
        if let Some(slot) = out.get_mut(4..8) {
            slot.copy_from_slice(&self.timestamp.to_be_bytes());
        }
        if let Some(slot) = out.get_mut(8..16) {
            slot.copy_from_slice(&self.short_id);
        }
        out
    }

    /// Восстановить метку из открытого текста.
    #[must_use]
    pub fn from_plaintext(bytes: &[u8; PLAINTEXT_LEN]) -> Self {
        let mut version = [0_u8; 3];
        if let Some(slice) = bytes.get(..3) {
            version.copy_from_slice(slice);
        }

        let mut timestamp_bytes = [0_u8; 4];
        if let Some(slice) = bytes.get(4..8) {
            timestamp_bytes.copy_from_slice(slice);
        }

        let mut short_id = [0_u8; SHORT_ID_LEN];
        if let Some(slice) = bytes.get(8..16) {
            short_id.copy_from_slice(slice);
        }

        Self {
            version,
            timestamp: u32::from_be_bytes(timestamp_bytes),
            short_id,
        }
    }

    /// Насколько метка расходится с указанным моментом времени, в секундах.
    ///
    /// Модуль разности: часы клиента могут и отставать, и спешить.
    #[must_use]
    pub const fn skew_from(self, now: u32) -> u32 {
        now.abs_diff(self.timestamp)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_specification() {
        let marker = Marker::new([1, 2, 3], 0x1234_5678, &[0xaa, 0xbb]).unwrap();
        assert_eq!(
            marker.to_plaintext(),
            [
                1, 2, 3, // версия
                0, // зарезервировано
                0x12, 0x34, 0x56, 0x78, // время, big-endian
                0xaa, 0xbb, 0, 0, 0, 0, 0, 0, // shortId с дополнением
            ]
        );
    }

    #[test]
    fn round_trips() {
        let marker = Marker::new([25, 3, 27], 1_800_000_000, &[1, 2, 3, 4]).unwrap();
        assert_eq!(Marker::from_plaintext(&marker.to_plaintext()), marker);
    }

    #[test]
    fn short_id_is_zero_padded() {
        let short = Marker::new([0; 3], 0, &[0xff]).unwrap();
        assert_eq!(short.short_id, [0xff, 0, 0, 0, 0, 0, 0, 0]);

        let full = Marker::new([0; 3], 0, &[7; SHORT_ID_LEN]).unwrap();
        assert_eq!(full.short_id, [7; SHORT_ID_LEN]);
    }

    #[test]
    fn rejects_oversized_short_id() {
        assert_eq!(
            Marker::new([0; 3], 0, &[0; SHORT_ID_LEN + 1]),
            Err(Error::ShortIdTooLong(SHORT_ID_LEN + 1))
        );
    }

    #[test]
    fn skew_is_symmetric() {
        let marker = Marker::new([0; 3], 1000, &[]).unwrap();
        assert_eq!(marker.skew_from(1090), 90);
        assert_eq!(marker.skew_from(910), 90);
        assert_eq!(marker.skew_from(1000), 0);
    }

    #[test]
    fn reserved_byte_stays_zero() {
        let marker = Marker::new([0xff; 3], u32::MAX, &[0xff; SHORT_ID_LEN]).unwrap();
        assert_eq!(marker.to_plaintext().get(3), Some(&0));
    }
}
