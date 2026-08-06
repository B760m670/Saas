//! Единственный источник случайности в проекте.
//!
//! Вся криптография берёт энтропию отсюда и только отсюда. Один источник —
//! одна точка аудита: чтобы убедиться, что нигде не используется слабый
//! генератор, достаточно проверить, что в проекте нет других реализаций
//! [`rand_core::CryptoRng`].

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

/// Системный криптографический генератор случайных чисел.
///
/// Обёртка над `getrandom`, приводящая его к инфаллибельному интерфейсу
/// [`rand_core::CryptoRng`], который требуют библиотеки подписи и KEM.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

impl OsRng {
    /// Заполнить буфер случайными байтами.
    ///
    /// # Panics
    ///
    /// Паникует, если операционная система не смогла выдать энтропию.
    /// Это намеренно: продолжение работы означало бы генерацию
    /// предсказуемых ключей, что хуже отказа. Ситуация не встречается
    /// на исправных системах — источник энтропии ядра доступен всегда.
    #[allow(clippy::panic, clippy::expect_used)]
    pub fn fill(dst: &mut [u8]) {
        getrandom::fill(dst).expect("системный источник энтропии недоступен");
    }

    /// Вернуть массив случайных байт фиксированного размера.
    #[must_use]
    pub fn bytes<const N: usize>() -> [u8; N] {
        let mut out = [0_u8; N];
        Self::fill(&mut out);
        out
    }
}

impl TryRng for OsRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes(Self::bytes()))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes(Self::bytes()))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        Self::fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_values() {
        // Совпадение двух 32-байтовых выборок означало бы либо сломанный
        // генератор, либо событие вероятностью 2^-256.
        assert_ne!(OsRng::bytes::<32>(), OsRng::bytes::<32>());
    }

    #[test]
    fn fills_whole_buffer() {
        let mut buf = [0_u8; 64];
        OsRng::fill(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
