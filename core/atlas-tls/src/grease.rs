//! Значения GREASE (RFC 8701).
//!
//! Браузеры подмешивают заведомо неизвестные значения в списки шифров,
//! групп, версий и расширений, чтобы серверы не «окаменели» на текущем
//! наборе. Для нас это важно с двух сторон: без GREASE наш `ClientHello`
//! отличается от браузерного, а при вычислении отпечатка эти значения,
//! наоборот, обязаны отбрасываться — иначе отпечаток менялся бы от
//! соединения к соединению.

/// Все шестнадцать зарезервированных значений.
pub const VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Является ли значение зарезервированным под GREASE.
///
/// Проверяется форма `0xNaNa`: младший полубайт каждого байта равен `a`,
/// а сами байты совпадают.
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

/// Выбрать случайное значение GREASE.
#[must_use]
pub fn pick() -> u16 {
    let index = usize::from(atlas_crypto::rng::OsRng::bytes::<1>()[0] >> 4);
    // Индекс заведомо в диапазоне 0..16, но паниковать здесь нельзя.
    *VALUES.get(index).unwrap_or(&0x0a0a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_all_reserved_values() {
        assert!(VALUES.iter().copied().all(is_grease));
    }

    #[test]
    fn rejects_real_values() {
        // Настоящие шифры, группы и расширения не должны попадать под маску.
        for value in [
            0x1301_u16, 0x1302, 0xc02b, 0x001d, 0x0000, 0x0010, 0xff01, 0x11ec,
        ] {
            assert!(!is_grease(value), "{value:#06x}");
        }
    }

    #[test]
    fn rejects_lookalikes() {
        // Форма похожа, но байты не совпадают либо полубайт не тот.
        assert!(!is_grease(0x0a1a));
        assert!(!is_grease(0x0b0b));
    }

    #[test]
    fn pick_returns_reserved_value() {
        for _ in 0..64 {
            assert!(is_grease(pick()));
        }
    }
}
