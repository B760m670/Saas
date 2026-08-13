//! Денежные суммы.
//!
//! Хранятся целым числом минорных единиц. Плавающая точка здесь запрещена
//! намеренно: `0.1 + 0.2` в двоичном представлении не равно `0.3`, и
//! расхождение в одну копейку между выставленным счётом и пришедшим
//! платежом ломает сверку — платёж считается «не на ту сумму», подписка не
//! выдаётся, разбираться приходится вручную с каждым таким покупателем.

use serde::{Deserialize, Serialize};

/// Валюта расчёта.
///
/// Список короткий намеренно: рубли берутся с покупателя, USDT приходит от
/// сервиса при выплате. Всё остальное добавляется по мере надобности —
/// пустые варианты только заставляли бы обрабатывать несуществующие случаи.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Currency {
    /// Российский рубль, минорная единица — копейка.
    Rub,
    /// Tether. Минорная единица соответствует шести знакам TRC-20.
    Usdt,
}

impl Currency {
    /// Сколько десятичных знаков у валюты.
    #[must_use]
    pub const fn exponent(self) -> u32 {
        match self {
            Self::Rub => 2,
            Self::Usdt => 6,
        }
    }

    /// Буквенный код для передачи платёжному сервису.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Rub => "RUB",
            Self::Usdt => "USDT",
        }
    }

    /// Разобрать код валюты, присланный сервисом (регистронезависимо).
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        match code.trim().to_ascii_uppercase().as_str() {
            "RUB" | "RUR" | "643" => Some(Self::Rub),
            "USDT" | "USDTTRC20" | "USDT_TRC20" => Some(Self::Usdt),
            _ => None,
        }
    }

    /// Множитель перехода от мажорной единицы к минорной.
    const fn scale(self) -> u64 {
        10u64.pow(self.exponent())
    }
}

/// Сумма в конкретной валюте.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    minor: u64,
    currency: Currency,
}

impl Money {
    /// Собрать сумму из минорных единиц.
    #[must_use]
    pub const fn from_minor(minor: u64, currency: Currency) -> Self {
        Self { minor, currency }
    }

    /// Собрать сумму из целых мажорных единиц: `Money::from_major(299, Rub)`.
    ///
    /// Возвращает `None` при переполнении.
    #[must_use]
    pub fn from_major(major: u64, currency: Currency) -> Option<Self> {
        major
            .checked_mul(currency.scale())
            .map(|minor| Self { minor, currency })
    }

    /// Количество минорных единиц.
    #[must_use]
    pub const fn minor(self) -> u64 {
        self.minor
    }

    /// Валюта суммы.
    #[must_use]
    pub const fn currency(self) -> Currency {
        self.currency
    }

    /// Десятичная запись для передачи сервису: `299.00`, `12.500000`.
    ///
    /// Знаков после точки ровно столько, сколько у валюты. Сервисы,
    /// сверяющие сумму строкой, на укороченной записи дают отказ.
    #[must_use]
    pub fn to_decimal(self) -> String {
        let width = self.currency.exponent() as usize;
        let scale = self.currency.scale();
        let major = self.minor / scale;
        let rest = self.minor % scale;
        format!("{major}.{rest:0width$}")
    }

    /// Разобрать десятичную запись, пришедшую от сервиса.
    ///
    /// Лишние нули справа допускаются (`299.000` при двух знаках у рубля) —
    /// сервисы часто выравнивают всё под шесть знаков. Значащая цифра за
    /// пределами точности валюты отвергается: молча отбросить её значит
    /// принять платёж не на ту сумму и не заметить этого.
    #[must_use]
    pub fn parse_decimal(text: &str, currency: Currency) -> Option<Self> {
        let text = text.trim();
        let (whole, frac) = text.split_once('.').unwrap_or((text, ""));

        if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }

        let width = currency.exponent() as usize;
        let (significant, tail) = frac.split_at_checked(width.min(frac.len()))?;
        if tail.bytes().any(|b| b != b'0') {
            return None;
        }

        let mut minor = whole.parse::<u64>().ok()?.checked_mul(currency.scale())?;
        if !significant.is_empty() {
            let mut value = significant.parse::<u64>().ok()?;
            for _ in significant.len()..width {
                value = value.checked_mul(10)?;
            }
            minor = minor.checked_add(value)?;
        }
        Some(Self { minor, currency })
    }
}

#[cfg(test)]
mod tests {
    use super::{Currency, Money};

    #[test]
    fn decimal_keeps_the_exact_number_of_places() {
        let price = Money::from_minor(29_900, Currency::Rub);
        assert_eq!(price.to_decimal(), "299.00");
        assert_eq!(Money::from_major(299, Currency::Rub), Some(price));

        let payout = Money::from_minor(12_500_000, Currency::Usdt);
        assert_eq!(payout.to_decimal(), "12.500000");
    }

    #[test]
    fn decimal_survives_a_round_trip() {
        for minor in [0, 1, 99, 100, 29_900, 1_000_000] {
            let money = Money::from_minor(minor, Currency::Rub);
            assert_eq!(
                Money::parse_decimal(&money.to_decimal(), Currency::Rub),
                Some(money)
            );
        }
    }

    #[test]
    fn padding_zeros_are_accepted_but_real_digits_are_not() {
        // Сервис выровнял рублёвую сумму под шесть знаков — это те же 299 ₽.
        assert_eq!(
            Money::parse_decimal("299.000000", Currency::Rub),
            Money::from_major(299, Currency::Rub)
        );
        // А здесь третий знак значащий: сумма не представима в копейках,
        // и принять её как 299.12 значило бы потерять деньги молча.
        assert_eq!(Money::parse_decimal("299.125", Currency::Rub), None);
    }

    #[test]
    fn missing_fraction_is_a_whole_amount() {
        assert_eq!(
            Money::parse_decimal("299", Currency::Rub),
            Money::from_major(299, Currency::Rub)
        );
    }

    #[test]
    fn junk_is_rejected() {
        for text in ["", ".", "-1", "1e3", "299,00", "abc", "29 9"] {
            assert_eq!(
                Money::parse_decimal(text, Currency::Rub),
                None,
                "принято мусорное значение {text:?}"
            );
        }
    }

    #[test]
    fn currency_codes_come_back_in_every_spelling_seen_in_the_wild() {
        assert_eq!(Currency::parse("rub"), Some(Currency::Rub));
        assert_eq!(Currency::parse("RUR"), Some(Currency::Rub));
        assert_eq!(Currency::parse("643"), Some(Currency::Rub));
        assert_eq!(Currency::parse("usdt_trc20"), Some(Currency::Usdt));
        assert_eq!(Currency::parse("EUR"), None);
    }
}
