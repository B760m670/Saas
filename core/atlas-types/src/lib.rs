//! Общие типы ATLAS.
//!
//! Крейт описывает то, чем оперирует вся остальная система: прокси-протоколы,
//! транспорты, слои маскировки и параметры доступа к точкам выхода.
//!
//! Здесь нет ни сети, ни криптографии — только модель данных и разбор. Это
//! позволяет тестировать разбор полностью детерминированно и держать крейт
//! зависимым лишь от разбора текста.
//!
//! # Откуда берутся учётные данные
//!
//! **ATLAS не требует и не предполагает покупку ключей.** [`ProxyKey`] — это
//! внутреннее описание «как достучаться до точки выхода», и у него три
//! источника, из которых покупной — ни один:
//!
//! 1. **Автопровижининг** (основной путь). Приложение само разворачивает точку
//!    на бесплатном аккаунте пользователя, само генерирует для неё пару X25519,
//!    идентификатор и `shortId`, само подбирает домен прикрытия. Пользователь
//!    не видит ни одного ключа и ничего никуда не вставляет.
//! 2. **Каталог сети.** Подписанный дескриптор, полученный из общего каталога
//!    по анонимному креденшелу.
//! 3. **Внешний URI.** Импорт `vless://` и подобных — только для совместимости
//!    и для обмена своей точкой с близкими. Никогда не является обязательным.
//!
//! Разбор URI живёт здесь потому, что транспортному слою всё равно, откуда
//! пришли параметры: он получает одну и ту же структуру во всех трёх случаях.
//! Обратная операция ([`ProxyKey::to_uri`]) нужна для экспорта **своей**
//! точки — чтобы поделиться ею с родственниками одной ссылкой или QR-кодом.
//!
//! # Пример
//!
//! ```
//! use atlas_types::{ProxyKey, Protocol, SecurityKind};
//!
//! let key = ProxyKey::parse(
//!     "vless://11111111-2222-3333-4444-555555555555@example.com:443\
//!      ?security=reality&pbk=Zm9vYmFy&sid=6ba1&sni=www.microsoft.com\
//!      &fp=chrome&flow=xtls-rprx-vision#Точка"
//! )?;
//!
//! assert_eq!(key.protocol, Protocol::Vless);
//! assert_eq!(key.security.kind, SecurityKind::Reality);
//! key.validate()?;
//! # Ok::<(), atlas_types::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod b64;
mod error;
mod key;
mod protocol;
mod subscription;
pub mod uri;

pub use error::{Error, Result};
pub use key::{
    Credentials, ObfsConfig, ProxyKey, RealityConfig, SecurityConfig, TransportConfig, Warning,
};
pub use protocol::{Fingerprint, Flow, Protocol, Resistance, SecurityKind, TransportKind};
pub use subscription::Subscription;
