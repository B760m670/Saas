//! Заголовок запроса и ответа VLESS.
//!
//! Формат запроса, по байтам:
//!
//! ```text
//! +---------+----------+----------+--------+---------+--------+----------+---------+
//! | Version | UUID     | AddonLen | Addons | Command | Port   | AddrType | Address |
//! | 1 байт  | 16 байт  | 1 байт   | M байт | 1 байт  | 2 байт | 1 байт   | N байт  |
//! +---------+----------+----------+--------+---------+--------+----------+---------+
//! ```
//!
//! Ответ короче: версия, длина addons, addons.
//!
//! Своего шифрования у VLESS нет — это осознанное решение авторов
//! протокола: шифрование делает TLS, а VLESS остаётся тонким адресным
//! конвертом с нулевым оверхедом. Практическое следствие: **UUID летит
//! открытым текстом**, и без TLS или REALITY протокол вскрывается по
//! первым семнадцати байтам. Проверка на это есть в `atlas-types`.

use crate::addons::Addons;
use crate::error::{Error, Result};

/// Единственная существующая версия протокола.
pub const VERSION: u8 = 0x00;

/// Команда запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Поток TCP.
    Tcp,
    /// Датаграммы UDP.
    Udp,
    /// Мультиплексирование; адрес назначения в заголовке отсутствует.
    Mux,
}

impl Command {
    /// Числовой код команды.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Tcp => 0x01,
            Self::Udp => 0x02,
            Self::Mux => 0x03,
        }
    }

    /// Разобрать числовой код.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownCommand`] для незнакомого кода.
    pub const fn from_code(code: u8) -> Result<Self> {
        match code {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            0x03 => Ok(Self::Mux),
            other => Err(Error::UnknownCommand(other)),
        }
    }
}

/// Адрес назначения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// Адрес IPv4.
    Ipv4([u8; 4]),
    /// Доменное имя.
    ///
    /// Предпочтительнее адресов: резолв выполняет точка выхода, а значит
    /// DNS-запрос не покидает туннель и не виден оператору.
    Domain(String),
    /// Адрес IPv6.
    Ipv6([u8; 16]),
}

impl Address {
    /// Код типа адреса.
    #[must_use]
    pub const fn type_code(&self) -> u8 {
        match self {
            Self::Ipv4(_) => 0x01,
            Self::Domain(_) => 0x02,
            Self::Ipv6(_) => 0x03,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.push(self.type_code());
        match self {
            Self::Ipv4(octets) => out.extend_from_slice(octets),
            Self::Ipv6(octets) => out.extend_from_slice(octets),
            Self::Domain(name) => {
                let len = u8::try_from(name.len())
                    .map_err(|_| Error::TooLong("доменное имя длиннее 255 байт"))?;
                if len == 0 {
                    return Err(Error::Malformed("пустое доменное имя"));
                }
                out.push(len);
                out.extend_from_slice(name.as_bytes());
            }
        }
        Ok(())
    }

    fn decode(input: &[u8]) -> Result<(Self, &[u8])> {
        let (type_code, rest) = input.split_first().ok_or(Error::Truncated)?;
        match type_code {
            0x01 => {
                let (raw, rest) = take(rest, 4)?;
                let octets: [u8; 4] = raw.try_into().map_err(|_| Error::Truncated)?;
                Ok((Self::Ipv4(octets), rest))
            }
            0x02 => {
                let (len, rest) = rest.split_first().ok_or(Error::Truncated)?;
                let (raw, rest) = take(rest, *len as usize)?;
                let name = core::str::from_utf8(raw).map_err(|_| Error::InvalidDomain)?;
                if name.is_empty() {
                    return Err(Error::Malformed("пустое доменное имя"));
                }
                Ok((Self::Domain(name.to_owned()), rest))
            }
            0x03 => {
                let (raw, rest) = take(rest, 16)?;
                let octets: [u8; 16] = raw.try_into().map_err(|_| Error::Truncated)?;
                Ok((Self::Ipv6(octets), rest))
            }
            other => Err(Error::UnknownAddressType(*other)),
        }
    }
}

/// Адрес и порт назначения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Адрес.
    pub address: Address,
    /// Порт.
    pub port: u16,
}

impl Endpoint {
    /// Создать точку назначения.
    #[must_use]
    pub const fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }
}

/// Заголовок запроса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Идентификатор пользователя, 16 байт.
    pub uuid: [u8; 16],
    /// Дополнительные поля, в первую очередь режим потока.
    pub addons: Addons,
    /// Команда.
    pub command: Command,
    /// Назначение. Отсутствует только для [`Command::Mux`].
    pub destination: Option<Endpoint>,
}

impl Request {
    /// Запрос на установление TCP-соединения.
    #[must_use]
    pub const fn tcp(uuid: [u8; 16], destination: Endpoint) -> Self {
        Self {
            uuid,
            addons: Addons::empty(),
            command: Command::Tcp,
            destination: Some(destination),
        }
    }

    /// Запрос на передачу датаграмм UDP.
    #[must_use]
    pub const fn udp(uuid: [u8; 16], destination: Endpoint) -> Self {
        Self {
            uuid,
            addons: Addons::empty(),
            command: Command::Udp,
            destination: Some(destination),
        }
    }

    /// Задать режим потока.
    #[must_use]
    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.addons = Addons::with_flow(flow);
        self
    }

    /// Закодировать заголовок.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`], если addons или доменное имя не помещаются в
    /// свои однобайтовые длины; [`Error::Malformed`], если для команды,
    /// требующей адрес, он не задан.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let addons = self.addons.encode();
        let addon_len =
            u8::try_from(addons.len()).map_err(|_| Error::TooLong("addons длиннее 255 байт"))?;

        let mut out = Vec::with_capacity(24 + addons.len());
        out.push(VERSION);
        out.extend_from_slice(&self.uuid);
        out.push(addon_len);
        out.extend_from_slice(&addons);
        out.push(self.command.code());

        match (&self.destination, self.command) {
            (Some(endpoint), _) => {
                out.extend_from_slice(&endpoint.port.to_be_bytes());
                endpoint.address.encode(&mut out)?;
            }
            // Mux мультиплексирует несколько потоков, у каждого из которых
            // свой адрес внутри, поэтому во внешнем заголовке его нет.
            (None, Command::Mux) => {}
            (None, _) => return Err(Error::Malformed("команде требуется адрес назначения")),
        }

        Ok(out)
    }

    /// Разобрать заголовок, вернув его и непрочитанный остаток.
    ///
    /// Остаток — это уже полезная нагрузка: в VLESS она идёт сразу за
    /// заголовком, без разделителя.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`], [`Error::UnknownCommand`],
    /// [`Error::UnknownAddressType`], [`Error::Truncated`].
    pub fn decode(input: &[u8]) -> Result<(Self, &[u8])> {
        let (version, rest) = input.split_first().ok_or(Error::Truncated)?;
        if *version != VERSION {
            return Err(Error::UnsupportedVersion(*version));
        }

        let (raw_uuid, rest) = take(rest, 16)?;
        let uuid: [u8; 16] = raw_uuid.try_into().map_err(|_| Error::Truncated)?;

        let (addon_len, rest) = rest.split_first().ok_or(Error::Truncated)?;
        let (raw_addons, rest) = take(rest, *addon_len as usize)?;
        let addons = Addons::decode(raw_addons)?;

        let (command_code, rest) = rest.split_first().ok_or(Error::Truncated)?;
        let command = Command::from_code(*command_code)?;

        let (destination, rest) = if command == Command::Mux {
            (None, rest)
        } else {
            let (raw_port, rest) = take(rest, 2)?;
            let port = match raw_port {
                [hi, lo] => u16::from_be_bytes([*hi, *lo]),
                _ => return Err(Error::Truncated),
            };
            let (address, rest) = Address::decode(rest)?;
            (Some(Endpoint::new(address, port)), rest)
        };

        Ok((
            Self {
                uuid,
                addons,
                command,
                destination,
            },
            rest,
        ))
    }
}

/// Заголовок ответа сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Версия протокола.
    pub version: u8,
    /// Дополнительные поля.
    pub addons: Addons,
}

impl Response {
    /// Ответ без дополнительных полей.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            version: VERSION,
            addons: Addons::empty(),
        }
    }

    /// Закодировать заголовок ответа.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`], если addons не помещаются в однобайтовую длину.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let addons = self.addons.encode();
        let addon_len =
            u8::try_from(addons.len()).map_err(|_| Error::TooLong("addons длиннее 255 байт"))?;

        let mut out = Vec::with_capacity(2 + addons.len());
        out.push(self.version);
        out.push(addon_len);
        out.extend_from_slice(&addons);
        Ok(out)
    }

    /// Разобрать заголовок ответа, вернув его и остаток — полезную нагрузку.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`], [`Error::Truncated`].
    pub fn decode(input: &[u8]) -> Result<(Self, &[u8])> {
        let (version, rest) = input.split_first().ok_or(Error::Truncated)?;
        if *version != VERSION {
            return Err(Error::UnsupportedVersion(*version));
        }
        let (addon_len, rest) = rest.split_first().ok_or(Error::Truncated)?;
        let (raw_addons, rest) = take(rest, *addon_len as usize)?;

        Ok((
            Self {
                version: *version,
                addons: Addons::decode(raw_addons)?,
            },
            rest,
        ))
    }
}

fn take(input: &[u8], n: usize) -> Result<(&[u8], &[u8])> {
    input.split_at_checked(n).ok_or(Error::Truncated)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    #[test]
    fn tcp_request_matches_expected_bytes() {
        let request = Request::tcp(UUID, Endpoint::new(Address::Ipv4([93, 184, 216, 34]), 443));
        let encoded = request.encode().unwrap();

        let mut expected = vec![0x00];
        expected.extend_from_slice(&UUID);
        expected.push(0x00); // addons отсутствуют
        expected.push(0x01); // команда TCP
        expected.extend_from_slice(&443_u16.to_be_bytes());
        expected.push(0x01); // тип адреса IPv4
        expected.extend_from_slice(&[93, 184, 216, 34]);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn domain_request_round_trips() {
        let request = Request::tcp(
            UUID,
            Endpoint::new(Address::Domain("www.example.org".into()), 80),
        )
        .with_flow("xtls-rprx-vision");

        let encoded = request.encode().unwrap();
        let (decoded, rest) = Request::decode(&encoded).unwrap();

        assert_eq!(decoded, request);
        assert!(rest.is_empty());
        assert_eq!(decoded.addons.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn payload_follows_header_without_separator() {
        let request = Request::udp(UUID, Endpoint::new(Address::Ipv6([0x11; 16]), 53));
        let mut wire = request.encode().unwrap();
        wire.extend_from_slice("полезная нагрузка".as_bytes());

        let (decoded, rest) = Request::decode(&wire).unwrap();
        assert_eq!(decoded.command, Command::Udp);
        assert_eq!(rest, "полезная нагрузка".as_bytes());
    }

    #[test]
    fn mux_carries_no_destination() {
        let request = Request {
            uuid: UUID,
            addons: Addons::empty(),
            command: Command::Mux,
            destination: None,
        };
        let encoded = request.encode().unwrap();
        // Версия, UUID, длина addons, команда — и ничего больше.
        assert_eq!(encoded.len(), 1 + 16 + 1 + 1);
        assert_eq!(Request::decode(&encoded).unwrap().0, request);
    }

    #[test]
    fn non_mux_without_destination_is_rejected() {
        let request = Request {
            uuid: UUID,
            addons: Addons::empty(),
            command: Command::Tcp,
            destination: None,
        };
        assert!(matches!(request.encode(), Err(Error::Malformed(_))));
    }

    #[test]
    fn response_round_trips() {
        let response = Response {
            version: VERSION,
            addons: Addons::with_flow("xtls-rprx-vision"),
        };
        let encoded = response.encode().unwrap();
        let (decoded, rest) = Response::decode(&encoded).unwrap();
        assert_eq!(decoded, response);
        assert!(rest.is_empty());
    }

    #[test]
    fn rejects_unknown_version_command_and_address() {
        let mut wire = Request::tcp(UUID, Endpoint::new(Address::Ipv4([1, 1, 1, 1]), 53))
            .encode()
            .unwrap();

        let mut bad_version = wire.clone();
        if let Some(byte) = bad_version.first_mut() {
            *byte = 0x01;
        }
        assert_eq!(
            Request::decode(&bad_version),
            Err(Error::UnsupportedVersion(1))
        );

        // Байт команды идёт сразу за длиной addons.
        if let Some(byte) = wire.get_mut(18) {
            *byte = 0x09;
        }
        assert_eq!(Request::decode(&wire), Err(Error::UnknownCommand(9)));
    }

    #[test]
    fn rejects_every_truncation() {
        let wire = Request::tcp(
            UUID,
            Endpoint::new(Address::Domain("example.org".into()), 443),
        )
        .encode()
        .unwrap();

        for cut in 1..wire.len() {
            let partial = wire.get(..cut).unwrap_or_default();
            assert!(
                Request::decode(partial).is_err(),
                "обрезка до {cut} байт должна отвергаться"
            );
        }
    }

    #[test]
    fn rejects_empty_and_oversized_domain() {
        let empty = Request::tcp(UUID, Endpoint::new(Address::Domain(String::new()), 80));
        assert!(matches!(empty.encode(), Err(Error::Malformed(_))));

        let long = Request::tcp(UUID, Endpoint::new(Address::Domain("a".repeat(256)), 80));
        assert!(matches!(long.encode(), Err(Error::TooLong(_))));
    }

    #[test]
    fn survives_arbitrary_garbage() {
        for seed in 0_u8..=255 {
            let noise: Vec<u8> = (0..seed).map(|i| i.wrapping_mul(seed) ^ 0x5a).collect();
            let _ = Request::decode(&noise);
            let _ = Response::decode(&noise);
        }
    }
}
