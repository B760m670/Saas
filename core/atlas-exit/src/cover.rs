//! Пригоден ли выбранный сайт прикрытия.
//!
//! # Зачем это отдельная проверка
//!
//! Сайт прикрытия — единственное, что видит посторонний, постучавшийся
//! на нашу точку выхода. Всё остальное в REALITY можно настроить
//! неправильно и заметить это сразу: ключ не подойдёт, соединение не
//! встанет. Неудачный сайт прикрытия ведёт себя иначе — точка выхода
//! **работает**, свои подключаются, и лишь посторонний видит нечто
//! неправдоподобное. Узнать об этом от пользователей нельзя: свои-то
//! как раз довольны.
//!
//! Поэтому проверка идёт до того, как точка встанет на порт.
//!
//! # Что здесь проверяется, а что нет
//!
//! Проверок две, и они разного веса.
//!
//! **TLS 1.3 — требование, а не пожелание.** REALITY выводит общий
//! секрет из доли `key_share`, а её не существует до TLS 1.3. Сайт
//! прикрытия, не умеющий TLS 1.3, делает схему неработоспособной
//! целиком — не «менее скрытной», а неработающей. Это отказ.
//!
//! **Выбор сертификата по имени — факт, а не приговор.** Если по тому
//! же адресу для чужого имени отдаётся другой сертификат, значит адрес
//! обслуживает не один сайт. Это признак CDN, и он важен: посторонний
//! трафик мы пересылаем на сайт прикрытия целиком, а значит точка
//! выхода становится видимым пересыльщиком в чужую сеть.
//!
//! Но предупреждением это здесь **не считается**, и вот почему. Тот же
//! ответ даёт сервер-одиночка, у которого на неизвестное имя отдаётся
//! сертификат основного узла. Отличить одно от другого по одному лишь
//! сравнению байт нельзя — нужен разбор списка имён в самом
//! сертификате. Пока его нет, значение попадает в отчёт как измерение,
//! и решает человек.
//!
//! Проверить это предположение в среде разработки невозможно: весь
//! исходящий TLS там перехватывается шлюзом, который выпускает
//! сертификат под каждое запрошенное имя. Любой адрес выглядит оттуда
//! как обслуживающий что угодно — см. `tests/cover_live.rs`.
//!
//! # Чего проверка не доказывает
//!
//! Она **не делает точку выхода неотличимой**. Активный наблюдатель
//! по-прежнему вправе заметить, что наш адрес отдаёт сертификат чужого
//! домена, хотя этот домен разрешается в совсем другие адреса. Это
//! свойство самого REALITY, и никакая проверка сайта прикрытия его не
//! отменяет.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_tls::client::{ClientConfig, PeerIdentity, ServerVerifier};
use atlas_tls::TlsStream;

/// Сколько ждать соединения и рукопожатия с сайтом прикрытия.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Имя, которым проверяется, не общий ли адрес.
///
/// Нужен домен, который заведомо не принадлежит проверяемому сайту.
/// `example.com` закреплён RFC 2606 как раз за такими случаями и никому
/// не выдаётся.
const FOREIGN_NAME: &str = "example.com";

/// Что выяснилось про сайт прикрытия.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Имя, которое проверяли.
    pub name: String,
    /// Адреса, в которые оно разрешилось.
    pub addresses: Vec<SocketAddr>,
    /// Адрес, на котором проводилась проверка.
    pub probed: SocketAddr,
    /// Удалось ли вообще открыть TCP до адреса.
    ///
    /// Отделено от [`Self::tls13`] намеренно. Недоступность — это «не
    /// проверили», а не «проверили и плохо». Смешать их значит не
    /// пустить точку выхода на порт из-за чужой минутной заминки, а под
    /// `systemd` с `Restart=always` — получить бесконечный цикл
    /// перезапусков в момент, когда сеть ещё поднимается.
    pub reachable: bool,
    /// Согласован ли TLS 1.3.
    ///
    /// Осмысленно только при [`Self::reachable`].
    pub tls13: bool,
    /// Согласованный протокол прикладного уровня, если он есть.
    pub alpn: Option<String>,
    /// Сколько заняло рукопожатие.
    pub handshake: Duration,
    /// Отдаёт ли адрес разные сертификаты разным именам.
    ///
    /// Названо по измерению, а не по выводу: «выбирает сертификат по
    /// имени» — это то, что видно, а «за CDN» — уже толкование, и
    /// неоднозначное. `None` — чужое имя адрес не обслуживает вовсе.
    pub selects_certificate_by_name: Option<bool>,
}

impl Report {
    /// Пригоден ли сайт для работы вообще.
    ///
    /// Отдельно от предупреждений: непригодность — это отказ, а
    /// предупреждение — повод подумать.
    #[must_use]
    pub const fn usable(&self) -> bool {
        // Недостижимый сайт непригодным не считается: мы про него
        // ничего не узнали. Отказывать по незнанию — значит наказывать
        // за моргнувшую сеть.
        !self.reachable || self.tls13
    }

    /// Замечания к выбору, от важных к второстепенным.
    ///
    /// Пусто — значит сайт годится и вопросов нет.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();

        if !self.reachable {
            out.push(format!(
                "до {} не достучаться — проверить сайт прикрытия не вышло. \
                 Это не отказ: возможно, сеть ещё поднимается",
                self.probed
            ));
        }

        if self.reachable && !self.tls13 {
            out.push(format!(
                "{} не согласовал TLS 1.3 — REALITY на нём работать не будет: \
                 общий секрет выводится из key_share, а до TLS 1.3 его нет",
                self.name
            ));
        }

        if self.reachable && self.alpn.is_none() {
            out.push(format!(
                "{} не согласовал ALPN. Наши клиенты объявляют h2 и http/1.1, \
                 и сайт прикрытия, не выбирающий ничего, ведёт себя не как \
                 обычный сайт",
                self.name
            ));
        }

        if self.reachable && self.handshake > Duration::from_millis(300) {
            out.push(format!(
                "рукопожатие с сайтом прикрытия заняло {} мс — он далеко от \
                 точки выхода. Посторонний увидит задержку, которой у соседних \
                 адресов нет",
                self.handshake.as_millis()
            ));
        }

        out
    }
}

/// Проверить сайт прикрытия.
///
/// `cover` — в том же виде, что и в настройках: `домен:порт`.
///
/// # Errors
///
/// [`io::Error`], если имя не разрешается или до адреса не достучаться.
/// Неудачное рукопожатие ошибкой не считается — оно попадает в отчёт,
/// потому что это и есть предмет проверки.
pub fn inspect(cover: &str) -> io::Result<Report> {
    let (name, _) = cover.rsplit_once(':').unwrap_or((cover, "443"));
    let name = name.to_owned();

    let addresses: Vec<SocketAddr> = cover.to_socket_addrs()?.collect();
    let probed = *addresses.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "имя сайта прикрытия не разрешается ни в один адрес",
        )
    })?;

    // Достижимость проверяется отдельным соединением: иначе неудачу
    // TCP не отличить от неудачи рукопожатия, а это разные исходы.
    let reachable = TcpStream::connect_timeout(&probed, TIMEOUT).is_ok();

    let started = Instant::now();
    let own = handshake(probed, &name);
    let handshake_took = started.elapsed();

    // Чужое имя спрашиваем только у живого адреса: если и своё не
    // отдалось, сравнивать нечего.
    let selects_certificate_by_name = own.as_ref().ok().and_then(|ours| {
        handshake(probed, FOREIGN_NAME)
            .ok()
            .map(|theirs| theirs.certificate != ours.certificate)
    });

    Ok(Report {
        name,
        addresses,
        probed,
        reachable,
        tls13: own.is_ok(),
        alpn: own.as_ref().ok().and_then(|o| o.alpn.clone()),
        handshake: handshake_took,
        selects_certificate_by_name,
    })
}

/// Что удалось узнать из одного рукопожатия.
struct Handshake {
    /// Сертификат целиком, в исходных байтах.
    ///
    /// Не разбирается: сравнение идёт побайтно, а для этого разбор не
    /// нужен. Разбор X.509 — отдельная работа со своими ошибками, и
    /// заводить её ради сравнения «то же или не то же» незачем.
    certificate: Vec<u8>,
    /// Согласованный протокол прикладного уровня.
    alpn: Option<String>,
}

/// Проверяющий, который ничего не проверяет, но запоминает сертификат.
///
/// Принимать кого угодно здесь правильно: мы ведём разведку, а не
/// доверяем собеседнику. Подлинность сайта прикрытия нам не нужна и
/// ничего бы не дала — мы к нему не подключаемся за данными.
#[derive(Debug, Default, Clone)]
struct Recording(Arc<Mutex<Vec<u8>>>);

impl ServerVerifier for Recording {
    fn verify(&self, peer: &PeerIdentity<'_>) -> atlas_tls::Result<()> {
        if let (Ok(mut slot), Some(leaf)) = (self.0.lock(), peer.certificate.entries.first()) {
            slot.clone_from(&leaf.data);
        }
        Ok(())
    }
}

/// Сходить на адрес и поднять TLS с указанным именем.
///
/// Успех означает, что собеседник говорит на TLS 1.3: наш клиент
/// другого не умеет, и рукопожатие иначе не завершится. Именно поэтому
/// отдельной проверки версии нет — она была бы недостижимой веткой.
fn handshake(address: SocketAddr, name: &str) -> io::Result<Handshake> {
    let socket = TcpStream::connect_timeout(&address, TIMEOUT)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;

    let seen = Recording::default();
    let config = ClientConfig::new(name.to_owned())
        .with_verifier(Box::new(seen.clone()) as Box<dyn ServerVerifier>)
        .with_alpn(vec!["h2".to_owned(), "http/1.1".to_owned()]);

    let stream = TlsStream::connect(socket, config)?;
    let certificate = seen.0.lock().map(|slot| slot.clone()).unwrap_or_default();
    Ok(Handshake {
        certificate,
        alpn: stream.alpn().map(str::to_owned),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn report() -> Report {
        Report {
            name: "www.microsoft.com".to_owned(),
            addresses: vec![([203, 0, 113, 7], 443).into()],
            probed: ([203, 0, 113, 7], 443).into(),
            reachable: true,
            tls13: true,
            alpn: Some("h2".to_owned()),
            handshake: Duration::from_millis(20),
            selects_certificate_by_name: Some(false),
        }
    }

    #[test]
    fn a_good_cover_raises_nothing() {
        let report = report();
        assert!(report.usable());
        assert!(report.warnings().is_empty(), "{:?}", report.warnings());
    }

    #[test]
    fn no_tls13_makes_the_cover_unusable_not_merely_suspicious() {
        // Разница существенная: без TLS 1.3 схема не «менее скрытна», а
        // не работает вовсе — общий секрет выводить не из чего.
        let report = Report {
            tls13: false,
            ..report()
        };
        assert!(!report.usable());
        assert!(report.warnings().iter().any(|w| w.contains("TLS 1.3")));
    }

    #[test]
    fn selecting_certificates_by_name_is_measured_but_not_warned_about() {
        // Тот же ответ даёт сервер-одиночка с сертификатом основного
        // узла на неизвестное имя. Отличить их сравнением байт нельзя,
        // а предупреждение, срабатывающее и на добром случае, хуже
        // отсутствующего: его перестают читать.
        for measured in [Some(true), Some(false), None] {
            let report = Report {
                selects_certificate_by_name: measured,
                ..report()
            };
            assert!(report.usable());
            assert!(
                report.warnings().is_empty(),
                "измерение {measured:?} не должно порождать предупреждение"
            );
        }
    }

    #[test]
    fn a_distant_cover_is_reported() {
        let report = Report {
            handshake: Duration::from_millis(450),
            ..report()
        };
        assert!(report.usable());
        assert!(report.warnings().iter().any(|w| w.contains("далеко")));
    }

    #[test]
    fn missing_alpn_is_reported() {
        let report = Report {
            alpn: None,
            ..report()
        };
        assert!(report.warnings().iter().any(|w| w.contains("ALPN")));
    }

    #[test]
    fn an_unreachable_cover_does_not_block_startup() {
        // Иначе точка выхода под systemd с Restart=always уходит в
        // бесконечный перезапуск в тот момент, когда сеть ещё
        // поднимается, — а это ровно момент загрузки машины.
        let report = Report {
            reachable: false,
            tls13: false,
            alpn: None,
            ..report()
        };
        assert!(report.usable(), "недоступность — не приговор");

        let warnings = report.warnings();
        assert_eq!(
            warnings.len(),
            1,
            "лишний шум про ALPN и TLS здесь не нужен"
        );
        assert!(warnings.first().unwrap().contains("не достучаться"));
    }

    #[test]
    fn a_reachable_cover_without_tls13_is_refused() {
        // А вот здесь мы узнали достаточно: сайт отвечает и TLS 1.3 не
        // умеет. REALITY на нём не заработает, и это надо сказать до
        // того, как человек вставит ключ в клиент.
        let report = Report {
            reachable: true,
            tls13: false,
            ..report()
        };
        assert!(!report.usable());
        assert!(report.warnings().iter().any(|w| w.contains("TLS 1.3")));
    }

    #[test]
    fn warnings_come_worst_first() {
        // Порядок не украшение: человек читает первую строку и часто
        // только её, поэтому отказ обязан стоять раньше замечаний.
        let report = Report {
            tls13: false,
            selects_certificate_by_name: Some(true),
            alpn: None,
            handshake: Duration::from_millis(450),
            ..report()
        };
        let warnings = report.warnings();
        assert_eq!(warnings.len(), 3);
        assert!(warnings.first().unwrap().contains("TLS 1.3"));
    }

    #[test]
    fn an_unresolvable_name_is_an_error_not_a_report() {
        // Отчёт о сайте, которого нет, вводил бы в заблуждение: он
        // выглядел бы как результат проверки.
        assert!(inspect("несуществующий.invalid:443").is_err());
    }
}
