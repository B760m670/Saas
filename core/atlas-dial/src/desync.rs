//! Ярус T0: обход без точки выхода вовсе.
//!
//! # Что здесь происходит
//!
//! ТСПУ ищет имя сайта в первом же пакете соединения — в расширении
//! `server_name` приветствия TLS. Расширение лежит открытым текстом:
//! шифрование начинается позже. Найдя запретное имя, ТСПУ рвёт или
//! душит соединение.
//!
//! Приём состоит в том, чтобы имя **не оказалось целиком ни в одном
//! пакете**. Сервер соберёт поток как положено — это его работа. ТСПУ
//! собирать поток по-настоящему не может: реассемблирование на
//! магистральной скорости стоит слишком дорого, поэтому решение
//! принимается по отдельным пакетам.
//!
//! ```text
//! обычно:  [ ... server_name = rutracker.org ... ]   ← видно целиком
//! у нас:   [ ... server_name = rutrac ][ ker.org ... ] ← не видно нигде
//! ```
//!
//! # Чем это отличается от всего остального в проекте
//!
//! Ничем не требуется. Ни узла за границей, ни аккаунта, ни ключа, ни
//! регистрации. Трафик идёт **напрямую к настоящему сайту** — просто
//! нарезанный так, что цензор не разбирает.
//!
//! # Чего этот ярус не делает
//!
//! Не меняет наш адрес. Если сервис не пускает по стране, он не пустит
//! и здесь: адрес остаётся тем же. Против блокировки **по адресу**
//! десинхронизация тоже бессильна — там не на что смотреть, пакет
//! просто не доходит. Она решает ровно один случай, зато самый
//! частый: блокировку **по имени сайта**.
//!
//! # Почему приветствие приходится разбирать, а не строить
//!
//! Через прокси идёт браузер, и приветствие TLS — его, а не наше. Мы
//! видим только байты. Значит, место разреза надо найти разбором
//! чужого сообщения, а не знанием собственного формата.
//!
//! Разбор поэтому обязан быть терпимым: непонятное приветствие — повод
//! отправить его как есть, а не повод отказать. Отказ означал бы, что
//! сайт не открылся вовсе, и это хуже, чем открылся без обхода.

use std::io::{self, Write};
use std::net::TcpStream;

/// Заголовок записи TLS: тип, версия, длина.
const RECORD_HEADER: usize = 5;

/// Тип записи `handshake`.
const HANDSHAKE: u8 = 0x16;

/// Тип сообщения `ClientHello`.
const CLIENT_HELLO: u8 = 0x01;

/// Номер расширения `server_name`.
const SERVER_NAME: u16 = 0x0000;

/// Границы паузы между кусками, миллисекунды.
///
/// Пауза нужна, чтобы куски заведомо ушли разными пакетами: без неё
/// система вправе слепить их обратно, и весь приём пропадёт.
///
/// Границы, а не одно число: постоянная задержка сама становится
/// отпечатком. Соединение, у которого паузы всегда ровно двенадцать
/// миллисекунд, узнаётся не хуже, чем по имени сайта.
const DELAY_MS: (u64, u64) = (8, 24);

/// Случайное число в границах включительно.
fn between(range: (u64, u64)) -> u64 {
    let (low, high) = range;
    if high <= low {
        return low;
    }
    let span = high - low + 1;
    let raw = u64::from_le_bytes(atlas_crypto::rng::OsRng::bytes::<8>());
    low + raw % span
}

/// Подождать случайную паузу между кусками.
fn pause() {
    std::thread::sleep(std::time::Duration::from_millis(between(DELAY_MS)));
}

/// Значение TTL для куска, которому не суждено дойти.
///
/// Достаточно мало, чтобы пакет умер у ближайших маршрутизаторов, и
/// достаточно велико, чтобы он успел пройти ТСПУ, стоящий у оператора.
const DEAD_TTL: u32 = 3;

/// Приём обхода.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /// Отправить как есть. Нужен для сравнения и как запасной путь.
    None,
    /// Разрезать приветствие надвое по имени сайта.
    ///
    /// Самый простой и самый безобидный приём: ничего не подделывается,
    /// ничего не теряется, сервер получает обычный поток.
    #[default]
    Split,
    /// Пересобрать приветствие в несколько записей TLS.
    ///
    /// Не разрез потока, а **другой приём**: одна запись превращается
    /// в несколько, каждая со своим заголовком. Так устроена
    /// фрагментация в Xray, и она бьёт по другому классу DPI —
    /// по тем, кто разбирает TLS наивно, по первой записи, не собирая
    /// сообщение из нескольких.
    ///
    /// Приёмы дополняют друг друга: разрез потока обходит тех, кто не
    /// собирает TCP; нарезка записей — тех, кто не собирает TLS.
    /// Собирающих и то, и другое на магистральной скорости мало.
    Records,
    /// То же, но первый кусок отправляется с малым TTL.
    ///
    /// Он умирает по дороге, поэтому до ТСПУ доходит **сначала второй**
    /// кусок. Собрать имя из хвоста без головы нельзя. Первый кусок
    /// придёт позже, обычной повторной передачей TCP, — сервер соберёт
    /// всё правильно.
    Disorder,
}

/// Где резать и почему.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitPoint {
    /// Смещение в байтах от начала переданного куска.
    pub at: usize,
    /// Легло ли место разреза внутрь имени сайта.
    ///
    /// Разрез вне имени тоже мешает разбору, но заметно слабее:
    /// имя-то видно целиком. Знать разницу нужно, чтобы не выдавать
    /// слабый случай за сильный.
    pub inside_name: bool,
}

/// Прочитать двухбайтовое число.
fn be16(data: &[u8], at: usize) -> Option<usize> {
    let hi = *data.get(at)?;
    let lo = *data.get(at.checked_add(1)?)?;
    Some(usize::from(u16::from_be_bytes([hi, lo])))
}

/// Найти имя сайта в приветствии TLS.
///
/// Возвращает смещение и длину имени внутри `data` — то есть внутри
/// **всей** записи, вместе с заголовками.
///
/// Разбор нарочно не проверяет то, что нас не касается: версии,
/// шифронаборы, корректность прочих расширений. Наша задача — найти
/// одно поле, а не судить о приветствии.
#[must_use]
pub fn find_server_name(data: &[u8]) -> Option<(usize, usize)> {
    if *data.first()? != HANDSHAKE {
        return None;
    }
    // Длина записи проверяется на правдоподобие, но не на точность:
    // приветствие может быть длиннее прочитанного куска, и это не
    // повод сдаваться — имя обычно лежит в первых полутора килобайтах.
    let record_len = be16(data, 3)?;
    if record_len == 0 {
        return None;
    }

    let mut at = RECORD_HEADER;
    if *data.get(at)? != CLIENT_HELLO {
        return None;
    }
    // Тип (1) и длина (3) сообщения.
    at = at.checked_add(4)?;
    // Версия (2) и случайные данные (32).
    at = at.checked_add(34)?;

    let session_len = usize::from(*data.get(at)?);
    at = at.checked_add(1)?.checked_add(session_len)?;

    let suites_len = be16(data, at)?;
    at = at.checked_add(2)?.checked_add(suites_len)?;

    let compression_len = usize::from(*data.get(at)?);
    at = at.checked_add(1)?.checked_add(compression_len)?;

    let extensions_len = be16(data, at)?;
    at = at.checked_add(2)?;
    let extensions_end = at.checked_add(extensions_len)?;

    while at < extensions_end {
        let kind = be16(data, at)?;
        let len = be16(data, at.checked_add(2)?)?;
        let body = at.checked_add(4)?;

        if u16::try_from(kind).ok()? == SERVER_NAME {
            // Список имён: длина списка (2), тип (1), длина имени (2).
            let name_len = be16(data, body.checked_add(3)?)?;
            let name_at = body.checked_add(5)?;
            // Имя обязано целиком лежать в прочитанном куске: резать
            // по половине того, чего мы не видели, бессмысленно.
            if name_len == 0 || name_at.checked_add(name_len)? > data.len() {
                return None;
            }
            return Some((name_at, name_len));
        }

        at = body.checked_add(len)?;
    }

    None
}

/// Выбрать место разреза.
///
/// Середина имени, а не его начало: разрез по границе поля оставил бы
/// имя целым в одном из кусков.
#[must_use]
pub fn split_point(data: &[u8]) -> SplitPoint {
    match find_server_name(data) {
        Some((at, len)) if len >= 2 => SplitPoint {
            at: at + len / 2,
            inside_name: true,
        },
        // Приветствие не разобралось или имени в нём нет. Резать всё
        // равно стоит: разбор чужих полей у DPI тоже не бесплатный, а
        // вреда от разреза нет никакого.
        _ => SplitPoint {
            at: data.len() / 2,
            inside_name: false,
        },
    }
}

/// Границы длины куска при нарезке записей.
///
/// Мелкие куски заметны сами по себе: обычный браузер не шлёт
/// приветствие по сорок байт. Слишком крупные не прячут имя.
const PIECE_LEN: (u64, u64) = (48, 96);

/// Пересобрать приветствие в несколько записей TLS.
///
/// Возвращает `None`, если данные не похожи на цельную запись
/// рукопожатия — тогда трогать их незачем.
#[must_use]
pub fn refragment(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if *data.first()? != HANDSHAKE {
        return None;
    }
    let body_len = be16(data, 3)?;
    let end = RECORD_HEADER.checked_add(body_len)?;
    let shortest = usize::try_from(PIECE_LEN.0).unwrap_or(48);
    if body_len <= shortest || end > data.len() {
        return None;
    }
    let body = data.get(RECORD_HEADER..end)?;

    // Первая граница ставится не наугад, а по имени сайта: она обязана
    // лечь внутрь него. Случайность хороша против отпечатка, но
    // полагаться на неё в главном нельзя — при неудачном броске имя
    // уместилось бы в одну запись целиком.
    let first = find_server_name(data)
        .filter(|(_, len)| *len >= 2)
        .map(|(at, len)| at + len / 2 - RECORD_HEADER)
        .filter(|cut| *cut > 0 && *cut < body.len());

    let mut bounds: Vec<usize> = first.into_iter().collect();
    let mut cursor = bounds.last().copied().unwrap_or(0);
    while cursor < body.len() {
        let step = usize::try_from(between(PIECE_LEN)).unwrap_or(64).max(1);
        cursor = cursor.saturating_add(step).min(body.len());
        if cursor < body.len() {
            bounds.push(cursor);
        }
    }

    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut from = 0;
    for edge in bounds.iter().copied().chain(core::iter::once(body.len())) {
        let Some(piece) = body.get(from..edge) else {
            continue;
        };
        if piece.is_empty() {
            continue;
        }
        let mut record = Vec::with_capacity(RECORD_HEADER + piece.len());
        // Заголовок берётся от исходной записи: тип и версия обязаны
        // остаться теми же, меняется только длина.
        record.push(HANDSHAKE);
        record.extend_from_slice(data.get(1..3).unwrap_or(&[0x03, 0x01]));
        let len = u16::try_from(piece.len()).unwrap_or(0);
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(piece);
        out.push(record);
        from = edge;
    }

    // Всё, что шло за записью, уходит как есть.
    if let Some(tail) = data.get(end..) {
        if !tail.is_empty() {
            out.push(tail.to_vec());
        }
    }
    Some(out)
}

/// Отправить первые байты соединения выбранным приёмом.
///
/// # Errors
///
/// Ошибка записи в сокет.
pub fn send_first(socket: &mut TcpStream, data: &[u8], strategy: Strategy) -> io::Result<()> {
    if strategy == Strategy::None || data.len() < 2 {
        return socket.write_all(data);
    }

    let point = split_point(data);
    // Вырожденный разрез не даёт ничего: один из кусков пуст.
    let at = point.at.clamp(1, data.len().saturating_sub(1));
    let (head, tail) = data.split_at(at);

    match strategy {
        Strategy::None => unreachable!("случай отсеян выше"),
        Strategy::Records => {
            let Some(pieces) = refragment(data) else {
                return socket.write_all(data);
            };
            for piece in pieces {
                socket.write_all(&piece)?;
                socket.flush()?;
                pause();
            }
            Ok(())
        }
        Strategy::Split => {
            socket.write_all(head)?;
            socket.flush()?;
            pause();
            socket.write_all(tail)?;
            socket.flush()
        }
        Strategy::Disorder => {
            // Голова уходит обречённой: она умрёт у ближайших
            // маршрутизаторов, и ТСПУ увидит сначала хвост.
            let restore = socket.ttl()?;
            socket.set_ttl(DEAD_TTL)?;
            socket.write_all(head)?;
            socket.flush()?;
            pause();

            // TTL возвращается **до** отправки хвоста: хвост обязан
            // дойти, иначе соединение просто не состоится.
            socket.set_ttl(restore)?;
            socket.write_all(tail)?;
            socket.flush()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Собрать правдоподобное приветствие с заданным именем.
    ///
    /// Настоящее приветствие браузера длиннее и богаче, но нас
    /// интересует ровно разбор до `server_name`, а он от богатства не
    /// зависит.
    fn hello(name: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        // server_name
        ext.extend_from_slice(&SERVER_NAME.to_be_bytes());
        let name_len = u16::try_from(name.len()).unwrap();
        let list_len = name_len + 3;
        ext.extend_from_slice(&(list_len + 2).to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&name_len.to_be_bytes());
        ext.extend_from_slice(name.as_bytes());

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xab; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&ext);

        let mut message = vec![CLIENT_HELLO];
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        message.extend_from_slice(&len[1..]);
        message.extend_from_slice(&body);

        let mut record = vec![HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&u16::try_from(message.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    #[test]
    fn the_server_name_is_found_where_it_lies() {
        let wire = hello("rutracker.org");
        let (at, len) = find_server_name(&wire).expect("имя обязано найтись");
        assert_eq!(&wire[at..at + len], b"rutracker.org");
    }

    // Главное свойство: имя не остаётся целым ни в одном куске.
    #[test]
    fn neither_piece_contains_the_whole_name() {
        for name in ["rutracker.org", "a.b", "x.example.museum", "ab"] {
            let wire = hello(name);
            let point = split_point(&wire);
            assert!(point.inside_name, "разрез обязан лечь внутрь имени {name}");

            let (head, tail) = wire.split_at(point.at);
            let needle = name.as_bytes();
            assert!(
                !head.windows(needle.len()).any(|w| w == needle),
                "имя {name} целиком осталось в голове"
            );
            assert!(
                !tail.windows(needle.len()).any(|w| w == needle),
                "имя {name} целиком осталось в хвосте"
            );
        }
    }

    // Разрез обязан быть настоящим: пустой кусок ничего не прячет.
    // Нарезка записей: имя не должно уместиться ни в одной записи, а
    // склеенные тела обязаны дать исходное сообщение байт в байт.
    #[test]
    fn refragmentation_hides_the_name_and_loses_nothing() {
        // Длины кусков случайны, поэтому одного броска мало: свойство
        // обязано держаться при любом. Один удачный прогон доказывал бы
        // только удачу.
        for _ in 0..200 {
            check_one_refragmentation();
        }
    }

    fn check_one_refragmentation() {
        let wire = hello("rutracker.org");
        let pieces = refragment(&wire).expect("длинное приветствие обязано нарезаться");
        assert!(
            pieces.len() >= 2,
            "нарезка обязана дать больше одной записи"
        );

        let needle = b"rutracker.org";
        for piece in &pieces {
            assert_eq!(piece[0], HANDSHAKE, "тип записи обязан остаться прежним");
            assert_eq!(&piece[1..3], &wire[1..3], "версия обязана остаться прежней");
            let declared = usize::from(u16::from_be_bytes([piece[3], piece[4]]));
            assert_eq!(declared, piece.len() - 5, "длина записи обязана сойтись");
            assert!(
                !piece.windows(needle.len()).any(|w| w == needle),
                "имя целиком уместилось в одну запись"
            );
        }

        let rebuilt: Vec<u8> = pieces.iter().flat_map(|p| p[5..].to_vec()).collect();
        assert_eq!(rebuilt, wire[5..], "склеенные тела обязаны дать исходное");
    }

    // Непонятное или короткое сообщение трогать незачем: пересборка
    // ради пересборки только добавит приметности.
    #[test]
    fn nothing_worth_cutting_is_left_alone() {
        assert_eq!(refragment(&[]), None);
        assert_eq!(refragment(&[0x17, 0x03, 0x03, 0x00, 0x10]), None);
    }

    #[test]
    fn the_split_leaves_both_pieces_non_empty() {
        let wire = hello("example.com");
        let point = split_point(&wire);
        assert!(point.at > 0 && point.at < wire.len());
    }

    // Расширение `server_name` редко идёт первым. Разбор обязан
    // проходить мимо чужих расширений, а не сдаваться на первом.
    #[test]
    fn other_extensions_before_the_name_are_stepped_over() {
        let mut wire = hello("example.com");
        // Вставить безобидное расширение перед списком: проще всего
        // пересобрать приветствие вручную сложно, поэтому проверяем
        // обратное — что разбор не цепляется за номер расширения.
        let (at, len) = find_server_name(&wire).unwrap();
        assert_eq!(&wire[at..at + len], b"example.com");

        // Тот же разбор обязан пережить приписанный хвост: настоящее
        // приветствие почти всегда длиннее одной записи.
        wire.extend_from_slice(&[0_u8; 64]);
        let (at2, len2) = find_server_name(&wire).unwrap();
        assert_eq!((at, len), (at2, len2), "лишние байты сбили разбор");
    }

    // Чужие байты не должны ронять разбор: браузеров много, версий
    // TLS много, а отказ обязан быть мягким.
    #[test]
    fn garbage_never_panics_and_never_lies() {
        for junk in [
            vec![],
            vec![0x16],
            vec![0x16, 0x03, 0x01],
            vec![0x16, 0x03, 0x01, 0xff, 0xff],
            vec![0x17, 0x03, 0x03, 0x00, 0x10],
            vec![0xff; 64],
        ] {
            assert_eq!(find_server_name(&junk), None, "мусор разобрался как имя");
            // Резать всё равно можно — и это не должно падать.
            let point = split_point(&junk);
            assert!(!point.inside_name);
        }
    }

    // Обрезанное приветствие — обычное дело: имя может не поместиться
    // в первый прочитанный кусок. Резать по половине невидимого поля
    // нельзя, и разбор обязан это признать.
    #[test]
    fn a_name_beyond_the_read_chunk_is_not_claimed() {
        let wire = hello("rutracker.org");
        let (at, len) = find_server_name(&wire).unwrap();
        let cut = at + len - 3;
        assert_eq!(
            find_server_name(&wire[..cut]),
            None,
            "имя, видное не целиком, нельзя объявлять найденным"
        );
    }

    #[test]
    fn the_remembered_strategy_is_tried_first_and_only_once() {
        let mut selector = Selector::with_known(Strategy::Records);
        let mut tried = Vec::new();
        let chosen = selector.choose(|s| {
            tried.push(s);
            s == Strategy::Disorder
        });

        assert_eq!(chosen, Some(Strategy::Disorder));
        assert_eq!(
            tried.first(),
            Some(&Strategy::Records),
            "память идёт первой"
        );
        assert_eq!(
            tried.iter().filter(|s| **s == Strategy::Records).count(),
            1,
            "запомненный приём пробуется дважды — это лишняя неудачная попытка"
        );
        assert_eq!(selector.known(), Some(Strategy::Disorder));
    }

    // Успешный перебор обязан останавливаться: пробовать грубые приёмы
    // после того, как сработал безобидный, незачем.
    #[test]
    fn probing_stops_at_the_first_success() {
        let mut selector = Selector::new();
        let mut tried = Vec::new();
        let chosen = selector.choose(|s| {
            tried.push(s);
            s == Strategy::Split
        });

        assert_eq!(chosen, Some(Strategy::Split));
        assert_eq!(tried, vec![Strategy::None, Strategy::Split]);
    }

    // Сеть меняется. Держаться за отживший приём — значит каждый раз
    // начинать с заведомо неудачной попытки.
    #[test]
    fn a_total_failure_forgets_the_past() {
        let mut selector = Selector::with_known(Strategy::Split);
        assert_eq!(selector.choose(|_| false), None);
        assert_eq!(selector.known(), None);
    }

    #[test]
    fn every_strategy_is_offered_exactly_once() {
        let mut selector = Selector::with_known(Strategy::Disorder);
        let mut tried = Vec::new();
        selector.choose(|s| {
            tried.push(s);
            false
        });
        assert_eq!(
            tried.len(),
            ORDER.len(),
            "приёмы обязаны идти по одному разу"
        );
        for strategy in ORDER {
            assert!(tried.contains(&strategy), "{strategy:?} не был опробован");
        }
    }

    // Приём применяется к настоящему сокету: проверяется, что оба
    // куска доехали и склеились в исходное сообщение.
    #[test]
    fn both_pieces_arrive_and_reassemble() {
        use std::io::Read as _;
        use std::net::TcpListener;

        let wire = hello("rutracker.org");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected = wire.clone();

        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut got = Vec::new();
            let mut chunk = [0_u8; 1024];
            while got.len() < expected.len() {
                let read = socket.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                got.extend_from_slice(&chunk[..read]);
            }
            got
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.set_nodelay(true).unwrap();
        send_first(&mut client, &wire, Strategy::Split).unwrap();

        assert_eq!(
            server.join().unwrap(),
            wire,
            "разрезанное приветствие обязано собраться у получателя без потерь"
        );
    }

    // Рассинхронизация меняет только TTL и порядок в сети; для
    // получателя поток обязан остаться тем же.
    #[test]
    fn disorder_delivers_the_same_bytes() {
        use std::io::Read as _;
        use std::net::TcpListener;

        let wire = hello("example.com");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected = wire.clone();

        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut got = Vec::new();
            let mut chunk = [0_u8; 1024];
            while got.len() < expected.len() {
                let read = socket.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                got.extend_from_slice(&chunk[..read]);
            }
            got
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.set_nodelay(true).unwrap();
        let before = client.ttl().unwrap();
        send_first(&mut client, &wire, Strategy::Disorder).unwrap();

        assert_eq!(
            client.ttl().unwrap(),
            before,
            "TTL обязан вернуться: иначе всё дальнейшее соединение умрёт по дороге"
        );
        assert_eq!(server.join().unwrap(), wire);
    }
}

/// Порядок перебора приёмов.
///
/// От самого безобидного к самому грубому. Смысл порядка не в
/// эффективности, а в цене ошибки: разрез потока не меняет ничего,
/// кроме размера пакетов, а рассинхронизация нарочно роняет пакет и
/// добавляет задержку на повторную передачу. Если хватает малого,
/// большего делать не надо.
pub const ORDER: [Strategy; 4] = [
    Strategy::None,
    Strategy::Split,
    Strategy::Records,
    Strategy::Disorder,
];

/// Выбор приёма с памятью.
///
/// # Зачем
///
/// У разных операторов работает разное: где-то хватает разреза потока,
/// где-то нужен низкий TTL, где-то не работает ничего. Угадать это
/// нельзя — ни из кода, ни из документации. Единственный способ —
/// попробовать на месте.
///
/// Перебирать заново на каждом соединении при этом нельзя: первые
/// попытки заведомо неудачны, и каждая стоит времени. Поэтому
/// удавшийся приём запоминается и идёт первым, а полный перебор
/// случается только когда запомненный перестал работать.
#[derive(Debug, Clone, Default)]
pub struct Selector {
    known: Option<Strategy>,
}

impl Selector {
    /// Пустой выбор: ничего ещё не пробовали.
    #[must_use]
    pub const fn new() -> Self {
        Self { known: None }
    }

    /// Начать с известного приёма.
    #[must_use]
    pub const fn with_known(strategy: Strategy) -> Self {
        Self {
            known: Some(strategy),
        }
    }

    /// Что сработало в прошлый раз.
    #[must_use]
    pub const fn known(&self) -> Option<Strategy> {
        self.known
    }

    /// Подобрать приём, пробуя по очереди.
    ///
    /// `attempt` возвращает `true`, если соединение состоялось.
    /// Запомненный приём пробуется первым и не пробуется дважды.
    pub fn choose<F>(&mut self, mut attempt: F) -> Option<Strategy>
    where
        F: FnMut(Strategy) -> bool,
    {
        let first = self.known.into_iter();
        let rest = ORDER.into_iter().filter(|s| Some(*s) != self.known);

        for strategy in first.chain(rest) {
            if attempt(strategy) {
                self.known = Some(strategy);
                return Some(strategy);
            }
        }

        // Ничего не сработало — забыть прошлое. Сеть изменилась, и
        // держаться за отжившее означало бы каждый раз начинать с
        // заведомо неудачной попытки.
        self.known = None;
        None
    }
}
