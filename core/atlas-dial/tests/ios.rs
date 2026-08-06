//! Правила и профиль проверяются теми, кто их будет читать.
//!
//! PAC — это исполняемый JavaScript, а не текст: единственная честная
//! проверка — **запустить** его и посмотреть, куда он направляет.
//! Профиль — это plist, и проверка та же по духу: разобрать сторонним
//! разборщиком, а не сравнить со строкой.
//!
//! Ни того, ни другого нельзя проверить на настоящем iPhone в этом
//! окружении. Что именно остаётся непроверенным, записано в реестре
//! слабых мест — здесь проверяется всё, что проверить можно.

// Вход теста — то, что он же и породил.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;

use atlas_dial::mobileconfig::{Encryption, Profile};
use atlas_dial::pac;

/// Заготовка функций PAC, которых в обычном JavaScript нет.
///
/// Их предоставляет сама операционная система; здесь они написаны так,
/// как описаны в спецификации Netscape, которой следует и Apple.
const HELPERS: &str = r#"
function isPlainHostName(host) { return host.indexOf('.') === -1; }
function dnsDomainIs(host, domain) {
    return host.length >= domain.length &&
           host.substring(host.length - domain.length) === domain;
}
function shExpMatch(str, shexp) {
    var re = shexp.replace(/[.^$+{}()|[\]\\]/g, '\\$&')
                  .replace(/\*/g, '.*').replace(/\?/g, '.');
    return new RegExp('^' + re + '$').test(str);
}
function isInNet(host, pattern, mask) {
    // Имя без разрешения в адрес в сеть не попадает — так же ведёт
    // себя и настоящий разрешатель, когда имя не адрес.
    var parts = host.split('.');
    if (parts.length !== 4 || !parts.every(function (p) {
        return /^\d+$/.test(p) && Number(p) <= 255;
    })) return false;
    var p = pattern.split('.'), m = mask.split('.');
    for (var i = 0; i < 4; i++) {
        if ((Number(parts[i]) & Number(m[i])) !== (Number(p[i]) & Number(m[i]))) return false;
    }
    return true;
}
"#;

/// Неповторяющееся имя для временного файла.
///
/// Тесты одного двоичного файла идут в потоках одного процесса, поэтому
/// `process::id()` для них общий — на этом первая редакция теста и
/// сломалась: два теста писали в один файл и мешали друг другу.
fn unique() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Прогнать скрипт узлом и вернуть решения для перечисленных имён.
fn decide(script: &str, hosts: &[&str]) -> Vec<String> {
    let queries: Vec<String> = hosts
        .iter()
        .map(|host| format!("console.log(FindProxyForURL('https://{host}/', '{host}'));"))
        .collect();
    let program = format!("{HELPERS}\n{script}\n{}", queries.join("\n"));

    let scratch = std::env::temp_dir().join(format!("atlas-pac-{}.js", unique()));
    std::fs::write(&scratch, program).unwrap();
    let run = Command::new("node").arg(&scratch).output().unwrap();
    let _ = std::fs::remove_file(&scratch);

    assert!(
        run.status.success(),
        "скрипт PAC не исполняется:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    String::from_utf8_lossy(&run.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_script_routes_where_it_promises() {
    let rules = pac::Rules::new("127.0.0.1:1080")
        .with_direct(vec!["gosuslugi.ru".to_owned(), "sberbank.ru".to_owned()])
        .with_blocked(vec!["ads.example.com".to_owned()]);
    let script = pac::script(&rules).unwrap();

    let hosts = [
        // Через туннель — всё незнакомое.
        "www.wikipedia.org",
        "example.org",
        // Мимо туннеля — по решению пользователя, включая поддомены.
        "gosuslugi.ru",
        "www.gosuslugi.ru",
        "online.sberbank.ru",
        // Отказано, включая поддомены.
        "ads.example.com",
        "tracker.ads.example.com",
        // Своё же устройство и локальная сеть.
        "localhost",
        "127.0.0.1",
        "192.168.1.1",
        "10.1.2.3",
        "printer.local",
        "myhost",
    ];
    let decisions = decide(&script, &hosts);

    let expected = [
        "PROXY 127.0.0.1:1080",
        "PROXY 127.0.0.1:1080",
        "DIRECT",
        "DIRECT",
        "DIRECT",
        "PROXY 0.0.0.0:0",
        "PROXY 0.0.0.0:0",
        "DIRECT",
        "DIRECT",
        "DIRECT",
        "DIRECT",
        "DIRECT",
        "DIRECT",
    ];
    for (at, host) in hosts.iter().enumerate() {
        assert_eq!(
            decisions.get(at).map(String::as_str),
            Some(expected[at]),
            "{host}: решение разошлось с обещанным"
        );
    }
}

/// Подделка имени не должна уводить трафик мимо туннеля.
///
/// Правило `gosuslugi.ru` обязано покрывать свои поддомены и **не
/// покрывать** чужой домен, который просто кончается так же.
#[test]
fn a_lookalike_domain_does_not_slip_past_the_tunnel() {
    let rules = pac::Rules::new("127.0.0.1:1080").with_direct(vec!["gosuslugi.ru".to_owned()]);
    let script = pac::script(&rules).unwrap();

    let hosts = ["notgosuslugi.ru", "gosuslugi.ru.evil.com", "GOSUSLUGI.RU"];
    let decisions = decide(&script, &hosts);

    assert_eq!(
        decisions.first().map(String::as_str),
        Some("PROXY 127.0.0.1:1080"),
        "чужой домен с тем же окончанием обязан идти через туннель"
    );
    assert_eq!(
        decisions.get(1).map(String::as_str),
        Some("PROXY 127.0.0.1:1080"),
        "домен, лишь начинающийся знакомо, обязан идти через туннель"
    );
    assert_eq!(
        decisions.get(2).map(String::as_str),
        Some("DIRECT"),
        "регистр имени не должен менять решение"
    );
}

/// Профиль обязан разбираться сторонним разборщиком plist.
#[test]
fn the_profile_parses_as_a_plist() {
    let profile = Profile::automatic("Дом \"Мой\" & Ко", "127.0.0.1:1080")
        .unwrap()
        .with_password(Encryption::Wpa, "пароль<с>знаками")
        .with_display_name("ATLAS — обход");
    let xml = profile.build().unwrap();

    let scratch = std::env::temp_dir().join(format!("atlas-profile-{}.plist", unique()));
    std::fs::write(&scratch, &xml).unwrap();

    let code = r#"
import plistlib, sys, json
with open(sys.argv[1], 'rb') as handle:
    parsed = plistlib.load(handle)
inner = parsed['PayloadContent'][0]
print(json.dumps({
    'type': parsed['PayloadType'],
    'inner_type': inner['PayloadType'],
    'ssid': inner['SSID_STR'],
    'proxy_type': inner['ProxyType'],
    'pac': inner.get('ProxyPACURL'),
    'fallback': inner.get('ProxyPACFallbackAllowed'),
    'password': inner.get('Password'),
    'encryption': inner['EncryptionType'],
    'removable': not parsed['PayloadRemovalDisallowed'],
    'name': parsed['PayloadDisplayName'],
}, ensure_ascii=False))
"#;
    let run = Command::new("python3")
        .arg("-c")
        .arg(code)
        .arg(&scratch)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&scratch);

    assert!(
        run.status.success(),
        "профиль не разбирается как plist:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let out = String::from_utf8_lossy(&run.stdout);

    // Экранирование обязано пережить круг: разборщик возвращает
    // исходный текст, а не сущности XML.
    assert!(
        out.contains("Дом \\\"Мой\\\" & Ко"),
        "имя сети испортилось при экранировании: {out}"
    );
    assert!(out.contains("\"type\": \"Configuration\""), "{out}");
    assert!(
        out.contains("\"inner_type\": \"com.apple.wifi.managed\""),
        "{out}"
    );
    assert!(out.contains("\"proxy_type\": \"Auto\""), "{out}");
    assert!(
        out.contains("http://127.0.0.1:1080/proxy.pac"),
        "адрес скрипта не тот: {out}"
    );
    assert!(
        out.contains("\"fallback\": false"),
        "молчаливый уход мимо туннеля обязан быть запрещён: {out}"
    );
    assert!(out.contains("пароль<с>знаками"), "пароль испортился: {out}");
    assert!(
        out.contains("\"removable\": true"),
        "профиль обязан сниматься: {out}"
    );
}

/// Прокси обязан отдавать скрипт по тому адресу, который стоит в профиле.
///
/// Проверяется вместе: адрес берётся из профиля, а запрашивается у
/// живого прокси. Разойдись они — и профиль указывал бы в пустоту, а
/// узнал бы об этом только пользователь.
#[test]
fn the_proxy_serves_the_script_at_the_address_the_profile_points_to() {
    let key = atlas_types::ProxyKey::parse(
        "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:8443\
         ?type=tcp&security=reality&sni=www.microsoft.com\
         &pbk=gJlCetp4vTHnF1QNWPaer9qTEuFPln_LskAsPGzMXnI&sid=dead&fp=chrome#proba",
    )
    .unwrap();

    let rules = pac::Rules::new("127.0.0.1:1080").with_direct(vec!["example.org".to_owned()]);
    let proxy = atlas_dial::Proxy::start_with_rules(
        key,
        "127.0.0.1:0",
        atlas_dial::DialOptions::default(),
        Some(rules),
    )
    .unwrap();

    let address = proxy.address().to_string();
    let profile = Profile::automatic("Дом", &address).unwrap();
    let xml = profile.build().unwrap();
    let expected_url = format!("http://{address}/proxy.pac");
    assert!(
        xml.contains(&expected_url),
        "профиль указывает не на этот прокси:\n{xml}"
    );

    // Запрос ровно тот, какой сделает iOS.
    let mut socket = TcpStream::connect(&address).unwrap();
    socket
        .write_all(format!("GET /proxy.pac HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .unwrap();
    let mut answer = String::new();
    socket.read_to_string(&mut answer).unwrap();

    assert!(
        answer.starts_with("HTTP/1.1 200 OK"),
        "прокси не отдал скрипт:\n{answer}"
    );
    assert!(
        answer.contains("application/x-ns-proxy-autoconfig"),
        "не тот тип содержимого:\n{answer}"
    );
    let body = answer.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert_eq!(body, proxy.pac_script(), "отдано не то, что собрано");

    // И отданное — исполнимо.
    let decisions = decide(body, &["example.org", "www.wikipedia.org"]);
    assert_eq!(decisions.first().map(String::as_str), Some("DIRECT"));
    assert_eq!(
        decisions.get(1).map(String::as_str),
        Some("PROXY 127.0.0.1:1080")
    );

    proxy.stop();
}
