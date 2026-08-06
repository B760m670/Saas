//! Граница C проверяется настоящей программой на C.
//!
//! Вызвать те же функции из Rust было бы проще и почти бесполезно: так
//! проверились бы сигнатуры в том виде, в каком их видит Rust. Здесь их
//! читает сторонний компилятор из сгенерированного заголовка — то есть
//! ровно так, как их прочитает Swift на iOS или Kotlin на Android. Если
//! заголовок разойдётся с библиотекой, сборка не пройдёт.

// Вход теста — то, что он же и породил.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Каталог сборки: рядом с исполняемым файлом теста.
fn target_dir() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    path.pop(); // debug
    path
}

/// Найти собранную статическую библиотеку.
///
/// Отсутствие — не повод молча пройти: тест обязан упасть, иначе он
/// будет годами «проходить», ничего не проверяя.
fn static_library() -> PathBuf {
    let candidate = target_dir().join("libatlas_ffi.a");
    assert!(
        candidate.exists(),
        "нет {}: собери `cargo build -p atlas-ffi`",
        candidate.display()
    );
    candidate
}

/// Есть ли в системе компилятор C.
fn c_compiler() -> Option<String> {
    for name in ["cc", "gcc", "clang"] {
        let found = Command::new(name).arg("--version").output();
        if matches!(found, Ok(output) if output.status.success()) {
            return Some(name.to_owned());
        }
    }
    None
}

#[test]
fn a_c_program_drives_the_whole_boundary() {
    let Some(compiler) = c_compiler() else {
        panic!("нет компилятора C — проверить границу нечем");
    };

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = manifest.join("tests/c/probe.c");
    let include = manifest.join("include");
    let library = static_library();
    let binary = target_dir().join("atlas-ffi-probe");

    let built = Command::new(&compiler)
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .arg("-I")
        .arg(&include)
        .arg(&library)
        // Статическая библиотека Rust тянет за собой это.
        .args(["-lpthread", "-ldl", "-lm"])
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "программа на C не собралась:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );

    // Ключ настоящий по форме; соединяться по нему тест не просит, так
    // что живая точка выхода здесь не нужна.
    let key = "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:8443\
               ?type=tcp&security=reality&sni=www.microsoft.com\
               &pbk=gJlCetp4vTHnF1QNWPaer9qTEuFPln_LskAsPGzMXnI&sid=dead\
               &fp=chrome&flow=xtls-rprx-vision#proba";

    let run = Command::new(&binary).arg(key).output().unwrap();
    let out = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "программа на C отработала с отказом:\n{out}\n{}",
        String::from_utf8_lossy(&run.stderr)
    );

    assert!(out.contains("version=0.1.0"), "версия не выдана:\n{out}");
    assert!(
        out.contains("не разбирается"),
        "испорченный ключ не объяснён:\n{out}"
    );
    assert!(
        out.contains("\"host\":\"127.0.0.1\"") && out.contains("\"reality\":true"),
        "описание ключа неполное:\n{out}"
    );
    assert!(
        out.contains("adres=127.0.0.1:") && !out.contains("adres=127.0.0.1:0"),
        "прокси не сообщил занятый порт:\n{out}"
    );
    assert!(out.contains("\"accepted\":0"), "счётчики не выданы:\n{out}");
    assert!(
        out.contains("gotovo"),
        "программа не дошла до конца:\n{out}"
    );

    let _ = std::fs::remove_file(&binary);
}

/// Заголовок обязан совпадать с тем, что породит `cbindgen` сейчас.
///
/// Заголовок лежит в репозитории, а не собирается на месте: клиентам
/// под iOS и Android он нужен без установленного `cbindgen`. Цена
/// такого решения — возможность расхождения, и вот проверка на неё.
/// Если `cbindgen` не установлен, проверять нечего — но молчать об этом
/// нельзя.
#[test]
fn the_committed_header_matches_the_source() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let committed = manifest.join("include/atlas.h");
    let fresh = target_dir().join("atlas-fresh.h");

    let generated = Command::new("cbindgen")
        .current_dir(&manifest)
        .args([
            "--config",
            "cbindgen.toml",
            "--crate",
            "atlas-ffi",
            "--output",
        ])
        .arg(&fresh)
        .output();

    let Ok(output) = generated else {
        eprintln!("cbindgen не установлен — расхождение заголовка не проверено");
        return;
    };
    assert!(
        output.status.success(),
        "cbindgen отказал:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let old = std::fs::read_to_string(&committed).unwrap();
    let new = std::fs::read_to_string(&fresh).unwrap();
    let _ = std::fs::remove_file(&fresh);

    assert_eq!(
        normalise(&old),
        normalise(&new),
        "заголовок в репозитории отстал от исходника — перегенерируй его"
    );
}

/// Убрать различия, не значащие ничего: пустые строки и хвосты.
fn normalise(text: &str) -> String {
    text.lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Заголовок обязан лежать там, где его ищут клиенты.
#[test]
fn the_header_is_where_clients_look_for_it() {
    let header = Path::new(env!("CARGO_MANIFEST_DIR")).join("include/atlas.h");
    let text = std::fs::read_to_string(&header).unwrap();
    for name in [
        "atlas_version",
        "atlas_last_error",
        "atlas_string_free",
        "atlas_key_describe",
        "atlas_proxy_start",
        "atlas_proxy_address",
        "atlas_proxy_stats",
        "atlas_proxy_stop",
    ] {
        assert!(text.contains(name), "в заголовке нет {name}");
    }
}

/// Граница C обязана носить трафик, а не только возвращать строки.
///
/// Проверять FFI по строкам мало: он существует ради того, чтобы
/// клиент под iOS поднял прокси и получил данные. Здесь поднимается
/// настоящая точка выхода, а программа на C идёт сквозь наш прокси
/// методом `CONNECT` — тем самым путём, каким пойдёт клиент.
#[test]
fn the_c_boundary_actually_carries_traffic() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Arc;

    let Some(compiler) = c_compiler() else {
        panic!("нет компилятора C — проверить границу нечем");
    };

    // Назначение: отвечает на сказанное и не говорит первым.
    let destination = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut socket) = incoming else { break };
                std::thread::spawn(move || {
                    let mut buf = [0_u8; 1024];
                    while let Ok(read) = socket.read(&mut buf) {
                        if read == 0 {
                            break;
                        }
                        let mut answer = b"pong:".to_vec();
                        answer.extend_from_slice(&buf[..read]);
                        if socket.write_all(&answer).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        address
    };

    // Сайт прикрытия: посторонних в этом тесте нет, но точке выхода
    // без него нельзя.
    let cover = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                drop(incoming);
            }
        });
        address
    };

    let reality = atlas_reality::Server::generate()
        .with_short_id(&[0xde, 0xad])
        .unwrap();
    let public_key = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reality.public_key())
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exit = listener.local_addr().unwrap().to_string();
    let point = Arc::new(atlas_exit::ExitPoint::new(
        atlas_exit::ExitConfig::new(reality, cover)
            .with_common_name("www.microsoft.com")
            .with_policy(atlas_exit::Policy {
                allow_private: true,
                ..atlas_exit::Policy::default()
            }),
    ));
    std::thread::spawn(move || {
        let _ = point.serve(&listener);
    });

    let key = format!(
        "vless://11111111-2222-3333-4444-555555555555@{exit}\
         ?type=tcp&security=reality&sni=www.microsoft.com\
         &pbk={public_key}&sid=dead&fp=chrome&flow=xtls-rprx-vision#skvoz"
    );

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary = target_dir().join("atlas-ffi-probe-traffic");
    let built = Command::new(&compiler)
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&binary)
        .arg(manifest.join("tests/c/probe.c"))
        .arg("-I")
        .arg(manifest.join("include"))
        .arg(static_library())
        .args(["-lpthread", "-ldl", "-lm"])
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "программа на C не собралась:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );

    let run = Command::new(&binary)
        .arg(&key)
        .arg(&destination)
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "сквозной проход не удался:\n{out}\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        out.contains("skvoz=pong:ping"),
        "ответ назначения не дошёл до программы на C:\n{out}"
    );
    assert!(
        out.contains("\"accepted\":1") && out.contains("\"failed\":0"),
        "счётчики не отразили соединение:\n{out}"
    );

    let _ = std::fs::remove_file(&binary);
}
