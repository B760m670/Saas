//! Проверка сайта прикрытия на настоящих сайтах.
//!
//! # Почему помечено `#[ignore]`
//!
//! Тест ходит в сеть. В наборе, который гоняется на каждый коммит, ему
//! не место: он зависит от чужой доступности, от того, куда сегодня
//! разрешается имя, и от площадки, с которой запущен. Красный тест по
//! такой причине не сообщает ничего о нашем коде и приучает не смотреть
//! на красное.
//!
//! Но и выбрасывать его нельзя: без него `cover::inspect` проверен
//! только на своих же данных, то есть проверена арифметика
//! предупреждений, а не хождение по сети.
//!
//! # Осторожно: из среды разработки этот тест лжёт
//!
//! Весь исходящий TLS в среде, где ведётся разработка, перехватывается
//! шлюзом, который выпускает сертификат под **каждое** запрошенное имя.
//! Проверено напрямую:
//!
//! ```text
//! $ openssl s_client -connect lwn.net:443 -servername example.com
//! issuer=O = Anthropic, CN = Egress Gateway SDS Issuing CA (production)
//! subject=CN = example.com
//! ```
//!
//! Последствия для этого теста:
//!
//! - `tls13` всегда истинно — это умеет шлюз, а не проверяемый сайт;
//! - `alpn` и время рукопожатия относятся к шлюзу;
//! - `selects_certificate_by_name` истинно **для любого** адреса, включая
//!   заведомо одиночные `lwn.net` и `www.openbsd.org`.
//!
//! Разрешение имён при этом не подменяется, поэтому список адресов
//! настоящий.
//!
//! Осмысленные показания этот тест даёт только с машины, где исходящий
//! TLS не трогают, — то есть с самой точки выхода. Оттуда его и надо
//! запускать, выбирая сайт прикрытия.
//!
//! Запуск вручную:
//!
//! ```text
//! cargo test -p atlas-exit --test cover_live -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::print_stdout)]

use atlas_exit::cover;

/// Показать отчёт целиком — глазами того, кто выбирает сайт прикрытия.
fn show(cover_name: &str) {
    match cover::inspect(cover_name) {
        Ok(report) => {
            println!("\n=== {cover_name}");
            println!("  адрес           {}", report.probed);
            println!("  всего адресов   {}", report.addresses.len());
            println!("  TLS 1.3         {}", report.tls13);
            println!("  ALPN            {:?}", report.alpn);
            println!("  рукопожатие     {} мс", report.handshake.as_millis());
            println!(
                "  сертификат по имени {}",
                match report.selects_certificate_by_name {
                    Some(true) => "разный для разных имён — признак CDN, но не доказательство",
                    Some(false) => "один и тот же для любого имени",
                    None => "чужое имя не обслуживается вовсе",
                }
            );
            println!("  пригоден        {}", report.usable());
            for warning in report.warnings() {
                println!("  ! {warning}");
            }
        }
        Err(error) => println!("\n=== {cover_name}\n  не проверить: {error}"),
    }
}

#[test]
#[ignore = "ходит в сеть"]
fn inspect_real_cover_sites() {
    for name in [
        "www.microsoft.com:443",
        "dl.google.com:443",
        "www.nvidia.com:443",
        "lwn.net:443",
        "www.openbsd.org:443",
    ] {
        show(name);
    }
}

#[test]
#[ignore = "ходит в сеть"]
fn the_default_cover_is_actually_usable() {
    // Умолчание из `docs/13-vps.md`. Если оно негодно, об этом обязан
    // узнать не пользователь после развёртывания, а мы здесь.
    let report = cover::inspect("www.microsoft.com:443").unwrap();
    assert!(
        report.usable(),
        "сайт прикрытия по умолчанию не годится: {:?}",
        report.warnings()
    );
}
