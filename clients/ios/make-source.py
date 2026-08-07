#!/usr/bin/env python3
"""Собрать источник приложений для AltStore/SideStore/LiveContainer.

Файл порождается сборкой, а не пишется руками: размер и хэш IPA
известны только после сборки, а расходиться они не должны. Источник,
обещающий не тот размер, установщик отвергнет.

Запуск:
    make-source.py <версия> <путь к ipa> <адрес загрузки> <выходной файл>
"""
import hashlib
import json
import os
import sys
from datetime import date

REPOSITORY = "https://github.com/B760m670/Saas"


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    version, ipa, download, output = sys.argv[1:]

    body = open(ipa, "rb").read()
    entry = {
        "version": version,
        "date": date.today().isoformat(),
        "localizedDescription": (
            "Первая сборка. Ядро на Rust: TLS 1.3 с отпечатком Chrome, "
            "REALITY, VLESS с обрамлением XTLS-Vision. Встроенный браузер "
            "ходит через туннель и отказывается загружать страницы, если "
            "туннель недоступен."
        ),
        "downloadURL": download,
        "size": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "minOSVersion": "16.0",
    }

    source = {
        "name": "ATLAS",
        "identifier": "org.atlas.source",
        "subtitle": "Обход сетевой цензуры без арендованных серверов",
        "description": (
            "Точкой выхода становится машина самого пользователя. "
            "Исходный код открыт целиком, включая список известных слабых "
            "мест."
        ),
        "website": REPOSITORY,
        "apps": [
            {
                "name": "ATLAS",
                "bundleIdentifier": "org.atlas.client",
                "developerName": "ATLAS",
                "subtitle": "Туннель и браузер поверх него",
                "localizedDescription": (
                    "Клиент VLESS + REALITY со своим ядром на Rust.\\n\\n"
                    "Приложение поднимает локальный прокси и уводит через "
                    "него трафик двумя путями: встроенным браузером — "
                    "везде, включая мобильный интернет; профилем "
                    "конфигурации — во всей сети Wi-Fi.\\n\\n"
                    "Браузер не загружает страницы, пока туннель "
                    "недоступен, и показывает, какие пути утечки закрыты "
                    "надёжно, а какие — по мере сил. Список известных "
                    "слабых мест открыт и ведётся вместе с кодом.\\n\\n"
                    "Сборка не подписана: подпись ставит тот, кто "
                    "устанавливает."
                ),
                "iconURL": (
                    f"{REPOSITORY}/raw/main/clients/ios/AtlasApp/Resources/"
                    "Assets.xcassets/AppIcon.appiconset/icon-1024.png"
                ),
                "category": "utilities",
                "screenshots": [],
                "versions": [entry],
                # Старое поле, которое всё ещё читают некоторые
                # установщики. Дублируется намеренно: источник, понятный
                # только свежим версиям, бесполезен половине тех, кому он
                # нужен.
                "version": entry["version"],
                "versionDate": entry["date"],
                "versionDescription": entry["localizedDescription"],
                "downloadURL": entry["downloadURL"],
                "size": entry["size"],
            }
        ],
        "news": [],
    }

    with open(output, "w", encoding="utf-8") as out:
        json.dump(source, out, ensure_ascii=False, indent=2)
        out.write("\n")

    print(f"источник собран: {output}")
    print(f"  версия {version}, {entry['size']} байт")
    print(f"  sha256 {entry['sha256']}")
    print(f"  загрузка {download}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
