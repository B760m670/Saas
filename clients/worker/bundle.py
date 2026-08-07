#!/usr/bin/env python3
"""Собрать край в один файл — чтобы его можно было вставить в панель.

Редактор в панели Cloudflare рассчитан на один модуль, а край живёт в
двух файлах. Без сборки развернуть его можно только с ноутбука через
`wrangler`, а это возвращает нас к тому, от чего мы уходим: человек с
одним телефоном остаётся ни с чем.

Сборка намеренно тупая — склейка с вырезанием `export` и `import`.
Тащить сборщик из мира npm ради двух файлов значило бы добавить в
цепочку поставки инструмента обхода цензуры десятки чужих пакетов.
"""

import pathlib
import re

HERE = pathlib.Path(__file__).parent

HEADER = """// ATLAS — точка выхода на Cloudflare Workers, одним файлом.
//
// СОБРАНО АВТОМАТИЧЕСКИ. Не правьте здесь: правки затрёт следующая
// сборка. Исходники — `src/edge.js` и `src/worker.js`, сборщик —
// `bundle.py`, а согласие с частью на Rust проверяет
// `core/atlas-transport/tests/interop.rs`.
//
// # Что с этим делать
//
// 1. В панели Cloudflare: Compute (Workers) → Workers & Pages →
//    Create → Start with Hello World → Deploy.
// 2. Edit code → выделить всё, вставить этот файл → Deploy.
// 3. Settings → Variables and Secrets → добавить два секрета:
//    ATLAS_SECRET (32 байта в base64url) и ATLAS_UUID.
//
// Ноутбук для этого не нужен: всё делается в браузере, в том числе на
// телефоне.

"""


def build() -> str:
    edge = (HERE / "src/edge.js").read_text(encoding="utf-8")
    worker = (HERE / "src/worker.js").read_text(encoding="utf-8")

    edge = re.sub(r"^export (const|class|async function|function) ", r"\1 ", edge, flags=re.M)
    edge = edge.replace(
        "// Сквозной канал до края — сторона края.",
        "// ── ЧАСТЬ 1: сквозной канал до края ──",
    )

    worker = worker.replace(
        'import { respond, MAX_RECORD, CLIENT_HELLO_LEN } from "./edge.js";\n', ""
    )
    worker = worker.replace(
        "// Точка выхода ATLAS на Cloudflare Workers.",
        "// ── ЧАСТЬ 2: сама точка выхода ──",
    )
    return HEADER + edge + "\n\n" + worker


if __name__ == "__main__":
    out = HERE / "atlas-edge.bundle.js"
    out.write_text(build(), encoding="utf-8")
    print(f"собрано: {out} ({build().count(chr(10))} строк)")
