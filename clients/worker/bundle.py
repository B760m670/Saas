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


EXPORT = re.compile(r"^export (const|class|async function|function) ", flags=re.M)

# Убирается только относительный импорт: `cloudflare:sockets` обязан
# остаться, без него край не откроет ни одного исходящего соединения.
# Список имён — `[^}]*`, а не `.*?` с `re.S`: с `re.S` точка матчит
# перевод строки, и нежадный шаблон перемахнул бы из одного импорта в
# другой, унеся оба.
LOCAL_IMPORT = re.compile(r"^import\s*\{[^}]*\}\s*from\s*\"\./[^\"]+\";\n", flags=re.M)


def build() -> str:
    edge = (HERE / "src/edge.js").read_text(encoding="utf-8")
    udp = (HERE / "src/udp.js").read_text(encoding="utf-8")
    worker = (HERE / "src/worker.js").read_text(encoding="utf-8")

    edge = EXPORT.sub(r"\1 ", edge)
    edge = edge.replace(
        "// Сквозной канал до края — сторона края.",
        "// ── ЧАСТЬ 1: сквозной канал до края ──",
    )

    udp = EXPORT.sub(r"\1 ", udp)
    udp = udp.replace(
        "// Датаграммы DNS внутри потока VLESS.",
        "// ── ЧАСТЬ 2: датаграммы DNS ──",
    )

    worker = LOCAL_IMPORT.sub("", worker)
    worker = worker.replace(
        "// Точка выхода ATLAS на Cloudflare Workers.",
        "// ── ЧАСТЬ 3: сама точка выхода ──",
    )
    return HEADER + edge + "\n\n" + udp + "\n\n" + worker


def check(bundle: str) -> None:
    """Убедиться, что склейка не выбросила лишнего.

    Один раз шаблон уже унёс `cloudflare:sockets` вместе с соседним
    импортом. Файл остался синтаксически верным, `node --check` его
    пропустил, и отказ вылез бы только на площадке.
    """
    if 'from "cloudflare:sockets"' not in bundle:
        raise SystemExit("нет импорта cloudflare:sockets — край не откроет соединений")
    if "export default" not in bundle:
        raise SystemExit("нет точки входа `export default`")
    if 'from "./' in bundle:
        raise SystemExit("остался относительный импорт — склейка неполна")


if __name__ == "__main__":
    bundle = build()
    check(bundle)
    out = HERE / "atlas-edge.bundle.js"
    out.write_text(bundle, encoding="utf-8")
    print(f"собрано: {out} ({bundle.count(chr(10))} строк)")
