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

# Импорт соседнего файла после склейки не нужен и невозможен. Убирается
# только относительный: `cloudflare:sockets` обязан остаться, без него
# край не откроет ни одного исходящего соединения.
#
# Список имён — `[^}]*`, а не `.*?` с `re.S`. Разница не косметическая:
# с `re.S` точка матчит и перевод строки, поэтому нежадный `.*?`
# перемахивал из импорта `cloudflare:sockets` в следующий за ним
# относительный и убирал оба разом. Собранный файл при этом оставался
# синтаксически верным и падал бы уже на площадке, при первом
# соединении. Класс символов до `}` перешагнуть через импорт не может.
LOCAL_IMPORT = re.compile(r"^import\s*\{[^}]*\}\s*from\s*\"\./[^\"]+\";\n", flags=re.M)


def build() -> str:
    edge = (HERE / "src/edge.js").read_text(encoding="utf-8")
    vless = (HERE / "src/vless.js").read_text(encoding="utf-8")
    worker = (HERE / "src/worker.js").read_text(encoding="utf-8")

    edge = EXPORT.sub(r"\1 ", edge)
    edge = edge.replace(
        "// Сквозной канал до края — сторона края.",
        "// ── ЧАСТЬ 1: сквозной канал до края ──",
    )

    vless = EXPORT.sub(r"\1 ", vless)
    vless = vless.replace(
        "// Разбор VLESS и обрамление UDP — та часть края, где нет площадки.",
        "// ── ЧАСТЬ 2: разбор VLESS и обрамление UDP ──",
    )

    worker = LOCAL_IMPORT.sub("", worker)
    worker = worker.replace(
        "// Точка выхода ATLAS на Cloudflare Workers.",
        "// ── ЧАСТЬ 3: сама точка выхода ──",
    )
    return HEADER + edge + "\n\n" + vless + "\n\n" + worker


def check(bundle: str) -> None:
    """Убедиться, что склейка не выбросила лишнего.

    Сборщик правит текст шаблонами, а шаблон легко задеть соседнюю
    строку. Один раз это уже случилось: убирая относительные импорты,
    шаблон унёс вместе с ними `cloudflare:sockets`. Файл остался
    синтаксически верным, `node --check` его пропустил, и отказ вылез бы
    только на площадке — при первом соединении, без внятной причины.

    Поэтому проверяется не синтаксис, а смысл: что осталось нужное и не
    осталось ненужного.
    """
    if 'from "cloudflare:sockets"' not in bundle:
        raise SystemExit(
            "в собранном файле нет импорта cloudflare:sockets — "
            "край не сможет открыть ни одного исходящего соединения"
        )
    if "export default" not in bundle:
        raise SystemExit("в собранном файле нет точки входа `export default`")
    for leftover in ('from "./', "\nexport const", "\nexport function", "\nexport class"):
        if leftover in bundle:
            raise SystemExit(f"в собранном файле остался {leftover!r} — склейка неполна")


if __name__ == "__main__":
    bundle = build()
    check(bundle)
    out = HERE / "atlas-edge.bundle.js"
    out.write_text(bundle, encoding="utf-8")
    print(f"собрано: {out} ({bundle.count(chr(10))} строк)")
