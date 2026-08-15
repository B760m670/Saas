"""Аватар бота: монограмма GL.

Композиция строится на одном правиле: свет принадлежит фону, знак — плоский.
Никакого свечения и градиента на самой фигуре; белое остаётся белым, и от
этого читается уверенно даже размером с ноготь.

Источник света стоит не произвольно, а точно в разрыве кольца: буква
разомкнута ровно в ту сторону, откуда бьёт свет, будто он оттуда и вышел.
"""

import math

from PIL import Image, ImageDraw

SS = 4                      # превышение: PIL плохо сглаживает дуги
SIZE = 1024
S = SIZE * SS
C = S // 2

# Три остановки от ядра к темноте. Тёплая гамма выбрана как отличие от
# бирюзы и синевы, которыми занят весь ряд соседей.
CORE = (255, 236, 190)
MID = (238, 152, 46)
DEEP = (36, 13, 5)
BLACK = (4, 4, 6)

GAP_DIR = -26               # куда смотрит разрыв кольца, градусы
LIGHT_DIST = 1.16           # ядро уходит за край: видно только затухание


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def ramp(t):
    """Ядро → тёплая середина → глубокая тень → чёрный."""
    if t <= 0:
        return BLACK
    if t >= 1:
        return CORE
    if t > 0.72:
        return lerp(MID, CORE, (t - 0.72) / 0.28)
    if t > 0.30:
        return lerp(DEEP, MID, (t - 0.30) / 0.42)
    return lerp(BLACK, DEEP, t / 0.30)


def light_field():
    """Радиальный источник. Считается мелко и растягивается — так гладко
    и без полос, а построчный проход по 16 миллионам точек не нужен."""
    n = 360
    field = Image.new("RGB", (n, n))
    px = field.load()

    angle = math.radians(GAP_DIR)
    lx = 0.5 + math.cos(angle) * LIGHT_DIST / 2
    ly = 0.5 + math.sin(angle) * LIGHT_DIST / 2
    reach = 1.12

    for y in range(n):
        fy = y / (n - 1)
        for x in range(n):
            fx = x / (n - 1)
            d = math.hypot(fx - lx, fy - ly) / reach
            # Квадратичное затухание: линейное оставляет видимую границу.
            px[x, y] = ramp(max(0.0, 1.0 - d) ** 2.6)

    return field.resize((S, S), Image.BICUBIC)


def monogram():
    """G — дуга с разрывом, L — вертикаль внутри. Горизонталь общая:
    она же перекладина G, она же подошва L. Срезы прямые, без скруглений —
    так фигура читается как архитектура, а не как надпись."""
    mask = Image.new("L", (S, S), 0)
    draw = ImageDraw.Draw(mask)

    r = 286 * SS
    w = 64 * SS

    bar_y = C + int(r * 0.30)
    end_deg = math.degrees(math.asin(0.30))     # где дуга приходит к горизонтали

    draw.arc(
        [C - r, C - r, C + r, C + r],
        start=end_deg, end=360 + GAP_DIR - 6,
        fill=255, width=w,
    )

    right = C + int(r * math.cos(math.radians(end_deg))) + w // 2
    left = C - int(r * 0.36)

    draw.rectangle([left - w // 2, bar_y - w // 2, right, bar_y + w // 2], fill=255)
    draw.rectangle([left - w // 2, C - int(r * 0.58), left + w // 2, bar_y + w // 2], fill=255)

    return mask


def build():
    img = light_field().convert("RGBA")

    white = Image.new("RGBA", (S, S), (255, 255, 255, 0))
    white.putalpha(monogram())
    img.alpha_composite(white)

    return img.convert("RGB").resize((SIZE, SIZE), Image.LANCZOS)


if __name__ == "__main__":
    out = build()
    out.save("design/gloria-avatar-1024.png", optimize=True)
    out.resize((512, 512), Image.LANCZOS).save("design/gloria-avatar-512.png", optimize=True)
    out.resize((96, 96), Image.LANCZOS).save("design/gloria-avatar-96.png", optimize=True)
    print("готово")
