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

GAP_DIR = -26               # куда смотрит разрыв буквы, градусы
LIGHT_DIST = 1.16           # ядро уходит за край: видно только затухание

# Знак строится плоскостями на своей сетке, а не шрифтом.
GRID = 1000
T = 88                     # толщина плоскости
CUT = 42                    # зазор там, где плоскости перекрываются
SHEAR = 0.10                # наклон: верх уходит вправо


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


def place(mask, rects, value):
    """Прямоугольники с сетки построения переносятся на холст с наклоном."""
    draw = ImageDraw.Draw(mask)
    k = S / GRID
    for x0, y0, x1, y1 in rects:
        poly = []
        for x, y in ((x0, y0), (x1, y0), (x1, y1), (x0, y1)):
            # Чем выше точка, тем сильнее уходит вправо.
            poly.append(((x + SHEAR * (GRID / 2 - y)) * k, y * k))
        draw.polygon(poly, fill=value)


MARK = 0.78                 # общий масштаб знака относительно кадра


def scaled(rects):
    """Сжатие к центру сетки: знак меняет размер целиком, пропорции
    и зазоры сохраняются сами собой."""
    m = GRID / 2
    return [
        tuple(m + (v - m) * MARK for v in (x0, y0, x1, y1))
        for x0, y0, x1, y1 in rects
    ]


def letter_l():
    """L: вертикаль и подошва, положенные поверх кольца."""
    return scaled([
        (372, 296, 372 + T, 664),
        (372, 664 - T, 664, 664),
    ])


def monogram():
    """Кольцо с разрывом читается как G, поверх лежит L. В месте
    перекрытия прорезан зазор: без него две фигуры слипаются в силуэт,
    с ним читаются как две плоскости, одна поверх другой.

    Толщина выбрана крупной намеренно — тонкая линия на аватаре
    размером с ноготь исчезает, а разбирать её никто не станет."""
    mask = Image.new("L", (S, S), 0)
    draw = ImageDraw.Draw(mask)

    r = int(300 * MARK) * SS
    w = int(84 * MARK) * SS
    draw.arc(
        [C - r, C - r, C + r, C + r],
        start=20, end=360 + GAP_DIR - 4,
        fill=255, width=w,
    )

    place(mask, [(a - CUT, b - CUT, c + CUT, d + CUT) for a, b, c, d in letter_l()], 0)
    place(mask, letter_l(), 255)
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
