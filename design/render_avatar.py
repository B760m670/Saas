"""Аватар бота: монограмма GL по философии «Гало».

Рисуется с четырёхкратным превышением и уменьшается по Ланцошу — PIL сам
сглаживает дуги плохо, а на краю толстой окружности ступенька видна всем.
"""

from PIL import Image, ImageDraw, ImageFilter

SS = 4                      # коэффициент превышения
SIZE = 1024                 # итоговая сторона
S = SIZE * SS               # сторона холста при отрисовке
C = S // 2                  # центр

# Две температуры и ничего больше: холодная основа, тёплый знак.
INK_EDGE = (8, 10, 22)
INK_CORE = (23, 27, 52)
GOLD = (244, 199, 107)
ROSE = (232, 160, 158)


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def ground(img):
    """Основа с подъёмом яркости к центру — свет пробивается снизу."""
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, S, S], fill=INK_EDGE)
    steps = 220
    for i in range(steps, 0, -1):
        t = i / steps
        r = int(S * 0.78 * t)
        # Квадратичное затухание: линейное даёт видимый ореол-кольцо.
        colour = lerp(INK_CORE, INK_EDGE, 1 - (1 - t) ** 2)
        draw.ellipse([C - r, C - r, C + r, C + r], fill=colour)


def rings(img):
    """Тонкие кольца с возрастающим шагом — затухание, а не сетка."""
    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    radius = 342 * SS
    gap = 26 * SS
    alpha = 30
    while radius < S * 0.47 and alpha > 2:
        draw.ellipse(
            [C - radius, C - radius, C + radius, C + radius],
            outline=GOLD + (alpha,),
            width=max(1, SS // 2),
        )
        radius += gap
        gap = int(gap * 1.34)     # шаг растёт — глаз читает как удаление
        alpha = int(alpha * 0.62)
    img.alpha_composite(layer)


def warm(width, height):
    """Вертикальный градиент золото → роза для заливки знака."""
    grad = Image.new("RGB", (1, height))
    px = grad.load()
    for y in range(height):
        px[0, y] = lerp(GOLD, ROSE, (y / (height - 1)) ** 1.15)
    return grad.resize((width, height), Image.BICUBIC)


def monogram():
    """Маска знака: одна горизонталь служит и перекладиной G, и подошвой L.

    Совмещение намеренное. Пока это были две разные линии на почти одной
    высоте, глаз читал промах, а не замысел; сведённые в одну — читаются
    как связка двух букв.
    """
    import math

    mask = Image.new("L", (S, S), 0)
    draw = ImageDraw.Draw(mask)

    r = 284 * SS              # радиус средней линии кольца
    w = 62 * SS               # толщина
    box = [C - r, C - r, C + r, C + r]

    bar_y = C + int(r * 0.30)                 # общая горизонталь
    end_deg = math.degrees(math.asin(0.30))   # где дуга приходит на эту высоту

    # G: дуга с разрывом справа. Нижний конец обрывается ровно там,
    # где начинается горизонталь, — стык, а не наложение.
    draw.arc(box, start=end_deg, end=330, fill=255, width=w)

    right = C + int(r * math.cos(math.radians(end_deg)))
    left = C - int(r * 0.35)

    draw.rounded_rectangle(
        [left - w // 2, bar_y - w // 2, right, bar_y + w // 2],
        radius=w // 2, fill=255,
    )

    # L: вертикаль опускается в ту же горизонталь.
    draw.rounded_rectangle(
        [left - w // 2, C - int(r * 0.58), left + w // 2, bar_y + w // 2],
        radius=w // 2, fill=255,
    )
    return mask


def build():
    img = Image.new("RGBA", (S, S), INK_EDGE + (255,))
    ground(img)
    rings(img)

    mask = monogram()
    # Мягкое свечение под знаком: не эффект, а признак того, что источник тёплый.
    glow = mask.filter(ImageFilter.GaussianBlur(26 * SS))
    halo = Image.new("RGBA", (S, S), GOLD + (0,))
    halo.putalpha(glow.point(lambda v: int(v * 0.30)))
    img.alpha_composite(halo)

    fill = warm(S, S).convert("RGBA")
    fill.putalpha(mask)
    img.alpha_composite(fill)

    return img.convert("RGB").resize((SIZE, SIZE), Image.LANCZOS)


if __name__ == "__main__":
    out = build()
    out.save("design/gloria-avatar-1024.png", optimize=True)
    out.resize((512, 512), Image.LANCZOS).save("design/gloria-avatar-512.png", optimize=True)
    out.resize((96, 96), Image.LANCZOS).save("design/gloria-avatar-96.png", optimize=True)
    print("готово")
