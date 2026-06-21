from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFilter

SS = 4
SIZE = 1024
W = SIZE * SS
HERE = os.path.dirname(os.path.abspath(__file__))


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(len(a)))


def vgrad(w, h, top, bottom):
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        c = lerp(top, bottom, y / max(1, h - 1))
        for x in range(w):
            px[x, y] = c
    return img


def rounded_mask(w, h, radius):
    m = Image.new("L", (w, h), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([0, 0, w - 1, h - 1], radius=radius, fill=255)
    return m


def build():
    base = Image.new("RGBA", (W, W), (0, 0, 0, 0))

    bg = vgrad(W, W, (32, 27, 74), (8, 8, 20)).convert("RGBA")
    bg.putalpha(rounded_mask(W, W, int(W * 0.22)))
    base.alpha_composite(bg)

    glow = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    cx = W / 2
    gd.ellipse([cx - W * 0.20, W * 0.20, cx + W * 0.20, W * 0.86],
               fill=(80, 180, 255, 120))
    glow = glow.filter(ImageFilter.GaussianBlur(W * 0.06))
    base.alpha_composite(glow)

    shadow = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    sd.ellipse([cx - W * 0.16, W * 0.80, cx + W * 0.16, W * 0.88], fill=(0, 0, 0, 160))
    shadow = shadow.filter(ImageFilter.GaussianBlur(W * 0.02))
    base.alpha_composite(shadow)

    apex = (cx, W * 0.16)
    pyr_l = (cx - W * 0.075, W * 0.30)
    pyr_r = (cx + W * 0.075, W * 0.30)
    bot_l = (cx - W * 0.11, W * 0.82)
    bot_r = (cx + W * 0.11, W * 0.82)
    poly = [apex, pyr_r, bot_r, bot_l, pyr_l]

    omask = Image.new("L", (W, W), 0)
    ImageDraw.Draw(omask).polygon(poly, fill=255)
    obel = vgrad(W, W, (150, 235, 255), (33, 92, 230)).convert("RGBA")
    obel.putalpha(omask)
    base.alpha_composite(obel)

    face = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    ImageDraw.Draw(face).polygon(
        [apex, pyr_l, bot_l, (cx, W * 0.82)], fill=(0, 0, 30, 90))
    base.alpha_composite(face)

    edge = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    ImageDraw.Draw(edge).line([apex, (cx, W * 0.82)], fill=(220, 250, 255, 150),
                              width=int(W * 0.006))
    base.alpha_composite(edge.filter(ImageFilter.GaussianBlur(W * 0.004)))

    key = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    kd = ImageDraw.Draw(key)
    kcx, kcy, r = cx, W * 0.50, W * 0.045
    kd.ellipse([kcx - r, kcy - r, kcx + r, kcy + r], fill=(255, 211, 107, 255))
    kd.polygon([(kcx - r * 0.45, kcy + r * 0.4), (kcx + r * 0.45, kcy + r * 0.4),
                (kcx + r * 0.8, kcy + r * 2.4), (kcx - r * 0.8, kcy + r * 2.4)],
               fill=(255, 211, 107, 255))
    g = key.filter(ImageFilter.GaussianBlur(W * 0.012))
    base.alpha_composite(g)
    base.alpha_composite(key)

    out = base.resize((SIZE, SIZE), Image.LANCZOS)
    out.save(os.path.join(HERE, "icon_1024.png"))
    out.resize((256, 256), Image.LANCZOS).save(os.path.join(HERE, "icon.png"))
    out.save(os.path.join(HERE, "icon.ico"),
             sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("wrote assets/icon_1024.png, assets/icon.png, assets/icon.ico")


if __name__ == "__main__":
    build()
