"""Generate Bastion's feature graphic: a 1920x1080 card for the Third Stone site
(thirdstone-astro's Projects page), in the same family as kindjams', Ndurance's and
Ptolemy's: the wordmark and tagline on the left, the product's own picture on the right.

The picture is Bastion's idea of security drawn as its logo: the hexagon (the nav bar's
"⬢") repeated as concentric layers of defence -- edge, web, app, data -- with attempts
coming in from outside and stopping at the outer layers. Three cards call out real
behaviour, each pinned to the layer that does it: passkey sign-in (app), refresh-token
theft detection (app/session), and the rows-only database login (data).

Palette is the SPA's (frontend/src/styles.css); the type is Inter, vendored in
brand/fonts/ under the OFL, as in the sibling projects.

Usage: python brand/generate-feature-graphic.py
  -> brand/out/feature-graphic-1920x1080.png and .webp
"""
import math
import os
import random

from PIL import Image, ImageDraw, ImageFilter, ImageFont

BRAND = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BRAND, "out")
FONT_REG = os.path.join(BRAND, "fonts", "Inter-Regular.ttf")
FONT_SEMI = os.path.join(BRAND, "fonts", "Inter-SemiBold.ttf")
FONT_XB = os.path.join(BRAND, "fonts", "Inter-ExtraBold.ttf")

# frontend/src/styles.css
BG_TOP = (17, 23, 36)
BG_BOT = (9, 12, 20)
SURFACE = (26, 32, 48)        # --surface #1a2030
BORDER = (46, 58, 80)         # --border #2e3a50
TEXT = (232, 236, 244)        # --text #e8ecf4
DIM = (154, 165, 187)         # --text-dim #9aa5bb
ACCENT = (79, 140, 255)       # --accent #4f8cff
ACCENT_HI = (107, 160, 255)   # --accent-hover #6ba0ff
DANGER = (229, 83, 75)        # --danger #e5534b
SUCCESS = (63, 178, 127)      # --success #3fb27f
FAINT = (70, 82, 106)

SS = 2  # supersample, then downscale for clean edges
W, H = 1920, 1080


def font(path, px):
    return ImageFont.truetype(path, round(px * SS))


def background():
    bg = Image.new("RGB", (W * SS, H * SS))
    d = ImageDraw.Draw(bg)
    for y in range(H * SS):
        t = y / (H * SS - 1)
        d.line([(0, y), (W * SS, y)], fill=tuple(round(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(3)))
    return bg.convert("RGBA")


def glow(cx, cy, r, color, alpha):
    layer = Image.new("RGBA", (W * SS, H * SS), (0, 0, 0, 0))
    ImageDraw.Draw(layer).ellipse([(cx - r) * SS, (cy - r) * SS, (cx + r) * SS, (cy + r) * SS], fill=color + (alpha,))
    return layer.filter(ImageFilter.GaussianBlur(r * SS * 0.5))


def hexagon(cx, cy, r):
    """Pointy-top, like the nav bar's ⬢."""
    return [(cx + r * math.cos(math.radians(90 + 60 * k)), cy - r * math.sin(math.radians(90 + 60 * k))) for k in range(6)]


def s(points):
    return [(x * SS, y * SS) for x, y in points]


def hex_edge_point(cx, cy, r, angle_deg):
    """Where a ray from the centre at angle_deg (0 = right, counter-clockwise) meets the hexagon."""
    a = math.radians(angle_deg)
    dx, dy = math.cos(a), -math.sin(a)
    best = None
    pts = hexagon(cx, cy, r)
    for i in range(6):
        (x1, y1), (x2, y2) = pts[i], pts[(i + 1) % 6]
        ex, ey = x2 - x1, y2 - y1
        den = dx * ey - dy * ex
        if abs(den) < 1e-9:
            continue
        t = ((x1 - cx) * ey - (y1 - cy) * ex) / den
        u = ((x1 - cx) * dy - (y1 - cy) * dx) / den
        if t > 0 and 0 <= u <= 1 and (best is None or t < best):
            best = t
    return cx + dx * best, cy + dy * best


def card_width(title, sub):
    tf, sf = font(FONT_SEMI, 29), font(FONT_REG, 23)
    text = max(d_len(tf, title), d_len(sf, sub)) / SS
    return 22 + 44 + 18 + text + 30


def d_len(f, text):
    return f.getlength(text)


def card(d, box, title, sub, icon):
    x0, y0, x1, y1 = box
    d.rounded_rectangle(s([(x0, y0), (x1, y1)]), 14 * SS, fill=SURFACE + (240,), outline=BORDER + (255,), width=2 * SS)
    tf, sf = font(FONT_SEMI, 29), font(FONT_REG, 23)
    pad = 22
    dia = 44
    icy = (y0 + y1) / 2
    ix = x0 + pad
    color = SUCCESS if icon == "check" else ACCENT
    d.ellipse(s([(ix, icy - dia / 2), (ix + dia, icy + dia / 2)]), fill=color + (255,))
    c = (ix + dia / 2, icy)
    if icon == "check":
        d.line(s([(c[0] - 10, c[1] + 1), (c[0] - 3, c[1] + 8), (c[0] + 11, c[1] - 8)]), fill=BG_BOT + (255,), width=5 * SS, joint="curve")
    elif icon == "key":
        d.ellipse(s([(c[0] - 13, c[1] - 7), (c[0] - 1, c[1] + 5)]), outline=BG_BOT + (255,), width=4 * SS)
        d.line(s([(c[0] - 1, c[1] - 1), (c[0] + 13, c[1] - 1)]), fill=BG_BOT + (255,), width=4 * SS)
        d.line(s([(c[0] + 9, c[1] - 1), (c[0] + 9, c[1] + 6)]), fill=BG_BOT + (255,), width=4 * SS)
    else:  # shield
        sh = [(c[0], c[1] - 13), (c[0] + 11, c[1] - 8), (c[0] + 9, c[1] + 5), (c[0], c[1] + 13), (c[0] - 9, c[1] + 5), (c[0] - 11, c[1] - 8)]
        d.polygon(s(sh), fill=BG_BOT + (255,))
    tx = ix + dia + 18
    d.text((tx * SS, (icy - 5) * SS), title, font=tf, fill=TEXT + (255,), anchor="ls")
    d.text((tx * SS, (icy + 27) * SS), sub, font=sf, fill=DIM + (255,), anchor="ls")


def render():
    img = background()
    cx, cy = 1385, 545
    rings = [  # radius, label
        (440, "EDGE"),
        (348, "WEB"),
        (256, "APP"),
        (164, "DATA"),
    ]
    img.alpha_composite(glow(cx, cy, 300, ACCENT, 40))

    # The layers: faint fills that deepen inward, each outlined. Drawn on their own
    # layer and composited: ImageDraw writes alpha, it doesn't blend.
    for i, (r, _) in enumerate(rings):
        layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
        ImageDraw.Draw(layer).polygon(s(hexagon(cx, cy, r)), fill=ACCENT + (14 + i * 6,))
        img.alpha_composite(layer)
    lines = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ld = ImageDraw.Draw(lines)
    for i, (r, _) in enumerate(rings):
        ld.polygon(s(hexagon(cx, cy, r)), outline=ACCENT_HI + (90 + i * 40,), width=(3 if i == 0 else 2) * SS)
    img.alpha_composite(lines)
    d = ImageDraw.Draw(img)

    # The core: the logo itself.
    d.polygon(s(hexagon(cx, cy, 72)), fill=ACCENT + (255,))
    # keyhole
    d.ellipse(s([(cx - 14, cy - 26), (cx + 14, cy + 2)]), fill=BG_BOT + (255,))
    d.polygon(s([(cx - 8, cy - 4), (cx + 8, cy - 4), (cx + 12, cy + 30), (cx - 12, cy + 30)]), fill=BG_BOT + (255,))

    # Layer names in a row along each ring's left edge, reading inward to the core.
    lf = font(FONT_SEMI, 19)
    for r, label in rings:
        d.text(((cx - r * math.cos(math.radians(30)) + 14) * SS, cy * SS), label, font=lf, fill=DIM + (235,), anchor="lm")

    # Attempts from outside, each stopped at a layer: a fading trail and a spark.
    rnd = random.Random(7)
    trails = Image.new("RGBA", img.size, (0, 0, 0, 0))
    td = ImageDraw.Draw(trails)
    stops = [0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 2, 0]
    angles = [6, 36, 52, -10, -26, -44, -62, 150, 214, 112, -78, -128]
    sparks = []
    for ang, layer in zip(angles, stops):
        ang += rnd.uniform(-4, 4)
        r = rings[layer][0]
        ex, ey = hex_edge_point(cx, cy, r, ang)
        a = math.radians(ang)
        length = rnd.uniform(130, 230)
        sx, sy = ex + math.cos(a) * length, ey - math.sin(a) * length
        steps = 40
        for k in range(steps):
            t0, t1 = k / steps, (k + 1) / steps
            p0 = (sx + (ex - sx) * t0, sy + (ey - sy) * t0)
            p1 = (sx + (ex - sx) * t1, sy + (ey - sy) * t1)
            td.line(s([p0, p1]), fill=DANGER + (int(15 + 150 * t1 ** 2),), width=3 * SS)
        sparks.append((ex, ey))
    img.alpha_composite(trails)
    halo = Image.new("RGBA", img.size, (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    for ex, ey in sparks:
        hd.ellipse(s([(ex - 16, ey - 16), (ex + 16, ey + 16)]), fill=DANGER + (120,))
    img.alpha_composite(halo.filter(ImageFilter.GaussianBlur(9 * SS)))
    d = ImageDraw.Draw(img)
    for ex, ey in sparks:
        d.ellipse(s([(ex - 6, ey - 6), (ex + 6, ey + 6)]), fill=DANGER + (255,))
        d.ellipse(s([(ex - 2.5, ey - 2.5), (ex + 2.5, ey + 2.5)]), fill=(255, 220, 215, 255))

    # Call-outs: a point on the layer that does it, a ring, a leader to the card.
    callouts = [
        # (x, y, x-anchor 0=left 1=right), anchor angle, ring index, title, sub, icon, where the leader meets the card
        ((1335, 70, 1), 140, 2, "Signed in with a passkey", "WebAuthn  ·  phishing-resistant", "key", "bottom"),
        ((1880, 285, 1), 20, 2, "Stolen token replayed", "Theft detected  ·  every session ended", "shield", "left"),
        ((1880, 890, 1), -60, 3, "The app’s database login", "Rows only  ·  TLS  ·  no DDL, no root", "check", "top"),
    ]
    for (bx, by, xa), ang, ring, title, sub, icon, side in callouts:
        cw = card_width(title, sub)
        x0 = bx - cw * xa
        x1, y0, y1 = x0 + cw, by, by + 100
        px, py = hex_edge_point(cx, cy, rings[ring][0], ang)
        if side == "bottom":
            ax, ay = x0 + (x1 - x0) * 0.62, y1
        elif side == "left":
            ax, ay = x0, (y0 + y1) / 2
        else:
            ax, ay = x0 + (x1 - x0) * 0.45, y0
        d.line(s([(px, py), (ax, ay)]), fill=TEXT + (120,), width=SS)
        d.ellipse(s([(px - 13, py - 13), (px + 13, py + 13)]), outline=TEXT + (230,), width=2 * SS)
        d.ellipse(s([(px - 7, py - 7), (px + 7, py + 7)]), fill=ACCENT_HI + (255,))
        card(d, (x0, y0, x1, y1), title, sub, icon)

    # Wordmark, tagline, facts: the same block the sibling cards use.
    wx, wy = 115, 505
    d.text((wx * SS, wy * SS), "Bastion", font=font(FONT_XB, 168), fill=ACCENT + (255,), anchor="ls")
    tag = font(FONT_REG, 54)
    for i, line in enumerate(["Authentication, done carefully.", "Start on the product."]):
        d.text((wx * SS, (wy + 102 + i * 74) * SS), line, font=tag, fill=TEXT + (225,), anchor="ls")
    d.text((wx * SS, (wy + 290) * SS), "SPRING BOOT 4  ·  REACT 19  ·  OPEN SOURCE",
           font=font(FONT_SEMI, 25), fill=ACCENT_HI + (220,), anchor="ls")

    return img.resize((W, H), Image.LANCZOS).convert("RGB")


def main():
    os.makedirs(OUT, exist_ok=True)
    img = render()
    img.save(os.path.join(OUT, "feature-graphic-1920x1080.png"), optimize=True)
    img.save(os.path.join(OUT, "feature-graphic-1920x1080.webp"), quality=86, method=6)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
