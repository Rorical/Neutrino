"""Drawing primitives: palette, easing, text and formula layout, glowing shapes."""

from __future__ import annotations

import math
import random
from functools import lru_cache
from pathlib import Path

import cairo
import numpy as np
from fontTools.ttLib import TTFont
from PIL import Image, ImageDraw, ImageFont

from lang import EN

W, H = 1920, 1080
TAU = math.tau

# Palette. The world is warm matter; only proofs and the mark carry cool colour.
BG = (0.028, 0.027, 0.025)
BONE = (0.925, 0.905, 0.860)
DIM = (0.58, 0.56, 0.52)
FAINT = (0.32, 0.31, 0.29)
GRAPHITE = (0.15, 0.145, 0.135)
AMBER = (1.0, 0.68, 0.28)
AMBER_HOT = (1.0, 0.86, 0.62)
EMBER = (1.0, 0.44, 0.12)
RED = (1.0, 0.27, 0.21)
CYAN = (0.31, 0.89, 1.0)  # brand particle #4FE3FF
VIOLET = (0.486, 0.361, 1.0)  # brand proof #7C5CFF
ICE = (0.91, 0.94, 1.0)  # brand ice #E8F0FF
WHITE = (1.0, 1.0, 1.0)

BRAND = Path(__file__).resolve().parent.parent
SYS = Path("/System/Library/Fonts")

FONTS = {
    "cn": (SYS / "Hiragino Sans GB.ttc", 0, None),
    "cn_b": (SYS / "Hiragino Sans GB.ttc", 2, None),
    "sans": (SYS / "SFNS.ttf", 0, b"Regular"),
    "grotesk": (BRAND / "fonts/SpaceGrotesk-SemiBold.ttf", 0, None),
    "mono": (SYS / "SFNSMono.ttf", 0, b"Regular"),
    "mono_m": (SYS / "SFNSMono.ttf", 0, b"Medium"),
    "math": (SYS / "Supplemental/STIXTwoMath.otf", 0, None),
    "math_it": (SYS / "Supplemental/STIXTwoText-Italic.ttf", 0, None),
    "math_rm": (SYS / "Supplemental/STIXTwoText.ttf", 0, None),
}
FALLBACK = ["math", "cn", "mono"]
if EN:
    # The English cut sets body copy in SF and headlines in the brand's Space Grotesk.
    FONTS["cn"] = FONTS["sans"]
    FONTS["cn_b"] = FONTS["grotesk"]


# ---------------------------------------------------------------- easing


def clamp(x, a=0.0, b=1.0):
    return a if x < a else b if x > b else x


def seg(t, a, b):
    """Normalised progress of t through [a, b]."""
    if b <= a:
        return 1.0 if t >= b else 0.0
    return clamp((t - a) / (b - a))


def smooth(x):
    x = clamp(x)
    return x * x * (3 - 2 * x)


def ease_out(x, p=3):
    x = clamp(x)
    return 1 - (1 - x) ** p


def ease_in(x, p=3):
    x = clamp(x)
    return x**p


def ease_io(x):
    x = clamp(x)
    return 4 * x**3 if x < 0.5 else 1 - (-2 * x + 2) ** 3 / 2


def ease_out_back(x, s=1.7):
    x = clamp(x)
    return 1 + (s + 1) * (x - 1) ** 3 + s * (x - 1) ** 2


def ease_out_expo(x):
    x = clamp(x)
    return 1.0 if x >= 1 else 1 - 2 ** (-10 * x)


def window(t, a, b, fin=0.4, fout=0.4):
    """1 inside [a, b] with soft edges, 0 outside."""
    return smooth(seg(t, a, a + fin)) * (1 - smooth(seg(t, b - fout, b)))


def lerp(a, b, x):
    return a + (b - a) * x


def mix(c1, c2, x):
    return tuple(lerp(a, b, x) for a, b in zip(c1, c2))


def scale_color(c, k):
    return tuple(v * k for v in c)


def hash01(*args):
    return random.Random(repr(args)).random()


# ---------------------------------------------------------------- fonts


@lru_cache(maxsize=None)
def pil_font(key, size):
    path, index, variation = FONTS[key]
    font = ImageFont.truetype(str(path), size=size, index=index)
    if variation:
        font.set_variation_by_name(variation)
    return font


@lru_cache(maxsize=None)
def cmap(key):
    path, index, _ = FONTS[key]
    if str(path).endswith(".ttc"):
        tt = TTFont(str(path), fontNumber=index, lazy=True)
    else:
        tt = TTFont(str(path), lazy=True)
    return frozenset(tt.getBestCmap())


def font_for(key, ch):
    if ch == " " or ord(ch) in cmap(key):
        return key
    for alt in FALLBACK:
        if ord(ch) in cmap(alt):
            return alt
    return key


_glyphs: dict = {}


def a8_surface(mask: np.ndarray):
    h, w = mask.shape
    stride = cairo.ImageSurface.format_stride_for_width(cairo.FORMAT_A8, w)
    buf = np.zeros((h, stride), np.uint8)
    buf[:, :w] = mask
    surf = cairo.ImageSurface.create_for_data(memoryview(buf), cairo.FORMAT_A8, w, h, stride)
    return surf, buf


def glyph(key, size, ch):
    """(advance, surface, ox, oy) for one character, origin at the baseline."""
    k = (key, size, ch)
    g = _glyphs.get(k)
    if g is not None:
        return g
    font = pil_font(key, size)
    adv = font.getlength(ch)
    x0, y0, x1, y1 = font.getbbox(ch, anchor="ls")
    if x1 <= x0 or y1 <= y0:
        g = (adv, None, 0, 0, None)
    else:
        pad = 2
        img = Image.new("L", (x1 - x0 + 2 * pad, y1 - y0 + 2 * pad), 0)
        ImageDraw.Draw(img).text((pad - x0, pad - y0), ch, font=font, fill=255, anchor="ls")
        surf, buf = a8_surface(np.asarray(img))
        g = (adv, surf, x0 - pad, y0 - pad, buf)
    _glyphs[k] = g
    return g


def layout(text, key, size, tracking=0.0):
    """Lay out a string; returns ([(ch, fontkey, x)], width)."""
    size = int(round(size))
    items = []
    x = 0.0
    for ch in text:
        fk = font_for(key, ch)
        adv = glyph(fk, size, ch)[0]
        items.append((ch, fk, x))
        x += adv + tracking
    return items, max(0.0, x - tracking)


def text_width(text, key, size, tracking=0.0):
    return layout(text, key, size, tracking)[1]


SCRAMBLE = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789#%&+<>/=*"


def draw_text(
    ctx,
    text,
    x,
    y,
    key="cn",
    size=24,
    color=BONE,
    alpha=1.0,
    tracking=0.0,
    align="left",
    mode=None,
    p=1.0,
    t=0.0,
    rise=10.0,
    hot=None,
):
    """Draw text at baseline (x, y).

    mode None: static. "rise": characters fade in and rise in sequence by p.
    "decode": characters resolve from scrambled glyphs by p.
    hot: colour each character passes through as it appears.
    """
    if alpha <= 0.002:
        return 0.0
    size = int(round(size))
    items, width = layout(text, key, size, tracking)
    if align == "center":
        x -= width / 2
    elif align == "right":
        x -= width
    n = max(1, len(items))
    soft = 4.0
    for i, (ch, fk, cx) in enumerate(items):
        a = alpha
        dy = 0.0
        col = color
        draw_ch = ch
        if mode == "rise":
            k = clamp((p * (n + soft) - i) / soft)
            k = smooth(k)
            a *= k
            dy = (1 - k) * rise
            if hot is not None:
                col = mix(hot, color, smooth(clamp((p * (n + soft) - i - soft) / (soft * 1.5))))
        elif mode == "decode":
            pos = p * (n + 6)
            if i > pos:
                continue
            if i > pos - 6 and ch != " ":
                r = random.Random(f"{i}|{int(t * 30)}|{text}")
                draw_ch = r.choice(SCRAMBLE)
                fk = "mono"
                a *= 0.55
                if hot is not None:
                    col = hot
        if a <= 0.002 or draw_ch == " ":
            continue
        _, surf, ox, oy, _ = glyph(fk, size, draw_ch)
        if surf is None:
            continue
        ctx.set_source_rgba(*col, a)
        ctx.mask_surface(surf, x + cx + ox, y + oy + dy)
    return width


# ---------------------------------------------------------------- formulas

CJK_RANGES = ((0x3000, 0x9FFF), (0xFF00, 0xFFEF))
UPRIGHT = set("0123456789()[]{},.;:|!?'\"")
SPACED = set("=⇒⟺→≥≤≠∧⊕≡∝←+−∩")


def _is_cjk(ch):
    o = ord(ch)
    return any(a <= o <= b for a, b in CJK_RANGES)


def _parse(src):
    """Yield (char, style, level) for a tiny TeX-like markup.

    \\rm{..} upright, \\tt{..} mono, _x/_{..} subscript, ^x/^{..} superscript.
    """
    out = []
    i = 0
    n = len(src)

    def group(j):
        if j < n and src[j] == "{":
            depth = 0
            for k in range(j, n):
                if src[k] == "{":
                    depth += 1
                elif src[k] == "}":
                    depth -= 1
                    if depth == 0:
                        return src[j + 1 : k], k + 1
            raise ValueError(src)
        return src[j], j + 1

    def emit(s, style, level):
        for item in _parse(s):
            ch, st, lv = item
            out.append((ch, st if st != "auto" else style, level + lv))

    while i < n:
        c = src[i]
        if c == "\\":
            for cmd in ("rm", "tt"):
                if src.startswith(cmd + "{", i + 1):
                    body, i = group(i + 1 + len(cmd))
                    emit(body, cmd, 0)
                    break
            else:
                out.append(("\\", "auto", 0))
                i += 1
            continue
        if c in "_^":
            body, i = group(i + 1)
            emit(body, "auto", -1 if c == "_" else 1)
            continue
        out.append((c, "auto", 0))
        i += 1
    return out


@lru_cache(maxsize=512)
def formula_layout(src, size):
    """Return ([(ch, fontkey, px, x, dy)], width)."""
    items = []
    x = 0.0
    prev_spaced = False
    for ch, style, level in _parse(src):
        s = size if level == 0 else size * 0.66
        dy = 0.0 if level == 0 else (size * 0.22 if level < 0 else -size * 0.40)
        px = int(round(s))
        if ch == " ":
            x += size * 0.28
            continue
        if style == "tt":
            fk = "mono"
        elif _is_cjk(ch):
            fk = "cn"
        elif style == "rm":
            fk = "math_rm"
        elif ch.isascii() and ch.isalpha():
            fk = "math_it"
        elif "Ͱ" <= ch <= "Ͽ":
            fk = "math_it"
        elif ch in UPRIGHT:
            fk = "math_rm"
        else:
            fk = "math"
        fk = font_for(fk, ch)
        spaced = ch in SPACED and level == 0
        if spaced and not prev_spaced:
            x += size * 0.22
        adv = glyph(fk, px, ch)[0]
        items.append((ch, fk, px, x, dy))
        x += adv
        if spaced:
            x += size * 0.22
        if ch == "," and level == 0:
            x += size * 0.12
        prev_spaced = spaced
    return tuple(items), x


def formula_width(src, size):
    return formula_layout(src, size)[1]


def draw_formula(ctx, src, x, y, size=36, color=BONE, alpha=1.0, align="left", wipe=1.0, scan=AMBER_HOT):
    """Draw a formula on baseline y. wipe reveals it left to right with a scan line."""
    if alpha <= 0.002 or wipe <= 0:
        return 0.0
    items, width = formula_layout(src, size)
    if align == "center":
        x -= width / 2
    elif align == "right":
        x -= width
    edge = x + (width + size * 0.4) * wipe
    ctx.save()
    if wipe < 1:
        ctx.rectangle(x - size, y - size * 1.6, edge - x + size, size * 3.2)
        ctx.clip()
    for ch, fk, px, cx, dy in items:
        _, surf, ox, oy, _ = glyph(fk, px, ch)
        if surf is None:
            continue
        ctx.set_source_rgba(*color, alpha)
        ctx.mask_surface(surf, x + cx + ox, y + dy + oy)
    ctx.restore()
    if 0 < wipe < 1:
        g = cairo.LinearGradient(edge, y - size * 1.2, edge, y + size * 0.5)
        g.add_color_stop_rgba(0, *scan, 0)
        g.add_color_stop_rgba(0.5, *scan, 0.9 * alpha)
        g.add_color_stop_rgba(1, *scan, 0)
        ctx.set_source(g)
        ctx.rectangle(edge - 1.2, y - size * 1.2, 2.4, size * 1.7)
        ctx.fill()
    return width


# ---------------------------------------------------------------- shapes


def rgba(ctx, c, a=1.0):
    ctx.set_source_rgba(c[0], c[1], c[2], a)


def circle(ctx, x, y, r):
    ctx.new_sub_path()
    ctx.arc(x, y, max(r, 0.01), 0, TAU)


def fill_circle(ctx, x, y, r, c, a=1.0):
    if a <= 0.002 or r <= 0:
        return
    rgba(ctx, c, a)
    circle(ctx, x, y, r)
    ctx.fill()


def stroke_circle(ctx, x, y, r, c, a=1.0, w=1.5):
    if a <= 0.002 or r <= 0:
        return
    rgba(ctx, c, a)
    ctx.set_line_width(w)
    circle(ctx, x, y, r)
    ctx.stroke()


def line(ctx, x1, y1, x2, y2, c, a=1.0, w=1.5, cap=cairo.LINE_CAP_ROUND):
    if a <= 0.002:
        return
    rgba(ctx, c, a)
    ctx.set_line_width(w)
    ctx.set_line_cap(cap)
    ctx.move_to(x1, y1)
    ctx.line_to(x2, y2)
    ctx.stroke()


def partial_line(ctx, x1, y1, x2, y2, p, c, a=1.0, w=1.5):
    if p <= 0:
        return
    line(ctx, x1, y1, lerp(x1, x2, p), lerp(y1, y2, p), c, a, w)


def halo(ctx, x, y, r, c, a=0.4):
    if a <= 0.002 or r <= 0:
        return
    g = cairo.RadialGradient(x, y, 0, x, y, r)
    g.add_color_stop_rgba(0, c[0], c[1], c[2], a)
    g.add_color_stop_rgba(0.35, c[0], c[1], c[2], a * 0.35)
    g.add_color_stop_rgba(1, c[0], c[1], c[2], 0)
    ctx.set_source(g)
    circle(ctx, x, y, r)
    ctx.fill()


def particle(ctx, x, y, r=6.0, c=CYAN, a=1.0, glow=1.0):
    """A proof particle: white-hot core, coloured body, soft halo."""
    if a <= 0.002:
        return
    halo(ctx, x, y, r * 7 * glow, c, 0.32 * a * glow)
    fill_circle(ctx, x, y, r, c, a)
    fill_circle(ctx, x, y, r * 0.5, WHITE, 0.95 * a)


def arc_stroke(ctx, x, y, r, a0, a1, c, a=1.0, w=2.0, cap=cairo.LINE_CAP_BUTT):
    if a <= 0.002 or a1 <= a0:
        return
    rgba(ctx, c, a)
    ctx.set_line_width(w)
    ctx.set_line_cap(cap)
    ctx.new_sub_path()
    ctx.arc(x, y, r, a0, a1)
    ctx.stroke()


def rect_path(ctx, x, y, w, h, r=0.0):
    if r <= 0:
        ctx.rectangle(x, y, w, h)
        return
    ctx.new_sub_path()
    ctx.arc(x + w - r, y + r, r, -TAU / 4, 0)
    ctx.arc(x + w - r, y + h - r, r, 0, TAU / 4)
    ctx.arc(x + r, y + h - r, r, TAU / 4, TAU / 2)
    ctx.arc(x + r, y + r, r, TAU / 2, TAU * 3 / 4)
    ctx.close_path()


def stroke_rect(ctx, x, y, w, h, c, a=1.0, lw=1.2, r=0.0):
    if a <= 0.002:
        return
    rgba(ctx, c, a)
    ctx.set_line_width(lw)
    rect_path(ctx, x, y, w, h, r)
    ctx.stroke()


def fill_rect(ctx, x, y, w, h, c, a=1.0, r=0.0):
    if a <= 0.002:
        return
    rgba(ctx, c, a)
    rect_path(ctx, x, y, w, h, r)
    ctx.fill()


def traced_rect(ctx, x, y, w, h, p, c, a=1.0, lw=1.2):
    """Outline drawn progressively from the top-left corner, both ways."""
    if p <= 0 or a <= 0.002:
        return
    if p >= 1:
        stroke_rect(ctx, x, y, w, h, c, a, lw)
        return
    half = (w + h) * p
    rgba(ctx, c, a)
    ctx.set_line_width(lw)
    ctx.set_line_cap(cairo.LINE_CAP_SQUARE)
    for path in (((x, y), (x + w, y), (x + w, y + h)), ((x, y), (x, y + h), (x + w, y + h))):
        rem = half
        ctx.move_to(*path[0])
        for (ax, ay), (bx, by) in zip(path, path[1:]):
            ln = math.hypot(bx - ax, by - ay)
            k = clamp(rem / ln)
            ctx.line_to(lerp(ax, bx, k), lerp(ay, by, k))
            rem -= ln
            if rem <= 0:
                break
        ctx.stroke()


def corner_frame(ctx, x, y, w, h, c, a=1.0, ln=14.0, lw=1.4):
    if a <= 0.002:
        return
    rgba(ctx, c, a)
    ctx.set_line_width(lw)
    ctx.set_line_cap(cairo.LINE_CAP_SQUARE)
    for cx, cy, dx, dy in ((x, y, 1, 1), (x + w, y, -1, 1), (x, y + h, 1, -1), (x + w, y + h, -1, -1)):
        ctx.move_to(cx + dx * ln, cy)
        ctx.line_to(cx, cy)
        ctx.line_to(cx, cy + dy * ln)
    ctx.stroke()


def polygon(ctx, cx, cy, r, n=6, rot=0.0):
    ctx.new_sub_path()
    for k in range(n):
        ang = rot + TAU * k / n
        ctx.line_to(cx + r * math.cos(ang), cy + r * math.sin(ang))
    ctx.close_path()


def traced_polygon(ctx, cx, cy, r, p, c, a=1.0, lw=1.5, n=6, rot=-TAU / 4):
    if p <= 0 or a <= 0.002:
        return
    pts = [(cx + r * math.cos(rot + TAU * k / n), cy + r * math.sin(rot + TAU * k / n)) for k in range(n + 1)]
    total = p * n
    rgba(ctx, c, a)
    ctx.set_line_width(lw)
    ctx.set_line_join(cairo.LINE_JOIN_ROUND)
    ctx.move_to(*pts[0])
    for k in range(n):
        if total <= k:
            break
        f = clamp(total - k)
        ctx.line_to(lerp(pts[k][0], pts[k + 1][0], f), lerp(pts[k][1], pts[k + 1][1], f))
    ctx.stroke()


def tick_ring(ctx, cx, cy, r, n, ln, rot, c, a=1.0, w=1.0, major=0, major_ln=None):
    if a <= 0.002:
        return
    rgba(ctx, c, a)
    ctx.set_line_width(w)
    for k in range(n):
        ang = rot + TAU * k / n
        L = (major_ln or ln * 2) if major and k % major == 0 else ln
        ca, sa = math.cos(ang), math.sin(ang)
        ctx.move_to(cx + r * ca, cy + r * sa)
        ctx.line_to(cx + (r + L) * ca, cy + (r + L) * sa)
    ctx.stroke()


def dashed_circle(ctx, cx, cy, r, dash, gap, rot, c, a=1.0, w=1.0):
    if a <= 0.002:
        return
    rgba(ctx, c, a)
    ctx.set_line_width(w)
    ctx.set_dash([dash, gap], rot * r)
    circle(ctx, cx, cy, r)
    ctx.stroke()
    ctx.set_dash([])


def bezier_point(p0, p1, p2, p3, u):
    v = 1 - u
    return (
        v**3 * p0[0] + 3 * v * v * u * p1[0] + 3 * v * u * u * p2[0] + u**3 * p3[0],
        v**3 * p0[1] + 3 * v * v * u * p1[1] + 3 * v * u * u * p2[1] + u**3 * p3[1],
    )


def bezier_partial(ctx, p0, p1, p2, p3, p, c, a=1.0, w=1.5, steps=48):
    if p <= 0 or a <= 0.002:
        return
    rgba(ctx, c, a)
    ctx.set_line_width(w)
    ctx.set_line_cap(cairo.LINE_CAP_ROUND)
    n = max(2, int(steps * p))
    ctx.move_to(*p0)
    for k in range(1, n + 1):
        ctx.line_to(*bezier_point(p0, p1, p2, p3, p * k / n))
    ctx.stroke()


def check_mark(ctx, x, y, s, p, c, a=1.0, w=2.2):
    """A tick drawn progressively; (x, y) is its centre."""
    if p <= 0 or a <= 0.002:
        return
    pts = [(x - s * 0.5, y), (x - s * 0.12, y + s * 0.38), (x + s * 0.55, y - s * 0.42)]
    rgba(ctx, c, a)
    ctx.set_line_width(w)
    ctx.set_line_cap(cairo.LINE_CAP_ROUND)
    ctx.set_line_join(cairo.LINE_JOIN_ROUND)
    ctx.move_to(*pts[0])
    if p < 0.4:
        f = p / 0.4
        ctx.line_to(lerp(pts[0][0], pts[1][0], f), lerp(pts[0][1], pts[1][1], f))
    else:
        ctx.line_to(*pts[1])
        f = (p - 0.4) / 0.6
        ctx.line_to(lerp(pts[1][0], pts[2][0], f), lerp(pts[1][1], pts[2][1], f))
    ctx.stroke()


def cross_mark(ctx, x, y, s, c, a=1.0, w=2.4):
    line(ctx, x - s, y - s, x + s, y + s, c, a, w)
    line(ctx, x - s, y + s, x + s, y - s, c, a, w)


def padlock(ctx, x, y, s, c, a=1.0, open_=0.0):
    """Padlock centred at (x, y); s is the body width."""
    if a <= 0.002:
        return
    rgba(ctx, c, a)
    ctx.set_line_width(max(1.4, s * 0.12))
    bw, bh = s, s * 0.78
    ctx.rectangle(x - bw / 2, y - bh * 0.2, bw, bh)
    ctx.stroke()
    lift = open_ * s * 0.3
    ctx.new_sub_path()
    ctx.arc(x, y - bh * 0.2 - s * 0.05 - lift, s * 0.3, math.pi, 0)
    ctx.stroke()
    fill_circle(ctx, x, y + bh * 0.22, s * 0.08, c, a)
