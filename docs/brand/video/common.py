"""Shared scene furniture: background, HUD, title blocks, captions."""

from __future__ import annotations

import math

import cairo
import numpy as np

from lang import EN, reveal_len, sentence
from gfx import (
    AMBER,
    AMBER_HOT,
    BG,
    BONE,
    DIM,
    FAINT,
    H,
    TAU,
    W,
    clamp,
    corner_frame,
    draw_text,
    text_width,
    fill_circle,
    line,
    seg,
    smooth,
    window,
)

TX = 150  # left edge of title blocks
CAPTION_Y = 968


# ---------------------------------------------------------------- background

_grid = None


def _grid_surface():
    global _grid
    if _grid is None:
        surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, W, H)
        c = cairo.Context(surf)
        step = 48
        for y in range(step // 2, H, step):
            for x in range(step // 2, W, step):
                major = (x // step) % 4 == 0 and (y // step) % 4 == 0
                c.set_source_rgba(*BONE, 0.075 if major else 0.035)
                c.rectangle(x - (1.0 if major else 0.6), y - (1.0 if major else 0.6), 2.0 if major else 1.2, 2.0 if major else 1.2)
                c.fill()
        _grid = surf
    return _grid


_rng = np.random.default_rng(1234)
DUST = np.column_stack(
    [
        _rng.uniform(0, W, 140),
        _rng.uniform(0, H, 140),
        _rng.uniform(0.15, 1.0, 140),  # depth
        _rng.uniform(-1, 1, 140),  # drift dir
        _rng.uniform(0, TAU, 140),  # phase
    ]
)


def background(ctx, t, grid_a=1.0, dust_a=1.0):
    ctx.set_source_rgb(*BG)
    ctx.paint()
    g = cairo.RadialGradient(W * 0.5, H * 0.55, 0, W * 0.5, H * 0.55, W * 0.7)
    g.add_color_stop_rgba(0, 0.16, 0.11, 0.06, 0.20)
    g.add_color_stop_rgba(1, 0, 0, 0, 0)
    ctx.set_source(g)
    ctx.paint()
    if grid_a > 0:
        ctx.set_source_surface(_grid_surface(), 0, 0)
        ctx.paint_with_alpha(grid_a)
    if dust_a > 0:
        for x0, y0, z, d, ph in DUST:
            x = (x0 + t * (6 + 14 * z) * (0.6 + 0.4 * d)) % W
            y = (y0 - t * (3 + 6 * z) + 8 * math.sin(t * 0.3 + ph)) % H
            tw = 0.6 + 0.4 * math.sin(t * (0.8 + z) + ph * 3)
            fill_circle(ctx, x, y, 0.5 + 1.5 * z, AMBER_HOT if z > 0.7 else BONE, dust_a * (0.03 + 0.11 * z) * tw)


# ---------------------------------------------------------------- HUD


def hud(ctx, t, alpha, scene_idx, scene_name, total, marks, sections):
    if alpha <= 0.002:
        return
    m = 36
    corner_frame(ctx, m, m, W - 2 * m, H - 2 * m, BONE, 0.30 * alpha, 22, 1.3)
    draw_text(ctx, "NEUTRINO", m + 34, m + 30, "grotesk", 14, BONE, 0.75 * alpha, tracking=3.0)
    draw_text(ctx, "/  TECHNICAL BRIEF", m + 150, m + 30, "mono", 11, BONE, 0.55 * alpha, tracking=2.5)
    secs = int(t)
    frac = int((t - secs) * 100)
    tc = f"T+{secs // 60:02d}:{secs % 60:02d}.{frac:02d}"
    draw_text(ctx, tc, W - m - 34, m + 30, "mono", 12, BONE, 0.6 * alpha, tracking=2.0, align="right")
    blink = 0.5 + 0.5 * math.sin(t * 4.0)
    fill_circle(ctx, W - m - 200, m + 26, 3.2, AMBER, alpha * (0.35 + 0.65 * blink))
    if scene_idx:
        draw_text(ctx, f"{scene_idx:02d}", m + 34, H - m - 26, "grotesk", 14, AMBER, 0.9 * alpha)
        draw_text(ctx, f"/ {sections:02d}   {scene_name}", m + 62, H - m - 26, "mono", 11, BONE, 0.55 * alpha, tracking=2.5)
    # Film progress rail.
    x0, x1, y = W - m - 34 - 420, W - m - 34, H - m - 30
    line(ctx, x0, y, x1, y, BONE, 0.14 * alpha, 1.0)
    p = clamp(t / total)
    line(ctx, x0, y, x0 + (x1 - x0) * p, y, AMBER, 0.75 * alpha, 1.4)
    for mk in marks:
        xx = x0 + (x1 - x0) * mk / total
        line(ctx, xx, y - 4, xx, y + 4, BONE, 0.3 * alpha, 1.0)
    # Right-edge ruler.
    rx = W - m - 6
    for k in range(41):
        yy = 340 + k * 10
        ln = 9 if k % 5 == 0 else 4
        line(ctx, rx - ln, yy, rx, yy, BONE, 0.16 * alpha, 1.0, cap=cairo.LINE_CAP_BUTT)
    my = 340 + 400 * (0.5 + 0.5 * math.sin(t * 0.37))
    line(ctx, rx - 18, my, rx - 2, my, AMBER, 0.7 * alpha, 1.4)


# ---------------------------------------------------------------- text blocks


def title_block(ctx, t, idx, en, entries, t0=0.2, t_out=None):
    """Section label, then one or more (start, end, headline, sub) entries."""
    out = 1.0 if t_out is None else 1 - smooth(seg(t, t_out, t_out + 0.45))
    if out <= 0:
        return
    p = seg(t, t0, t0 + 0.7)
    grow = smooth(seg(t, t0, t0 + 0.5))
    line(ctx, TX - 24, 166, TX - 24, 166 + 140 * grow, AMBER, 0.85 * out, 2.0, cap=cairo.LINE_CAP_BUTT)
    draw_text(ctx, idx, TX, 186, "grotesk", 19, AMBER, out, mode="decode", p=p, t=t, hot=AMBER_HOT)
    draw_text(ctx, en, TX + 40, 185, "mono", 12, AMBER, 0.9 * out, tracking=3.6, mode="decode", p=p, t=t, hot=AMBER_HOT)
    for start, end, head, sub in entries:
        if t < start or t > end:
            continue
        fade = 1 - smooth(seg(t, end - 0.45, end))
        shift = -14 * smooth(seg(t, end - 0.45, end))
        a = out * fade
        n = reveal_len(head)
        ph = seg(t, start + 0.15, start + 0.5 + 0.035 * n)
        draw_text(ctx, head, TX + shift, 254, "cn_b", 50, BONE, a, mode="rise", p=ph, rise=14, hot=AMBER_HOT)
        if sub:
            ps = seg(t, start + 0.55, start + 0.95 + 0.018 * reveal_len(sub))
            draw_text(ctx, sub, TX + shift, 302, "cn", 23, DIM, a, mode="rise", p=ps, rise=8)


def caption(ctx, t, text, start, end, y=CAPTION_Y, size=25, color=BONE, alpha=0.9):
    if t < start or t > end:
        return
    a = alpha * (1 - smooth(seg(t, end - 0.4, end)))
    p = seg(t, start, start + 0.35 + 0.02 * reveal_len(text))
    draw_text(ctx, text, W / 2, y, "cn", size, color, a, align="center", mode="rise", p=p, rise=8)


def label(ctx, t, cn, en, x, y, start, end=None, align="left", color=BONE, en_color=DIM, size=20, alpha=1.0, text=None):
    """Chinese label with a small mono English tag under it.

    The English cut shows one sentence-case label instead: `text`, or the tag.
    """
    if t < start or (end is not None and t > end):
        return
    if EN:
        cn, en = text or sentence(en or ""), None
    a = alpha * (1 if end is None else 1 - smooth(seg(t, end - 0.35, end)))
    p = seg(t, start, start + 0.3 + 0.03 * reveal_len(cn))
    if cn:
        draw_text(ctx, cn, x, y, "cn", size, color, a, align=align, mode="rise", p=p, rise=6)
    if en:
        pe = seg(t, start + 0.1, start + 0.6)
        draw_text(ctx, en, x, y + size * 0.95 + 4, "mono", 10.5, en_color, a * 0.9, tracking=2.4, align=align, mode="decode", p=pe, t=t)


def tag_pair(ctx, cn, tag, x, y, size, color, alpha, text=None, tag_color=DIM):
    """Inline label followed by its mono tag; the English cut shows one label."""
    if EN:
        return draw_text(ctx, text or sentence(tag), x, y, "cn", size, color, alpha)
    w = draw_text(ctx, cn, x, y, "cn", size, color, alpha)
    draw_text(ctx, tag, x + w + 12, y - 1, "mono", 10.5 if size >= 18 else 9.5, tag_color, alpha, tracking=2.2)
    return w + 12 + text_width(tag, "mono", 10.5 if size >= 18 else 9.5, 2.2)


def mono(ctx, t, text, x, y, start, end=None, size=11, color=DIM, alpha=1.0, align="left", tracking=2.4):
    if t < start or (end is not None and t > end):
        return
    a = alpha * (1 if end is None else 1 - smooth(seg(t, end - 0.35, end)))
    draw_text(ctx, text, x, y, "mono", size, color, a, tracking=tracking, align=align, mode="decode", p=seg(t, start, start + 0.5), t=t)


def env(t, start, end, fin=0.4, fout=0.4):
    return window(t, start, end, fin, fout)


def faint_rule(ctx, x0, x1, y, a=1.0):
    line(ctx, x0, y, x1, y, FAINT, 0.6 * a, 1.0, cap=cairo.LINE_CAP_BUTT)
