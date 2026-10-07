"""The Neutrino mark, built from its construction rules, plus the outlined wordmark."""

from __future__ import annotations

import math
import re

import cairo

from gfx import BRAND, CYAN, ICE, TAU, VIOLET, WHITE, clamp, fill_circle, halo, lerp, stroke_circle

# 256-unit construction grid (docs/brand/README.md).
C = 128.0
R = 84.0
STROKE = 12.0
GAP_START = math.atan2(171.3 - C, 56.0 - C)  # ~149 degrees
GAP_END = math.atan2(200.0 - C, 84.7 - C) + TAU  # ~121 degrees, one turn on
CROSS = math.radians(-45.0)  # where the trajectory crosses the ring
TRAJ0 = (212.0, 44.0)
TRAJ1 = (74.0, 182.0)
PART = (50.0, 206.0)
PART_R = 11.0
HALO_R = 22.0

# Lockup: icon at translate(16 16) scale(0.875) inside a 751 x 256 box.
LOCKUP_W, LOCKUP_H = 751.0, 256.0
ICON_OFF, ICON_SCALE = 16.0, 0.875
WORD_X0, WORD_X1 = 272.0, 712.0


def _parse_wordmark():
    svg = (BRAND / "neutrino-logo-dark.svg").read_text()
    d = re.findall(r'<path fill="#E8F0FF" d="([^"]+)"', svg)[0]
    tokens = re.findall(r"[MLHVQZ]|-?\d+(?:\.\d+)?", d)
    ops = []
    i = 0
    cmd = None
    cur = (0.0, 0.0)
    start = cur
    while i < len(tokens):
        tok = tokens[i]
        if tok in "MLHVQZ":
            cmd = tok
            i += 1
            if cmd == "Z":
                ops.append(("Z",))
                cur = start
            continue
        if cmd == "M":
            cur = (float(tokens[i]), float(tokens[i + 1]))
            start = cur
            ops.append(("M", cur))
            i += 2
            cmd = "L"
        elif cmd == "L":
            cur = (float(tokens[i]), float(tokens[i + 1]))
            ops.append(("L", cur))
            i += 2
        elif cmd == "H":
            cur = (float(tokens[i]), cur[1])
            ops.append(("L", cur))
            i += 1
        elif cmd == "V":
            cur = (cur[0], float(tokens[i]))
            ops.append(("L", cur))
            i += 1
        elif cmd == "Q":
            q = (float(tokens[i]), float(tokens[i + 1]))
            e = (float(tokens[i + 2]), float(tokens[i + 3]))
            c1 = (cur[0] + 2 / 3 * (q[0] - cur[0]), cur[1] + 2 / 3 * (q[1] - cur[1]))
            c2 = (e[0] + 2 / 3 * (q[0] - e[0]), e[1] + 2 / 3 * (q[1] - e[1]))
            ops.append(("C", c1, c2, e))
            cur = e
            i += 4
    return ops


WORDMARK = _parse_wordmark()


def wordmark_path(ctx):
    for op in WORDMARK:
        if op[0] == "M":
            ctx.move_to(*op[1])
        elif op[0] == "L":
            ctx.line_to(*op[1])
        elif op[0] == "C":
            ctx.curve_to(*op[1], *op[2], *op[3])
        else:
            ctx.close_path()


def on_traj(u):
    """Point on the trajectory line v = 256 - u."""
    return (u, 256.0 - u)


def draw_mark(
    ctx,
    cx,
    cy,
    s,
    ring=1.0,
    traj=1.0,
    part_u=None,
    part_a=1.0,
    halo_a=1.0,
    alpha=1.0,
    ring_color=ICE,
    pulse=0.0,
    comet=0.0,
):
    """Draw the mark centred at screen (cx, cy) with s screen pixels per grid unit.

    ring: 0..1 fuse from the crossing point around to the gap edges.
    traj: 0..1 how much of the trajectory segment is drawn from its start.
    part_u: particle position along the trajectory (u coordinate); None hides it.
    pulse: 0..1 progress of a ripple leaving the particle.
    comet: strength of a motion tail behind the particle.
    """
    if alpha <= 0.002:
        return

    def P(u, v):
        return cx + (u - C) * s, cy + (v - C) * s

    ctx.save()
    ctx.set_line_cap(cairo.LINE_CAP_ROUND)
    ctx.set_line_width(STROKE * s)
    if ring > 0:
        ctx.set_source_rgba(*ring_color, alpha)
        span_cw = (GAP_END - (CROSS + TAU)) * ring
        span_ccw = ((CROSS + TAU) - GAP_START) * ring
        x, y = P(C, C)
        ctx.new_sub_path()
        ctx.arc(x, y, R * s, CROSS + TAU, CROSS + TAU + span_cw)
        ctx.stroke()
        ctx.new_sub_path()
        ctx.arc_negative(x, y, R * s, CROSS + TAU, CROSS + TAU - span_ccw)
        ctx.stroke()

    if traj > 0:
        u_end = lerp(TRAJ0[0], TRAJ1[0], clamp(traj))
        x0, y0 = P(*TRAJ0)
        x1, y1 = P(*on_traj(u_end))
        gx0, gy0 = P(*TRAJ0)
        gx1, gy1 = P(*PART)
        g = cairo.LinearGradient(gx0, gy0, gx1, gy1)
        g.add_color_stop_rgba(0, *VIOLET, alpha)
        g.add_color_stop_rgba(1, *CYAN, alpha)
        ctx.set_source(g)
        ctx.move_to(x0, y0)
        ctx.line_to(x1, y1)
        ctx.stroke()

    if part_u is not None and part_a > 0:
        px, py = P(*on_traj(part_u))
        a = alpha * part_a
        if comet > 0:
            tail = 90 * s * comet
            d = 1 / math.sqrt(2)
            g = cairo.LinearGradient(px, py, px + tail * d, py - tail * d)
            g.add_color_stop_rgba(0, *CYAN, 0.9 * a)
            g.add_color_stop_rgba(1, *CYAN, 0.0)
            ctx.set_source(g)
            ctx.set_line_width(PART_R * s * 1.1)
            ctx.move_to(px, py)
            ctx.line_to(px + tail * d, py - tail * d)
            ctx.stroke()
        fill_circle(ctx, px, py, HALO_R * s, CYAN, 0.22 * a * halo_a)
        fill_circle(ctx, px, py, PART_R * s, CYAN, a)
        halo(ctx, px, py, HALO_R * s * 3.2, CYAN, 0.25 * a * halo_a)
        fill_circle(ctx, px, py, PART_R * s * 0.42, WHITE, 0.8 * a)
        if pulse > 0:
            rr = HALO_R * s * (1 + 3.5 * pulse)
            stroke_circle(ctx, px, py, rr, CYAN, a * (1 - pulse) * 0.8, 2.0 * (1 - pulse) + 0.5)
    ctx.restore()


def lockup_layout(cx, cy, L):
    """Screen placement of the horizontal lockup centred at (cx, cy), scale L."""
    ox = cx - LOCKUP_W * L / 2
    oy = cy - LOCKUP_H * L / 2
    icon_cx = ox + (ICON_OFF + ICON_SCALE * C) * L
    icon_cy = oy + (ICON_OFF + ICON_SCALE * C) * L
    return ox, oy, icon_cx, icon_cy, ICON_SCALE * L


def draw_wordmark(ctx, ox, oy, L, reveal=1.0, alpha=1.0, color=ICE, scan=CYAN):
    if alpha <= 0.002 or reveal <= 0:
        return
    edge = WORD_X0 + (WORD_X1 - WORD_X0 + 10) * clamp(reveal)
    ctx.save()
    ctx.translate(ox, oy)
    ctx.scale(L, L)
    ctx.save()
    ctx.rectangle(0, 0, edge, LOCKUP_H)
    ctx.clip()
    wordmark_path(ctx)
    ctx.set_source_rgba(*color, alpha)
    ctx.fill()
    ctx.restore()
    if reveal < 1:
        g = cairo.LinearGradient(edge, 60, edge, 180)
        g.add_color_stop_rgba(0, *scan, 0)
        g.add_color_stop_rgba(0.5, *scan, 0.95 * alpha)
        g.add_color_stop_rgba(1, *scan, 0)
        ctx.set_source(g)
        ctx.rectangle(edge - 1.0, 60, 2.0, 120)
        ctx.fill()
    ctx.restore()
