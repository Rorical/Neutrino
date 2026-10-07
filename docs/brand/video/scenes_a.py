"""Intro, 01 state transition, 02 one function, 03 state commitment."""

from __future__ import annotations

import math

import cairo
import numpy as np

import logo
from common import CAPTION_Y, caption, label, mono, tag_pair, title_block
from lang import EN, tr
from gfx import (
    AMBER,
    AMBER_HOT,
    BONE,
    CYAN,
    DIM,
    FAINT,
    GRAPHITE,
    H,
    RED,
    TAU,
    W,
    WHITE,
    bezier_partial,
    bezier_point,
    check_mark,
    circle,
    clamp,
    corner_frame,
    cross_mark,
    dashed_circle,
    draw_formula,
    draw_text,
    text_width,
    ease_in,
    ease_io,
    ease_out,
    ease_out_back,
    fill_circle,
    fill_rect,
    halo,
    lerp,
    line,
    mix,
    particle,
    partial_line,
    rgba,
    seg,
    smooth,
    stroke_circle,
    stroke_rect,
    tick_ring,
    traced_polygon,
    traced_rect,
    window,
)

# =====================================================================
# Intro: detector wall -> ring -> mark -> lockup
# =====================================================================

INTRO = dict(
    p_start=4.5,
    p_end=6.3,
    land=6.3,
    wall_out=(6.0, 7.5),
    callouts=(7.4, 9.2),
    move=(9.0, 10.2),
    word=(9.85, 10.9),
    tagline=10.8,
)
MARK_S = 2.0
RING_PX = logo.R * MARK_S


def _particle_u(t):
    k = ease_out(seg(t, INTRO["p_start"], INTRO["p_end"]), 2.2)
    return lerp(470.0, logo.PART[0], k)


def _cross_time():
    target = logo.C + logo.R / math.sqrt(2)  # u where the trajectory meets the ring
    ts = np.linspace(INTRO["p_start"], INTRO["p_end"], 2000)
    for t in ts:
        if _particle_u(t) <= target:
            return float(t)
    return INTRO["p_end"]


INTRO["cross"] = _cross_time()
FUSE = 0.55


class PMTWall:
    def __init__(self):
        sp = 0.86
        pts = []
        for j in range(-24, 25):
            for i in range(-40, 41):
                pts.append((i * sp + (sp / 2 if j % 2 else 0.0), j * sp * 0.866))
        self.P = np.array(pts)
        rng = np.random.default_rng(7)
        self.r1 = rng.random(len(pts))
        self.r2 = rng.random(len(pts))
        self.ph = rng.random(len(pts)) * TAU
        self.rad = 0.34

    def project(self, zc, yaw, pitch, f=880.0):
        x, y = self.P[:, 0], self.P[:, 1]
        x1 = x * math.cos(yaw)
        z1 = x * math.sin(yaw)
        y1 = y * math.cos(pitch) - z1 * math.sin(pitch)
        z2 = y * math.sin(pitch) + z1 * math.cos(pitch)
        Z = z2 + zc
        sc = f / Z
        return W / 2 + x1 * sc, H / 2 + y1 * sc, sc


_wall = None


def _pmt_wall():
    global _wall
    if _wall is None:
        _wall = PMTWall()
    return _wall


def draw_wall(ctx, t):
    wall = _pmt_wall()
    wa = smooth(seg(t, 0.5, 1.6)) * (1 - smooth(seg(t, *INTRO["wall_out"])))
    if wa <= 0.002:
        return
    zc = 17.0 - 3.6 * ease_io(seg(t, 0.0, 7.6))
    yaw = 0.24 - 0.10 * seg(t, 0, 7.6)
    sx, sy, sc = wall.project(zc, yaw, -0.13)
    r = wall.rad * sc
    vis = (sx > -40) & (sx < W + 40) & (sy > -40) & (sy < H + 40)

    dx, dy = sx - W / 2, sy - H / 2
    d = np.hypot(dx, dy)
    # Calibration sweep.
    wave = (t - 0.9) / 2.0 * 1300
    online = np.clip((wave - d) / 120, 0, 1)
    cal = np.exp(-(((d - wave) / 70) ** 2)) * 0.35 * (t < 3.4)

    # Cherenkov ring: lights from the crossing point around to the gap edges.
    tc = INTRO["cross"]
    ang = np.arctan2(dy, dx)
    delta = np.abs((ang - logo.CROSS + math.pi) % TAU - math.pi)  # 0..pi
    span = (logo.CROSS + TAU) - logo.GAP_START  # 166 degrees
    t_hit = tc + delta / span * FUSE
    tau_ = t - t_hit
    on = (tau_ > 0) & (delta <= span + 0.05)
    env = np.where(on, (1 - np.exp(-np.maximum(tau_, 0) * 22)) * np.exp(-np.maximum(tau_, 0) * 0.35), 0.0)
    prox = np.exp(-(((d - RING_PX) / 24.0) ** 2))
    fuzz = np.exp(-(((d - RING_PX + 22) / 45.0) ** 2)) * (wall.r2 > 0.72) * 0.45
    ring_lit = env * (prox * (0.55 + 0.45 * wall.r1) + fuzz)
    ring_lit *= 0.82 + 0.18 * np.sin(t * 31 + wall.ph)

    # Light leaking from the passing particle.
    pu = _particle_u(t)
    moving = INTRO["p_start"] <= t <= INTRO["p_end"] + 0.3
    if moving:
        px = W / 2 + (pu - logo.C) * MARK_S
        py = H / 2 + (256 - pu - logo.C) * MARK_S
        trail = np.exp(-((np.hypot(sx - px, sy - py) / 42.0) ** 2)) * 0.35
    else:
        trail = 0.0
    # Dark-count noise.
    noise = np.maximum(0, np.sin(t * (1.1 + 1.6 * wall.r1) + wall.ph)) ** 400 * 0.5 * (wall.r2 > 0.55)

    lit = np.clip(cal + ring_lit + trail + noise * online, 0, 1.3)
    depth = np.clip((sc - sc[vis].min()) / max(1e-6, sc[vis].max() - sc[vis].min()), 0, 1)

    ctx.save()
    ctx.set_line_width(1.0)
    for i in np.nonzero(vis)[0]:
        x, y, rr = sx[i], sy[i], r[i]
        on_i = online[i]
        li = lit[i]
        shade = 0.55 + 0.45 * depth[i]
        rgba(ctx, (0.05, 0.046, 0.041), wa * on_i * 0.95)
        circle(ctx, x, y, rr)
        ctx.fill()
        cath = mix((0.26, 0.17, 0.07), AMBER_HOT, clamp(li))
        rgba(ctx, cath, wa * shade * (0.18 * on_i + 0.82 * clamp(li)))
        circle(ctx, x, y, rr * 0.64)
        ctx.fill()
        rgba(ctx, AMBER, wa * shade * (0.06 + 0.22 * on_i + 0.4 * clamp(li)))
        circle(ctx, x, y, rr)
        ctx.stroke()
        # Specular glint on the glass.
        rgba(ctx, AMBER_HOT, wa * shade * on_i * 0.10)
        ctx.new_sub_path()
        ctx.arc(x, y, rr * 0.8, math.pi * 1.1, math.pi * 1.45)
        ctx.stroke()
        if li > 0.12:
            halo(ctx, x, y, rr * 3.2, AMBER, wa * 0.45 * clamp(li))
            if li > 0.6:
                fill_circle(ctx, x, y, rr * 0.28, WHITE, wa * (li - 0.6))
    ctx.restore()


BOOT = [
    (0.25, "NEUTRINO  //  DETECTOR ARRAY", DIM),
    (0.75, "PHOTOSENSOR GRID .......... ONLINE", DIM),
    (1.25, "TRIGGER ................... ARMED", DIM),
]


def draw_boot(ctx, t):
    a = 1 - smooth(seg(t, 7.2, 7.8))
    if a <= 0:
        return
    x, y = 86, 112
    for k, (t0, s, c) in enumerate(BOOT):
        if t >= t0:
            draw_text(ctx, s, x, y + k * 22, "mono", 12, c, 0.85 * a, tracking=2.2, mode="decode", p=seg(t, t0, t0 + 0.6), t=t, hot=AMBER)
    if t >= 4.2:
        blink = 1.0 if (t > 5.0 or int(t * 8) % 2 == 0) else 0.25
        draw_text(ctx, "EVENT DETECTED  ν", x, y + 3 * 22 + 10, "mono_m", 12, AMBER, a * blink, tracking=2.2, mode="decode", p=seg(t, 4.2, 4.6), t=t)
    if t >= INTRO["cross"] + 0.6:
        draw_text(ctx, "TRACK RECONSTRUCTED  ·  RING FIT", x, y + 4 * 22 + 10, "mono", 12, DIM, 0.85 * a, tracking=2.2, mode="decode", p=seg(t, INTRO["cross"] + 0.6, INTRO["cross"] + 1.2), t=t)
    corner_frame(ctx, 36, 36, W - 72, H - 72, (0.925, 0.905, 0.86), 0.22 * a * smooth(seg(t, 0.1, 0.8)), 22, 1.3)


def _callout(ctx, t, t0, anchor, elbow, end, cn, en, align, text):
    a = window(t, t0, INTRO["callouts"][1], 0.3, 0.45)
    if a <= 0:
        return
    p1 = ease_out(seg(t, t0, t0 + 0.35))
    p2 = ease_out(seg(t, t0 + 0.3, t0 + 0.6))
    stroke_circle(ctx, *anchor, 5, AMBER, a * 0.9, 1.3)
    fill_circle(ctx, *anchor, 1.8, AMBER_HOT, a)
    partial_line(ctx, anchor[0], anchor[1], elbow[0], elbow[1], p1, AMBER, 0.65 * a, 1.1)
    if p1 >= 1:
        partial_line(ctx, elbow[0], elbow[1], end[0], end[1], p2, AMBER, 0.65 * a, 1.1)
    tx = end[0] + (10 if align == "left" else -10)
    label(ctx, t, cn, en, tx, end[1] + 7, t0 + 0.45, None, align=align, size=22, alpha=a, text=text)


def scene_intro(ctx, t, dur):
    draw_wall(ctx, t)
    draw_boot(ctx, t)

    tc = INTRO["cross"]
    pu = _particle_u(t) if t >= INTRO["p_start"] else None
    traj = clamp((logo.TRAJ0[0] - (pu if pu is not None else 999)) / (logo.TRAJ0[0] - logo.TRAJ1[0]))
    fuse = ease_out(seg(t, tc, tc + FUSE), 2)
    ring_a = 0.35 + 0.65 * smooth(seg(t, tc + 0.3, tc + 1.5))

    mv = ease_io(seg(t, *INTRO["move"]))
    L = 1.15
    ox, oy, icx, icy, isc = logo.lockup_layout(W / 2, 505, L)
    cx = lerp(W / 2, icx, mv)
    cy = lerp(H / 2, icy, mv)
    s = lerp(MARK_S, isc, mv)

    pulse = seg(t, INTRO["land"], INTRO["land"] + 1.1)
    comet = 1 - smooth(seg(t, INTRO["p_end"] - 0.9, INTRO["p_end"]))
    pre_a = smooth(seg(t, INTRO["p_start"], INTRO["p_start"] + 0.25))
    if t >= tc:
        logo.draw_mark(ctx, cx, cy, s, ring=fuse, traj=0, part_u=None, alpha=ring_a)
    logo.draw_mark(ctx, cx, cy, s, ring=0, traj=traj, part_u=pu, part_a=pre_a, pulse=pulse if t > INTRO["land"] else 0, comet=comet)
    if t >= tc and t < tc + 1.2:
        # Flash where the particle meets the ring.
        k = seg(t, tc, tc + 1.2)
        hx = cx + logo.R / math.sqrt(2) * s
        hy = cy - logo.R / math.sqrt(2) * s
        halo(ctx, hx, hy, 160 * (0.4 + k), AMBER_HOT, 0.55 * (1 - k) ** 2)

    # Callouts explaining the mark.
    c0 = INTRO["callouts"][0]
    a200 = math.radians(200)
    _callout(ctx, t, c0, (W / 2 + RING_PX * math.cos(a200), H / 2 + RING_PX * math.sin(a200)), (650, 420), (470, 420), "环 · 共识边界", "RING — CONSENSUS BOUNDARY", "right", "Ring — consensus boundary")
    _callout(ctx, t, c0 + 0.25, (W / 2 + 72 * MARK_S, H / 2 - 72 * MARK_S), (1240, 300), (1300, 300), "轨迹 · 穿过，而不重演", "TRAJECTORY — PASSES THROUGH", "left", "Trajectory — passes through, never replays")
    _callout(ctx, t, c0 + 0.5, (W / 2 - 78 * MARK_S, H / 2 + 78 * MARK_S), (700, 820), (560, 820), "粒子 · 恒定大小的证明", "PARTICLE — CONSTANT-SIZE PROOF", "right", "Particle — a constant-size proof")

    # Wordmark and tagline.
    wr = seg(t, *INTRO["word"])
    logo.draw_wordmark(ctx, ox, oy, L, reveal=ease_io(wr))
    tg = INTRO["tagline"]
    if t >= tg:
        draw_text(ctx, tr("证明穿过整段历史，而不必重演它", "A proof passes through the whole history — without replaying it."), W / 2, 728, "cn", 30, BONE, 0.92, align="center", mode="rise", p=seg(t, tg, tg + 0.9), rise=10)
        draw_text(ctx, "A PROOF-AWARE LAYER-1 BLOCKCHAIN", W / 2, 772, "mono", 12, DIM, 0.85, tracking=5, align="center", mode="decode", p=seg(t, tg + 0.4, tg + 1.1), t=t)


# =====================================================================
# 01  The problem: replay vs. proof
# =====================================================================

PROB = dict(swap=7.4, replay=(2.8, 6.9), proofs=8.0, checks=9.7)
NODE_X = [250 + k * 205 for k in range(8)]
NODE_Y = 600


def _fmt(n):
    return f"{n:,}"


def scene_problem(ctx, t, dur):
    title_block(
        ctx,
        t,
        "01",
        "STATE TRANSITION",
        [
            (0.2, PROB["swap"], tr("验证一条链，通常意味着重放它", "Verifying a chain usually means replaying it"), tr("新节点从创世开始，把每一个区块重新执行一遍。", "A new node starts at genesis and re-executes every block.")),
            (PROB["swap"] + 0.3, dur, tr("每一次状态转移，都附带一个证明", "Every state transition carries a proof"), tr("验证者检查证明，而不是重新执行——成本不再随历史增长。", "Verifiers check the proof instead of re-executing — the cost stops growing with history.")),
        ],
        t_out=dur - 0.6,
    )
    r0, r1 = PROB["replay"]
    xs = lerp(NODE_X[0], NODE_X[-1] + 110, seg(t, r0, r1))
    replay_fade = 1 - smooth(seg(t, PROB["swap"] - 0.4, PROB["swap"] + 0.4))
    proof_mode = smooth(seg(t, PROB["proofs"], PROB["proofs"] + 0.8))

    # Chain of states.
    for k, x in enumerate(NODE_X):
        ap = ease_out_back(seg(t, 0.8 + k * 0.12, 1.2 + k * 0.12))
        if ap <= 0:
            continue
        if k < len(NODE_X) - 1:
            pa = ease_out(seg(t, 0.95 + k * 0.12, 1.35 + k * 0.12))
            x2 = NODE_X[k + 1]
            lit_arrow = (xs > x2 - 28) * replay_fade
            col = mix(FAINT, AMBER, lit_arrow * 0.8)
            partial_line(ctx, x + 30, NODE_Y, x2 - 30, NODE_Y, pa, col, 0.9, 1.4)
            if pa >= 1:
                line(ctx, x2 - 38, NODE_Y - 6, x2 - 30, NODE_Y, col, 0.9, 1.4)
                line(ctx, x2 - 38, NODE_Y + 6, x2 - 30, NODE_Y, col, 0.9, 1.4)
                draw_formula(ctx, "F", (x + x2) / 2, NODE_Y - 14, 22, DIM, 0.8 * (1 - proof_mode), align="center")
                # Proof particles ride the arrows.
                pp = ease_out_back(seg(t, PROB["proofs"] + k * 0.1, PROB["proofs"] + 0.4 + k * 0.1))
                if pp > 0:
                    mx = (x + x2) / 2
                    particle(ctx, mx, NODE_Y - 22, 5.5 * pp, CYAN, clamp(pp))
                    draw_formula(ctx, f"π_{k}", mx, NODE_Y - 44, 21, CYAN, 0.85 * clamp(pp), align="center")
        lit = 0.0
        if xs > x and t < PROB["swap"] + 0.5:
            tp = r0 + (x - NODE_X[0]) / (NODE_X[-1] + 110 - NODE_X[0]) * (r1 - r0)
            lit = (0.35 + 0.65 * math.exp(-(t - tp) * 1.5)) * replay_fade
        ok = smooth(seg(t, PROB["checks"] + k * 0.08, PROB["checks"] + 0.3 + k * 0.08))
        ring_col = mix(mix(BONE, AMBER, lit), CYAN, ok * 0.85)
        fill_circle(ctx, x, NODE_Y, 24 * ap, mix((0.06, 0.055, 0.05), (0.35, 0.22, 0.08), lit), 1.0)
        stroke_circle(ctx, x, NODE_Y, 24 * ap, ring_col, 0.9, 1.6)
        if lit > 0.5:
            halo(ctx, x, NODE_Y, 70, AMBER, 0.35 * (lit - 0.5))
        check_mark(ctx, x, NODE_Y, 16, ok, CYAN, 1.0, 2.2)
        draw_formula(ctx, f"S_{k}", x, NODE_Y + 62, 26, BONE, 0.85 * clamp(ap), align="center")
    if t > 1.9:
        draw_text(ctx, "⋯", NODE_X[-1] + 105, NODE_Y + 9, "math", 30, DIM, 0.7 * smooth(seg(t, 1.9, 2.3)), align="center")

    # Replay scanner.
    sa = window(t, r0 - 0.2, PROB["swap"], 0.3, 0.4)
    if sa > 0:
        g = cairo.LinearGradient(xs - 60, 0, xs, 0)
        g.add_color_stop_rgba(0, *AMBER, 0)
        g.add_color_stop_rgba(1, *AMBER, 0.18 * sa)
        ctx.set_source(g)
        ctx.rectangle(xs - 60, NODE_Y - 70, 60, 140)
        ctx.fill()
        line(ctx, xs, NODE_Y - 74, xs, NODE_Y + 74, AMBER_HOT, sa, 2.0)
        draw_text(ctx, "REPLAY", xs, NODE_Y - 84, "mono", 11, AMBER, sa, tracking=2.5, align="center")

    # Cost meter.
    ma = smooth(seg(t, 2.4, 3.0)) * (1 - smooth(seg(t, dur - 0.9, dur - 0.4)))
    if ma > 0:
        y = 800
        x0, x1 = NODE_X[0], NODE_X[-1]
        line(ctx, x0, y, x1, y, FAINT, 0.7 * ma, 6, cap=cairo.LINE_CAP_BUTT)
        retract = ease_io(seg(t, PROB["swap"] + 0.2, PROB["swap"] + 1.4))
        replay_w = clamp((xs - x0) / (x1 - x0)) * (x1 - x0)
        w = lerp(replay_w, 34, retract)
        col = mix(AMBER, CYAN, retract)
        line(ctx, x0, y, x0 + w, y, col, ma, 6, cap=cairo.LINE_CAP_BUTT)
        if retract < 0.5:
            tag_pair(ctx, "重放成本", "REPLAY COST", x0, y - 24, 20, BONE, ma * (1 - retract * 2))
            n = int(10 ** (seg(t, r0, r1) * 6.62))
            draw_text(ctx, f"BLOCKS REPLAYED  {_fmt(n)}", x1, y - 24, "mono_m", 13, AMBER, ma * (1 - retract * 2), tracking=1.5, align="right")
            draw_formula(ctx, "∝ n", x1 + 24, y + 9, 26, AMBER, ma * (1 - retract * 2) * seg(t, r0 + 0.5, r0 + 1.0))
        else:
            k = (retract - 0.5) * 2
            tag_pair(ctx, "验证成本", "VERIFY COST", x0, y - 24, 20, BONE, ma * k)
            draw_formula(ctx, "O(1)", x0 + 52, y + 10, 28, CYAN, ma * k)
            draw_text(ctx, tr("与历史长度无关", "independent of history length"), x1, y - 24, "cn", 20, CYAN, ma * k, align="right")

    # Formulas.
    fa = 1 - smooth(seg(t, PROB["swap"] - 0.4, PROB["swap"]))
    draw_formula(ctx, "S_{n+1} = F(S_n, B_n)", W / 2, 455, 42, BONE, fa, align="center", wipe=ease_io(seg(t, 1.3, 2.2)))
    fb = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    draw_formula(
        ctx,
        "\\rm{Verify}(π_n) = 1  ⇒  S_n = F(⋯F(F(S_0, B_0), B_1)⋯, B_{n−1})",
        W / 2,
        455,
        34,
        BONE,
        fb,
        align="center",
        wipe=ease_io(seg(t, PROB["proofs"] + 0.5, PROB["proofs"] + 1.7)),
        scan=CYAN,
    )
    caption(ctx, t, tr("一条链，就是同一个函数 F 的反复作用。", "A chain is one function F, applied again and again."), 2.3, PROB["swap"] - 0.2)
    caption(ctx, t, tr("证明 π 把“我执行过了”变成一个任何人都能快速检查的数学事实。", "A proof π turns “I executed it” into a mathematical fact anyone can check quickly."), PROB["checks"], dur - 0.5)


# =====================================================================
# 02  One transition function, two compilations
# =====================================================================

ONE = dict(core=0.9, branches=1.8, boxes=2.4, trace=(3.4, 7.0), poly=(7.0, 8.0), commit=(8.0, 8.7), travel=(8.7, 9.5), same=10.3, formula=11.0)
CORE = (430, 615)
UP = (800, 410, 380, 120)
LO = (800, 676, 380, 190)
GRID_X, GRID_Y, CELL, COLS, ROWS = 832, 742, 16, 20, 5


def _curve_y(u):
    """A smooth 'polynomial' through the trace, u in [0, 1] -> row coordinate."""
    return 2.0 + 1.35 * math.sin(u * 5.1 + 0.6) + 0.55 * math.sin(u * 11.3 + 2.0)


_trng = np.random.default_rng(3)
TRACE = np.zeros((ROWS, COLS))
for _c in range(COLS):
    cy = _curve_y((_c + 0.5) / COLS)
    for _r in range(ROWS):
        TRACE[_r, _c] = math.exp(-(((_r - cy) / 0.9) ** 2)) * 0.8 + _trng.random() * 0.25


def scene_onefunc(ctx, t, dur):
    title_block(ctx, t, "02", "ONE TRANSITION FUNCTION", [(0.2, dur, tr("状态转移函数，只写一次", "The transition function is written once"), tr("同一份逻辑编译到两端：普通执行，与可验证计算。", "One codebase, compiled for ordinary execution and for verifiable computation."))], t_out=dur - 0.6)
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    cx, cy = CORE

    # Core.
    pc = ease_out(seg(t, ONE["core"], ONE["core"] + 0.9))
    traced_polygon(ctx, cx, cy, 92, pc, BONE, 0.9 * out, 1.6)
    if pc > 0:
        rot = t * 0.35
        dashed_circle(ctx, cx, cy, 122, 6, 10, rot, AMBER, 0.45 * pc * out, 1.2)
        tick_ring(ctx, cx, cy, 138, 72, 4, -rot * 0.6, BONE, 0.25 * pc * out, 1.0, major=6, major_ln=9)
        halo(ctx, cx, cy, 160, AMBER, 0.10 * pc * out)
        draw_formula(ctx, "F", cx - 2, cy + 26, 80, BONE, pc * out, align="center")
        label(ctx, t, "状态转移函数", "STATE TRANSITION FUNCTION", cx, cy + 190, ONE["core"] + 0.6, None, align="center", alpha=out)

    # Branches.
    pb = ease_io(seg(t, ONE["branches"], ONE["branches"] + 1.0))
    up_path = ((cx + 92, cy), (640, cy), (680, UP[1] + UP[3] / 2), (UP[0], UP[1] + UP[3] / 2))
    lo_path = ((cx + 92, cy), (640, cy), (680, LO[1] + LO[3] / 2), (LO[0], LO[1] + LO[3] / 2))
    bezier_partial(ctx, *up_path, pb, BONE, 0.55 * out, 1.3)
    bezier_partial(ctx, *lo_path, pb, BONE, 0.55 * out, 1.3)

    # Boxes.
    pbox = ease_out(seg(t, ONE["boxes"], ONE["boxes"] + 0.8))
    traced_rect(ctx, *UP, pbox, BONE, 0.7 * out, 1.2)
    traced_rect(ctx, *LO, pbox, BONE, 0.7 * out, 1.2)
    label(ctx, t, "普通执行", "EXECUTE", UP[0] + 18, UP[1] + 34, ONE["boxes"] + 0.4, None, size=22, alpha=out)
    label(ctx, t, "可验证计算", "PROVE", LO[0] + 18, LO[1] + 34, ONE["boxes"] + 0.5, None, size=22, alpha=out)

    # Fast path: chips and pulses.
    if t > ONE["boxes"] + 0.6:
        ca = smooth(seg(t, ONE["boxes"] + 0.6, ONE["boxes"] + 1.2)) * out
        chips = (tr("模拟", "Simulate"), tr("查询", "Query"), tr("出块", "Produce"))
        widths = [text_width(c, "cn", 16) + 22 for c in chips]
        x = UP[0] + UP[2] - 18 - sum(widths) - 10 * (len(chips) - 1)
        for k, chip in enumerate(chips):
            flick = 0.5 + 0.5 * math.sin(t * 9 + k * 2.1)
            stroke_rect(ctx, x, UP[1] + 62, widths[k], 30, AMBER, ca * (0.35 + 0.4 * flick), 1.0)
            draw_text(ctx, chip, x + widths[k] / 2, UP[1] + 84, "cn", 16, BONE, ca, align="center")
            x += widths[k] + 10
        for k in range(6):
            u = ((t * 1.6 + k / 6) % 1.0)
            px, py = bezier_point(*up_path, u)
            fill_circle(ctx, px, py, 2.6, AMBER_HOT, ca * math.sin(u * math.pi))
    # Fast output arrives early.
    oy_up = UP[1] + UP[3] / 2
    oy_lo = LO[1] + LO[3] / 2
    pu = ease_out(seg(t, 3.6, 4.1))
    partial_line(ctx, UP[0] + UP[2], oy_up, 1330, oy_up, pu, BONE, 0.55 * out, 1.3)
    if t > 4.0:
        draw_formula(ctx, "r′ =", 1352, oy_up + 9, 28, BONE, out)
        draw_text(ctx, "9c4e·d02b·a71f", 1416, oy_up + 8, "mono_m", 20, AMBER, out, tracking=1.0, mode="decode", p=seg(t, 4.0, 4.7), t=t, hot=AMBER_HOT)

    # Proving path: trace -> polynomial -> commitment -> pi.
    t0, t1 = ONE["trace"]
    squash = ease_in(seg(t, *ONE["commit"]), 2)
    gx_right = GRID_X + COLS * CELL
    if t > t0 and squash < 1:
        ga = (1 - squash) * out
        for c in range(COLS):
            tc = t0 + c * (t1 - t0 - 0.4) / COLS
            fillp = smooth(seg(t, tc, tc + 0.25))
            if fillp <= 0:
                continue
            x = gx_right - (gx_right - (GRID_X + c * CELL)) * (1 - squash)
            fresh = math.exp(-max(0.0, t - tc) * 3.0)
            dim_after = 1 - 0.55 * smooth(seg(t, *ONE["poly"]))
            for r in range(ROWS):
                v = TRACE[r, c]
                col = mix(GRAPHITE, AMBER, clamp(v))
                fill_rect(ctx, x + 1.5, GRID_Y + r * CELL + 1.5, (CELL - 3) * (1 - squash), CELL - 3, col, ga * fillp * (0.25 + 0.75 * v) * dim_after)
                if fresh > 0.05:
                    fill_rect(ctx, x + 1.5, GRID_Y + r * CELL + 1.5, (CELL - 3) * (1 - squash), CELL - 3, AMBER_HOT, ga * fresh * 0.6 * v)
        pp = ease_io(seg(t, *ONE["poly"]))
        if pp > 0:
            rgba(ctx, AMBER_HOT, ga)
            ctx.set_line_width(2.2)
            n = 80
            for k in range(int(n * pp) + 1):
                u = k / n
                x = gx_right - (gx_right - (GRID_X + u * COLS * CELL)) * (1 - squash)
                y = GRID_Y + (_curve_y(u) + 0.5) * CELL
                if k == 0:
                    ctx.move_to(x, y)
                else:
                    ctx.line_to(x, y)
            ctx.stroke()
    if squash > 0:
        ghost = 0.10 * smooth(seg(t, ONE["commit"][1], ONE["commit"][1] + 0.6)) * out
        for c in range(COLS):
            for r in range(ROWS):
                stroke_rect(ctx, GRID_X + c * CELL + 1.5, GRID_Y + r * CELL + 1.5, CELL - 3, CELL - 3, AMBER, ghost * (0.6 + TRACE[r, c]), 0.8)
    stages = [("TRACE", t0, t1), ("POLYNOMIAL", *ONE["poly"]), ("COMMIT", *ONE["commit"]), ("π", ONE["commit"][1], 99)]
    if t > t0 - 0.3:
        sx = GRID_X
        for k, (name, a0, a1) in enumerate(stages):
            active = 1.0 if a0 <= t < a1 else 0.0
            done = 1.0 if t >= a1 else 0.0
            col = AMBER if active else (BONE if done else DIM)
            key = "mono" if name != "π" else "math"
            wdt = draw_text(ctx, name, sx, LO[1] + LO[3] - 16, key, 11 if name != "π" else 15, col, out * (0.5 + 0.5 * max(active, done)), tracking=2.0)
            sx += wdt + 14
            if k < 3:
                draw_text(ctx, "→", sx, LO[1] + LO[3] - 16, "math", 13, DIM, out * 0.7)
                sx += 24
    # Pi emerges and travels.
    if t > ONE["commit"][0] + 0.3:
        k = ease_out_back(seg(t, ONE["commit"][0] + 0.3, ONE["commit"][1]))
        tv = ease_io(seg(t, *ONE["travel"]))
        px = lerp(gx_right, 1342, tv)
        py = lerp(GRID_Y + 2.5 * CELL, oy_lo, tv)
        if tv > 0:
            partial_line(ctx, LO[0] + LO[2], oy_lo, 1330, oy_lo, tv, BONE, 0.55 * out, 1.3)
        particle(ctx, px, py, 6.5 * k, CYAN, clamp(k) * out)
        if t > ONE["travel"][1]:
            draw_formula(ctx, "π", px, py - 18, 22, CYAN, out * smooth(seg(t, ONE["travel"][1], ONE["travel"][1] + 0.3)), align="center")
    if t > ONE["travel"][1]:
        draw_formula(ctx, "r′ =", 1372, oy_lo + 9, 28, BONE, out)
        draw_text(ctx, "9c4e·d02b·a71f", 1436, oy_lo + 8, "mono_m", 20, AMBER, out, tracking=1.0, mode="decode", p=seg(t, ONE["travel"][1], ONE["travel"][1] + 0.7), t=t, hot=AMBER_HOT)

    # Identity.
    sa = smooth(seg(t, ONE["same"], ONE["same"] + 0.6)) * out
    if sa > 0:
        xx = 1560
        line(ctx, xx, oy_up + 28, xx, oy_lo - 28, AMBER, 0.5 * sa, 1.2)
        fill_rect(ctx, xx - 26, (oy_up + oy_lo) / 2 - 26, 52, 52, (0.03, 0.03, 0.03), sa)
        draw_formula(ctx, "≡", xx, (oy_up + oy_lo) / 2 + 16, 46, AMBER_HOT, sa, align="center")
        halo(ctx, xx, (oy_up + oy_lo) / 2, 70, AMBER, 0.25 * sa * (1 - seg(t, ONE["same"], ONE["same"] + 1.5)))
        label(ctx, t, "结果一致", "IDENTICAL BY CONSTRUCTION", xx + 44, (oy_up + oy_lo) / 2 + 8, ONE["same"] + 0.2, None, size=20, alpha=out)

    draw_formula(
        ctx,
        "\\rm{Verify}(π; r, r′, \\rm{txs}) = 1  ⟺  r′ = F(r, \\rm{txs})",
        W / 2,
        CAPTION_Y,
        36,
        BONE,
        out,
        align="center",
        wipe=ease_io(seg(t, ONE["formula"], ONE["formula"] + 1.2)),
        scan=CYAN,
    )
    caption(ctx, t, tr("执行路径负责速度；证明路径把同一次计算压缩成一个可检查的 π。", "The execution path is fast; the proving path compresses the same computation into a checkable π."), 4.4, ONE["formula"] - 0.3)


# =====================================================================
# 03  State commitment: an authenticated tree
# =====================================================================

STATE = dict(leaves=(0.9, 2.0), hash=(2.0, 3.8), touch=4.2, path=(5.0, 6.4), write=8.0, ripple=(8.6, 10.2), absent=11.0, probe=12.8)
DEPTH = 5
NLEAF = 2**DEPTH
TREE_X0, TREE_X1, ROOT_Y, LEAF_Y = 420, 1500, 380, 850
TOUCH = (5, 18, 19)
ABSENT = 27
PROBE = 11


def node_xy(level, i):
    span = (TREE_X1 - TREE_X0) / 2**level
    return TREE_X0 + (i + 0.5) * span, ROOT_Y + level * (LEAF_Y - ROOT_Y) / DEPTH


def _path(leaf):
    return {(lv, leaf >> (DEPTH - lv)) for lv in range(DEPTH + 1)}


PATH_NODES = set().union(*[_path(i) for i in TOUCH])
SIBLINGS = {(lv, i ^ 1) for (lv, i) in PATH_NODES if lv > 0} - PATH_NODES
ABSENT_PATH = _path(ABSENT)
ABSENT_SIB = {(lv, i ^ 1) for (lv, i) in ABSENT_PATH if lv > 0} - ABSENT_PATH - PATH_NODES


def scene_state(ctx, t, dur):
    title_block(ctx, t, "03", "STATE COMMITMENT", [(0.2, dur, tr("整个世界状态，收敛为一个根", "The whole world state converges to one root"), tr("认证状态树：任何一片叶子改变，根都随之改变。", "An authenticated tree: change any leaf and the root changes with it."))], t_out=dur - 0.6)
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    h0, h1 = STATE["hash"]
    focus = smooth(seg(t, STATE["path"][0], STATE["path"][1]))
    ripple0, ripple1 = STATE["ripple"]
    absent_on = smooth(seg(t, STATE["absent"], STATE["absent"] + 0.8))

    def level_time(lv):
        return h0 + (DEPTH - lv) * (h1 - h0) / DEPTH

    def node_weight(lv, i):
        if (lv, i) in PATH_NODES or (lv, i) in SIBLINGS:
            return 1.0
        if absent_on > 0 and ((lv, i) in ABSENT_PATH or (lv, i) in ABSENT_SIB):
            return lerp(0.22, 1.0, absent_on)
        return lerp(1.0, 0.22, focus)

    # Edges.
    for lv in range(DEPTH):
        for i in range(2**lv):
            px, py = node_xy(lv, i)
            for c in (2 * i, 2 * i + 1):
                cx_, cy_ = node_xy(lv + 1, c)
                pe = ease_out(seg(t, level_time(lv + 1), level_time(lv + 1) + 0.35))
                if pe <= 0:
                    continue
                w = min(node_weight(lv, i), node_weight(lv + 1, c))
                on_path = (lv + 1, c) in PATH_NODES and (lv, i) in PATH_NODES
                on_abs = (lv + 1, c) in ABSENT_PATH and (lv, i) in ABSENT_PATH
                col = AMBER if on_path and focus > 0 else BONE
                a = (0.28 + (0.45 if on_path else 0.0) * focus) * w
                if on_abs and absent_on > 0 and not on_path:
                    rgba(ctx, BONE, 0.65 * absent_on * out)
                    ctx.set_line_width(1.2)
                    ctx.set_dash([4, 5])
                    ctx.move_to(cx_, cy_)
                    ctx.line_to(lerp(cx_, px, pe), lerp(cy_, py, pe))
                    ctx.stroke()
                    ctx.set_dash([])
                    continue
                partial_line(ctx, cx_, cy_, px, py, pe, col, a * out, 1.2 if not on_path else 1.8)
                # Hash pulse travelling up during construction.
                if 0 < pe < 1:
                    fill_circle(ctx, lerp(cx_, px, pe), lerp(cy_, py, pe), 2.2, AMBER_HOT, 0.9 * out)

    # Ripple of recomputation along touched paths.
    if ripple0 <= t <= ripple1 + 0.3:
        for leaf in TOUCH:
            u = seg(t, ripple0, ripple1) * DEPTH
            lv = DEPTH - int(min(u, DEPTH - 1e-6))
            f = u - int(min(u, DEPTH - 1e-6))
            ax, ay = node_xy(lv, leaf >> (DEPTH - lv))
            bx, by = node_xy(lv - 1, leaf >> (DEPTH - lv + 1))
            particle(ctx, lerp(ax, bx, f), lerp(ay, by, f), 3.2, AMBER_HOT, out * (1 - seg(t, ripple1, ripple1 + 0.3)), 0.6)

    # Nodes.
    for lv in range(DEPTH + 1):
        for i in range(2**lv):
            x, y = node_xy(lv, i)
            if lv == DEPTH:
                pa = ease_out_back(seg(t, STATE["leaves"][0] + i * 0.03, STATE["leaves"][0] + 0.25 + i * 0.03))
            else:
                pa = ease_out_back(seg(t, level_time(lv) + 0.3, level_time(lv) + 0.55))
            if pa <= 0:
                continue
            w = node_weight(lv, i) * out
            touched = lv == DEPTH and i in TOUCH
            on_path = (lv, i) in PATH_NODES
            sib = (lv, i) in SIBLINGS
            size = (9 if lv == DEPTH else (13 if lv == 0 else 6)) * pa
            col = BONE
            fill = (0.06, 0.055, 0.05)
            if on_path and focus > 0:
                col = mix(BONE, AMBER, focus)
            if touched:
                ta = smooth(seg(t, STATE["touch"], STATE["touch"] + 0.4))
                fill = mix(fill, (0.45, 0.28, 0.08), ta)
                col = mix(col, AMBER_HOT, ta)
                flash = math.exp(-max(0.0, t - STATE["write"]) * 4) if t > STATE["write"] else 0
                if flash > 0.02:
                    halo(ctx, x, y, 40, AMBER_HOT, 0.6 * flash * out)
            if t > ripple0 and on_path:
                u = seg(t, ripple0, ripple1) * DEPTH
                passed = (DEPTH - lv) <= u
                if passed:
                    fl = math.exp(-max(0.0, t - (ripple0 + (DEPTH - lv) / DEPTH * (ripple1 - ripple0))) * 3)
                    if fl > 0.02:
                        halo(ctx, x, y, 36, AMBER_HOT, 0.6 * fl * out)
            ctx.save()
            ctx.translate(x, y)
            if lv != DEPTH:
                ctx.rotate(math.pi / 4)
            fill_rect(ctx, -size / 2, -size / 2, size, size, fill, w)
            stroke_rect(ctx, -size / 2, -size / 2, size, size, col, w * 0.9, 1.3)
            ctx.restore()
            if sib and focus > 0:
                stroke_circle(ctx, x, y, size + 7, BONE, 0.7 * focus * out, 1.0)
    # Absent leaf.
    if absent_on > 0:
        x, y = node_xy(DEPTH, ABSENT)
        dashed_circle(ctx, x, y, 15, 3, 3, t * 0.5, BONE, 0.9 * absent_on * out, 1.1)
        draw_formula(ctx, "∅", x, y + 44, 24, BONE, absent_on * out, align="center")
        label(ctx, t, "不存在，也要证明", "ABSENCE IS PROVEN TOO", x + 30, y + 52, STATE["absent"] + 0.3, None, size=18, alpha=out)

    # Root label.
    rx, ry = node_xy(0, 0)
    ra = smooth(seg(t, h1, h1 + 0.5)) * out
    if ra > 0:
        halo(ctx, rx, ry, 90, AMBER, 0.22 * ra)
        changed = smooth(seg(t, ripple1 - 0.1, ripple1 + 0.3))
        draw_formula(ctx, "r", rx + 30, ry + 10, 34, BONE, ra * (1 - changed))
        draw_formula(ctx, "r′", rx + 30, ry + 10, 34, AMBER_HOT, ra * changed)
        if changed < 0.5:
            draw_text(ctx, "0x3f9a·61d0·c2e1", rx + 76, ry + 8, "mono", 15, DIM, ra, tracking=1.0, mode="decode", p=seg(t, h1, h1 + 0.7), t=t)
        else:
            draw_text(ctx, "0xb71d·08e4·09fa", rx + 76, ry + 8, "mono_m", 15, AMBER, ra, tracking=1.0, mode="decode", p=seg(t, ripple1, ripple1 + 0.7), t=t)
        mono(ctx, t, "STATE ROOT", rx - 34, ry + 6, h1 + 0.2, None, 10.5, DIM, out, align="right")

    # Probe: an unwitnessed read is refused.
    p0 = STATE["probe"]
    if t > p0:
        stop_lv = 3
        pts = [node_xy(lv, PROBE >> (DEPTH - lv)) for lv in range(stop_lv + 1)]
        fa = out * (1 - smooth(seg(t, dur - 1.4, dur - 0.9)))
        k = ease_out(seg(t, p0, p0 + 0.9)) * stop_lv
        hit = smooth(seg(t, p0 + 0.9, p0 + 1.1))
        rgba(ctx, RED, 0.85 * fa)
        ctx.set_line_width(2.0)
        ctx.move_to(*pts[0])
        for j in range(stop_lv):
            f = clamp(k - j)
            if f <= 0:
                break
            ctx.line_to(lerp(pts[j][0], pts[j + 1][0], f), lerp(pts[j][1], pts[j + 1][1], f))
        ctx.stroke()
        if hit < 1:
            j = min(int(k), stop_lv - 1)
            f = clamp(k - j)
            fill_circle(ctx, lerp(pts[j][0], pts[j + 1][0], f), lerp(pts[j][1], pts[j + 1][1], f), 3.5, RED, fa)
        sx_, sy_ = pts[-1]
        lx, ly = node_xy(DEPTH, PROBE)
        if hit > 0:
            cross_mark(ctx, sx_, sy_, 10, RED, hit * fa, 2.6)
            halo(ctx, sx_, sy_, 60, RED, 0.5 * hit * fa * math.exp(-(t - p0 - 1.0) * 2))
            ctx.set_dash([3, 4])
            stroke_circle(ctx, lx, ly, 15, RED, 0.8 * hit * fa, 1.2)
            ctx.set_dash([])
            label(ctx, t, "未见证的读取：拒绝", "UNWITNESSED READ — REJECTED", lx, ly + 52, p0 + 1.0, None, align="center", color=RED, size=18, alpha=fa)

    if t < STATE["write"] - 0.3:
        caption(ctx, t, tr("执行只携带被触及的叶子与它们的兄弟路径：这就是“见证”。", "Execution carries only the touched leaves and their sibling paths: the witness."), STATE["path"][0], STATE["write"] - 0.3)
    wa = smooth(seg(t, STATE["path"][1], STATE["path"][1] + 0.5)) * out
    if wa > 0:
        label(ctx, t, "见证大小", "WITNESS SIZE", 1580, 600, STATE["path"][1], None, size=18, alpha=out)
        draw_formula(ctx, "|w| = O(k · \\rm{log} N)", 1580, 680, 28, BONE, wa)
        draw_formula(ctx, "k = 3,  N = 2^{5}", 1580, 724, 22, DIM, wa)
    caption(ctx, t, tr("写入之后，只沿被改写的路径重新哈希，得到新根 r′。", "After the writes, only the rewritten paths are re-hashed, giving the new root r′."), STATE["write"], STATE["absent"] - 0.1)
    caption(ctx, t, tr("缺失的键要证明“不存在”；没有被见证的读取，计算直接拒绝。", "A missing key must be proven absent; any unwitnessed read is rejected outright."), STATE["absent"], dur - 0.5)
