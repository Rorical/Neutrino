"""04 consensus, 05 chunk proof, 06 accountability, 07 recursion, 08 pruning, outro."""

from __future__ import annotations

import math

import cairo
import numpy as np

import logo
from common import CAPTION_Y, TX, caption, label, mono, tag_pair, title_block
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
    arc_stroke,
    bezier_point,
    check_mark,
    clamp,
    corner_frame,
    dashed_circle,
    draw_formula,
    draw_text,
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
    padlock,
    particle,
    partial_line,
    polygon,
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
# 04  Chunk consensus
# =====================================================================

CONS = dict(
    wheel=(0.8, 2.4),
    cand=(2.0, 3.3),
    leader=(3.4, 4.6),
    propose=(4.6, 5.4),
    prevote=(5.6, 8.6),
    precommit=(9.2, 11.6),
    agg=(11.7, 12.5),
    inter=(12.8, 17.4),
    live=17.6,
)
WC = (1180.0, 610.0)
RV, R1, R2, R3 = 205.0, 258.0, 284.0, 336.0
NV = 19
_crng = np.random.default_rng(11)
STAKE = _crng.dirichlet(np.ones(NV) * 2.4)
_cum = np.concatenate([[0], np.cumsum(STAKE)])
A0 = -math.pi / 2 + TAU * _cum[:-1]
A1 = -math.pi / 2 + TAU * _cum[1:]
AMID = (A0 + A1) / 2
GAP = math.radians(0.7)
LEADER = 4
LEADER2 = 5  # missing in the liveness round
LEADER3 = 6
_small = [int(i) for i in np.argsort(STAKE) if i not in (LEADER, LEADER2, LEADER3)]
OFF_PV = {_small[1], _small[6], _small[9]}
OFF_PC = OFF_PV | {_small[4]}
PC_COL = (1.0, 0.80, 0.52)


def _votes(voters, t0, t1, seed):
    r = np.random.default_rng(seed)
    order = [int(i) for i in r.permutation(sorted(voters))]
    times = {}
    span = (t1 - t0) - 0.5
    for k, i in enumerate(order):
        times[i] = t0 + k * span / len(order) + r.uniform(0, 0.08)
    acc = 0.0
    cross = None
    for i in sorted(times, key=times.get):
        acc += STAKE[i]
        if cross is None and acc >= 2 / 3:
            cross = times[i] + 0.35
    return times, cross


PV_T, PV_CROSS = _votes(set(range(NV)) - OFF_PV, *CONS["prevote"], 21)
PC_T, PC_CROSS = _votes(set(range(NV)) - OFF_PC, *CONS["precommit"], 22)
NIL_T, NIL_CROSS = _votes(set(range(NV)) - {LEADER2} - set(_small[:1]), CONS["live"] + 1.5, CONS["live"] + 3.1, 23)
CONS["pv_cross"] = PV_CROSS
CONS["pc_cross"] = PC_CROSS
CONS["nil_cross"] = NIL_CROSS


def _pt(r, a):
    return WC[0] + r * math.cos(a), WC[1] + r * math.sin(a)


def _track_fill(times, t, travel=0.35, fill=0.25):
    """Per-validator fill fraction and summed arrived stake."""
    out = np.zeros(NV)
    for i, ti in times.items():
        out[i] = smooth(seg(t, ti + travel, ti + travel + fill))
    return out, float((out > 0.5) @ STAKE)


def _phase_bar(ctx, t, y, name_cn, name_en, frac, active, done, a, nil=False, name_text=None):
    col = AMBER if active else (BONE if done else DIM)
    fill_circle(ctx, TX + 4, y - 7, 4.5, col, a * (1.0 if active or done else 0.4))
    if active:
        halo(ctx, TX + 4, y - 7, 18, AMBER, 0.4 * a)
    tag_pair(ctx, name_cn, name_en, TX + 22, y, 22, BONE if (active or done) else DIM, a, text=name_text)
    if frac is None:
        return
    bx0, bx1, by = TX + 22, TX + 420, y + 22
    line(ctx, bx0, by, bx1, by, FAINT, 0.8 * a, 4, cap=cairo.LINE_CAP_BUTT)
    line(ctx, bx0, by, bx0 + (bx1 - bx0) * frac, by, BONE if nil else AMBER, a, 4, cap=cairo.LINE_CAP_BUTT)
    tx = bx0 + (bx1 - bx0) * 2 / 3
    ok = frac >= 2 / 3
    line(ctx, tx, by - 9, tx, by + 9, AMBER_HOT if ok else BONE, a * (1.0 if ok else 0.6), 1.4)
    draw_text(ctx, "2/3", tx, by + 26, "mono", 10.5, AMBER_HOT if ok else DIM, a, align="center", tracking=1)
    draw_text(ctx, f"{frac * 100:4.1f}%", bx1 + 14, by + 5, "mono_m", 13, AMBER if ok else BONE, a, tracking=1)


def scene_consensus(ctx, t, dur):
    title_block(
        ctx,
        t,
        "05",
        "CHUNK CONSENSUS",
        [
            (0.2, CONS["inter"][0], tr("区块成组，由三分之二权益共同签署", "Blocks form chunks, signed by two-thirds of stake"), tr("提议 → 预投票 → 预提交：两轮法定人数，缺一不可。", "Propose → prevote → precommit: two quorums, both required.")),
            (CONS["inter"][0] + 0.2, CONS["live"], tr("两个法定人数，必然相交", "Any two quorums must intersect"), tr("交集里的签名者若签了两次，就留下了可被证明的冲突。", "A signer in the intersection who signs twice leaves a provable conflict.")),
            (CONS["live"] + 0.2, dur, tr("领导者缺席，系统依然前进", "The leader is missing; the chain still moves"), tr("空票推进轮次，期限逐轮增长；已锁定的值不会被空票抹去。", "Nil votes advance the round and deadlines grow; nil votes never erase a locked value.")),
        ],
        t_out=dur - 0.6,
    )
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    cx, cy = WC
    inter = smooth(seg(t, CONS["inter"][0], CONS["inter"][0] + 0.6)) * (1 - smooth(seg(t, CONS["inter"][1] - 0.6, CONS["inter"][1])))
    live = t >= CONS["live"]
    reset = smooth(seg(t, CONS["live"], CONS["live"] + 0.6))
    dimw = 1 - 0.65 * inter

    # Wheel guide.
    pw = ease_out(seg(t, *CONS["wheel"]))
    if pw > 0:
        arc_stroke(ctx, cx, cy, RV, -math.pi / 2, -math.pi / 2 + TAU * pw, FAINT, 0.7 * out * dimw, 1.0)
        tick_ring(ctx, cx, cy, R3 + 30, 120, 3, 0, BONE, 0.12 * pw * out, 1.0, major=10, major_ln=7)

    pv_fill, pv_sum = _track_fill(PV_T, t)
    pc_fill, pc_sum = _track_fill(PC_T, t)
    if live:
        pv_fill *= 1 - reset
        pc_fill *= 1 - reset
    nil_fill, nil_sum = _track_fill(NIL_T, t)

    # Stake tracks.
    for i in range(NV):
        ap = smooth(seg(t, CONS["wheel"][0] + i * 0.05, CONS["wheel"][0] + 0.4 + i * 0.05))
        if ap <= 0:
            continue
        a0, a1 = A0[i] + GAP, A1[i] - GAP
        for R, f, col in ((R1, pv_fill[i], AMBER), (R2, pc_fill[i], PC_COL)):
            arc_stroke(ctx, cx, cy, R, a0, a0 + (a1 - a0) * ap, GRAPHITE, out, 9)
            if f > 0:
                arc_stroke(ctx, cx, cy, R, a0, a0 + (a1 - a0) * f, col, out * dimw, 9)
        if nil_fill[i] > 0:
            rgba(ctx, BONE, 0.85 * out)
            ctx.set_line_width(1.4)
            for R in (R1 - 4.5, R1 + 4.5):
                ctx.new_sub_path()
                ctx.arc(cx, cy, R, a0, a0 + (a1 - a0) * nil_fill[i])
                ctx.stroke()

    # Validators.
    for i in range(NV):
        ap = ease_out_back(seg(t, CONS["wheel"][0] + i * 0.05, CONS["wheel"][0] + 0.35 + i * 0.05))
        if ap <= 0:
            continue
        x, y = _pt(RV, AMID[i])
        r = (4.5 + 11 * math.sqrt(STAKE[i] / STAKE.max())) * ap
        offline = (i in (OFF_PV if t < CONS["precommit"][0] else OFF_PC) and CONS["prevote"][0] < t < CONS["live"]) or (live and i == LEADER2 and t > CONS["live"] + 0.9)
        col = BONE
        if live and i == LEADER2 and t > CONS["live"] + 0.9:
            col = RED
        fill_circle(ctx, x, y, r, (0.05, 0.048, 0.045), out)
        if offline:
            stroke_circle(ctx, x, y, r, col, 0.5 * out * dimw + (0.4 if col == RED else 0), 1.2)
        else:
            fill_circle(ctx, x, y, r * 0.55, col, 0.8 * out * dimw)
            stroke_circle(ctx, x, y, r, col, 0.7 * out * dimw, 1.2)

    # Candidate.
    c0, c1 = CONS["cand"]
    if t > c0:
        for k in range(4):
            sx, sy = 720, cy - 60 + k * 40
            u = ease_io(seg(t, c0 + k * 0.12, c1 - 0.3 + k * 0.08))
            if u < 1:
                particle(ctx, lerp(sx, cx, u), lerp(sy, cy, u), 4.5, CYAN, out * smooth(seg(t, c0 - 0.2 + k * 0.1, c0 + k * 0.1)))
        ph = ease_out(seg(t, c1 - 0.4, c1 + 0.3))
        sig = smooth(seg(t, CONS["agg"][0] + 0.2, CONS["agg"][1]))
        traced_polygon(ctx, cx, cy, 36, ph, CYAN, out * (1 - 0.5 * inter), 1.6)
        if ph > 0:
            halo(ctx, cx, cy, 80, CYAN, 0.18 * ph * out)
            draw_formula(ctx, "C", cx, cy + 11, 30, BONE, ph * out * (1 - sig) * (1 - reset), align="center")
            draw_formula(ctx, "σ", cx, cy + 10, 32, AMBER_HOT, out * sig * (1 - reset) * (1 - inter), align="center")
            if not live:
                mono(ctx, t, "CANDIDATE", cx, cy + 66, c1, CONS["agg"][0], 10, DIM, out * (1 - inter), align="center")

    # Leader selection: a fair rotation steps through indices.
    l0, l1 = CONS["leader"]
    arm_a = 0.0
    if t > l0 and t < CONS["inter"][0] + 0.3:
        k = ease_out(seg(t, l0, l1), 2)
        idx = min(LEADER, int(k * (LEADER + 1)))
        arm_a = window(t, l0, CONS["inter"][0] + 0.3, 0.2, 0.4) * out
        ang = AMID[idx]
        line(ctx, cx + 44 * math.cos(ang), cy + 44 * math.sin(ang), *_pt(RV - 22, ang), AMBER, 0.6 * arm_a, 1.3)
        x, y = _pt(RV, AMID[idx])
        stroke_circle(ctx, x, y, 22, AMBER_HOT, arm_a, 1.6)
        if t > l1:
            lx, ly = _pt(R3 + 64, AMID[LEADER])
            label(ctx, t, "轮值领导者", "ROUND LEADER", lx, ly, l1, CONS["inter"][0] + 0.3, align="left", size=18, alpha=out)
    if l0 < t < CONS["live"]:
        draw_formula(ctx, "ℓ(c, r) = \\rm{eligible}[(h(c) + r) \\rm{mod} n]", TX, 760, 26, DIM, window(t, l0 + 0.3, CONS["inter"][0], 0.4, 0.4) * out)
        mono(ctx, t, "EVERY ELIGIBLE VALIDATOR LEADS WITHIN ONE CYCLE", TX, 796, l0 + 0.5, CONS["inter"][0], 10, DIM, out)
    # Proposal broadcast.
    p0, p1 = CONS["propose"]
    if p0 < t < p1 + 0.6:
        k = seg(t, p0, p1 + 0.6)
        lx, ly = _pt(RV, AMID[LEADER])
        stroke_circle(ctx, lx, ly, 20 + 520 * ease_out(k), AMBER, 0.6 * (1 - k) * out, 1.5)
        partial_line(ctx, lx, ly, cx, cy, ease_out(seg(t, p0, p0 + 0.4)), AMBER_HOT, 0.8 * (1 - k) * out, 1.6)

    # Vote packets.
    def packets(times, t, col, hollow=False):
        for i, ti in times.items():
            u = seg(t, ti, ti + 0.35)
            if 0 < u < 1:
                x, y = _pt(RV, AMID[i])
                px, py = lerp(x, cx, ease_in(u, 2)), lerp(y, cy, ease_in(u, 2))
                if hollow:
                    stroke_circle(ctx, px, py, 3.6, col, out, 1.2)
                else:
                    fill_circle(ctx, px, py, 3.0, col, out)
                    halo(ctx, px, py, 14, col, 0.4 * out)

    if not live:
        packets(PV_T, t, AMBER)
        packets(PC_T, t, PC_COL)
    else:
        packets(NIL_T, t, BONE, hollow=True)

    # Threshold flashes.
    for tc_ in (PV_CROSS, PC_CROSS):
        if tc_ < t < tc_ + 1.0 and not live:
            k = seg(t, tc_, tc_ + 1.0)
            stroke_circle(ctx, cx, cy, 60 + 260 * ease_out(k), AMBER_HOT, 0.5 * (1 - k) * out, 2.0)

    # Aggregation: signatures collapse into one.
    g0, g1 = CONS["agg"]
    if g0 < t < g1 + 0.3:
        k = ease_in(seg(t, g0, g1), 2)
        for i in PC_T:
            x, y = _pt(RV, AMID[i])
            partial_line(ctx, x, y, cx, cy, 1.0, AMBER_HOT, 0.35 * (1 - k) * out, 1.0)
            fill_circle(ctx, lerp(x, cx, k), lerp(y, cy, k), 2.4, AMBER_HOT, out * (1 - seg(t, g1, g1 + 0.3)))
    if g1 < t < CONS["inter"][0] + 0.3:
        a = window(t, g1, CONS["inter"][0] + 0.3, 0.2, 0.4) * out
        label(ctx, t, "聚合签名 · 最终性证书", "AGGREGATE SIGNATURE · FINALITY CERTIFICATE", cx, cy + 92, g1, CONS["inter"][0] + 0.3, align="center", size=18, color=AMBER_HOT, alpha=out, text="Aggregate signature · finality certificate")
        halo(ctx, cx, cy, 120, AMBER, 0.3 * a * math.exp(-(t - g1) * 1.5))

    # Left panel: phase bars.
    pa = smooth(seg(t, 1.2, 1.8)) * out * (1 - inter * 0.85)
    if pa > 0:
        if not live:
            pv_frac, pc_frac = pv_sum, pc_sum
            nil_bar = False
        else:
            pv_frac, pc_frac = nil_sum, 0.0
            nil_bar = True
        act_prop = CONS["leader"][0] < t < CONS["prevote"][0]
        act_pv = CONS["prevote"][0] <= t < CONS["precommit"][0] or (live and t < NIL_CROSS + 0.5)
        act_pc = CONS["precommit"][0] <= t < CONS["agg"][1] and not live
        _phase_bar(ctx, t, 420, "提议", "PROPOSE", None, act_prop, t >= CONS["prevote"][0] and not live, pa)
        _phase_bar(ctx, t, 500, "预投票", "PREVOTE" if not live else "PREVOTE · NIL", pv_frac, act_pv, pv_frac >= 2 / 3, pa, nil=nil_bar, name_text="Prevote" if not live else "Prevote · nil")
        _phase_bar(ctx, t, 600, "预提交", "PRECOMMIT", pc_frac, act_pc, pc_frac >= 2 / 3, pa)

    # Quorum intersection.
    if inter > 0:
        i0 = CONS["inter"][0]
        q1 = ease_io(seg(t, i0 + 0.1, i0 + 0.9))
        q2 = ease_io(seg(t, i0 + 0.8, i0 + 1.6))
        ov = smooth(seg(t, i0 + 1.7, i0 + 2.4))
        a1s = -math.pi / 2
        a2s = a1s + TAU / 3
        span = TAU * 2 / 3
        if ov > 0:
            ctx.save()
            ctx.new_path()
            ctx.arc(cx, cy, R3 + 30, a2s, a1s + span)
            ctx.arc_negative(cx, cy, 70, a1s + span, a2s)
            ctx.close_path()
            rgba(ctx, AMBER, 0.12 * ov * inter * out)
            ctx.fill_preserve()
            ctx.clip()
            rgba(ctx, AMBER_HOT, 0.22 * ov * inter * out)
            ctx.set_line_width(1.0)
            for k in range(-40, 40):
                x = cx + k * 14
                ctx.move_to(x - 400, cy - 400)
                ctx.line_to(x + 400, cy + 400)
            ctx.stroke()
            ctx.restore()
        arc_stroke(ctx, cx, cy, R3, a1s, a1s + span * q1, AMBER, inter * out, 5)
        arc_stroke(ctx, cx, cy, R3 + 18, a2s, a2s + span * q2, BONE, inter * out, 5)
        if q1 > 0.9:
            x, y = _pt(R3 + 58, -math.pi / 6)
            draw_formula(ctx, "Q_1 ≥ 2/3", x, y, 28, AMBER, inter * out * smooth(seg(t, i0 + 0.8, i0 + 1.1)))
        if q2 > 0.9:
            x, y = _pt(R3 + 66, math.radians(205))
            draw_formula(ctx, "Q_2 ≥ 2/3", x, y, 28, BONE, inter * out * smooth(seg(t, i0 + 1.5, i0 + 1.8)), align="right")
        if ov > 0:
            draw_formula(ctx, "Q_1 ∩ Q_2", cx, cy + 128, 30, AMBER_HOT, ov * inter * out, align="center")
            draw_formula(ctx, "≥ 1/3", cx, cy + 166, 26, AMBER_HOT, ov * inter * out, align="center")
        draw_formula(ctx, "|Q_1 ∩ Q_2| ≥ 2/3 + 2/3 − 1 = 1/3", TX, 760, 30, BONE, inter * out, wipe=ease_io(seg(t, i0 + 2.2, i0 + 3.2)))
        caption(ctx, t, tr("两个结论若冲突，交集中必有人违规签名——这种冲突可以被证明，并被惩罚。", "If two outcomes conflict, someone in the intersection signed against the rules — provably, and punishably."), i0 + 2.8, CONS["inter"][1] - 0.2)

    # Liveness: missing leader, nil votes, certified round change.
    if live:
        L0 = CONS["live"]
        la = smooth(seg(t, L0 + 0.2, L0 + 0.8)) * out
        # Lock retained at the centre.
        padlock(ctx, cx, cy - 4, 26, AMBER_HOT, la)
        label(ctx, t, "已锁定的值", "LOCK RETAINED", cx, cy + 64, L0 + 0.5, None, align="center", size=17, color=AMBER_HOT, alpha=out)
        # Arm to the missing leader, then on to the next.
        step = 1.0 if t < L0 + 4.2 else 2.0
        ang = AMID[LEADER2] if step < 2 else AMID[LEADER3]
        line(ctx, cx + 44 * math.cos(ang), cy + 44 * math.sin(ang), *_pt(RV - 22, ang), AMBER, 0.6 * la, 1.3)
        x, y = _pt(RV, ang)
        stroke_circle(ctx, x, y, 22, RED if step < 2 else AMBER_HOT, la, 1.6)
        if step < 2:
            lx, ly = _pt(R3 + 60, AMID[LEADER2])
            label(ctx, t, "领导者缺席", "LEADER MISSING", lx, ly, L0 + 0.9, L0 + 4.2, size=18, color=RED, alpha=out)
        else:
            k = seg(t, L0 + 4.4, L0 + 5.4)
            stroke_circle(ctx, x, y, 20 + 520 * ease_out(k), AMBER, 0.6 * (1 - k) * out, 1.5)
            lx, ly = _pt(R3 + 60, AMID[LEADER2])
            label(ctx, t, "下一位领导者 · 携带轮次证书", "NEXT LEADER + ROUND-CHANGE CERTIFICATE", lx, ly, L0 + 4.3, None, size=18, alpha=out, text="Next leader + round-change certificate")
        if NIL_CROSS < t:
            k = seg(t, NIL_CROSS, NIL_CROSS + 1.0)
            stroke_circle(ctx, cx, cy, 60 + 260 * ease_out(k), BONE, 0.45 * (1 - k) * out, 1.6)
            draw_text(ctx, "ROUND  r → r + 1", cx, cy - RV - 112, "mono_m", 13, BONE, out * smooth(seg(t, NIL_CROSS, NIL_CROSS + 0.4)), tracking=3, align="center")
        # Growing deadlines.
        draw_formula(ctx, "T_r = T_0 + r · Δ", TX, 760, 30, BONE, la, wipe=ease_io(seg(t, L0 + 0.6, L0 + 1.4)))
        for r_ in range(4):
            yy = 800 + r_ * 26
            wdt = 90 + 46 * r_
            prog = seg(t, L0 + 0.8 + r_ * 0.9, L0 + 1.7 + r_ * 0.9) if r_ < 2 else 0.0
            draw_text(ctx, f"r={r_}", TX, yy + 5, "mono", 11, DIM, la, tracking=1)
            line(ctx, TX + 48, yy, TX + 48 + wdt, yy, FAINT, la, 5, cap=cairo.LINE_CAP_BUTT)
            if prog > 0:
                line(ctx, TX + 48, yy, TX + 48 + wdt * prog, yy, AMBER if r_ else BONE, la, 5, cap=cairo.LINE_CAP_BUTT)
        caption(ctx, t, tr("超时只产生空票，不能单独进入新一轮：新一轮需要带签名的轮次证书。", "A timeout only yields nil votes; entering a new round needs a signed round-change certificate."), L0 + 1.4, dur - 0.5)


# =====================================================================
# 05  Complete chunk proof
# =====================================================================

CHUNK = dict(engine=(0.8, 2.2), inputs=1.2, launch=2.6, spin=(7.6, 9.0), emit=(9.0, 9.8), card=(9.8, 11.4))
EC = (840.0, 625.0)
INPUTS = [
    ("π_1", tr("区块证明", "Block proofs"), "BLOCK PROOF", CYAN, 445),
    ("π_2", "", "", CYAN, 495),
    ("π_3", "", "", CYAN, 545),
    ("π_4", "", "", CYAN, 595),
    ("v", tr("出块者签名 · 随机资格", "Proposer signature · eligibility"), "PROPOSER · ELIGIBILITY", AMBER, 670),
    ("σ", tr("两轮法定人数", "Both quorums"), "BOTH QUORUMS", AMBER_HOT, 735),
    ("P", tr("轮值提议 · 轮次证书", "Leader proposal · round entry"), "LEADER PROPOSAL · ROUND ENTRY", BONE, 800),
]
LAUNCH = [CHUNK["launch"] + k * 0.62 for k in range(len(INPUTS))]
CHECKS = [
    (tr("每个区块证明 · 递归验证", "Every block proof, recursively"), "EVERY BLOCK PROOF, RECURSIVELY", LAUNCH[3] + 1.0),
    (tr("出块者签名 · 随机资格", "Proposer signature · eligibility"), "PROPOSER SIGNATURE · ELIGIBILITY", LAUNCH[4] + 1.0),
    (tr("预投票 / 预提交 ≥ 2/3", "Prevote / precommit ≥ 2/3"), "BOTH QUORUMS", LAUNCH[5] + 1.0),
    (tr("轮值提议 · 轮次证书", "Leader proposal · round entry"), "LEADER PROPOSAL · ROUND ENTRY", LAUNCH[6] + 1.0),
    (tr("验证者轮换 · 下一个种子", "Validator rotation · next seed"), "ROTATION · NEXT SEED", LAUNCH[6] + 1.6),
]
CHUNK["checks"] = [c[2] for c in CHECKS]


def _input_pos(k, t):
    """Screen position and alpha of input k along launch -> orbit -> absorb."""
    x0, y0 = 180.0, float(INPUTS[k][4])
    tl = LAUNCH[k]
    entry = (EC[0] - 150, EC[1])
    u = seg(t, tl, tl + 0.7)
    if u < 1:
        e = ease_in(u, 2)
        p = bezier_point((x0, y0), (420, y0), (560, EC[1]), entry, e)
        return p, 1.0
    v = seg(t, tl + 0.7, tl + 1.3)
    ang = math.pi + v * math.pi * 1.1
    r = 150 - 30 * v
    return (EC[0] + r * math.cos(ang), EC[1] + r * math.sin(ang)), 1 - v


def scene_chunk(ctx, t, dur):
    title_block(ctx, t, "07", "COMPLETE CHUNK PROOF", [(0.2, dur, tr("最终性，只有一条路", "Finality has exactly one path"), tr("完整的块组证明：递归验证全部区块证明与签名，输出一个紧凑边界。", "A complete chunk proof verifies every block proof and signature recursively, then outputs a compact boundary."))], t_out=dur - 0.6)
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    cx, cy = EC
    pe = ease_out(seg(t, *CHUNK["engine"]))
    absorbed = sum(1 for k in range(len(INPUTS)) if t > LAUNCH[k] + 1.3)
    s0, s1 = CHUNK["spin"]
    spin = ease_in(seg(t, s0, s1), 2)
    speed = 0.25 + 0.15 * absorbed + 3.5 * spin
    rot = t * 0.25 + (absorbed * 0.12) * t * 0.2 + spin * 6.0
    energy = 0.1 + 0.08 * absorbed + 0.6 * spin
    emit = seg(t, *CHUNK["emit"])
    if emit > 0:
        energy *= 1 - 0.6 * ease_out(emit)

    if pe > 0:
        halo(ctx, cx, cy, 240, AMBER, energy * 0.4 * out)
        arc_stroke(ctx, cx, cy, 150, -math.pi / 2, -math.pi / 2 + TAU * pe, AMBER, (0.55 + energy * 0.5) * out, 2.4)
        tick_ring(ctx, cx, cy, 166, 120, 4, rot, BONE, 0.3 * pe * out, 1.0, major=10, major_ln=10)
        dashed_circle(ctx, cx, cy, 126, 10, 8, -rot * 1.3, AMBER, 0.4 * pe * out, 1.2)
        for k in range(6):
            a0 = rot * 0.6 + k * TAU / 6
            arc_stroke(ctx, cx, cy, 196, a0, a0 + math.radians(38), BONE, 0.32 * pe * out, 3)
        fill_circle(ctx, cx, cy, 22 + 30 * energy, AMBER_HOT, 0.10 * pe * out)
        fill_circle(ctx, cx, cy, 5 + 10 * energy, WHITE, min(1.0, 0.25 + energy) * pe * out)
        mono(ctx, t, "RECURSIVE VERIFIER", cx, cy + 238, CHUNK["engine"][0] + 0.5, None, 10.5, DIM, out, align="center")

    # Inputs.
    for k, (sym, cn, en, col, y) in enumerate(INPUTS):
        ap = ease_out_back(seg(t, CHUNK["inputs"] + k * 0.1, CHUNK["inputs"] + 0.35 + k * 0.1))
        if ap <= 0:
            continue
        (px, py), a = _input_pos(k, t)
        if a > 0:
            if sym.startswith("π"):
                particle(ctx, px, py, 5.5 * ap, CYAN, a * out)
            elif sym == "σ":
                polygon(ctx, px, py, 10 * ap, 6, 0)
                rgba(ctx, col, a * out)
                ctx.set_line_width(1.6)
                ctx.stroke()
                fill_circle(ctx, px, py, 3, col, a * out)
            elif sym == "v":
                for j in range(3):
                    fill_circle(ctx, px - 8 + j * 8, py + (j % 2) * 4 - 2, 2.4 * ap, col, a * out)
            else:
                stroke_rect(ctx, px - 8 * ap, py - 10 * ap, 16 * ap, 20 * ap, col, a * out, 1.4)
            if t > LAUNCH[k] and a < 1:
                halo(ctx, px, py, 30, col, 0.4 * a * out)
        la = out * (1 - smooth(seg(t, LAUNCH[k], LAUNCH[k] + 0.3)) * 0.65)
        draw_formula(ctx, sym, 208, y + 9, 24, col, la * clamp(ap))
        if cn:
            draw_text(ctx, cn, 254, y + 8, "cn", 18, BONE, la * clamp(ap))
            if not EN:
                draw_text(ctx, en, 254, y + 28, "mono", 9.5, DIM, la * clamp(ap), tracking=2)
        if t > LAUNCH[k] + 1.1 and t < LAUNCH[k] + 1.6:
            kk = seg(t, LAUNCH[k] + 1.1, LAUNCH[k] + 1.6)
            stroke_circle(ctx, cx, cy, 30 + 120 * kk, col, 0.5 * (1 - kk) * out, 1.5)

    # Checklist.
    for k, (cn, en, tchk) in enumerate(CHECKS):
        y = 412 + k * 56
        ap = smooth(seg(t, 1.6 + k * 0.12, 2.0 + k * 0.12)) * out
        if ap <= 0:
            continue
        done = ease_out(seg(t, tchk, tchk + 0.35))
        stroke_rect(ctx, 1190, y - 17, 20, 20, AMBER if done > 0 else DIM, ap, 1.2)
        check_mark(ctx, 1200, y - 7, 14, done, AMBER_HOT, ap, 2.2)
        if 0 < done < 1:
            halo(ctx, 1200, y - 7, 34, AMBER, 0.5 * (1 - done) * ap)
        draw_text(ctx, cn, 1228, y, "cn", 20, BONE if done > 0 else DIM, ap)
        if not EN:
            draw_text(ctx, en, 1228, y + 21, "mono", 9.5, DIM, ap * 0.9, tracking=2)

    # Emission of the chunk proof.
    e0, e1 = CHUNK["emit"]
    if t > e0:
        k = ease_out(seg(t, e0, e1), 2)
        px, py = lerp(cx + 160, 1214, k), lerp(cy, 760, k)
        if k < 1:
            line(ctx, cx + 160, cy, px, py, CYAN, 0.45 * out * (1 - k), 2)
            stroke_circle(ctx, cx, cy, 160 + 300 * k, CYAN, 0.3 * (1 - k) * out, 2.0)
        particle(ctx, px, py, 8, CYAN, out, 1.3)
        draw_formula(ctx, "π_C", px, py - 22, 24, CYAN, out * smooth(seg(t, e1, e1 + 0.3)), align="center")

    # Boundary card.
    c0, c1 = CHUNK["card"]
    ca = smooth(seg(t, c0 - 0.3, c0 + 0.2)) * out
    if ca > 0:
        corner_frame(ctx, 1180, 700, 600, 200, BONE, 0.45 * ca, 14, 1.3)
        mono(ctx, t, "NEXT CONSENSUS BOUNDARY", 1250, 728, c0, None, 10.5, DIM, out)
        draw_formula(ctx, "B_{n+1} = ⟨h, \\rm{hash}, r, V, s′, A⟩", 1250, 785, 32, BONE, ca, wipe=ease_io(seg(t, c0, c0 + 0.9)), scan=CYAN)
        draw_formula(ctx, "s′ = H(s ‖ v_1 ‖ ⋯ ‖ v_k)", 1250, 838, 26, AMBER, ca, wipe=ease_io(seg(t, c0 + 0.6, c1)))
        mono(ctx, t, "HEIGHT · BLOCK · STATE · VALIDATORS · SEED · HISTORY", 1250, 876, c1 - 0.3, None, 9.5, DIM, out)

    caption(ctx, t, tr("块组证明不重新执行交易：区块证明已经证明的事实，不再证明第二次。", "The chunk proof never re-executes transactions: what block proofs established is not proven twice."), 2.6, 9.6)
    caption(ctx, t, tr("没有经过验证的完整证明，就没有最终性。", "No verified complete proof, no finality."), 11.6, dur - 0.5, color=BONE)


# =====================================================================
# 06  Accountability
# =====================================================================

ACC = dict(node=0.8, emit=(1.6, 2.6), detect=(3.2, 4.2), formula=3.6, capture=(4.6, 5.8), pev=6.0, travel=(6.4, 7.6), exec=(8.6, 10.2), slash=9.1, window=12.0)
VN = (400.0, 620.0)
CARD_U = (620, 452, 300, 86)
CARD_L = (620, 702, 300, 86)
CAPS = (1110.0, 620.0)
BLOCK = (1420, 395, 290, 450)


def _slot_rects():
    x, y, w, h = BLOCK
    mand = [(x + 20, y + 62 + k * 40, w - 40, 30) for k in range(3)]
    tx = [(x + 20, y + 232 + k * 34, w - 40, 24) for k in range(6)]
    return mand, tx


def scene_account(ctx, t, dur):
    title_block(ctx, t, "08", "ACCOUNTABILITY", [(0.2, dur, tr("作恶，会留下数学证据", "Misbehaviour leaves mathematical evidence"), tr("同一签名者、同一轮次、两条冲突消息——证据本身就是判决。", "Same signer, same round, two conflicting messages — the evidence is the verdict."))], t_out=dur - 0.6)
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    vx, vy = VN
    d0, d1 = ACC["detect"]
    guilty = smooth(seg(t, d0, d1))
    na = ease_out_back(seg(t, ACC["node"], ACC["node"] + 0.4))
    vcol = mix(BONE, RED, guilty)

    # Validator.
    if na > 0:
        stroke_circle(ctx, vx, vy, 32 * na, vcol, out, 1.8)
        fill_circle(ctx, vx, vy, 12 * na, vcol, 0.85 * out)
        if guilty > 0:
            halo(ctx, vx, vy, 90, RED, 0.35 * guilty * out * (0.7 + 0.3 * math.sin(t * 6)))
        draw_formula(ctx, "v", vx, vy + 70, 28, vcol, out * clamp(na), align="center")
        # Stake bar.
        s_cut = ease_out(seg(t, ACC["slash"], ACC["slash"] + 0.6))
        bx, by, bw = vx - 80, vy + 104, 160
        line(ctx, bx, by, bx + bw, by, FAINT, out, 7, cap=cairo.LINE_CAP_BUTT)
        keep = 1 - 0.32 * s_cut
        line(ctx, bx, by, bx + bw * keep, by, AMBER, out, 7, cap=cairo.LINE_CAP_BUTT)
        if s_cut > 0:
            fall = ease_in(seg(t, ACC["slash"] + 0.3, ACC["slash"] + 1.3), 2)
            fill_rect(ctx, bx + bw * keep, by - 3.5 + 60 * fall, bw * 0.32 * s_cut, 7, RED, out * (1 - fall))
            mono(ctx, t, "SLASHED", bx + bw + 14, by + 4, ACC["slash"] + 0.2, None, 10.5, RED, out)
        mono(ctx, t, "STAKE", bx, by - 12, ACC["node"] + 0.3, None, 9.5, DIM, out)
        lk = smooth(seg(t, ACC["slash"] + 0.5, ACC["slash"] + 0.9))
        if lk > 0:
            padlock(ctx, bx + 10, by + 40, 16, AMBER_HOT, lk * out)
            label(ctx, t, "提款冻结", "WITHDRAWAL HELD", bx + 30, by + 44, ACC["slash"] + 0.6, None, size=16, color=AMBER_HOT, alpha=out)

    # Two signed messages.
    e0, e1 = ACC["emit"]
    cap0, cap1 = ACC["capture"]
    cap = ease_in(seg(t, cap0, cap1), 2)
    for k, (card, val) in enumerate(((CARD_U, "x"), (CARD_L, "y"))):
        x, y, w, h = card
        pe = ease_out(seg(t, e0 + k * 0.25, e0 + 0.6 + k * 0.25))
        if pe <= 0:
            continue
        ax, ay = vx + 34, vy + (-12 if k == 0 else 12)
        partial_line(ctx, ax, ay, x, y + h / 2, pe, vcol, 0.55 * out * (1 - cap), 1.3)
        # Card moves into the capsule.
        mx = lerp(x, CAPS[0] - w * 0.1, cap)
        my = lerp(y, CAPS[1] - h * 0.1 + (k - 0.5) * 20 * (1 - cap), cap)
        sc = 1 - 0.8 * cap
        ca = out * (1 - smooth(seg(t, cap1 - 0.3, cap1)))
        ctx.save()
        ctx.translate(mx, my)
        ctx.scale(sc, sc)
        traced_rect(ctx, 0, 0, w, h, pe, mix(BONE, RED, guilty), 0.85 * ca, 1.3)
        if pe >= 1:
            draw_formula(ctx, f"⟨c, r, φ, {val}⟩", 22, h / 2 + 11, 30, BONE, ca)
            draw_formula(ctx, "σ_v", w - 22, h / 2 + 10, 26, AMBER, ca, align="right")
        ctx.restore()
    # Conflict bracket.
    if guilty > 0 and cap < 1:
        ba = guilty * out * (1 - cap)
        bx = CARD_U[0] + CARD_U[2] + 26
        y0_, y1_ = CARD_U[1] + CARD_U[3] / 2, CARD_L[1] + CARD_L[3] / 2
        line(ctx, bx - 10, y0_, bx, y0_, RED, ba, 1.6)
        line(ctx, bx - 10, y1_, bx, y1_, RED, ba, 1.6)
        partial_line(ctx, bx, y0_, bx, y1_, guilty, RED, ba, 1.6)
        draw_formula(ctx, "x ≠ y", bx + 16, (y0_ + y1_) / 2 + 10, 30, RED, ba)
    # Capsule and evidence proof.
    if t > cap0 - 0.2:
        ka = smooth(seg(t, cap0 - 0.2, cap0 + 0.3)) * out
        rot = t * 0.4
        traced_polygon(ctx, CAPS[0], CAPS[1], 64, 1.0, RED, 0.85 * ka, 1.6, rot=rot)
        traced_polygon(ctx, CAPS[0], CAPS[1], 78, 1.0, RED, 0.3 * ka, 1.0, rot=-rot)
        label(ctx, t, "证据证明", "EVIDENCE PROOF", CAPS[0], CAPS[1] + 120, cap0 + 0.2, None, align="center", size=18, alpha=out)
        inner = smooth(seg(t, cap1 - 0.2, cap1 + 0.4)) * out
        if inner > 0:
            draw_formula(ctx, "σ_v  σ′_v", CAPS[0], CAPS[1] - 4, 24, AMBER, inner * 0.8, align="center")
            draw_formula(ctx, "x ≠ y", CAPS[0], CAPS[1] + 30, 20, RED, inner * 0.9, align="center")
    mand, txs = _slot_rects()
    tv0, tv1 = ACC["travel"]
    if t > ACC["pev"]:
        k = ease_out_back(seg(t, ACC["pev"], ACC["pev"] + 0.4))
        m = ease_io(seg(t, tv0, tv1))
        tx, ty = mand[0][0] + 24, mand[0][1] + mand[0][3] / 2
        px, py = lerp(CAPS[0], tx, m), lerp(CAPS[1], ty, m) - math.sin(m * math.pi) * 60
        stroke_circle(ctx, px, py, 13 * k, RED, out * clamp(k), 1.6)
        particle(ctx, px, py, 6 * k, CYAN, out * clamp(k))
        if m == 0:
            draw_formula(ctx, "π_{ev}", px, py - 28, 24, CYAN, out * clamp(k), align="center")

    # Block with the mandatory queue ahead of ordinary transactions.
    bx, by, bw, bh = BLOCK
    ba = ease_out(seg(t, 5.2, 6.2))
    if ba > 0:
        traced_rect(ctx, bx, by, bw, bh, ba, BONE, 0.7 * out, 1.2)
        mono(ctx, t, "BLOCK", bx, by - 14, 5.4, None, 10.5, DIM, out)
        tag_pair(ctx, "强制队列", "MANDATORY FIFO", bx + 20, by + 44, 18, RED, out * ba, text="Mandatory queue (FIFO)")
        tag_pair(ctx, "普通交易", "TRANSACTIONS", bx + 20, by + 214, 18, AMBER, out * ba, text="Ordinary transactions")
        x0_, x1_ = ACC["exec"]
        scan_y = lerp(by + 50, by + bh - 10, seg(t, x0_, x1_))
        for k, (x, y, w, h) in enumerate(mand):
            filled = (k == 0 and t > tv1) or (k == 1 and t > tv1 + 0.4)
            done = t > x0_ and scan_y > y + h
            stroke_rect(ctx, x, y, w, h, RED, 0.5 * out * ba, 1.0)
            if filled:
                fill_rect(ctx, x + 2, y + 2, w - 4, h - 4, RED, (0.25 if done else 0.55) * out)
                draw_text(ctx, "OFFENCE → DEDUCTION" if k == 0 else "PENDING", x + 52, y + h / 2 + 4, "mono", 10, BONE, out * 0.9, tracking=1)
        for k, (x, y, w, h) in enumerate(txs):
            filled = t > 6.4 + k * 0.12
            done = t > x0_ and scan_y > y + h
            stroke_rect(ctx, x, y, w, h, AMBER, 0.35 * out * ba, 1.0)
            if filled:
                fill_rect(ctx, x + 2, y + 2, (w - 4) * (0.5 + 0.5 * ((k * 37) % 10) / 10), h - 4, AMBER, (0.18 if done else 0.4) * out)
        if x0_ < t < x1_ + 0.3:
            sa = out * (1 - seg(t, x1_, x1_ + 0.3))
            line(ctx, bx - 8, scan_y, bx + bw + 8, scan_y, AMBER_HOT, sa, 1.8)
            halo(ctx, bx + bw / 2, scan_y, 60, AMBER, 0.3 * sa)

    # Evidence window strip.
    w0 = ACC["window"]
    wa = smooth(seg(t, w0, w0 + 0.5)) * out
    if wa > 0:
        y = 846
        for k in range(10):
            x = 380 + k * 52
            cur = k == 9
            inwin = 1 <= k <= 8
            stroke_rect(ctx, x, y - 14, 36, 28, AMBER_HOT if cur else (BONE if inwin else FAINT), wa * (1 if inwin or cur else 0.6), 1.2)
            if inwin:
                fill_rect(ctx, x + 3, y - 11, 30, 22, AMBER, 0.18 * wa)
        k = ease_out(seg(t, w0 + 0.4, w0 + 1.0))
        xa, xb = 380 + 52 - 6, 380 + 8 * 52 + 36 + 6
        partial_line(ctx, xa, y + 26, xb, y + 26, k, AMBER, wa, 1.4)
        line(ctx, xa, y + 20, xa, y + 26, AMBER, wa * k, 1.4)
        line(ctx, xb, y + 20, xb, y + 26, AMBER, wa * k, 1.4)
        draw_text(ctx, tr("当前", "current"), 380 + 9 * 52 + 18, y - 24, "cn", 14, AMBER_HOT, wa, align="center")
        draw_text(ctx, tr("证据窗口：前 8 个块组 · 可向对等节点检索", "Evidence window: preceding 8 chunks · retrievable from peers"), (xa + xb) / 2, y + 54, "cn", 18, BONE, wa * k, align="center")

    draw_formula(
        ctx,
        "\\rm{Sig}_v(c, r, φ, x) ∧ \\rm{Sig}_v(c, r, φ, y) ∧ x ≠ y  ⇒  \\rm{Offence}(v)",
        W / 2,
        CAPTION_Y,
        32,
        BONE,
        out * (1 - smooth(seg(t, 9.8, 10.2))),
        align="center",
        wipe=ease_io(seg(t, ACC["formula"], ACC["formula"] + 1.2)),
        scan=RED,
    )
    caption(ctx, t, tr("每个区块先执行强制队列，再处理普通交易；待罚没的金额先冻结，无法提走。", "Every block runs the mandatory queue before ordinary transactions; amounts pending a penalty are frozen."), 10.3, 13.6)
    caption(ctx, t, tr("只有客观、可证明、未过期的违规才能进入队列；畸形的证明永远不能确立罪责。", "Only objective, provable, unexpired offences enter the queue; a malformed proof never establishes guilt."), 13.8, 17.2)
    caption(ctx, t, tr("签过名的共识消息在最近 8 个块组内被认证保存、建立索引，并可向对等节点检索。", "Signed consensus messages are authenticated, indexed and retrievable from peers within the recent eight-chunk window."), 17.4, dur - 0.5)


# =====================================================================
# 07  Recursive history
# =====================================================================

HIST = dict(chunks=0.8, step=0.2, light=(8.4, 9.6), grow=(11.5, 16.5))
NCH = 32  # chunks shown in real time
BATCH = 4  # chunks absorbed per fold on screen (the protocol allows up to 16)
GROW_EXTRA = 96  # chunks streamed during the time-lapse
CELL_X0, CELL_DX, CELL_Y = 250.0, 36.5, 862.0
LANE_Y = 742.0
X_MAX = CELL_X0 + NCH * CELL_DX + 22
FOLDS = (NCH + GROW_EXTRA) // BATCH


def chunk_time(k):
    if k < NCH:
        return HIST["chunks"] + k * HIST["step"]
    g0, g1 = HIST["grow"]
    u = (k - NCH + 1) / GROW_EXTRA
    return g0 + (g1 - g0 - 0.6) * u**0.5


def fold_time(g):
    return chunk_time(BATCH * g + BATCH - 1) + (0.35 if g < NCH // BATCH else 0.12)


FOLD_TIMES = [fold_time(g) for g in range(FOLDS)]
HIST["last_live_fold"] = fold_time(NCH // BATCH - 1)


def _latest_index(t):
    """Continuous index of the newest chunk on screen (drives the time-lapse scroll)."""
    g0, g1 = HIST["grow"]
    if t <= g0:
        return float(NCH - 1)
    return NCH - 1 + GROW_EXTRA * clamp((t - g0) / (g1 - g0 - 0.6)) ** 2


def _scroll(t):
    return max(0.0, CELL_X0 + (_latest_index(t) + 1) * CELL_DX + 22 - X_MAX)


def _cell_x(k, scroll):
    return CELL_X0 + k * CELL_DX - scroll


def _node_x(g, scroll):
    if g < 0:
        return CELL_X0 - 52 - scroll
    return _cell_x(BATCH * g + BATCH - 1, scroll) + 11


def _edge_fade(x):
    return clamp((x - (CELL_X0 - 70)) / 90)


def scene_history(ctx, t, dur):
    title_block(ctx, t, "10", "RECURSIVE HISTORY", [(0.2, dur, tr("整段历史，折叠成一个证明", "All of history, folded into one proof"), tr("每一次折叠，都把上一个证明连同新的块组证明一起吸收——大小始终不变。", "Each fold absorbs the previous proof together with new chunk proofs — the size never changes."))], t_out=dur - 0.6)
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    scroll = _scroll(t)
    done = [g for g in range(FOLDS) if t >= FOLD_TIMES[g]]
    g_last = done[-1] if done else -1
    grow = t > HIST["grow"][0]

    # Chunk proofs.
    for k in range(NCH + GROW_EXTRA):
        tk = chunk_time(k)
        if t < tk:
            break
        x = _cell_x(k, scroll)
        if x > X_MAX + 10 or x < CELL_X0 - 80:
            continue
        ef = _edge_fade(x)
        ap = ease_out_back(seg(t, tk, tk + (0.3 if k < NCH else 0.12)))
        absorbed = t >= FOLD_TIMES[k // BATCH] if k // BATCH < FOLDS else False
        stroke_rect(ctx, x, CELL_Y - 11, 22, 22, BONE, 0.45 * out * ef, 1.0)
        particle(ctx, x + 11, CELL_Y, 3.2 * ap, CYAN, out * clamp(ap) * ef * (0.45 if absorbed else 1.0), 0.5)
        if k % 4 == 0 and k < NCH:
            draw_formula(ctx, f"C_{{{k}}}", x + 11, CELL_Y + 40, 17, DIM, out * clamp(ap) * ef, align="center")

    # Genesis boundary: the chain's trusted start.
    ga = smooth(seg(t, 0.9, 1.4)) * out
    gx = _node_x(-1, scroll)
    if ga > 0 and gx > CELL_X0 - 120:
        gf = _edge_fade(gx + 60)
        ctx.save()
        ctx.translate(gx, LANE_Y)
        ctx.rotate(math.pi / 4)
        stroke_rect(ctx, -7, -7, 14, 14, BONE, 0.9 * ga * gf, 1.4)
        ctx.restore()
        draw_formula(ctx, "B_0", gx, LANE_Y - 22, 20, BONE, ga * gf, align="center")
        mono(ctx, t, "GENESIS", gx, LANE_Y + 30, 1.0, None, 9.5, DIM, out * gf, align="center")

    # Coverage bracket [0, b).
    if g_last >= 0:
        xa = max(CELL_X0 - 6 - scroll, CELL_X0 - 70)
        tf = FOLD_TIMES[g_last]
        prev_end = _cell_x(BATCH * g_last - 1, scroll) + 22 + 6 if g_last > 0 else xa
        new_end = _cell_x(BATCH * g_last + BATCH - 1, scroll) + 22 + 6
        xb = lerp(prev_end, new_end, ease_out(seg(t, tf, tf + 0.3)))
        y = 806
        line(ctx, xa, y, xb, y, CYAN, 0.55 * out, 1.4)
        line(ctx, xb, y - 7, xb, y + 3, CYAN, 0.7 * out, 1.4)
        if scroll < 40:
            line(ctx, xa, y - 7, xa, y + 3, CYAN, 0.7 * out, 1.4)
        else:
            draw_text(ctx, "←", xa - 4, y + 5, "math", 16, CYAN, 0.7 * out, align="right")

    # The fold chain: each step consumes the previous proof and a new batch.
    for g in range(FOLDS):
        tf = FOLD_TIMES[g]
        dur_f = 0.3 if g < NCH // BATCH else 0.11
        if t < tf - dur_f:
            break
        nx = _node_x(g, scroll)
        px = _node_x(g - 1, scroll)
        if nx < CELL_X0 - 120:
            continue
        ef = _edge_fade(nx)
        u = seg(t, tf - dur_f, tf)
        # Lane segment from the previous proof.
        partial_line(ctx, px + 8, LANE_Y, nx - 8, LANE_Y, ease_out(u), CYAN, 0.35 * out * ef, 1.3)
        # New chunk proofs rising into the fold.
        if u < 1:
            for c in range(BATCH * g, BATCH * g + BATCH):
                cx_ = _cell_x(c, scroll) + 11
                partial_line(ctx, cx_, CELL_Y - 12, nx, LANE_Y + 8, 1.0, CYAN, 0.25 * out * ef * (1 - u), 1.0)
                fill_circle(ctx, lerp(cx_, nx, ease_in(u, 2)), lerp(CELL_Y - 12, LANE_Y, ease_in(u, 2)), 2.2, CYAN, out * ef)
            # The previous constant-size proof travels along the lane.
            if g > 0:
                particle(ctx, lerp(px, nx, ease_io(u)), LANE_Y, 6.0, CYAN, out * ef, 1.0)
        latest = g == g_last
        if t >= tf:
            if latest:
                k = seg(t, tf, tf + 0.6)
                stroke_circle(ctx, nx, LANE_Y, 10 + 34 * ease_out(k), CYAN, 0.6 * (1 - k) * out * ef, 1.5)
                dashed_circle(ctx, nx, LANE_Y, 15, 3, 3, t * 1.5, CYAN, 0.6 * out * ef, 1.0)
                particle(ctx, nx, LANE_Y, 6.0, CYAN, out * ef, 1.2)
                b = BATCH * (g + 1)
                txt = "π[0, n)" if grow else f"π[0, {b})"
                la = 1.0 if grow else smooth(seg(t, tf, tf + 0.25))
                draw_formula(ctx, txt, nx, LANE_Y - 28, 24, CYAN, out * ef * la, align="center")
            else:
                stroke_circle(ctx, nx, LANE_Y, 6.5, CYAN, 0.28 * out * ef, 1.1)

    # Rules.
    draw_formula(ctx, tr("折叠：", "\\rm{Fold}:  ") + "π[0, b) + C_b ⋯ C_{b+k−1} → π[0, b+k),   k ≤ 16", TX, 400, 30, BONE, out, wipe=ease_io(seg(t, 1.6, 2.6)))
    draw_formula(ctx, "|π[0, b+k)| = |π[0, b)| = \\rm{const}", TX, 452, 30, CYAN, out, wipe=ease_io(seg(t, 3.4, 4.4)), scan=CYAN)
    label(ctx, t, "旧证明被新证明取代", "THE PREVIOUS PROOF IS REPLACED", TX, 506, 4.6, None, size=18, color=DIM, alpha=out)

    # Meters.
    ma = smooth(seg(t, 1.0, 1.6)) * out
    if ma > 0:
        mx = 1560
        n_now = sum(1 for k in range(NCH) if t > chunk_time(k))
        if grow:
            n_now = int(32 * 2 ** (15 * ease_in(seg(t, *HIST["grow"]), 2)))
        label(ctx, t, "历史长度", "CHAIN LENGTH", mx, 560, 1.0, None, size=18, alpha=out)
        nw = draw_text(ctx, f"{n_now:,}", mx, 630, "grotesk", 40, BONE, ma)
        draw_text(ctx, "CHUNKS", mx + nw + 12, 630, "mono", 10.5, DIM, ma, tracking=2)
        gfrac = clamp(math.log2(max(n_now, 1)) / 20)
        line(ctx, mx, 648, mx + 240, 648, FAINT, ma, 4, cap=cairo.LINE_CAP_BUTT)
        line(ctx, mx, 648, mx + 240 * gfrac, 648, AMBER, ma, 4, cap=cairo.LINE_CAP_BUTT)
        label(ctx, t, "陈述大小", "STATEMENT SIZE", mx, 712, 1.2, None, size=18, alpha=out)
        draw_text(ctx, "624 B", mx, 782, "grotesk", 40, CYAN, ma)
        line(ctx, mx, 800, mx + 240, 800, FAINT, ma, 4, cap=cairo.LINE_CAP_BUTT)
        line(ctx, mx, 800, mx + 18, 800, CYAN, ma, 4, cap=cairo.LINE_CAP_BUTT)
        draw_text(ctx, tr("常数，与链龄无关", "constant, independent of chain age"), mx, 830, "cn", 15, DIM, ma)

    # Light client.
    l0, l1 = HIST["light"]
    da = smooth(seg(t, l0 - 0.6, l0)) * out
    if da > 0:
        dx, dy = 1620, 900
        stroke_rect(ctx, dx - 22, dy - 40, 44, 74, BONE, 0.8 * da, 1.4, r=7)
        line(ctx, dx - 8, dy + 26, dx + 8, dy + 26, BONE, 0.6 * da, 1.4)
        got = smooth(seg(t, l1, l1 + 0.4))
        fill_rect(ctx, dx - 15, dy - 32, 30, 50, CYAN, 0.10 * got * da, r=3)
        check_mark(ctx, dx, dy - 8, 14, got, CYAN, da, 2.2)
        label(ctx, t, "轻客户端", "LIGHT CLIENT", dx + 40, dy - 6, l0 - 0.4, None, size=18, alpha=out)
        sx = _node_x(NCH // BATCH - 1, 0.0)
        if l0 < t < l1 + 0.1:
            k = ease_io(seg(t, l0, l1))
            px = lerp(sx, dx, k)
            py = lerp(LANE_Y, dy - 8, k) - math.sin(k * math.pi) * 120
            particle(ctx, px, py, 5, CYAN, out, 1.0)
        if t > HIST["grow"][0]:
            # The client keeps only the newest proof: each fold refreshes it.
            for tf in FOLD_TIMES[NCH // BATCH :]:
                if tf <= t < tf + 0.25:
                    fill_rect(ctx, dx - 15, dy - 32, 30, 50, CYAN, 0.18 * (1 - seg(t, tf, tf + 0.25)) * da, r=3)

    caption(ctx, t, tr("每一步只读取上一个证明与新到的块组证明；更早的历史，不再被读取。", "Each step reads only the previous proof and the newly arrived chunk proofs; older history is never read again."), 2.2, l1)
    caption(ctx, t, tr("轻客户端只保存最新的一个证明：从可信锚点出发，验证全部规则，无需重放。", "A light client keeps only the latest proof: from a trusted anchor it checks every rule, with no replay."), l1 + 0.2, HIST["grow"][0] + 1.6)
    caption(ctx, t, tr("无论历史多长，陈述始终同样大小；历史证明在后台生成，从不阻塞最终性。", "However long the history, the statement stays the same size; history proofs run in the background and never gate finality."), HIST["grow"][0] + 1.8, dur - 0.5)


# =====================================================================
# 08  Proof-backed pruning and bootstrap
# =====================================================================

PRUNE = dict(rows=0.8, cover=(2.6, 3.6), dissolve=(4.2, 7.4), boot=7.6, frag=(8.6, 10.4), install=11.0)
NPR = 30
COVER = 22
PX0, PDX = 330.0, 36.5
ROW_A, ROW_B = 560.0, 770.0
_prng = np.random.default_rng(5)
DUSTP = _prng.normal(size=(NPR, 10, 3))


def scene_prune(ctx, t, dur):
    title_block(ctx, t, "11", "PROOF-BACKED PRUNING", [(0.2, dur, tr("被证明覆盖的过去，可以放下", "The proven past can be let go"), tr("全节点只保留最近 8 个块组；归档节点自愿保存全部历史。", "Full nodes keep only the last 8 chunks; archive nodes choose to keep everything."))], t_out=dur - 0.6)
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    d0, d1 = PRUNE["dissolve"]
    for row_y, cn, en, text, archive in ((ROW_A, "全节点", "FULL · VALIDATOR", "Full / validator", False), (ROW_B, "归档节点", "ARCHIVE", "Archive", True)):
        label(ctx, t, cn, en, TX, row_y + 6, PRUNE["rows"] + (0.2 if archive else 0), None, size=20, alpha=out, text=text)
        for k in range(NPR):
            ap = ease_out_back(seg(t, PRUNE["rows"] + k * 0.03 + (0.2 if archive else 0), PRUNE["rows"] + 0.3 + k * 0.03 + (0.2 if archive else 0)))
            if ap <= 0:
                continue
            x = PX0 + k * PDX
            col = BONE
            a = out * (0.55 if archive else 0.75)
            dis = 0.0
            if not archive and k < COVER:
                tk = d0 + k * (d1 - d0 - 0.8) / COVER
                dis = seg(t, tk, tk + 0.8)
            if dis < 1:
                stroke_rect(ctx, x, row_y - 12, 24, 24, col, a * (1 - dis) * clamp(ap), 1.0)
                fill_rect(ctx, x + 4, row_y - 8, 16, 16, AMBER if not archive else DIM, (0.35 if not archive else 0.18) * out * (1 - dis) * clamp(ap))
            else:
                ctx.set_dash([2, 3])
                stroke_rect(ctx, x, row_y - 12, 24, 24, FAINT, 0.5 * out, 1.0)
                ctx.set_dash([])
            if 0 < dis < 1:
                for j in range(10):
                    dx_, dy_, z = DUSTP[k, j]
                    px = x + 12 + dx_ * 10 + dis * dx_ * 18
                    py = row_y - dis * (50 + 40 * abs(dy_)) + dy_ * 6
                    fill_circle(ctx, px, py, 1.2 + 0.6 * abs(z), AMBER_HOT, out * (1 - dis) * 0.9)
    # Coverage bracket.
    c0, c1 = PRUNE["cover"]
    p = ease_out(seg(t, c0, c1))
    if p > 0:
        xa, xb = PX0 - 6, PX0 + (COVER - 1) * PDX + 30
        y = ROW_A - 42
        partial_line(ctx, xa, y, xb, y, p, CYAN, 0.8 * out, 1.6)
        line(ctx, xa, y, xa, y + 10, CYAN, 0.8 * out * p, 1.6)
        line(ctx, xb, y, xb, y + 10, CYAN, 0.8 * out * p, 1.6)
        particle(ctx, (xa + xb) / 2, y, 6 * p, CYAN, out)
        draw_formula(ctx, f"π[0, {COVER})", (xa + xb) / 2, y - 24, 24, CYAN, out * smooth(seg(t, c1 - 0.3, c1 + 0.2)), align="center")
        mono(ctx, t, "COVERED BY A RECURSIVE PROOF", (xa + xb) / 2 + 100, y - 28, c1, None, 10, DIM, out)
    # Retention window.
    wa = smooth(seg(t, d0 - 0.4, d0 + 0.2)) * out
    if wa > 0:
        xa, xb = PX0 + COVER * PDX - 6, PX0 + (NPR - 1) * PDX + 30
        stroke_rect(ctx, xa, ROW_A - 20, xb - xa, 40, AMBER_HOT, 0.8 * wa, 1.4)
        draw_text(ctx, tr("最近 8 个块组", "Last 8 chunks"), (xa + xb) / 2, ROW_A + 52, "cn", 17, AMBER_HOT, wa, align="center")
        if not EN:
            draw_text(ctx, "RETAINED WINDOW", (xa + xb) / 2, ROW_A + 72, "mono", 9.5, DIM, wa, align="center", tracking=2)

    # Bootstrap.
    b0 = PRUNE["boot"]
    ba = smooth(seg(t, b0 - 0.4, b0 + 0.2)) * out
    if ba > 0:
        nx, ny = 1650.0, 470.0
        installed = smooth(seg(t, PRUNE["install"], PRUNE["install"] + 0.5))
        stroke_circle(ctx, nx, ny, 30, mix(BONE, AMBER_HOT, installed), ba, 1.8)
        fill_circle(ctx, nx, ny, 10, mix(DIM, AMBER_HOT, installed), ba)
        if installed > 0:
            halo(ctx, nx, ny, 110, AMBER, 0.35 * installed * ba)
            k = seg(t, PRUNE["install"], PRUNE["install"] + 1.2)
            stroke_circle(ctx, nx, ny, 30 + 160 * ease_out(k), AMBER, 0.6 * (1 - k) * ba, 1.5)
        label(ctx, t, "新节点", "NEW NODE", nx + 46, ny + 6, b0, None, size=18, alpha=out)
        steps = [
            (tr("验证检查点证明", "Verify checkpoint proof"), "CHECKPOINT PROOF", b0 + 0.9),
            (tr("状态分片 · 根认证", "State fragments · root check"), "STATE FRAGMENTS → ROOT", PRUNE["frag"][1]),
            (tr("原子安装", "Atomic install"), "ATOMIC INSTALL", PRUNE["install"]),
        ]
        for k, (cn, en, tk) in enumerate(steps):
            y = 600 + k * 60
            ap = smooth(seg(t, b0 + k * 0.15, b0 + 0.4 + k * 0.15)) * out
            done = ease_out(seg(t, tk, tk + 0.35))
            stroke_rect(ctx, 1470, y - 17, 20, 20, AMBER if done > 0 else DIM, ap, 1.2)
            check_mark(ctx, 1480, y - 7, 14, done, AMBER_HOT, ap, 2.2)
            draw_text(ctx, cn, 1506, y, "cn", 19, BONE if done > 0 else DIM, ap)
            if not EN:
                draw_text(ctx, en, 1506, y + 20, "mono", 9.5, DIM, ap, tracking=2)
        # The checkpoint proof flies in.
        xa, xb = PX0 - 6, PX0 + (COVER - 1) * PDX + 30
        sx, sy = (xa + xb) / 2, ROW_A - 42
        if b0 < t < b0 + 1.0:
            k = ease_io(seg(t, b0, b0 + 0.9))
            particle(ctx, lerp(sx, nx, k), lerp(sy, ny, k) - math.sin(k * math.pi) * 90, 5, CYAN, out)
        # State fragments assemble into a root.
        f0, f1 = PRUNE["frag"]
        if t > f0:
            tx0, ty0 = 1560.0, 880.0
            for j in range(8):
                tj = f0 + j * 0.12
                k = ease_io(seg(t, tj, tj + 0.7))
                srcx = PX0 + (22 + j) * PDX + 12
                px = lerp(srcx, tx0 + j * 26, k)
                py = lerp(ROW_B, ty0, k) - math.sin(k * math.pi) * 40
                fill_rect(ctx, px - 5, py - 5, 10, 10, AMBER, 0.85 * out)
            jo = smooth(seg(t, f1 - 0.6, f1))

            def tnode(lv, j):
                span = 26 * 2**lv
                return tx0 + j * span + span / 2 - 13, ty0 - lv * 26

            for lv, n in ((1, 4), (2, 2), (3, 1)):
                for j in range(n):
                    x, y = tnode(lv, j)
                    for c in (2 * j, 2 * j + 1):
                        line(ctx, x, y, *tnode(lv - 1, c), BONE, 0.45 * out * jo, 1.0)
            for lv, n in ((1, 4), (2, 2), (3, 1)):
                for j in range(n):
                    x, y = tnode(lv, j)
                    fill_circle(ctx, x, y, 3.2, AMBER_HOT if lv == 3 else BONE, out * jo)
            if jo > 0:
                draw_formula(ctx, "r ✓", tx0 + 104 + 20, ty0 - 78 + 8, 22, AMBER_HOT, out * jo)

    caption(ctx, t, tr("被递归证明覆盖、又早于最近 8 个块组的原始数据，全节点可以删除。", "Raw data covered by a recursive proof and older than the last 8 chunks can be deleted by full nodes."), d0, PRUNE["boot"] - 0.1)
    caption(ctx, t, tr("新节点先验证检查点与状态快照，根一致后一次性原子安装，再继续同步。", "A new node verifies the checkpoint and the state snapshot, installs atomically once the root matches, then syncs on."), PRUNE["boot"] + 0.2, dur - 0.5)


# =====================================================================
# Outro
# =====================================================================

OUTRO = dict(lines=(0.5, 1.7, 2.9), lines_out=(6.0, 6.8), ring=(7.0, 7.9), particle=(7.5, 8.7), move=(9.5, 10.5), word=(10.2, 11.1), tagline=11.0)
LINES = [(tr("同一份逻辑", "One transition function."), "ONE TRANSITION FUNCTION"), (tr("逐层递归的证明", "Proofs, recursively."), "RECURSIVE PROOFS"), (tr("无需重放的信任", "Trust without replay."), "TRUST WITHOUT REPLAY")]


def scene_outro(ctx, t, dur):
    la = 1 - smooth(seg(t, *OUTRO["lines_out"]))
    if la > 0:
        for k, (cn, en) in enumerate(LINES):
            t0 = OUTRO["lines"][k]
            if t < t0:
                continue
            y = 430 + k * 110
            draw_text(ctx, cn, W / 2, y, "cn_b", 52, BONE, la, align="center", mode="rise", p=seg(t, t0, t0 + 0.8), rise=14, hot=AMBER_HOT)
            if not EN:
                draw_text(ctx, en, W / 2, y + 36, "mono", 12, DIM, la, align="center", tracking=5, mode="decode", p=seg(t, t0 + 0.3, t0 + 0.9), t=t)
    # Logo reprise.
    r0, r1 = OUTRO["ring"]
    if t > r0:
        ring = ease_io(seg(t, r0, r1))
        p0, p1 = OUTRO["particle"]
        k = ease_out(seg(t, p0, p1), 2.2)
        pu = lerp(470.0, logo.PART[0], k) if t > p0 else None
        traj = clamp((logo.TRAJ0[0] - (pu if pu is not None else 999)) / (logo.TRAJ0[0] - logo.TRAJ1[0]))
        mv = ease_io(seg(t, *OUTRO["move"]))
        L = 1.15
        ox, oy, icx, icy, isc = logo.lockup_layout(W / 2, 505, L)
        cx = lerp(W / 2, icx, mv)
        cy = lerp(H / 2, icy, mv)
        s = lerp(2.0, isc, mv)
        pulse = seg(t, p1, p1 + 1.1)
        comet = 1 - smooth(seg(t, p1 - 0.9, p1))
        logo.draw_mark(ctx, cx, cy, s, ring=ring, traj=0, part_u=None, alpha=smooth(seg(t, r0, r0 + 0.4)))
        logo.draw_mark(ctx, cx, cy, s, ring=0, traj=traj, part_u=pu, part_a=smooth(seg(t, p0, p0 + 0.2)), pulse=pulse if t > p1 else 0, comet=comet)
        logo.draw_wordmark(ctx, ox, oy, L, reveal=ease_io(seg(t, *OUTRO["word"])))
        tg = OUTRO["tagline"]
        if t > tg:
            draw_text(ctx, tr("证明穿过整段历史，而不必重演它", "A proof passes through the whole history — without replaying it."), W / 2, 728, "cn", 30, BONE, 0.92, align="center", mode="rise", p=seg(t, tg, tg + 0.9), rise=10)
            draw_text(ctx, "A PROOF-AWARE LAYER-1 BLOCKCHAIN", W / 2, 772, "mono", 12, DIM, 0.85, tracking=5, align="center", mode="decode", p=seg(t, tg + 0.4, tg + 1.1), t=t)
