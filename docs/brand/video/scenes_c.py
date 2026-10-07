"""04 block production, 06 cryptographic facts, 09 signing discipline."""

from __future__ import annotations

import math

import cairo

from common import CAPTION_Y, TX, caption, label, mono, title_block
from gfx import (
    AMBER,
    AMBER_HOT,
    BONE,
    CYAN,
    DIM,
    FAINT,
    GRAPHITE,
    RED,
    W,
    check_mark,
    clamp,
    corner_frame,
    cross_mark,
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
    particle,
    partial_line,
    polygon,
    rgba,
    seg,
    smooth,
    stroke_circle,
    stroke_rect,
    traced_polygon,
    traced_rect,
    window,
)
from lang import EN, tr

# =====================================================================
# 04  Block production: slot lottery, block, proof, fork choice, chunks
# =====================================================================

BLK = dict(slots=(2.0, 4.0, 6.0), lottery_out=8.0, build=8.4, chain=14.6, invalid=16.5, brackets=17.6, cand=19.2)
LOT_N = 8
LOT_W = [0.20, 0.08, 0.14, 0.17, 0.06, 0.12, 0.15, 0.08]  # stake shares; E = 1 expected proposer per slot
LOT_Y = [
    [0.52, 0.31, 0.66, 0.09, 0.47, 0.83, 0.38, 0.71],  # slot s: one proposer
    [0.44, 0.92, 0.27, 0.58, 0.19, 0.36, 0.77, 0.25],  # slot s+1: empty
    [0.12, 0.63, 0.41, 0.88, 0.33, 0.55, 0.05, 0.49],  # slot s+2: two proposers
]
AX0, AX1 = 330.0, 1110.0
ROW0, ROWDY = 412.0, 54.0
CHAIN_Y, FORK_Y = 650.0, 540.0
CHAIN_X0, CHAIN_DX = 300.0, 112.0
K_CHUNK = 4


def _row_y(i):
    return ROW0 + i * ROWDY


def _eligible(slot, i):
    return LOT_Y[slot][i] < LOT_W[i]


def _block_glyph(ctx, x, y, a, proof=1.0, col=BONE, bad=0.0):
    fill_rect(ctx, x - 28, y - 17, 56, 34, (0.05, 0.048, 0.045), a)
    stroke_rect(ctx, x - 28, y - 17, 56, 34, mix(col, RED, bad), a * 0.85, 1.3)
    line(ctx, x - 20, y - 5, x + 8, y - 5, mix(col, RED, bad), 0.4 * a, 1.0)
    line(ctx, x - 20, y + 4, x + 2, y + 4, mix(col, RED, bad), 0.3 * a, 1.0)
    if proof > 0:
        if bad > 0:
            stroke_circle(ctx, x + 18, y - 7, 4.5, RED, a * proof, 1.4)
        else:
            particle(ctx, x + 18, y - 7, 3.6 * proof, CYAN, a * clamp(proof), 0.6)


def scene_blocks(ctx, t, dur):
    title_block(
        ctx,
        t,
        "04",
        "BLOCK PRODUCTION",
        [
            (0.2, BLK["lottery_out"] + 0.1, tr("每个时隙，一次可验证的抽签", "Every slot, a verifiable lottery"), tr("出块资格由可验证随机函数与权益共同决定：自己算得出，别人验得了。", "Eligibility comes from a verifiable random function weighted by stake: computed privately, checked by anyone.")),
            (BLK["build"] - 0.1, BLK["chain"] - 0.1, tr("一个区块：执行、承诺、证明", "A block: execute, commit, prove"), tr("区块头承诺父块、高度、随机证明与状态根；区块证明保证这次执行确实正确。", "The header commits to parent, height, randomness proof and state root; the block proof covers the execution.")),
            (BLK["chain"] + 0.1, dur, tr("区块连成链，每 K 个组成一个块组", "Blocks chain; every K of them form a chunk"), tr("分叉选择只沿已证明的分支前进；无效证明连同其后代一起被剔除。", "Fork choice follows proven branches; an invalid proof drops its block and every descendant.")),
        ],
        t_out=dur - 0.6,
    )
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))

    # ---- Part A: the lottery ------------------------------------------
    la = smooth(seg(t, 0.6, 1.2)) * (1 - smooth(seg(t, BLK["lottery_out"] - 0.4, BLK["lottery_out"] + 0.2)))
    if la > 0:
        slot = max([k for k, ts in enumerate(BLK["slots"]) if t >= ts - 0.3] or [0])
        ts = BLK["slots"][slot]
        draw_text(ctx, f"SLOT  s + {slot}" if slot else "SLOT  s", AX0, ROW0 - 40, "mono_m", 13, AMBER, la, tracking=3, mode="decode", p=seg(t, ts - 0.3, ts + 0.2), t=t)
        draw_text(ctx, "0", AX0, _row_y(LOT_N - 1) + 34, "mono", 10, DIM, la)
        draw_formula(ctx, "2^{256}", AX1, _row_y(LOT_N - 1) + 36, 15, DIM, la, align="right")
        for i in range(LOT_N):
            y = _row_y(i)
            ap = smooth(seg(t, 0.8 + i * 0.06, 1.2 + i * 0.06)) * la
            draw_formula(ctx, f"v_{i}", AX0 - 30, y + 7, 22, BONE, ap, align="right")
            line(ctx, AX0, y, AX1, y, GRAPHITE, ap, 6, cap=cairo.LINE_CAP_BUTT)
            thr = AX0 + (AX1 - AX0) * LOT_W[i]
            line(ctx, AX0, y, thr, y, AMBER, 0.45 * ap, 6, cap=cairo.LINE_CAP_BUTT)
            line(ctx, thr, y - 11, thr, y + 11, AMBER_HOT, 0.8 * ap, 1.3)
            # The output for the current slot.
            settle = seg(t, ts + i * 0.06, ts + 0.35 + i * 0.06)
            if settle <= 0:
                continue
            fade_prev = 1 - smooth(seg(t, ts + 1.55, ts + 1.85)) if slot < 2 else 1.0
            yv = LOT_Y[slot][i]
            if settle < 1:
                jitter = (math.sin(t * 91 + i * 7.3) * 0.5 + 0.5) * (1 - settle)
                yv = lerp(yv, jitter, 1 - settle)
            x = AX0 + (AX1 - AX0) * yv
            ok = _eligible(slot, i) and settle >= 1
            if ok:
                halo(ctx, x, y, 40, AMBER_HOT, 0.6 * ap * fade_prev)
                fill_circle(ctx, x, y, 6.5, AMBER_HOT, ap * fade_prev)
                fill_rect(ctx, AX0 - 6, y - 16, AX1 - AX0 + 12, 32, AMBER, 0.06 * ap * fade_prev)
                check_mark(ctx, AX1 + 26, y, 14, smooth(seg(t, ts + 0.45 + i * 0.06, ts + 0.75 + i * 0.06)), AMBER_HOT, ap * fade_prev, 2.2)
            else:
                fill_circle(ctx, x, y, 4.5, BONE, 0.75 * ap * fade_prev)
        # Formulas and slot outcomes.
        draw_formula(ctx, "y_v = \\rm{VRF}_{sk}(\\rm{seed} ‖ \\rm{slot})", 1210, 450, 30, BONE, la, wipe=ease_io(seg(t, 1.0, 1.9)))
        draw_formula(ctx, "y_v < (2^{256} − 1) · E · w_v / W", 1210, 516, 30, AMBER, la, wipe=ease_io(seg(t, 1.6, 2.5)))
        draw_formula(ctx, tr("E ：每个时隙期望的出块者数", "E \\rm{: expected proposers per slot}"), 1210, 568, 19, DIM, la * smooth(seg(t, 2.2, 2.6)))
        draw_formula(ctx, tr("w_v / W ：验证者的权益占比", "w_v / W \\rm{: the validator's share of stake}"), 1210, 600, 19, DIM, la * smooth(seg(t, 2.3, 2.7)))
        results = [
            (tr("时隙 s：1 位出块者", "slot s: one proposer"), BONE),
            (tr("时隙 s+1：空", "slot s+1: empty"), DIM),
            (tr("时隙 s+2：2 位出块者 → 可能分叉", "slot s+2: two proposers → a possible fork"), AMBER_HOT),
        ]
        for k, (txt, col) in enumerate(results):
            tk = BLK["slots"][k] + 0.9
            if t >= tk:
                draw_text(ctx, txt, 1210, 680 + k * 36, "cn", 19, col, la, mode="rise", p=seg(t, tk, tk + 0.6), rise=6)

    # ---- Part B: building one block --------------------------------------
    b0 = BLK["build"]
    ba = smooth(seg(t, b0, b0 + 0.5)) * (1 - smooth(seg(t, BLK["chain"] - 0.5, BLK["chain"])))
    if ba > 0:
        cx0, cy0, cw, ch = 640.0, 392.0, 500.0, 420.0
        traced_rect(ctx, cx0, cy0, cw, ch, ease_out(seg(t, b0, b0 + 0.6)), BONE, 0.75 * ba, 1.3)
        draw_formula(ctx, "B_h", cx0, cy0 - 14, 24, BONE, ba)
        mono(ctx, t, "HEADER", cx0 + cw, cy0 - 14, b0 + 0.2, None, 10, DIM, ba, align="right")
        rows = [
            ("PARENT", "H(B_{h−1})"),
            ("HEIGHT · SLOT", "h,  s"),
            ("PROPOSER · VRF", "v_3,  π_{vrf}"),
            ("STATE ROOT", "r′"),
            ("TX ROOT", "\\rm{Root}(\\rm{txs})"),
            ("RECEIPTS · GAS", "\\rm{Root}(\\rm{rcpts}),  g"),
            ("SIGNATURE", "σ_{v_3}"),
        ]
        for j, (tag, val) in enumerate(rows):
            tj = b0 + 0.4 + j * 0.32
            if j == 3:
                tj = b0 + 2.1
            if j == 6:
                tj = b0 + 3.4
            if t < tj:
                continue
            y = cy0 + 52 + j * 54
            hot = math.exp(-max(0.0, t - tj) * 2.5)
            draw_text(ctx, tag, cx0 + 24, y, "mono", 11, DIM, ba, tracking=2.2, mode="decode", p=seg(t, tj, tj + 0.4), t=t)
            draw_formula(ctx, val, cx0 + 230, y + 2, 24, mix(BONE, AMBER_HOT, hot), ba, wipe=ease_out(seg(t, tj, tj + 0.35)))
            line(ctx, cx0 + 18, y + 18, cx0 + cw - 18, y + 18, FAINT, 0.35 * ba, 1.0, cap=cairo.LINE_CAP_BUTT)
        # Transactions flow through F into the state root.
        fx, fy = 520.0, cy0 + 52 + 3 * 54 - 6
        fa = smooth(seg(t, b0 + 0.6, b0 + 1.0)) * ba
        if fa > 0:
            traced_polygon(ctx, fx, fy, 30, 1.0, BONE, 0.8 * fa, 1.3)
            draw_formula(ctx, "F", fx, fy + 11, 30, BONE, fa, align="center")
            for k in range(6):
                u = seg(t, b0 + 0.8 + k * 0.18, b0 + 1.5 + k * 0.18)
                if 0 < u < 1:
                    px = lerp(300, fx - 34, ease_in(u, 2))
                    fill_rect(ctx, px - 5, fy - 5 + (k % 3 - 1) * 10 * (1 - u), 10, 10, AMBER, fa)
            partial_line(ctx, fx + 32, fy, cx0, fy, ease_out(seg(t, b0 + 1.8, b0 + 2.1)), AMBER, 0.7 * fa, 1.4)
            label(ctx, t, "交易", "TXS", 300, fy - 26, b0 + 0.8, None, size=17, alpha=ba, text="Transactions")
        # The block proof.
        p0 = b0 + 2.8
        if t > p0:
            k = ease_out_back(seg(t, p0, p0 + 0.5))
            m = ease_io(seg(t, p0 + 0.2, p0 + 0.9))
            px = lerp(cx0 + cw, cx0 + cw + 90, m)
            py = cy0 + ch / 2
            particle(ctx, px, py, 7 * k, CYAN, ba * clamp(k), 1.2)
            draw_formula(ctx, "π_b", px, py - 24, 24, CYAN, ba * smooth(seg(t, p0 + 0.6, p0 + 0.9)), align="center")
            draw_formula(ctx, "π_b :  r′ = F(r, \\rm{txs})", 1300, py + 60, 30, CYAN, ba, wipe=ease_io(seg(t, p0 + 0.8, p0 + 1.6)), scan=CYAN)
            label(ctx, t, "区块证明", "BLOCK PROOF", 1300, py + 110, p0 + 1.0, None, size=18, alpha=ba)
        caption(ctx, t, tr("出块者先执行交易、得到新状态根，再签名并为这次执行生成区块证明。", "The proposer executes the transactions, obtains the new state root, signs, and proves the execution."), b0 + 0.8, BLK["chain"] - 0.3)

    # ---- Part C: the chain, fork choice and chunks -------------------------
    c0 = BLK["chain"]
    if t > c0 - 0.2:
        ca = smooth(seg(t, c0 - 0.2, c0 + 0.3)) * out
        n_main = 11
        bad = smooth(seg(t, BLK["invalid"], BLK["invalid"] + 0.6))

        def bt(j):
            return c0 + 0.2 + j * 0.3

        def bx(j):
            return CHAIN_X0 + j * CHAIN_DX

        # Fork choice glow along the proven branch.
        last = max([j for j in range(n_main) if t >= bt(j)] or [0])
        if t > bt(0):
            g = cairo.LinearGradient(bx(0), 0, bx(last), 0)
            g.add_color_stop_rgba(0, *AMBER, 0.0)
            g.add_color_stop_rgba(1, *AMBER, 0.35 * ca)
            ctx.set_source(g)
            ctx.rectangle(bx(0) - 30, CHAIN_Y - 2, bx(last) - bx(0) + 30, 4)
            ctx.fill()
        for j in range(n_main):
            ap = ease_out_back(seg(t, bt(j), bt(j) + 0.3))
            if ap <= 0:
                continue
            x = bx(j)
            if j > 0:
                line(ctx, bx(j - 1) + 28, CHAIN_Y, x - 28, CHAIN_Y, BONE, 0.45 * ca, 1.2)
            _block_glyph(ctx, x, CHAIN_Y, ca * clamp(ap), smooth(seg(t, bt(j) + 0.15, bt(j) + 0.45)))
        draw_text(ctx, "h", bx(0), CHAIN_Y + 44, "math_it", 18, DIM, ca * smooth(seg(t, bt(0), bt(0) + 0.3)), align="center")
        draw_formula(ctx, "h + 10", bx(10), CHAIN_Y + 46, 18, DIM, ca * smooth(seg(t, bt(10), bt(10) + 0.3)), align="center")
        # The competing branch from the two-proposer slot.
        fj = 3
        for k in range(2):
            tb = bt(fj + k) + 0.05
            ap = ease_out_back(seg(t, tb, tb + 0.3))
            if ap <= 0:
                continue
            x = bx(fj + k)
            px_, py_ = (bx(fj - 1), CHAIN_Y) if k == 0 else (bx(fj), FORK_Y)
            fade = 1 - 0.55 * bad
            partial_line(ctx, px_ + 28, py_ - (12 if k == 0 else 0), x - 28, FORK_Y, 1.0, mix(BONE, RED, bad), 0.45 * ca * fade, 1.2)
            _block_glyph(ctx, x, FORK_Y, ca * clamp(ap) * fade, smooth(seg(t, tb + 0.15, tb + 0.45)), bad=bad)
        if bad > 0:
            x = bx(fj) + 18
            cross_mark(ctx, x, FORK_Y - 7, 8, RED, ca * bad, 2.4)
            halo(ctx, x, FORK_Y - 7, 50, RED, 0.5 * ca * bad * math.exp(-(t - BLK["invalid"]) * 1.5))
            label(ctx, t, "无效证明：连同后代剔除", "INVALID PROOF — SUBTREE DROPPED", bx(fj + 1) + 46, FORK_Y + 6, BLK["invalid"] + 0.2, None, size=17, color=RED, alpha=ca, text="Invalid proof — subtree dropped")
        # Chunks of K consecutive heights.
        for n in range(2):
            tb = BLK["brackets"] + n * 0.5
            p = ease_out(seg(t, tb, tb + 0.5))
            if p <= 0:
                continue
            xa = bx(n * K_CHUNK) - 34
            xb = bx(n * K_CHUNK + K_CHUNK - 1) + 34
            y = CHAIN_Y + 66
            hot = n == 1 and t > BLK["cand"]
            col = AMBER_HOT if hot else BONE
            partial_line(ctx, xa, y, xb, y, p, col, 0.7 * ca, 1.4)
            line(ctx, xa, y - 9, xa, y, col, 0.7 * ca * p, 1.4)
            line(ctx, xb, y - 9, xb, y, col, 0.7 * ca * p, 1.4)
            draw_text(ctx, tr(f"块组 {'n' if n == 0 else 'n+1'}", f"chunk {'n' if n == 0 else 'n+1'}"), (xa + xb) / 2, y + 28, "cn", 18, col, ca * p, align="center")
        draw_formula(ctx, "c(h) = ⌊(h − 1) / K⌋", TX, 430, 30, BONE, ca, wipe=ease_io(seg(t, BLK["brackets"], BLK["brackets"] + 0.9)))
        draw_text(ctx, tr("块组 n 覆盖高度 nK+1 … (n+1)K", "chunk n covers heights nK+1 … (n+1)K"), TX, 470, "cn", 18, DIM, ca * smooth(seg(t, BLK["brackets"] + 0.6, BLK["brackets"] + 1.0)))
        # The finished chunk becomes the candidate handed to consensus.
        cd = BLK["cand"]
        if t > cd:
            k = ease_io(seg(t, cd, cd + 1.2))
            xa = bx(K_CHUNK) - 34
            xb = bx(2 * K_CHUNK - 1) + 34
            sx, sy = (xa + xb) / 2, CHAIN_Y + 110
            hx, hy = lerp(sx, 1640, k), lerp(sy, 470, k)
            for j in range(K_CHUNK):
                u = ease_in(seg(t, cd, cd + 0.6), 2)
                particle(ctx, lerp(bx(K_CHUNK + j) + 18, sx, u), lerp(CHAIN_Y - 7, sy, u), 3.2, CYAN, ca * (1 - seg(t, cd + 0.5, cd + 0.7)), 0.6)
            ph = ease_out(seg(t, cd + 0.4, cd + 0.9))
            traced_polygon(ctx, hx, hy, 30, ph, CYAN, ca, 1.6)
            if ph > 0:
                halo(ctx, hx, hy, 70, CYAN, 0.2 * ph * ca)
                draw_formula(ctx, "C", hx, hy + 10, 26, BONE, ph * ca, align="center")
            label(ctx, t, "块组候选 → 共识", "CHUNK CANDIDATE → CONSENSUS", 1640, 540, cd + 1.0, None, align="center", size=18, alpha=ca, text="Chunk candidate → consensus")
        caption(ctx, t, tr("同一时隙可能有多位出块者：分叉选择沿最重的已证明分支前进。", "Several proposers may share a slot: fork choice follows the heaviest proven branch."), c0 + 0.4, BLK["brackets"] - 0.1)
        caption(ctx, t, tr("每 K 个连续高度组成一个块组，交给下一步的共识。", "Every K consecutive heights form a chunk, handed on to consensus."), BLK["brackets"] + 0.1, dur - 0.5)


# =====================================================================
# 06  Cryptographic facts: random-weighted batch checks, proven once
# =====================================================================

FACT = dict(tiles=0.8, coef=2.8, merge=(4.8, 6.4), check=6.9, cancel=7.6, proof=(10.3, 11.4), reuse=12.0)
TILE_X, TILE_W, TILE_H = 214.0, 430.0, 44.0
TILE_Y0, TILE_DY = 396.0, 56.0
SOURCES = ("VOTE", "ATTEST", "HEADER", "VRF", "VOTE", "ROUND", "ATTEST", "PROPOSAL")
BATCH_C = (1120.0, 612.0)


def scene_facts(ctx, t, dur):
    title_block(
        ctx,
        t,
        "06",
        "CRYPTOGRAPHIC FACTS",
        [(0.2, dur, tr("签名检查，先压缩成事实", "Signature checks, compressed into facts"), tr("大量签名验证合并为一次随机加权检查；证明一次，到处复用。", "Many signature checks merge into one randomly weighted check — proven once, reused everywhere."))],
        t_out=dur - 0.6,
    )
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    m0, m1 = FACT["merge"]
    merge = ease_in(seg(t, m0, m1), 2)
    bx, by = BATCH_C

    # Individual pairing checks.
    for i, src in enumerate(SOURCES):
        tt = FACT["tiles"] + i * 0.13
        ap = ease_out(seg(t, tt, tt + 0.35))
        if ap <= 0 or merge >= 1:
            continue
        mi = clamp(merge * 1.3 - i * 0.04)
        x = lerp(TILE_X, bx - 60, mi)
        y = lerp(TILE_Y0 + i * TILE_DY, by, mi)
        s = 1 - 0.8 * mi
        a = out * clamp(ap) * (1 - smooth(seg(mi, 0.6, 1.0)))
        ctx.save()
        ctx.translate(x - 30 * (1 - ap), y)
        ctx.scale(s, s)
        stroke_rect(ctx, 0, 0, TILE_W, TILE_H, BONE, 0.45 * a, 1.1)
        draw_formula(ctx, f"e(g, σ_{i}) = e(pk_{i}, H(m_{i}))", 16, 30, 20, BONE, a)
        draw_text(ctx, src, TILE_W - 12, 27, "mono", 9.5, DIM, a, tracking=2, align="right")
        cp = ease_out_back(seg(t, FACT["coef"] + i * 0.1, FACT["coef"] + 0.35 + i * 0.1))
        if cp > 0:
            fill_circle(ctx, -24, TILE_H / 2, 15 * cp, (0.08, 0.06, 0.03), a)
            stroke_circle(ctx, -24, TILE_H / 2, 15 * cp, AMBER, a, 1.3)
            draw_formula(ctx, f"r_{i}", -24, TILE_H / 2 + 7, 17, AMBER_HOT, a * clamp(cp), align="center")
        ctx.restore()

    # Fiat–Shamir coefficients.
    fs_a = smooth(seg(t, FACT["coef"], FACT["coef"] + 0.4)) * out * (1 - smooth(seg(t, FACT["cancel"] - 0.3, FACT["cancel"])))
    if fs_a > 0:
        draw_formula(ctx, "r_i = H(\\rm{transcript} ‖ i)", 760, 430, 28, AMBER, fs_a, wipe=ease_io(seg(t, FACT["coef"], FACT["coef"] + 0.8)))
        draw_text(ctx, tr("系数由整批输入的哈希决定，没有人能预先挑选", "coefficients hash the entire batch — nobody can choose them"), 760, 470, "cn", 18, DIM, fs_a * smooth(seg(t, FACT["coef"] + 0.5, FACT["coef"] + 0.9)))

    # The combined equation and its single check.
    ca = smooth(seg(t, m1 - 0.4, m1 + 0.2)) * out
    pr0, pr1 = FACT["proof"]
    collapse = ease_in(seg(t, pr0, pr1), 2)
    if ca > 0 and collapse < 1:
        a = ca * (1 - collapse)
        w = 760 * (1 - 0.9 * collapse)
        corner_frame(ctx, bx - w / 2, by - 54, w, 108, AMBER, 0.6 * a, 14, 1.3)
        ctx.save()
        ctx.translate(bx, by)
        ctx.scale(1 - 0.9 * collapse, 1 - 0.9 * collapse)
        draw_formula(ctx, "e(g, ∑_i r_i σ_i) = ∏_i e(r_i · pk_i, H(m_i))", 0, 12, 34, BONE, a, align="center", wipe=ease_io(seg(t, m1 - 0.3, m1 + 0.5)))
        ctx.restore()
        ck = ease_out(seg(t, FACT["check"], FACT["check"] + 0.4))
        if ck > 0:
            check_mark(ctx, bx + w / 2 + 34, by, 22, ck, AMBER_HOT, a, 2.8)
            halo(ctx, bx + w / 2 + 34, by, 60, AMBER, 0.5 * a * math.exp(-(t - FACT["check"]) * 1.5))
        label(ctx, t, "一次最终检查", "ONE FINAL CHECK", bx, by + 92, FACT["check"], pr0, align="center", size=18, alpha=out)
    # Why the weights must be random.
    k0 = FACT["cancel"]
    ka = window(t, k0, pr0 + 0.2, 0.4, 0.4) * out
    if ka > 0:
        y1, y2 = by + 170, by + 222
        draw_text(ctx, tr("不加权", "unweighted"), bx - 250, y1, "cn", 19, RED, ka, align="right")
        draw_formula(ctx, "δ_1 + δ_2 = 0", bx - 220, y1 + 2, 30, RED, ka, wipe=ease_io(seg(t, k0, k0 + 0.6)), scan=RED)
        draw_text(ctx, tr("两个错误可以互相抵消", "two errors can cancel"), bx + 60, y1, "cn", 18, DIM, ka * smooth(seg(t, k0 + 0.5, k0 + 0.9)))
        draw_text(ctx, tr("随机加权", "random weights"), bx - 250, y2, "cn", 19, AMBER, ka * smooth(seg(t, k0 + 1.0, k0 + 1.4)), align="right")
        draw_formula(ctx, "r_1 δ_1 + r_2 δ_2 ≠ 0", bx - 220, y2 + 2, 30, AMBER_HOT, ka, wipe=ease_io(seg(t, k0 + 1.0, k0 + 1.6)))
        draw_text(ctx, tr("以压倒性的概率", "with overwhelming probability"), bx + 140, y2, "cn", 18, DIM, ka * smooth(seg(t, k0 + 1.5, k0 + 1.9)))
    # The fact proof and its reuse.
    if t > pr0 + 0.6:
        k = ease_out_back(seg(t, pr0 + 0.6, pr1))
        particle(ctx, bx, by, 8 * k, CYAN, out * clamp(k), 1.4)
        draw_formula(ctx, "π_{fact}", bx, by - 28, 26, CYAN, out * smooth(seg(t, pr1 - 0.2, pr1 + 0.2)), align="center")
        label(ctx, t, "事实证明 · 每份最多 64 条", "FACT PROOF · UP TO 64 FACTS", bx, by + 52, pr1, None, align="center", size=18, alpha=out, text="Fact proof · up to 64 facts")
    r0 = FACT["reuse"]
    for k, (cn, tag, text, ty) in enumerate(((tr("证据证明", "Evidence proof"), "EVIDENCE PROOF", None, 470.0), (tr("块组证明", "Chunk proof"), "CHUNK PROOF", None, 760.0))):
        tk = r0 + k * 0.4
        if t < tk:
            continue
        p = ease_io(seg(t, tk, tk + 0.8))
        tx_ = 1560.0
        partial_line(ctx, bx + 14, by, tx_ - 20, ty, p, CYAN, 0.5 * out, 1.3)
        if p < 1:
            particle(ctx, lerp(bx, tx_ - 20, p), lerp(by, ty, p), 4, CYAN, out, 0.8)
        ap = smooth(seg(t, tk + 0.6, tk + 1.0)) * out
        traced_rect(ctx, tx_ - 20, ty - 32, 250, 64, ap, BONE, 0.7 * out, 1.2)
        draw_text(ctx, cn, tx_ + 4, ty + 7, "cn", 20, BONE, ap)
        if not EN:
            draw_text(ctx, tag, tx_ + 4 + 96, ty + 6, "mono", 9.5, DIM, ap, tracking=2)
    caption(ctx, t, tr("签名、聚合签名、投票与随机证明，都化为同一种配对等式。", "Signatures, aggregates, votes and randomness proofs all reduce to one kind of pairing equation."), 1.0, FACT["cancel"] - 0.2)
    caption(ctx, t, tr("随机系数让无效签名无法互相抵消；否定的判决总是单独检查。", "Random coefficients stop invalid signatures from cancelling out; negative verdicts are always checked one by one."), FACT["cancel"], r0 - 0.1)
    caption(ctx, t, tr("事实证明并行生成；块组证明直接引用，未覆盖的检查当场批量完成，结论完全相同。", "Fact proofs run in parallel; chunk proofs reuse them and batch-check the rest, committing the same result."), r0 + 0.1, dur - 0.5)


# =====================================================================
# 09  Signing discipline: durable journal and the full-spec domain
# =====================================================================

SIGN = dict(node=0.8, req1=1.2, record=1.9, sync=2.5, emit=2.9, crash=3.7, restart=4.6, req2=5.2, refuse=6.2, retry=7.3, same=8.1, domain=9.4, foreign=11.8)
NODE = (330.0, 612.0)
JOUR = (660.0, 400.0, 460.0, 400.0)
NET = (1560.0, 612.0)


def scene_signing(ctx, t, dur):
    title_block(
        ctx,
        t,
        "09",
        "SIGNING DISCIPLINE",
        [(0.2, dur, tr("诚实节点，不会自相矛盾", "Honest nodes never contradict themselves"), tr("先把要签的内容同步写入持久日志，再签名：崩溃重启也签不出冲突的消息。", "The exact payload is reserved in a durable journal before signing — a crash cannot lead to a conflicting signature."))],
        t_out=dur - 0.6,
    )
    out = 1 - smooth(seg(t, dur - 0.9, dur - 0.4))
    S = SIGN
    nx, ny = NODE
    jx, jy, jw, jh = JOUR
    part1 = 1 - smooth(seg(t, S["domain"] - 0.5, S["domain"]))
    crash = window(t, S["crash"], S["restart"], 0.05, 0.3)

    if part1 > 0:
        a1 = out * part1
        # Validator.
        na = ease_out_back(seg(t, S["node"], S["node"] + 0.4))
        glitch = (math.sin(t * 97) > 0.2) * crash
        ncol = mix(BONE, RED, crash)
        ox = 6 * glitch
        stroke_circle(ctx, nx + ox, ny, 34 * na, ncol, a1 * (1 - 0.6 * glitch), 1.8)
        fill_circle(ctx, nx + ox, ny, 12 * na, ncol, 0.85 * a1 * (1 - 0.6 * glitch))
        label(ctx, t, "验证者", "VALIDATOR", nx, ny + 74, S["node"] + 0.2, None, align="center", size=18, alpha=a1)
        if crash > 0:
            draw_text(ctx, "CRASH", nx, ny - 60, "mono_m", 13, RED, a1 * crash, tracking=3, align="center")
            for k in range(5):
                yy = jy + 40 + k * 70 + 20 * math.sin(t * 37 + k)
                fill_rect(ctx, jx - 40, yy, jw + 80, 2, RED, 0.25 * a1 * crash * (math.sin(t * 53 + k * 3) > 0))
        if S["restart"] <= t < S["req2"] + 0.4:
            draw_text(ctx, "RESTART · JOURNAL RELOADED", nx, ny - 60, "mono", 11, AMBER, a1 * window(t, S["restart"], S["req2"] + 0.4, 0.2, 0.3), tracking=2, align="center", mode="decode", p=seg(t, S["restart"], S["restart"] + 0.5), t=t)

        # Journal.
        ja = smooth(seg(t, S["node"] + 0.2, S["node"] + 0.7)) * a1 * (1 - 0.7 * crash)
        traced_rect(ctx, jx, jy, jw, jh, ease_out(seg(t, S["node"] + 0.2, S["node"] + 0.9)), BONE, 0.7 * ja, 1.2)
        label(ctx, t, "签名日志", "SIGNING JOURNAL", jx, jy - 34, S["node"] + 0.4, None, size=18, alpha=a1 * (1 - 0.7 * crash), text="Signing journal")
        records = [
            ("(11, 1, \\rm{precommit}) ↦ \\tt{3a9f…}", S["node"] + 0.5),
            ("(12, 0, \\rm{propose}) ↦ \\tt{77c2…}", S["node"] + 0.6),
            ("(12, 0, \\rm{prevote}) ↦ H(m_1)", S["record"]),
        ]
        reload = S["restart"]
        for k, (txt, tk) in enumerate(records):
            if t < tk:
                continue
            y = jy + 52 + k * 62
            fresh = math.exp(-max(0.0, t - tk) * 2.0) if k == 2 else 0.0
            relit = smooth(seg(t, reload + k * 0.15, reload + 0.3 + k * 0.15)) if t > reload else 1.0
            ra = ja * relit
            fill_rect(ctx, jx + 14, y - 26, jw - 28, 42, AMBER if k == 2 else GRAPHITE, (0.10 + 0.25 * fresh if k == 2 else 0.35) * ra)
            draw_formula(ctx, txt, jx + 30, y + 2, 21, mix(BONE, AMBER_HOT, fresh) if k == 2 else DIM, ra, wipe=ease_out(seg(t, tk, tk + 0.4)))
            # Compare against the conflicting and the identical request.
            if k == 2 and S["req2"] + 0.6 < t < S["retry"]:
                bad = smooth(seg(t, S["req2"] + 0.6, S["refuse"]))
                stroke_rect(ctx, jx + 14, y - 26, jw - 28, 42, RED, ra * bad, 1.6)
            if k == 2 and S["retry"] + 0.5 < t < S["domain"]:
                ok = smooth(seg(t, S["retry"] + 0.5, S["same"]))
                stroke_rect(ctx, jx + 14, y - 26, jw - 28, 42, CYAN, ra * ok, 1.6)
        # Durable sync.
        sy = jy + jh - 30
        if t > S["sync"]:
            sp = ease_out(seg(t, S["sync"], S["sync"] + 0.35))
            line(ctx, jx + 20, sy, jx + 20 + (jw - 40) * sp, sy, AMBER_HOT, ja, 3, cap=cairo.LINE_CAP_BUTT)
            draw_text(ctx, "FSYNC", jx + jw - 20, sy - 10, "mono_m", 10.5, AMBER_HOT, ja * sp, tracking=2, align="right")
        # Requests.
        reqs = [
            (S["req1"], "⟨12, 0, \\rm{prevote}, x⟩", BONE, "m_1"),
            (S["req2"], "⟨12, 0, \\rm{prevote}, y⟩", RED, "m_2"),
            (S["retry"], "⟨12, 0, \\rm{prevote}, x⟩", CYAN, "m_1"),
        ]
        for k, (tq, txt, col, name) in enumerate(reqs):
            end = (S["req2"] if k == 0 else (S["retry"] if k == 1 else S["domain"] - 0.4))
            if not (tq <= t < end):
                continue
            ra = window(t, tq, end, 0.25, 0.35) * a1
            mv = ease_io(seg(t, tq + 0.2, tq + 0.7))
            draw_formula(ctx, f"{name} = {txt}", nx - 120, ny - 170, 24, col if k else BONE, ra)
            partial_line(ctx, nx + 40, ny - 30, jx - 8, jy + 52 + 2 * 62, mv, col if k else BONE, 0.45 * ra, 1.2)
        rf = S["refuse"]
        if rf < t < S["retry"]:
            ra = window(t, rf, S["retry"], 0.15, 0.3) * a1
            cross_mark(ctx, nx, ny, 12, RED, ra, 3)
            halo(ctx, nx, ny, 70, RED, 0.45 * ra * math.exp(-(t - rf) * 1.5))
            label(ctx, t, "冲突：拒绝签名", "CONFLICT — REFUSED", nx, ny + 146, rf, S["retry"], align="center", size=18, color=RED, alpha=a1, text="Conflict — refused")
        # Signatures leave only after the journal is durable.
        for k, (te, txt, col) in enumerate(((S["emit"], "σ_1", AMBER_HOT), (S["same"], "σ_1", CYAN))):
            if te < t < te + 1.4:
                p = ease_io(seg(t, te, te + 0.9))
                fade = 1 - seg(t, te + 1.0, te + 1.4)
                x0, y0 = jx + jw + 6, jy + 52 + 2 * 62
                px, py = lerp(x0, NET[0], p), lerp(y0, NET[1], p)
                partial_line(ctx, x0, y0, NET[0], NET[1], p, col, 0.4 * a1 * fade, 1.2)
                particle(ctx, px, py, 5, col, a1 * fade, 0.8)
                draw_formula(ctx, txt, px, py - 18, 22, col, a1 * fade, align="center")
        na2 = smooth(seg(t, S["emit"] - 0.3, S["emit"])) * a1
        if na2 > 0:
            stroke_circle(ctx, NET[0], NET[1], 22, BONE, 0.6 * na2, 1.2)
            for k in range(3):
                ang = t * 0.6 + k * math.tau / 3
                fill_circle(ctx, NET[0] + 22 * math.cos(ang), NET[1] + 22 * math.sin(ang), 3, BONE, na2)
            label(ctx, t, "网络", "NETWORK", NET[0], NET[1] + 58, S["emit"], None, align="center", size=18, alpha=a1)
        if S["same"] < t < S["domain"]:
            label(ctx, t, "相同请求 → 相同签名", "SAME REQUEST → SAME SIGNATURE", (jx + jw + NET[0]) / 2, NET[1] + 120, S["same"] + 0.2, S["domain"], align="center", size=18, color=CYAN, alpha=a1, text="Same request → same signature")

    # ---- Domain binding ------------------------------------------------------
    d0 = S["domain"]
    da = smooth(seg(t, d0, d0 + 0.5)) * out
    if da > 0:
        draw_formula(ctx, "σ = \\rm{Sign}_{sk}(\\rm{tag} ‖ \\rm{id} ‖ H(\\rm{spec}) ‖ m)", W / 2, 440, 34, BONE, da, align="center", wipe=ease_io(seg(t, d0 + 0.2, d0 + 1.1)))
        segs = [("TAG", 150, BONE), ("CHAIN ID", 200, BONE), ("H(SPEC)", 380, AMBER), ("PAYLOAD", 420, BONE)]
        total = sum(s[1] for s in segs) + 8 * (len(segs) - 1)
        for row, (y, foreign, t_row) in enumerate(((560.0, False, d0 + 0.8), (720.0, True, S["foreign"]))):
            if t < t_row:
                continue
            ra = smooth(seg(t, t_row, t_row + 0.5)) * out
            x = W / 2 - total / 2
            for k, (tag, w, col) in enumerate(segs):
                p = ease_out(seg(t, t_row + k * 0.15, t_row + 0.4 + k * 0.15))
                c = RED if (foreign and tag == "H(SPEC)") else col
                fill_rect(ctx, x, y - 22, w * p, 44, c, (0.22 if tag == "H(SPEC)" else 0.10) * ra)
                stroke_rect(ctx, x, y - 22, w * p, 44, c, 0.7 * ra, 1.2)
                if p > 0.5:
                    name = tag if not (foreign and tag == "H(SPEC)") else "H(SPEC′)"
                    draw_text(ctx, name, x + w / 2, y + 5, "mono_m", 12, c, ra * (p - 0.5) * 2, tracking=2.5, align="center")
                x += w + 8
            if not foreign:
                label(ctx, t, "本链：完整链规格参与签名", "THIS CHAIN — THE FULL SPEC IS SIGNED", W / 2 - total / 2, y + 56, t_row + 0.6, None, size=18, alpha=out, text="This chain — the full specification is signed")
            else:
                label(ctx, t, "另一条链：链 ID 相同，规格不同", "ANOTHER CHAIN — SAME ID, DIFFERENT SPEC", W / 2 - total / 2, y + 56, t_row + 0.4, None, size=18, color=RED, alpha=out, text="Another chain — same ID, different spec")
                xk = W / 2 + total / 2 + 44
                ck = smooth(seg(t, t_row + 1.0, t_row + 1.3))
                cross_mark(ctx, xk, y, 11, RED, ra * ck, 3)
                draw_formula(ctx, "H(\\rm{spec}′) ≠ H(\\rm{spec})  ⇒  \\rm{Verify} = 0", W / 2, y + 120, 28, RED, ra, align="center", wipe=ease_io(seg(t, t_row + 1.2, t_row + 2.0)), scan=RED)

    caption(ctx, t, tr("每次签名之前，先把（块组, 轮次, 阶段）对应的确切内容同步落盘。", "Before any signature, the exact payload for (chunk, round, phase) is synced to disk."), 1.2, S["crash"] - 0.1)
    caption(ctx, t, tr("冲突的请求被拒绝；完全相同的重试，得到完全相同的签名。", "A conflicting request is refused; an identical retry yields the identical signature."), S["req2"], d0 - 0.2)
    caption(ctx, t, tr("每个共识签名都绑定完整的链规格：数字链 ID 相同，也无法跨规格重放。", "Every consensus signature binds the full chain specification: an equal chain ID cannot replay across specs."), d0 + 0.3, dur - 0.5)
