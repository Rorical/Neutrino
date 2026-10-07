"""Timeline and per-frame composition."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable

import cairo
import numpy as np

import scenes_a as A
import scenes_b as B
import scenes_c as C
from common import background, hud
from gfx import AMBER_HOT, H, W, seg, smooth
from post import Post


@dataclass(frozen=True)
class Scene:
    key: str
    start: float
    dur: float
    fn: Callable
    index: int = 0
    name: str = ""

    @property
    def end(self):
        return self.start + self.dur


def _build():
    spec = [
        ("intro", 13.0, A.scene_intro, 0, ""),
        ("problem", 15.0, A.scene_problem, 1, "STATE TRANSITION"),
        ("onefunc", 15.0, A.scene_onefunc, 2, "ONE TRANSITION FUNCTION"),
        ("state", 17.0, A.scene_state, 3, "STATE COMMITMENT"),
        ("blocks", 22.0, C.scene_blocks, 4, "BLOCK PRODUCTION"),
        ("consensus", 24.5, B.scene_consensus, 5, "CHUNK CONSENSUS"),
        ("facts", 16.0, C.scene_facts, 6, "CRYPTOGRAPHIC FACTS"),
        ("chunk", 17.0, B.scene_chunk, 7, "COMPLETE CHUNK PROOF"),
        ("account", 21.0, B.scene_account, 8, "ACCOUNTABILITY"),
        ("signing", 16.0, C.scene_signing, 9, "SIGNING DISCIPLINE"),
        ("history", 20.0, B.scene_history, 10, "RECURSIVE HISTORY"),
        ("prune", 14.0, B.scene_prune, 11, "PROOF-BACKED PRUNING"),
        ("outro", 15.0, B.scene_outro, 0, ""),
    ]
    out = []
    t = 0.0
    for key, dur, fn, idx, name in spec:
        out.append(Scene(key, t, dur, fn, idx, name))
        t += dur
    return out


SCENES = _build()
TOTAL = SCENES[-1].end
BOUNDARIES = [s.start for s in SCENES[1:]]
SCENE = {s.key: s for s in SCENES}
SECTIONS = max(s.index for s in SCENES)
FADE_IN, FADE_OUT = 0.45, 0.55


def scene_alpha(lt, dur):
    return smooth(seg(lt, 0, FADE_IN)) * (1 - smooth(seg(lt, dur - FADE_OUT, dur)))


def hud_alpha(t):
    a = SCENE["problem"].start - 0.3
    b = SCENE["outro"].start + 6.4
    return smooth(seg(t, a, a + 0.8)) * (1 - smooth(seg(t, b, b + 0.8)))


def transition(ctx, t):
    """A thin scan line sweeps the frame at every scene boundary."""
    for b in BOUNDARIES:
        k = (t - (b - 0.25)) / 0.7
        if 0 <= k <= 1:
            y = H * smooth(k)
            a = math.sin(k * math.pi)
            g = cairo.LinearGradient(0, y - 90, 0, y + 2)
            g.add_color_stop_rgba(0, *AMBER_HOT, 0)
            g.add_color_stop_rgba(1, *AMBER_HOT, 0.06 * a)
            ctx.set_source(g)
            ctx.rectangle(0, y - 90, W, 92)
            ctx.fill()
            ctx.set_source_rgba(*AMBER_HOT, 0.5 * a)
            ctx.rectangle(0, y, W, 1.2)
            ctx.fill()


def draw_world(ctx, t):
    active = None
    dust = 1.0
    if t < SCENE["intro"].end:
        dust = smooth(seg(t, 9.0, 11.0))
    background(ctx, t, grid_a=hud_alpha(t) * 0.9 + 0.1 * dust, dust_a=dust)
    for sc in SCENES:
        if sc.start <= t < sc.end:
            lt = t - sc.start
            a = scene_alpha(lt, sc.dur) if sc.key != "intro" else 1 - smooth(seg(lt, sc.dur - FADE_OUT, sc.dur))
            if sc.key == "outro":
                a = smooth(seg(lt, 0, FADE_IN)) * (1 - smooth(seg(lt, sc.dur - 1.4, sc.dur - 0.2)))
            active = sc
            if a <= 0.002:
                continue
            if a < 0.999:
                ctx.push_group()
                sc.fn(ctx, lt, sc.dur)
                ctx.pop_group_to_source()
                ctx.paint_with_alpha(a)
            else:
                sc.fn(ctx, lt, sc.dur)
    if active is not None:
        hud(ctx, t, hud_alpha(t), active.index, active.name, TOTAL, BOUNDARIES, SECTIONS)
    transition(ctx, t)


_post = None


def render_frame(i, fps):
    global _post
    if _post is None:
        _post = Post()
    t = i / fps
    surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, W, H)
    ctx = cairo.Context(surf)
    draw_world(ctx, t)
    surf.flush()
    arr = np.ndarray((H, W, 4), np.uint8, surf.get_data())
    rgb = arr[..., 2::-1].astype(np.float32) * (1 / 255)
    return _post(rgb, i)
