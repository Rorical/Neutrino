"""Procedural score and sound design, cued from the same constants the scenes use."""

from __future__ import annotations

import math
import wave
from pathlib import Path

import numpy as np

import film
import scenes_a as A
import scenes_b as B
import scenes_c as SC
from gfx import ease_out, seg

SR = 48000
RNG = np.random.default_rng(2026)


# ---------------------------------------------------------------- helpers


def note(name):
    names = {"C": 0, "C#": 1, "Db": 1, "D": 2, "D#": 3, "Eb": 3, "E": 4, "F": 5, "F#": 6, "Gb": 6, "G": 7, "G#": 8, "Ab": 8, "A": 9, "A#": 10, "Bb": 10, "B": 11}
    pitch, octave = (name[:2], name[2:]) if name[1:2] in ("#", "b") else (name[:1], name[1:])
    midi = 12 * (int(octave) + 1) + names[pitch]
    return 440.0 * 2 ** ((midi - 69) / 12)


TABLE = 4096


def _table(nh, tilt):
    ph = np.arange(TABLE) / TABLE
    w = sum(np.sin(2 * np.pi * h * ph) / h**tilt for h in range(1, nh + 1))
    return (w / np.abs(w).max()).astype(np.float32)


DARK = _table(4, 2.0)
BRIGHT = _table(11, 1.35)


def osc(table, freq, n, phase=0.0):
    ph = (phase + np.arange(n) * (freq / SR)) % 1.0
    return table[(ph * TABLE).astype(np.int32)]


def env_ar(n, attack, release):
    e = np.ones(n, np.float32)
    a = min(n, int(attack * SR))
    r = min(n, int(release * SR))
    if a:
        e[:a] = np.sin(np.linspace(0, np.pi / 2, a)) ** 2
    if r:
        e[n - r :] *= np.cos(np.linspace(0, np.pi / 2, r)) ** 2
    return e


def bandpass_noise(n, lo, hi):
    x = RNG.standard_normal(n).astype(np.float32)
    spec = np.fft.rfft(x)
    f = np.fft.rfftfreq(n, 1 / SR)
    mask = 1 / (1 + (lo / np.maximum(f, 1)) ** 4) / (1 + (f / hi) ** 4)
    return np.fft.irfft(spec * mask, n).astype(np.float32)


class Bus:
    def __init__(self, seconds):
        self.n = int(seconds * SR)
        self.L = np.zeros(self.n, np.float32)
        self.R = np.zeros(self.n, np.float32)

    def add(self, t, sig, gain=1.0, pan=0.0):
        i = int(t * SR)
        if i >= self.n or len(sig) == 0:
            return
        if i < 0:
            sig = sig[-i:]
            i = 0
        j = min(self.n, i + len(sig))
        s = sig[: j - i] * gain
        a = (pan + 1) * np.pi / 4
        self.L[i:j] += s * math.cos(a)
        self.R[i:j] += s * math.sin(a)


# ---------------------------------------------------------------- instruments


def tick(freq=4200.0, decay=0.004):
    n = int(0.03 * SR)
    t = np.arange(n) / SR
    s = np.sin(2 * np.pi * freq * t) * np.exp(-t / decay)
    s[:48] += RNG.standard_normal(48) * np.exp(-np.arange(48) / 10) * 0.6
    return s.astype(np.float32)


def blip(freq, dur=0.16, drop=0.04):
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = freq * (1 - drop * (1 - np.exp(-t * 30)))
    ph = np.cumsum(2 * np.pi * f / SR)
    s = (np.sin(ph) + 0.25 * np.sin(2 * ph)) * np.exp(-t / (dur * 0.35))
    s[:96] *= np.linspace(0, 1, 96)
    return s.astype(np.float32)


def chime(freq, length=3.0):
    n = int(length * SR)
    t = np.arange(n) / SR
    s = np.zeros(n)
    for ratio, amp, dec in ((1, 1, 1.9), (2.0, 0.42, 1.2), (2.76, 0.3, 0.9), (4.07, 0.16, 0.55), (5.43, 0.09, 0.4)):
        s += amp * np.sin(2 * np.pi * freq * ratio * t + ratio) * np.exp(-t / dec)
    s[:144] *= np.linspace(0, 1, 144)
    return (s / 1.6).astype(np.float32)


def thump(gain=1.0, f0=95.0, f1=40.0, dur=0.6):
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = f1 + (f0 - f1) * np.exp(-t * 18)
    s = np.sin(np.cumsum(2 * np.pi * f / SR)) * np.exp(-t / (dur * 0.35))
    return (s * gain).astype(np.float32)


def impact(dur=3.0):
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = 34 + 90 * np.exp(-t * 9)
    body = np.sin(np.cumsum(2 * np.pi * f / SR)) * np.exp(-t / 0.9)
    crack = bandpass_noise(n, 80, 1800) * np.exp(-t / 0.12) * 0.5
    air = bandpass_noise(n, 2000, 9000) * np.exp(-t / 0.5) * 0.08
    return (body + crack + air).astype(np.float32)


def sweep_noise(dur, f0, f1, shape="arc"):
    """Noise through a band that glides from f0 to f1 (log), with an envelope."""
    n = int(dur * SR)
    win, hop = 2048, 512
    src = RNG.standard_normal(n + win).astype(np.float32)
    out = np.zeros(n + win, np.float32)
    hann = np.hanning(win).astype(np.float32)
    freqs = np.fft.rfftfreq(win, 1 / SR)
    lf = np.log(np.maximum(freqs, 1))
    for i in range(0, n, hop):
        u = i / max(1, n)
        c = f0 * (f1 / f0) ** u
        mask = np.exp(-(((lf - math.log(c)) / 0.45) ** 2))
        spec = np.fft.rfft(src[i : i + win] * hann)
        out[i : i + win] += np.fft.irfft(spec * mask, win).astype(np.float32) * hann
    out = out[:n]
    u = np.linspace(0, 1, n)
    if shape == "arc":
        e = np.sin(np.pi * u) ** 1.6
    elif shape == "rise":
        e = u**2.2 * (1 - np.clip((u - 0.96) / 0.04, 0, 1))
    else:  # "fall"
        e = (1 - u) ** 2 * np.clip(u / 0.03, 0, 1)
    return (out * e / (np.abs(out).max() + 1e-6)).astype(np.float32)


def gliss(dur, f0, f1, gain=1.0, table=None):
    n = int(dur * SR)
    u = np.linspace(0, 1, n)
    f = f0 * (f1 / f0) ** u
    ph = np.cumsum(f / SR) % 1.0
    tb = DARK if table is None else table
    s = tb[(ph * TABLE).astype(np.int32)] * np.sin(np.pi * u) ** 1.2
    return (s * gain).astype(np.float32)


def stab(freqs, dur=2.2):
    n = int(dur * SR)
    t = np.arange(n) / SR
    s = np.zeros(n, np.float32)
    for k, f in enumerate(freqs):
        s += osc(DARK, f * (1 + 0.002 * (k - 1)), n, k * 0.13)
    s *= np.exp(-t / 0.7) * np.clip(t / 0.01, 0, 1)
    return (s / len(freqs)).astype(np.float32)


def alarm(dur=1.4):
    n = int(dur * SR)
    t = np.arange(n) / SR
    sq = lambda f: np.sin(2 * np.pi * f * t) + np.sin(6 * np.pi * f * t) / 3 + np.sin(10 * np.pi * f * t) / 5
    s = (sq(110.0) + sq(116.54)) * 0.5
    s *= (0.55 + 0.45 * np.sign(np.sin(2 * np.pi * 6 * t))) * np.exp(-t / 0.6) * np.clip(t / 0.01, 0, 1)
    return s.astype(np.float32)


def sparkle(dur, density, lo=2500, hi=6000):
    n = int(dur * SR)
    s = np.zeros(n, np.float32)
    count = int(dur * density)
    for _ in range(count):
        f = RNG.uniform(lo, hi)
        b = blip(f, 0.05, 0.0) * RNG.uniform(0.3, 1.0)
        i = RNG.integers(0, max(1, n - len(b)))
        s[i : i + len(b)] += b
    return s


# ---------------------------------------------------------------- score

CHORDS = {
    "intro": ["D2", "A2", "D3", "F3", "E4"],
    "problem": ["Bb1", "Bb2", "F3", "A3", "D4"],
    "onefunc": ["F2", "C3", "E3", "A3", "G4"],
    "state": ["C2", "G2", "D3", "E3", "B3"],
    "blocks": ["E2", "B2", "D3", "G3", "A3"],
    "facts": ["F2", "C3", "A3", "E4", "G4"],
    "signing": ["Eb2", "Bb2", "G3", "D4"],
    "consensus": ["D2", "A2", "D3", "F3", "C4"],
    "chunk": ["G1", "G2", "D3", "Bb3", "A3"],
    "account": ["A1", "A2", "E3", "G3", "Bb3"],
    "history": ["Bb1", "Bb2", "F3", "A3", "E4"],
    "prune": ["F2", "C3", "A3", "G4"],
    "outro": ["D2", "A2", "D3", "F#3", "A3", "E4"],
}


def pads(bus):
    for sc in film.SCENES:
        a = max(0.0, sc.start - 1.2) if sc.key != "intro" else 3.2
        b = min(film.TOTAL + 1.5, sc.end + 1.8)
        if sc.key == "outro":
            b = sc.end + 0.5
        n = int((b - a) * SR)
        t = np.arange(n) / SR
        e = env_ar(n, 2.4, 2.8)
        for k, nm in enumerate(CHORDS[sc.key]):
            f = note(nm)
            lvl = 0.034 if f > 120 else 0.05
            for v, (cents, pan) in enumerate(((-6, -0.55), (0, 0.0), (6, 0.55))):
                ff = f * 2 ** (cents / 1200)
                lfo = 0.5 + 0.5 * np.sin(2 * np.pi * t / (9.0 + k + v) + k * 1.7 + v)
                s = osc(DARK, ff, n, k * 0.31 + v * 0.17) * (1 - 0.35 * lfo) + osc(BRIGHT, ff, n, v * 0.23) * 0.35 * lfo
                trem = 0.85 + 0.15 * np.sin(2 * np.pi * t * (0.13 + 0.05 * v) + k)
                bus.add(a, (s * e * trem).astype(np.float32), lvl, pan)


def drone(bus):
    n = bus.n
    t = np.arange(n) / SR
    tension = np.full(n, 0.55, np.float32)
    for sc in film.SCENES:
        if sc.key in ("consensus", "account", "chunk", "signing"):
            i, j = int(sc.start * SR), int(sc.end * SR)
            tension[i:j] = 0.9
    k = int(1.5 * SR)
    kernel = np.hanning(k) / np.hanning(k).sum()
    tension = np.convolve(tension, kernel, mode="same").astype(np.float32)
    d = 0.16 * np.sin(2 * np.pi * 36.71 * t) + 0.06 * np.sin(2 * np.pi * 73.42 * t + 0.4) + 0.025 * np.sin(2 * np.pi * 110.0 * t)
    d *= tension * (0.85 + 0.15 * np.sin(2 * np.pi * t / 7.3))
    d *= env_ar(n, 7.0, 4.0) * 0.75
    bus.add(0, d.astype(np.float32), 1.0, 0.0)
    air = bandpass_noise(n, 1800, 7000) * 0.012 * (0.6 + 0.4 * np.sin(2 * np.pi * t / 13.0)) * env_ar(n, 3.0, 4.0)
    bus.L += air
    bus.R += np.roll(air, 1733)


def cues(sfx, low):
    S = film.SCENE
    pent = [note(n) for n in ("D5", "E5", "G5", "A5", "C6", "D6", "E6", "G6", "A6", "C7")]

    # Intro ----------------------------------------------------------
    for t0, _, _ in A.BOOT:
        for k in range(14):
            sfx.add(t0 + k * 0.035, tick(3800 + 300 * (k % 3)), 0.10, -0.4)
    sfx.add(0.9, gliss(2.2, 180, 720, 0.6, BRIGHT), 0.05, 0.2)
    sfx.add(4.2, blip(1760, 0.12), 0.14, 0.3)
    sfx.add(4.36, blip(1760, 0.12), 0.11, 0.3)
    I = A.INTRO
    sfx.add(I["p_start"] - 0.1, sweep_noise(I["p_end"] - I["p_start"] + 0.2, 7000, 350, "arc"), 0.55, 0.5)
    low.add(I["cross"], impact(), 0.85)
    sfx.add(I["cross"], chime(note("E5")), 0.3, 0.2)
    sfx.add(I["cross"], gliss(0.6, 1800, 3600, 1.0, BRIGHT), 0.05, -0.3)
    sfx.add(I["land"], chime(note("E6"), 4.0), 0.38, -0.2)
    low.add(I["land"], thump(1.0, 80, 38, 0.8), 0.45)
    for k in range(3):
        sfx.add(I["callouts"][0] + 0.45 + k * 0.25, tick(5200), 0.16, (-0.5, 0.5, -0.3)[k])
    sfx.add(I["move"][0], sweep_noise(1.2, 400, 2400, "arc"), 0.14)
    sfx.add(I["word"][0], sweep_noise(1.0, 2500, 9000, "rise"), 0.12, 0.3)
    sfx.add(I["word"][1], chime(note("A5"), 4.0), 0.22, 0.1)

    # Section hits ---------------------------------------------------
    for sc in film.SCENES[1:-1]:
        low.add(sc.start + 0.12, thump(1.0, 90, 42, 0.7), 0.42)
        sfx.add(sc.start - 0.3, sweep_noise(0.8, 600, 5000, "arc"), 0.10)
        for k in range(10):
            sfx.add(sc.start + 0.2 + k * 0.05, tick(4400), 0.06, -0.6)

    # 01 problem -----------------------------------------------------
    s = S["problem"].start
    P = A.PROB
    for k in range(8):
        sfx.add(s + 0.8 + k * 0.12, blip(pent[k % 6] / 2, 0.14), 0.08, -0.6 + k * 0.17)
    r0, r1 = P["replay"]
    sfx.add(s + r0, gliss(r1 - r0, 110, 220, 1.0, BRIGHT), 0.05)
    span = A.NODE_X[-1] + 110 - A.NODE_X[0]
    for x in A.NODE_X:
        sfx.add(s + r0 + (x - A.NODE_X[0]) / span * (r1 - r0), tick(2600), 0.18, (x - 960) / 1200)
    tt = 4.4
    while tt < r1:
        u = seg(tt, 4.4, r1)
        sfx.add(s + tt, tick(5600), 0.035 + 0.03 * u, 0.6)
        tt += 1 / (6 + 40 * u)
    sfx.add(s + P["swap"] - 0.5, sweep_noise(0.7, 5000, 500, "fall"), 0.22)
    for k in range(7):
        sfx.add(s + P["proofs"] + k * 0.1, blip(pent[k + 2], 0.25, 0.0), 0.10, -0.6 + k * 0.2)
    sfx.add(s + P["proofs"] + 0.7, chime(note("D6"), 3.0), 0.14)
    for k in range(8):
        sfx.add(s + P["checks"] + k * 0.08, tick(3000), 0.1, -0.6 + k * 0.17)

    # 02 one function ------------------------------------------------
    s = S["onefunc"].start
    O = A.ONE
    low.add(s + O["core"], thump(1.0, 70, 36, 0.9), 0.4)
    sfx.add(s + O["core"], chime(note("A3"), 3.5), 0.18)
    sfx.add(s + O["branches"], sweep_noise(1.0, 500, 2500, "arc"), 0.1)
    for k in range(6):
        sfx.add(s + O["boxes"] + k * 0.06, tick(4000), 0.08, 0.3)
    tt = 3.3
    while tt < 9.0:
        sfx.add(s + tt, tick(6200, 0.002), 0.035, -0.2)
        tt += 0.21
    sfx.add(s + 4.0, blip(note("A5"), 0.2), 0.12, 0.5)
    t0, t1 = O["trace"]
    for c in range(A.COLS):
        sfx.add(s + t0 + c * (t1 - t0 - 0.4) / A.COLS, blip(pent[(c * 3) % 8] / 2, 0.09), 0.06, 0.2)
    sfx.add(s + O["poly"][0], gliss(1.0, 400, 900, 1.0, BRIGHT), 0.06, 0.2)
    sfx.add(s + O["commit"][0], sweep_noise(0.7, 6000, 300, "rise"), 0.25, 0.2)
    sfx.add(s + O["commit"][1], chime(note("E6")), 0.3, 0.2)
    sfx.add(s + O["travel"][1], blip(note("A5"), 0.2), 0.12, 0.5)
    sfx.add(s + O["same"], stab([note(n) for n in ("F3", "A3", "C4", "E4")]), 0.32)
    sfx.add(s + O["formula"], sweep_noise(1.2, 800, 4000, "arc"), 0.06)

    # 03 state -------------------------------------------------------
    s = S["state"].start
    ST = A.STATE
    for i in range(A.NLEAF):
        sfx.add(s + ST["leaves"][0] + i * 0.03, tick(3000 + 60 * i), 0.05, -0.7 + i * 0.045)
    h0, h1 = ST["hash"]
    for lv in range(A.DEPTH, -1, -1):
        lt = h0 + (A.DEPTH - lv) * (h1 - h0) / A.DEPTH
        sfx.add(s + lt + 0.3, blip(pent[A.DEPTH - lv] / 2, 0.22, 0.0), 0.1)
    sfx.add(s + h1, chime(note("A5")), 0.26)
    for k in range(3):
        sfx.add(s + ST["touch"] + k * 0.1, blip(note("D5"), 0.12), 0.08, (-0.5, 0.2, 0.3)[k])
    sfx.add(s + ST["path"][0], sweep_noise(1.4, 800, 5000, "rise"), 0.09)
    low.add(s + ST["write"], thump(1.0, 100, 45, 0.5), 0.3)
    rp0, rp1 = ST["ripple"]
    for k in range(A.DEPTH + 1):
        sfx.add(s + rp0 + k / A.DEPTH * (rp1 - rp0), blip(pent[k + 2], 0.2, 0.0), 0.11, 0.0)
    sfx.add(s + rp1, chime(note("C6")), 0.26)
    sfx.add(s + ST["absent"], chime(note("A3"), 2.5), 0.15, 0.5)
    sfx.add(s + ST["probe"], gliss(0.9, 900, 300, 1.0, BRIGHT), 0.06, -0.3)
    sfx.add(s + ST["probe"] + 0.95, alarm(1.0), 0.16, -0.3)

    # Block production -----------------------------------------------
    s = S["blocks"].start
    K = SC.BLK
    for slot, ts in enumerate(K["slots"]):
        for i in range(SC.LOT_N):
            sfx.add(s + ts + i * 0.06, tick(3000 + 220 * i, 0.003), 0.07, -0.6 + i * 0.15)
            if SC._eligible(slot, i):
                sfx.add(s + ts + 0.45 + i * 0.06, blip(pent[i % 6 + 2], 0.25, 0.0), 0.14, -0.6 + i * 0.15)
        sfx.add(s + ts + 0.9, tick(2400, 0.006), 0.12, 0.6)
    sfx.add(s + 1.0, sweep_noise(1.0, 800, 4000, "arc"), 0.06, 0.4)
    sfx.add(s + 1.6, sweep_noise(1.0, 800, 4000, "arc"), 0.06, 0.4)
    b0 = K["build"]
    low.add(s + b0, thump(1.0, 85, 40, 0.7), 0.4)
    for j in range(7):
        tj = b0 + 2.1 if j == 3 else (b0 + 3.4 if j == 6 else b0 + 0.4 + j * 0.32)
        sfx.add(s + tj, tick(3900, 0.004), 0.12, 0.1)
    for k in range(6):
        sfx.add(s + b0 + 1.5 + k * 0.18, tick(2600, 0.005), 0.07, -0.5)
    sfx.add(s + b0 + 2.1, chime(note("A5"), 2.5), 0.16)
    sfx.add(s + b0 + 2.8, chime(note("E6"), 3.0), 0.26, 0.4)
    c0 = K["chain"]
    for j in range(11):
        sfx.add(s + c0 + 0.2 + j * 0.3, blip(pent[j % 7] / 2, 0.14), 0.07, -0.7 + j * 0.14)
    sfx.add(s + c0 + 0.2 + 3 * 0.3 + 0.05, blip(note("F5"), 0.14), 0.06, -0.2)
    sfx.add(s + K["invalid"], alarm(1.2), 0.2, -0.2)
    low.add(s + K["invalid"], thump(1.0, 70, 35, 0.6), 0.3)
    for n in range(2):
        sfx.add(s + K["brackets"] + n * 0.5, gliss(0.5, 500, 900, 1.0, BRIGHT), 0.05, -0.3 + n * 0.5)
    sfx.add(s + K["cand"], sweep_noise(1.2, 600, 4000, "arc"), 0.14, 0.6)
    sfx.add(s + K["cand"] + 0.9, chime(note("D6"), 3.0), 0.24, 0.6)

    # 04 consensus ---------------------------------------------------
    s = S["consensus"].start
    C = B.CONS
    for i in range(B.NV):
        sfx.add(s + C["wheel"][0] + i * 0.05, tick(2800 + 90 * i), 0.06, math.cos(B.AMID[i]) * 0.7)
    for k in range(4):
        sfx.add(s + C["cand"][0] + k * 0.12, blip(pent[k + 4], 0.12), 0.06, -0.5)
    sfx.add(s + C["cand"][1], chime(note("D6"), 2.5), 0.16)
    l0, l1 = C["leader"]
    prev = -1
    tt = l0
    while tt < l1:
        idx = min(B.LEADER, int(ease_out(seg(tt, l0, l1), 2) * (B.LEADER + 1)))
        if idx != prev:
            sfx.add(s + tt, tick(3600), 0.2, math.cos(B.AMID[idx]) * 0.7)
            prev = idx
        tt += 1 / 240
    sfx.add(s + C["propose"][0], sweep_noise(1.0, 300, 3000, "fall"), 0.22, 0.5)
    for i, ti in B.PV_T.items():
        sfx.add(s + ti + 0.35, blip(1200 + 1600 * B.STAKE[i] / B.STAKE.max(), 0.07), 0.06, math.cos(B.AMID[i]) * 0.8)
    for i, ti in B.PC_T.items():
        sfx.add(s + ti + 0.35, blip(1500 + 1800 * B.STAKE[i] / B.STAKE.max(), 0.07), 0.06, math.cos(B.AMID[i]) * 0.8)
    for tc, ch in ((B.PV_CROSS, ("D3", "A3", "D4", "F4")), (B.PC_CROSS, ("D3", "A3", "E4", "A4"))):
        low.add(s + tc, thump(1.0, 110, 45, 0.7), 0.55)
        sfx.add(s + tc, stab([note(n) for n in ch]), 0.3)
    tt = C["prevote"][0]
    while tt < C["agg"][0]:
        low.add(s + tt, thump(1.0, 60, 40, 0.35), 0.16)
        tt += 0.5
    sfx.add(s + C["agg"][0], sweep_noise(C["agg"][1] - C["agg"][0], 6000, 400, "rise"), 0.25)
    sfx.add(s + C["agg"][1], chime(note("D6"), 3.5), 0.32)
    low.add(s + C["agg"][1], impact(2.0), 0.35)
    i0 = C["inter"][0]
    sfx.add(s + i0 + 0.1, gliss(0.8, 300, 600, 1.0), 0.07, 0.5)
    sfx.add(s + i0 + 0.8, gliss(0.8, 450, 900, 1.0), 0.07, -0.5)
    sfx.add(s + i0 + 1.8, chime(note("A5")), 0.18, -0.2)
    sfx.add(s + i0 + 1.8, chime(note("E6")), 0.14, 0.2)
    L0 = C["live"]
    sfx.add(s + L0 + 0.9, alarm(1.4), 0.2, 0.4)
    for i, ti in B.NIL_T.items():
        sfx.add(s + ti + 0.35, blip(700, 0.05), 0.05, math.cos(B.AMID[i]) * 0.8)
    low.add(s + B.NIL_CROSS, thump(1.0, 80, 40, 0.6), 0.4)
    sfx.add(s + B.NIL_CROSS, sweep_noise(0.9, 400, 4000, "arc"), 0.15)
    sfx.add(s + L0 + 4.2, blip(note("A5"), 0.2), 0.14, -0.4)
    sfx.add(s + L0 + 4.4, sweep_noise(1.0, 300, 3000, "fall"), 0.18, -0.4)

    # Cryptographic facts --------------------------------------------
    s = S["facts"].start
    F_ = SC.FACT
    for i in range(len(SC.SOURCES)):
        sfx.add(s + F_["tiles"] + i * 0.13, tick(3400 + 120 * i, 0.004), 0.08, -0.6)
        sfx.add(s + F_["coef"] + i * 0.1, blip(pent[i % 8 + 1], 0.12, 0.0), 0.08, -0.5)
    m0, m1 = F_["merge"]
    sfx.add(s + m0, sweep_noise(m1 - m0, 5000, 400, "rise"), 0.24)
    low.add(s + F_["check"], thump(1.0, 100, 45, 0.6), 0.4)
    sfx.add(s + F_["check"], stab([note(n) for n in ("F3", "A3", "C4", "E4")]), 0.3)
    sfx.add(s + F_["cancel"], gliss(0.6, 220, 207, 1.0), 0.08)
    sfx.add(s + F_["cancel"] + 1.0, chime(note("A5"), 2.0), 0.16)
    p0, p1 = F_["proof"]
    sfx.add(s + p0, sweep_noise(p1 - p0, 6000, 300, "rise"), 0.28)
    sfx.add(s + p1, chime(note("E6"), 3.5), 0.32)
    low.add(s + p1, impact(2.0), 0.4)
    for k in range(2):
        sfx.add(s + F_["reuse"] + k * 0.4, sweep_noise(0.8, 800, 3500, "arc"), 0.12, 0.6)
        sfx.add(s + F_["reuse"] + k * 0.4 + 0.8, blip(note("A5") * (1 + 0.5 * k), 0.2), 0.12, 0.6)

    # 05 chunk -------------------------------------------------------
    s = S["chunk"].start
    K = B.CHUNK
    e0 = s + K["engine"][0]
    e1 = s + K["emit"][1]
    n = int((e1 - e0) * SR)
    tl = np.arange(n) / SR + K["engine"][0]
    absorbed = np.zeros(n)
    for L_ in B.LAUNCH:
        absorbed += tl > L_ + 1.3
    spin = np.clip((tl - K["spin"][0]) / (K["spin"][1] - K["spin"][0]), 0, 1) ** 2
    f = 55 * (1 + 0.08 * absorbed + 1.2 * spin)
    ph = np.cumsum(f / SR) % 1.0
    hum = BRIGHT[(ph * TABLE).astype(np.int32)] * (0.3 + 0.08 * absorbed + 0.5 * spin)
    hum *= env_ar(n, 0.8, 0.25)
    sfx.add(e0, hum.astype(np.float32), 0.07)
    for k, L_ in enumerate(B.LAUNCH):
        sfx.add(s + L_, sweep_noise(0.7, 1200, 5000, "rise"), 0.08, -0.6)
        sfx.add(s + L_ + 1.1, blip(pent[k + 2], 0.18, 0.0), 0.12, -0.1)
    for tchk in K["checks"]:
        sfx.add(s + tchk, tick(3400), 0.18, 0.5)
    sfx.add(s + K["spin"][0], sweep_noise(K["spin"][1] - K["spin"][0], 300, 7000, "rise"), 0.3)
    low.add(s + K["emit"][0], impact(), 0.9)
    sfx.add(s + K["emit"][0], chime(note("E6"), 4.0), 0.36, 0.3)
    sfx.add(s + K["card"][0], sweep_noise(1.2, 900, 4000, "arc"), 0.07, 0.5)

    # 06 accountability ----------------------------------------------
    s = S["account"].start
    Q = B.ACC
    low.add(s + Q["node"], thump(1.0, 80, 40, 0.5), 0.3)
    sfx.add(s + Q["emit"][0], blip(note("E5"), 0.3), 0.14, 0.2)
    sfx.add(s + Q["emit"][0] + 0.25, blip(note("F5"), 0.3), 0.14, -0.2)
    sfx.add(s + Q["detect"][0], alarm(1.6), 0.3)
    low.add(s + Q["detect"][0], thump(1.0, 70, 35, 0.8), 0.4)
    sfx.add(s + Q["formula"], sweep_noise(1.2, 800, 4000, "arc"), 0.06)
    sfx.add(s + Q["capture"][0], sweep_noise(Q["capture"][1] - Q["capture"][0], 5000, 400, "rise"), 0.25, 0.3)
    sfx.add(s + Q["pev"], chime(note("E6")), 0.22, 0.3)
    sfx.add(s + Q["pev"], chime(note("F6")), 0.12, 0.3)
    sfx.add(s + Q["travel"][0], sweep_noise(Q["travel"][1] - Q["travel"][0], 800, 3000, "arc"), 0.12, 0.6)
    low.add(s + Q["travel"][1], thump(1.0, 120, 50, 0.4), 0.35)
    sfx.add(s + Q["exec"][0], gliss(Q["exec"][1] - Q["exec"][0], 300, 700, 1.0, BRIGHT), 0.05, 0.6)
    low.add(s + Q["slash"], impact(2.5), 0.8)
    sfx.add(s + Q["slash"], bandpass_noise(int(0.5 * SR), 200, 3000) * np.exp(-np.arange(int(0.5 * SR)) / SR / 0.08), 0.25, -0.5)
    sfx.add(s + Q["slash"] + 0.6, tick(2200, 0.008), 0.25, -0.5)
    for k in range(10):
        sfx.add(s + Q["window"] + k * 0.03, tick(3200 + 80 * k), 0.06, -0.6 + k * 0.08)

    # Signing discipline ---------------------------------------------
    s = S["signing"].start
    G = SC.SIGN
    low.add(s + G["node"], thump(1.0, 80, 40, 0.5), 0.3)
    for k, tq in enumerate((G["req1"], G["req2"], G["retry"])):
        sfx.add(s + tq, blip((note("E5"), note("F5"), note("E5"))[k], 0.2), 0.12, -0.5)
    sfx.add(s + G["record"], tick(3600, 0.005), 0.2, 0.0)
    sfx.add(s + G["sync"], gliss(0.35, 900, 1800, 1.0, BRIGHT), 0.08)
    sfx.add(s + G["sync"] + 0.35, tick(2200, 0.01), 0.22)
    for te in (G["emit"], G["same"]):
        sfx.add(s + te, sweep_noise(0.9, 900, 3500, "arc"), 0.12, 0.6)
    sfx.add(s + G["same"] + 0.9, chime(note("A5"), 2.5), 0.22, 0.6)
    n = int(0.9 * SR)
    burst = bandpass_noise(n, 300, 6000) * (np.sign(np.sin(2 * np.pi * 23 * np.arange(n) / SR)) * 0.5 + 0.5) * np.exp(-np.arange(n) / SR / 0.4)
    sfx.add(s + G["crash"], burst.astype(np.float32), 0.25)
    low.add(s + G["crash"], thump(1.0, 60, 30, 0.8), 0.45)
    sfx.add(s + G["restart"], gliss(0.8, 200, 800, 1.0, BRIGHT), 0.07)
    for k in range(3):
        sfx.add(s + G["restart"] + k * 0.15, tick(3000), 0.1)
    sfx.add(s + G["refuse"], alarm(1.2), 0.22, -0.4)
    sfx.add(s + G["domain"], sweep_noise(1.2, 800, 4000, "arc"), 0.08)
    for k in range(4):
        sfx.add(s + G["domain"] + 0.8 + k * 0.15, tick(3200 + 300 * k), 0.1)
        sfx.add(s + G["foreign"] + k * 0.15, tick(2800 + 300 * k), 0.1)
    sfx.add(s + G["foreign"] + 1.0, alarm(1.0), 0.2)
    low.add(s + G["foreign"] + 1.0, thump(1.0, 70, 35, 0.6), 0.3)

    # 07 history -----------------------------------------------------
    s = S["history"].start
    for k in range(B.NCH + B.GROW_EXTRA):
        live = k < B.NCH
        sfx.add(s + B.chunk_time(k), tick(5200, 0.003), 0.06 if live else 0.025, -0.7 + (k % 32) * 0.04)
    for g, tf in enumerate(B.FOLD_TIMES):
        live = g < B.NCH // B.BATCH
        if live:
            sfx.add(s + tf - 0.3, sweep_noise(0.3, 1500, 5000, "rise"), 0.05, 0.1)
            sfx.add(s + tf, blip(pent[min(g, 9)], 0.3, 0.0), 0.12, -0.4 + g * 0.1)
        else:
            sfx.add(s + tf, blip(pent[g % 5 + 3], 0.12, 0.0), 0.05, 0.5)
    tl = B.HIST["last_live_fold"]
    sfx.add(s + tl, chime(note("D5"), 4.0), 0.3)
    sfx.add(s + tl, stab([note(n) for n in ("Bb2", "F3", "A3", "D4")]), 0.2)
    sfx.add(s + 1.6, sweep_noise(1.0, 800, 4000, "arc"), 0.05)
    sfx.add(s + 3.4, sweep_noise(1.0, 800, 4000, "arc"), 0.05)
    l0, l1 = B.HIST["light"]
    sfx.add(s + l0, sweep_noise(l1 - l0, 600, 4000, "arc"), 0.14, 0.6)
    sfx.add(s + l1, chime(note("A6"), 2.5), 0.2, 0.6)
    g0, g1 = B.HIST["grow"]
    sfx.add(s + g0, sweep_noise(g1 - g0, 400, 6000, "rise"), 0.12)
    sfx.add(s + g1, chime(note("D6"), 3.0), 0.2)

    # 08 pruning -----------------------------------------------------
    s = S["prune"].start
    R = B.PRUNE
    for k in range(B.NPR):
        sfx.add(s + R["rows"] + k * 0.03, tick(3000 + 50 * k), 0.04, -0.6 + k * 0.04)
    sfx.add(s + R["cover"][0], gliss(R["cover"][1] - R["cover"][0], 500, 1000, 1.0, BRIGHT), 0.05)
    sfx.add(s + R["cover"][1], chime(note("A5")), 0.2)
    d0, d1 = R["dissolve"]
    sfx.add(s + d0, sparkle(d1 - d0, 70), 0.12, -0.3)
    sfx.add(s + d0, sweep_noise(d1 - d0, 3000, 9000, "arc"), 0.05)
    sfx.add(s + R["boot"], sweep_noise(0.9, 700, 3500, "arc"), 0.12, 0.6)
    sfx.add(s + R["boot"] + 0.9, chime(note("E6"), 2.0), 0.18, 0.6)
    f0, f1 = R["frag"]
    for j in range(8):
        sfx.add(s + f0 + j * 0.12 + 0.7, tick(3600 + 100 * j), 0.1, 0.6)
    sfx.add(s + f1, chime(note("A5"), 2.5), 0.18, 0.6)
    sfx.add(s + R["install"], stab([note(n) for n in ("F3", "C4", "A4", "G4")]), 0.3, 0.4)
    low.add(s + R["install"], thump(1.0, 90, 42, 0.7), 0.4)

    # Outro ----------------------------------------------------------
    s = S["outro"].start
    U = B.OUTRO
    for k, t0 in enumerate(U["lines"]):
        low.add(s + t0, thump(1.0, 80, 40, 0.8), 0.35)
        sfx.add(s + t0 + 0.1, chime(note(("D5", "F#5", "A5")[k]), 3.5), 0.2)
    r0, r1 = U["ring"]
    sfx.add(s + r0, sweep_noise(r1 - r0, 1500, 7000, "rise"), 0.12)
    p0, p1 = U["particle"]
    sfx.add(s + p0 - 0.1, sweep_noise(p1 - p0 + 0.2, 7000, 350, "arc"), 0.5, 0.5)
    low.add(s + p1, impact(4.0), 0.7)
    sfx.add(s + p1, chime(note("D6"), 5.0), 0.38)
    sfx.add(s + p1, chime(note("A5"), 5.0), 0.22)
    sfx.add(s + U["word"][0], sweep_noise(0.9, 2500, 9000, "rise"), 0.1, 0.3)
    sfx.add(s + U["word"][1], chime(note("F#6"), 4.0), 0.18, 0.1)


def reverb(L, R, seconds=2.8, wet=0.3):
    n = len(L)
    m = int(seconds * SR)
    t = np.arange(m) / SR
    irs = []
    for seed in (1, 2):
        r = np.random.default_rng(seed)
        ir = r.standard_normal(m) * np.exp(-t / (seconds / 6.5))
        spec = np.fft.rfft(ir)
        f = np.fft.rfftfreq(m, 1 / SR)
        ir = np.fft.irfft(spec / (1 + (f / 5000) ** 2), m)
        ir[: int(0.012 * SR)] = 0
        irs.append(ir / np.sqrt(np.sum(ir**2)))
    nfft = 1 << int(math.ceil(math.log2(n + m)))
    out = []
    for x, ir in ((L, irs[0]), (R, irs[1])):
        y = np.fft.irfft(np.fft.rfft(x, nfft) * np.fft.rfft(ir, nfft), nfft)[:n]
        out.append(y.astype(np.float32))
    return L * (1 - wet) + out[0] * wet * 2.2, R * (1 - wet) + out[1] * wet * 2.2


def loudness(mix):
    """Integrated loudness (BS.1770-style K-weighting and gating), LUFS."""
    n = len(mix)
    f = np.fft.rfftfreq(n, 1 / SR)
    shelf = 1 + (10 ** (4 / 20) - 1) * (f**2 / (f**2 + 1500.0**2))
    hp = f**2 / (f**2 + 38.0**2)
    kw = np.stack([np.fft.irfft(np.fft.rfft(mix[:, c]) * shelf * hp, n) for c in range(2)], axis=1)
    block, hop = int(0.4 * SR), int(0.1 * SR)
    ms = np.array([np.mean(kw[i : i + block] ** 2, axis=0).sum() for i in range(0, n - block, hop)])
    lk = -0.691 + 10 * np.log10(ms + 1e-12)
    g = ms[lk > -70]
    rel = -0.691 + 10 * np.log10(g.mean()) - 10
    g = ms[lk > max(-70, rel)]
    return -0.691 + 10 * np.log10(g.mean())


def render():
    total = film.TOTAL + 1.0
    music = Bus(total)
    sfx = Bus(total)
    low = Bus(total)
    pads(music)
    for ch in ("L", "R"):
        x = getattr(music, ch)
        f = np.fft.rfftfreq(len(x), 1 / SR)
        shape = 0.35 + 0.65 * f**2 / (f**2 + 240.0**2)
        setattr(music, ch, np.fft.irfft(np.fft.rfft(x) * shape, len(x)).astype(np.float32))
    drone(low)
    cues(sfx, low)
    L = music.L + sfx.L
    R = music.R + sfx.R
    L, R = reverb(L, R)
    L += low.L * 0.9
    R += low.R * 0.9
    mix = np.stack([L, R], axis=1)
    mix *= 10 ** ((-16.0 - loudness(mix)) / 20)
    ceiling = 10 ** (-1.2 / 20)
    knee = 0.6 * ceiling
    a = np.abs(mix)
    over = a > knee
    mix[over] = np.sign(mix[over]) * (knee + (ceiling - knee) * np.tanh((a[over] - knee) / (ceiling - knee)))
    n = len(mix)
    fade = np.ones(n, np.float32)
    fi, fo = int(0.8 * SR), int(2.5 * SR)
    fade[:fi] = np.linspace(0, 1, fi) ** 2
    end = int(film.TOTAL * SR)
    fade[end - fo : end] *= np.linspace(1, 0, fo) ** 1.5
    fade[end:] = 0
    return (mix * fade[:, None]).astype(np.float32)


def write(path: Path):
    mix = render()
    pcm = (np.clip(mix, -1, 1) * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(pcm.tobytes())
    print(f"wrote {path}  {len(mix) / SR:.1f}s")


if __name__ == "__main__":
    import sys

    out = Path(__file__).resolve().parent / "out"
    out.mkdir(exist_ok=True)
    write(out / "soundtrack.wav")
    sys.exit(0)
