# Neutrino technical film

A ~3:45 sci-fi technical film, in Chinese and English, about how Neutrino works, rendered entirely by the
code in this directory: pycairo draws each frame, numpy/OpenCV apply bloom,
halation, chromatic fringe, vignette and grain, and ffmpeg encodes. The score and
sound design are synthesised in numpy (`audio.py`) from the same timing constants
the scenes use, so every cue lands on its visual event.

The film explains principles, not libraries, in eleven sections: state transition
`S_{n+1} = F(S_n, B_n)`; one transition function compiled for execution and for
proving; authenticated state trees and witnesses; block production (stake-weighted
VRF slot lottery, header commitments, block proofs, proven fork choice, K-height
chunks); two 2/3 quorums and their intersection, nil votes and certified round
changes; random-weighted batch signature checks compressed into fact proofs;
complete chunk proofs; provable equivocation, the mandatory sanction queue and
retrievable signed evidence; the durable signing journal and full-spec signing
domain; history folded into one constant-size proof that absorbs the previous
proof at every step; and proof-backed pruning with snapshot bootstrap. The palette is warm matter (amber, bone, graphite, signal red); the only
cool colours belong to the brand mark and to proofs, drawn as the mark's particle.

## Render

Requires Python 3.12 with `pycairo`, `numpy`, `opencv-python`, `Pillow`,
`fontTools`, plus `ffmpeg`. Fonts: the brand's Space Grotesk (`../fonts`) and
macOS system fonts (Hiragino Sans GB, SF Mono, STIX Two).

```text
python render.py --still 6.5 42 70            # PNG stills (seconds) into out/
python render.py --fps 30 --from 60 --to 84   # partial preview clip
python render.py                               # full 1080p60 Chinese film with soundtrack
python render.py --lang en                     # the English cut
python audio.py                                # soundtrack only (out/soundtrack.wav)
```

## Layout

| File | Role |
| --- | --- |
| `film.py` | Scene timeline and per-frame composition |
| `scenes_a.py` | Intro (detector wall → animated mark), 01 state transition, 02 one function, 03 state commitment |
| `scenes_b.py` | 05 chunk consensus, 07 complete chunk proof, 08 accountability, 10 recursive history, 11 pruning, outro |
| `scenes_c.py` | 04 block production, 06 cryptographic facts, 09 signing discipline |
| `lang.py` | Language switch (`NEUTRINO_LANG=zh/en`); every on-screen string has both versions |
| `logo.py` | The mark from its construction grid, plus the outlined wordmark parsed from `../neutrino-logo-dark.svg` |
| `common.py` | Background, HUD, title blocks, captions |
| `gfx.py` | Palette, easing, text and formula layout, shapes |
| `post.py` | Film post-processing |
| `audio.py` | Procedural score and cue sheet |
| `render.py` | Stills, previews and the full encode |
