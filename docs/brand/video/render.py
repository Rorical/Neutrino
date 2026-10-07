"""Render the Neutrino technical film.

    python render.py --still 6.5 42 70           # PNG stills at those seconds
    python render.py --fps 30 --from 60 --to 84  # partial preview clip
    python render.py                              # full Chinese film with soundtrack
    python render.py --lang en                    # full English film
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from multiprocessing import get_context
from pathlib import Path

os.environ.setdefault("PYTHONHASHSEED", "0")
HERE = Path(__file__).resolve().parent
OUT = HERE / "out"


def _frame(args):
    i, fps = args
    import film

    return film.render_frame(i, fps).tobytes()


def stills(times, fps):
    import film
    from PIL import Image

    OUT.mkdir(exist_ok=True)
    for s in times:
        i = round(s * fps)
        t0 = time.time()
        img = film.render_frame(i, fps)
        path = OUT / f"still_{os.environ['NEUTRINO_LANG']}_{s:07.2f}.png"
        Image.fromarray(img).save(path)
        print(f"{path.name}  {time.time() - t0:.2f}s")


def video(fps, start, end, workers, out_path, with_audio):
    import film

    OUT.mkdir(exist_ok=True)
    end = film.TOTAL if end is None else min(end, film.TOTAL)
    frames = range(round(start * fps), round(end * fps))
    cmd = [
        "ffmpeg", "-y", "-loglevel", "error",
        "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", "1920x1080", "-r", str(fps), "-i", "-",
    ]
    if with_audio:
        wav = OUT / "soundtrack.wav"
        if not wav.exists():
            import audio

            audio.write(wav)
        cmd += ["-ss", f"{start:.3f}", "-t", f"{end - start:.3f}", "-i", str(wav)]
    cmd += [
        "-c:v", "libx264", "-preset", "medium", "-crf", "17", "-pix_fmt", "yuv420p",
        "-x264-params", "aq-mode=3:aq-strength=0.9",
        "-movflags", "+faststart",
    ]
    if with_audio:
        cmd += ["-c:a", "aac", "-b:a", "256k", "-shortest"]
    cmd.append(str(out_path))
    enc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    t0 = time.time()
    n = len(frames)
    with get_context("spawn").Pool(workers) as pool:
        for k, buf in enumerate(pool.imap(_frame, ((i, fps) for i in frames), chunksize=2)):
            enc.stdin.write(buf)
            if k % fps == 0 or k == n - 1:
                el = time.time() - t0
                eta = el / (k + 1) * (n - k - 1)
                print(f"\r{k + 1}/{n} frames  {el:6.1f}s elapsed  eta {eta:6.1f}s", end="", flush=True)
    enc.stdin.close()
    enc.wait()
    print(f"\nwrote {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--still", type=float, nargs="*")
    ap.add_argument("--fps", type=int, default=60)
    ap.add_argument("--from", dest="start", type=float, default=0.0)
    ap.add_argument("--to", dest="end", type=float, default=None)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 1))
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--no-audio", action="store_true")
    ap.add_argument("--lang", choices=("zh", "en"), default="zh")
    args = ap.parse_args()
    # Workers are spawned, so they inherit the language through the environment.
    os.environ["NEUTRINO_LANG"] = args.lang
    sys.path.insert(0, str(HERE))
    if args.still:
        stills(args.still, args.fps)
        return
    full = args.start == 0 and args.end is None
    out = args.out or OUT / (f"neutrino-film-{args.lang}.mp4" if full else f"preview_{args.lang}_{args.start:g}-{args.end:g}.mp4")
    video(args.fps, args.start, args.end, args.workers, out, not args.no_audio)


if __name__ == "__main__":
    main()
