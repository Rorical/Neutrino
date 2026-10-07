"""Film post-processing: bloom, halation, chromatic fringe, vignette, grain, soft shoulder."""

from __future__ import annotations

import cv2
import numpy as np

from gfx import H, W

LUMA = np.array([0.2126, 0.7152, 0.0722], np.float32)


class Post:
    def __init__(self, bloom=0.62, grain=0.022):
        self.bloom = bloom
        self.grain = grain
        yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
        nx = (xx - W / 2) / (W / 2)
        ny = (yy - H / 2) / (H / 2)
        r2 = nx * nx * 0.75 + ny * ny * 0.9
        self.vignette = (1.0 - 0.38 * np.clip(r2, 0, 2) ** 1.25)[..., None].astype(np.float32)

        def zoom(k):
            return np.float32([[k, 0, (1 - k) * W / 2], [0, k, (1 - k) * H / 2]])

        self.zoom_r = zoom(1.0016)
        self.zoom_b = zoom(0.9984)
        self.halation = np.array([1.0, 0.78, 0.58], np.float32)

    def __call__(self, rgb: np.ndarray, frame: int) -> np.ndarray:
        hw, hh = W // 2, H // 2
        small = cv2.resize(rgb, (hw, hh), interpolation=cv2.INTER_AREA)
        lum = small @ LUMA
        weight = np.clip((lum - 0.5) / 0.45, 0, 1)
        bright = small * (weight * weight)[..., None]
        acc = cv2.GaussianBlur(bright, (0, 0), 2.5) * 0.55
        level = bright
        for sigma, wt in ((3.0, 0.65), (4.0, 0.6), (5.0, 0.55), (6.0, 0.5)):
            level = cv2.resize(level, (level.shape[1] // 2, level.shape[0] // 2), interpolation=cv2.INTER_AREA)
            blurred = cv2.GaussianBlur(level, (0, 0), sigma)
            acc += cv2.resize(blurred, (hw, hh), interpolation=cv2.INTER_LINEAR) * wt
        # A wide, warm halation under everything bright.
        wide = cv2.GaussianBlur(cv2.resize(small * weight[..., None], (hw // 8, hh // 8), interpolation=cv2.INTER_AREA), (0, 0), 6)
        acc += cv2.resize(wide, (hw, hh), interpolation=cv2.INTER_LINEAR) * self.halation * 0.35
        bloom = cv2.resize(acc, (W, H), interpolation=cv2.INTER_LINEAR)
        out = rgb + bloom * self.bloom

        r = cv2.warpAffine(out[..., 0], self.zoom_r, (W, H), flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE)
        b = cv2.warpAffine(out[..., 2], self.zoom_b, (W, H), flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE)
        out = cv2.merge([r, out[..., 1], b])
        out *= self.vignette

        rng = np.random.default_rng(frame * 7919 + 17)
        g = rng.standard_normal((hh, hw), dtype=np.float32)
        g = cv2.resize(g, (W, H), interpolation=cv2.INTER_LINEAR)
        l = out @ LUMA
        out += (g * (self.grain * (1.15 - 0.6 * np.clip(l, 0, 1))))[..., None]

        # Soft shoulder above 0.82 keeps hot cores from clipping flat.
        knee = 0.82
        over = out > knee
        out = np.where(over, knee + (1 - knee) * (1 - np.exp(-(out - knee) / (1 - knee))), out)
        np.clip(out, 0, 1, out=out)
        return (out * 255 + 0.5).astype(np.uint8)
