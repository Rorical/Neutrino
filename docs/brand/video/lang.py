"""Film language. Set NEUTRINO_LANG=en for the English cut; Chinese is the default."""

from __future__ import annotations

import os

LANG = os.environ.get("NEUTRINO_LANG", "zh")
EN = LANG == "en"


def tr(zh: str, en: str) -> str:
    return en if EN else zh


def sentence(tag: str) -> str:
    """Turn a mono tag such as 'ROUND LEADER' into 'Round leader'."""
    low = tag.lower()
    return low[:1].upper() + low[1:]


def reveal_len(text: str) -> float:
    """Character count that paces reveals; Latin letters are narrower than CJK."""
    return len(text) * (0.45 if EN else 1.0)
