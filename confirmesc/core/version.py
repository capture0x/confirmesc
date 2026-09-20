"""Tiny dependency-free version comparator.

Handles the version strings we actually encounter here: kernel releases
("5.15.0-91-generic"), sudo releases ("1.8.31p2"), and plain dotted versions
("0.105"). Not a general-purpose semver library - deliberately small.
"""
from __future__ import annotations

import re

_NUM_RE = re.compile(r"\d+")


def parse_version(raw: str) -> tuple[int, ...]:
    """Extract the leading numeric version core as a tuple of ints.

    Only looks at the substring up to the first '-', '+' or whitespace, so
    kernel suffixes like '-91-generic' are ignored, but a sudo patch level
    like '31p2' still yields (1, 8, 31, 2).
    """
    core = re.split(r"[-+\s]", raw.strip(), maxsplit=1)[0]
    nums = _NUM_RE.findall(core)
    return tuple(int(n) for n in nums) if nums else (0,)


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    length = max(len(a), len(b))
    return a + (0,) * (length - len(a)), b + (0,) * (length - len(b))


def version_lt(a: str, b: str) -> bool:
    va, vb = parse_version(a), parse_version(b)
    va, vb = _pad(va, vb)
    return va < vb


def version_gte(a: str, b: str) -> bool:
    return not version_lt(a, b)


def in_vulnerable_range(version: str, min_version: str, max_version_exclusive: str) -> bool:
    return version_gte(version, min_version) and version_lt(version, max_version_exclusive)
