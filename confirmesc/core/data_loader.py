"""Loads the curated JSON reference data shipped in confirmesc/data/."""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources


@lru_cache(maxsize=None)
def load_gtfobins() -> dict:
    with resources.files("confirmesc.data").joinpath("gtfobins.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=None)
def load_cve_matrix() -> dict:
    with resources.files("confirmesc.data").joinpath("cve_matrix.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)
