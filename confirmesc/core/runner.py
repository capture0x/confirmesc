"""Discovers and executes checks, collecting findings and per-check errors.

Checks are independent (each opens its own subprocesses/files) and mostly
I/O-bound (waiting on `find`, `getcap`, `sudo`, ...), so we run them
concurrently in a small thread pool. This is a real wall-clock win: the
SUID/SGID `find /` walk and the `getcap -r /` walk are each the slowest
single step, and running them in parallel with everything else instead of
back-to-back roughly halves total scan time on a typical filesystem.
"""
from __future__ import annotations

import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from .base import Check, Confidence, Finding


@dataclass
class RunResult:
    findings: list[Finding] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    durations: dict[str, float] = field(default_factory=dict)


def _run_one(check: Check) -> tuple[str, list[Finding], Optional[str], float]:
    start = time.monotonic()
    try:
        findings = check.run()
        return check.id, findings, None, time.monotonic() - start
    except Exception as exc:  # a single check must never abort the whole scan
        error = f"{exc}\n{traceback.format_exc()}"
        crash_finding = Finding(
            check_id=check.id,
            category=check.category,
            title=f"{check.id} check crashed",
            confidence=Confidence.ERROR,
            description=str(exc),
        )
        return check.id, [crash_finding], error, time.monotonic() - start


def run_checks(
    checks: list[Check],
    max_workers: int = 6,
    on_check_done: Optional[Callable[[str, float], None]] = None,
) -> RunResult:
    result = RunResult()
    if not checks:
        return result

    with ThreadPoolExecutor(max_workers=min(max_workers, len(checks))) as pool:
        futures = {pool.submit(_run_one, check): check for check in checks}
        for future in as_completed(futures):
            check_id, findings, error, duration = future.result()
            result.findings.extend(findings)
            result.durations[check_id] = duration
            if error:
                result.errors[check_id] = error
            if on_check_done:
                on_check_done(check_id, duration)
    return result
