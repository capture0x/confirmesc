"""Discovers and executes checks, collecting findings and per-check errors."""
from __future__ import annotations

import traceback
from dataclasses import dataclass, field

from .base import Check, Confidence, Finding


@dataclass
class RunResult:
    findings: list[Finding] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


def run_checks(checks: list[Check]) -> RunResult:
    result = RunResult()
    for check in checks:
        try:
            result.findings.extend(check.run())
        except Exception as exc:  # a single check must never abort the whole scan
            result.errors[check.id] = f"{exc}\n{traceback.format_exc()}"
            result.findings.append(
                Finding(
                    check_id=check.id,
                    category=check.category,
                    title=f"{check.id} check crashed",
                    confidence=Confidence.ERROR,
                    description=str(exc),
                )
            )
    return result
