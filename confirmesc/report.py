"""Text and JSON report rendering."""
from __future__ import annotations

import json
from dataclasses import asdict

from .core.base import Confidence, confidence_sort_key
from .core.runner import RunResult

_COLOR = {
    Confidence.CONFIRMED: "\033[91m",  # red - most actionable
    Confidence.LIKELY: "\033[93m",  # yellow
    Confidence.INFO: "\033[94m",  # blue
    Confidence.ERROR: "\033[90m",  # grey
}
_RESET = "\033[0m"


def render_text(result: RunResult, use_color: bool = True) -> str:
    lines: list[str] = []
    findings = sorted(result.findings, key=confidence_sort_key)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.confidence] = counts.get(f.confidence, 0) + 1

    lines.append("=" * 72)
    lines.append("confirmesc - Linux privilege escalation report")
    lines.append("=" * 72)
    lines.append(
        "Summary: "
        + ", ".join(f"{c}={counts.get(c, 0)}" for c in (Confidence.CONFIRMED, Confidence.LIKELY, Confidence.INFO, Confidence.ERROR))
    )
    lines.append("")

    for f in findings:
        color = _COLOR[f.confidence] if use_color else ""
        reset = _RESET if use_color else ""
        lines.append(f"{color}[{f.confidence.value}]{reset} {f.title}")
        lines.append(f"    category   : {f.category}")
        if f.cve:
            lines.append(f"    cve        : {f.cve}")
        lines.append(f"    description: {f.description}")
        if f.evidence:
            lines.append(f"    evidence   : {json.dumps(f.evidence, default=str)}")
        if f.remediation:
            lines.append(f"    fix        : {f.remediation}")
        if f.references:
            lines.append(f"    refs       : {', '.join(f.references)}")
        lines.append("")

    if result.errors:
        lines.append("-" * 72)
        lines.append(f"{len(result.errors)} check(s) failed to run completely - see ERROR findings above.")

    return "\n".join(lines)


def render_json(result: RunResult) -> str:
    payload = {
        "findings": [
            {**asdict(f), "confidence": f.confidence.value} for f in sorted(result.findings, key=confidence_sort_key)
        ],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2, default=str)
