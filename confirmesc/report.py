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


_HTML_BADGE_CLASS = {
    Confidence.CONFIRMED: "badge-confirmed",
    Confidence.LIKELY: "badge-likely",
    Confidence.INFO: "badge-info",
    Confidence.ERROR: "badge-error",
}


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_html(result: RunResult) -> str:
    findings = sorted(result.findings, key=confidence_sort_key)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.confidence] = counts.get(f.confidence, 0) + 1

    rows = []
    for f in findings:
        badge = _HTML_BADGE_CLASS[f.confidence]
        evidence_html = (
            f"<pre>{_html_escape(json.dumps(f.evidence, indent=2, default=str))}</pre>" if f.evidence else ""
        )
        refs_html = (
            "<p><strong>refs:</strong> "
            + ", ".join(f'<a href="{_html_escape(r)}">{_html_escape(r)}</a>' for r in f.references)
            + "</p>"
            if f.references
            else ""
        )
        cve_html = f'<p><strong>cve:</strong> {_html_escape(f.cve)}</p>' if f.cve else ""
        rows.append(
            f"""
        <details class="finding {badge}">
          <summary><span class="badge {badge}">{f.confidence.value}</span> {_html_escape(f.title)}</summary>
          <div class="finding-body">
            <p><strong>category:</strong> {_html_escape(f.category)}</p>
            {cve_html}
            <p>{_html_escape(f.description)}</p>
            {evidence_html}
            {f'<p><strong>fix:</strong> {_html_escape(f.remediation)}</p>' if f.remediation else ""}
            {refs_html}
          </div>
        </details>"""
        )

    summary_html = "".join(
        f'<span class="badge {_HTML_BADGE_CLASS[c]}">{c.value}: {counts.get(c, 0)}</span>'
        for c in (Confidence.CONFIRMED, Confidence.LIKELY, Confidence.INFO, Confidence.ERROR)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>confirmesc report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; background:#0f1115; color:#e6e6e6; }}
  h1 {{ font-size: 1.4rem; }}
  .summary {{ margin: 1rem 0 1.5rem; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.8rem; font-weight:600; margin-right:6px; }}
  .badge-confirmed {{ background:#7a1f1f; color:#ffb3b3; }}
  .badge-likely {{ background:#7a5a1f; color:#ffe0a3; }}
  .badge-info {{ background:#1f3a5f; color:#a8c8ff; }}
  .badge-error {{ background:#333; color:#bbb; }}
  details.finding {{ border:1px solid #2a2d34; border-radius:6px; margin-bottom:8px; padding:8px 12px; background:#161920; }}
  details.finding summary {{ cursor:pointer; font-weight:500; }}
  .finding-body {{ margin-top:8px; font-size:0.92rem; line-height:1.5; }}
  .finding-body pre {{ background:#0b0d11; padding:8px; border-radius:4px; overflow-x:auto; font-size:0.8rem; }}
  a {{ color:#8ab4ff; }}
</style>
</head>
<body>
  <h1>confirmesc report</h1>
  <div class="summary">{summary_html}</div>
  {"".join(rows) if rows else "<p>No findings.</p>"}
</body>
</html>
"""


def render_json(result: RunResult) -> str:
    payload = {
        "findings": [
            {**asdict(f), "confidence": f.confidence.value} for f in sorted(result.findings, key=confidence_sort_key)
        ],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2, default=str)
