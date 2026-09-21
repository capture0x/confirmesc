"""Text, HTML and JSON report rendering.

Design intent for text/HTML: a human should be able to see, in the first
screen, exactly what to act on, on which host, and when. CONFIRMED/LIKELY
findings get a full, numbered card (what it is, why, evidence, how to fix).
INFO findings are pure "reviewed, nothing wrong found yet" noise by
comparison - LinEnum/linpeas-style tools give them the same visual weight as
real findings, which is exactly the "200 lines, which ones matter?" problem
this tool exists to fix. So INFO findings are grouped by category and
collapsed to one line each; JSON output is untouched (it's for machines,
not eyes) and keeps every field in full.
"""
from __future__ import annotations

import getpass
import json
import os
import socket
from dataclasses import asdict

from .core.base import Confidence, Finding, confidence_sort_key
from .core.runner import RunResult

_COLOR = {
    Confidence.CONFIRMED: "\033[91m",  # red - most actionable
    Confidence.LIKELY: "\033[93m",  # yellow
    Confidence.INFO: "\033[94m",  # blue
    Confidence.ERROR: "\033[90m",  # grey
}
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_ACTIONABLE = (Confidence.CONFIRMED, Confidence.LIKELY)
_MAX_EVIDENCE_VALUE_LEN = 140

_CATEGORY_LABELS = {
    "suid_sgid_sudo": "SUID/SGID & sudo",
    "known_cves": "Kernel / sudo / polkit CVEs",
    "scheduled_tasks_and_path": "Cron / systemd / $PATH",
    "capabilities_and_critical_files": "Capabilities & critical files",
    "group_membership": "Group membership (docker/lxd/disk)",
    "nfs": "NFS exports",
    "wildcard_injection": "Cron wildcard injection",
    "sudo_env_keep": "sudo env_keep",
    "secrets_recon": "Credential recon",
}


def _category_label(category: str) -> str:
    return _CATEGORY_LABELS.get(category, category.replace("_", " ").title())


def _gather_meta() -> dict[str, str]:
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"
    try:
        user = getpass.getuser()
    except Exception:
        user = f"uid={os.getuid()}"
    try:
        kernel = os.uname().release
    except Exception:
        kernel = "unknown"
    return {"hostname": hostname, "user": user, "kernel": kernel}


def _stringify_evidence_value(value) -> str:
    if isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, (list, tuple)):
        text = ", ".join(str(v) for v in value) if value else "(none)"
    elif isinstance(value, dict):
        text = ", ".join(f"{k}={v}" for k, v in value.items()) if value else "(none)"
    else:
        text = str(value)
    text = " ".join(text.split())  # collapse embedded newlines/whitespace - keep each evidence entry on one line
    if len(text) > _MAX_EVIDENCE_VALUE_LEN:
        text = text[: _MAX_EVIDENCE_VALUE_LEN] + "…"
    return text


def _evidence_lines(evidence: dict) -> list[str]:
    return [
        f"{key}: {_stringify_evidence_value(value)}"
        for key, value in evidence.items()
        if value not in (None, "", [], {})
    ]


def _group_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.category, []).append(f)
    return dict(sorted(groups.items()))


# --------------------------------------------------------------------------
# text
# --------------------------------------------------------------------------


def _text_card(f: Finding, index: int, total: int, use_color: bool) -> list[str]:
    color = _COLOR[f.confidence] if use_color else ""
    bold = _BOLD if use_color else ""
    dim = _DIM if use_color else ""
    reset = _RESET if use_color else ""

    lines = [f"{color}{bold}{index}/{total} [{f.confidence.value}]{reset} {bold}{f.title}{reset}"]
    meta = f"category: {_category_label(f.category)}" + (f"   cve: {f.cve}" if f.cve else "")
    lines.append(f"  {dim}{meta}{reset}")
    lines.append(f"  {f.description}")
    if f.evidence:
        for line in _evidence_lines(f.evidence):
            lines.append(f"  {dim}· {line}{reset}")
    if f.remediation:
        lines.append(f"  {color}→ fix:{reset} {f.remediation}")
    if f.references:
        lines.append(f"  {dim}→ ref: {', '.join(f.references)}{reset}")
    lines.append("")
    return lines


def render_text(result: RunResult, use_color: bool = True, duration: float | None = None) -> str:
    findings = sorted(result.findings, key=confidence_sort_key)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.confidence] = counts.get(f.confidence, 0) + 1

    def badge(c: Confidence) -> str:
        color = _COLOR[c] if use_color else ""
        reset = _RESET if use_color else ""
        return f"{color}{c.value}={counts.get(c, 0)}{reset}"

    meta = _gather_meta()
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("confirmesc - Linux privilege escalation report")
    lines.append("=" * 72)
    duration_str = f"   duration: {duration:.1f}s" if duration is not None else ""
    lines.append(f"  host: {meta['hostname']}   user: {meta['user']}   kernel: {meta['kernel']}{duration_str}")
    lines.append("  " + "   ".join(badge(c) for c in (Confidence.CONFIRMED, Confidence.LIKELY, Confidence.INFO, Confidence.ERROR)))
    lines.append("")

    actionable = [f for f in findings if f.confidence in _ACTIONABLE]
    info_findings = [f for f in findings if f.confidence == Confidence.INFO]
    error_findings = [f for f in findings if f.confidence == Confidence.ERROR]

    if actionable:
        lines.append(f"ACTIONABLE FINDINGS ({len(actionable)})")
        lines.append("-" * 72)
        lines.append("")
        for i, f in enumerate(actionable, start=1):
            lines.extend(_text_card(f, i, len(actionable), use_color))
    else:
        lines.append("No CONFIRMED or LIKELY findings - nothing actionable found this pass.")
        lines.append("")

    if info_findings:
        lines.append("-" * 72)
        lines.append(f"CONTEXT ({len(info_findings)} reviewed, nothing confirmed exploitable) - one line each, grouped by category:")
        lines.append("-" * 72)
        for category, group in _group_by_category(info_findings).items():
            lines.append(f"  {_category_label(category)} ({len(group)}):")
            for f in group:
                lines.append(f"    · {f.title}")
        lines.append("")

    if error_findings:
        lines.append("-" * 72)
        lines.append(f"{len(error_findings)} check(s) could not complete:")
        for f in error_findings:
            lines.append(f"  · [{f.check_id}] {f.description.splitlines()[0] if f.description else f.title}")
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# html
# --------------------------------------------------------------------------

_HTML_BADGE_CLASS = {
    Confidence.CONFIRMED: "badge-confirmed",
    Confidence.LIKELY: "badge-likely",
    Confidence.INFO: "badge-info",
    Confidence.ERROR: "badge-error",
}


def _html_escape(text) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _html_card(f: Finding, index: int, total: int) -> str:
    badge = _HTML_BADGE_CLASS[f.confidence]
    evidence_html = ""
    ev_lines = _evidence_lines(f.evidence) if f.evidence else []
    if ev_lines:
        items = "".join(f"<li>{_html_escape(line)}</li>" for line in ev_lines)
        evidence_html = f'<ul class="evidence">{items}</ul>'
    refs_html = (
        '<p class="refs">refs: '
        + ", ".join(f'<a href="{_html_escape(r)}">{_html_escape(r)}</a>' for r in f.references)
        + "</p>"
        if f.references
        else ""
    )
    cve_html = f'<p class="cve">{_html_escape(f.cve)}</p>' if f.cve else ""
    return f"""
      <div class="card {badge}">
        <div class="card-head"><span class="badge {badge}">{f.confidence.value}</span> <span class="card-index">{index}/{total}</span> {_html_escape(f.title)}</div>
        <div class="card-body">
          <p class="category">{_html_escape(_category_label(f.category))}</p>
          {cve_html}
          <p>{_html_escape(f.description)}</p>
          {evidence_html}
          {f'<p class="fix"><strong>fix:</strong> {_html_escape(f.remediation)}</p>' if f.remediation else ""}
          {refs_html}
        </div>
      </div>"""


def render_html(result: RunResult, duration: float | None = None) -> str:
    findings = sorted(result.findings, key=confidence_sort_key)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.confidence] = counts.get(f.confidence, 0) + 1

    actionable = [f for f in findings if f.confidence in _ACTIONABLE]
    info_findings = [f for f in findings if f.confidence == Confidence.INFO]
    error_findings = [f for f in findings if f.confidence == Confidence.ERROR]

    actionable_html = (
        "".join(_html_card(f, i, len(actionable)) for i, f in enumerate(actionable, start=1))
        if actionable
        else '<p class="empty">No CONFIRMED or LIKELY findings this pass.</p>'
    )

    info_groups_html = "".join(
        f'<div class="info-group"><span class="info-group-name">{_html_escape(_category_label(cat))}</span>'
        + "".join(f'<span class="info-item">{_html_escape(f.title)}</span>' for f in group)
        + "</div>"
        for cat, group in _group_by_category(info_findings).items()
    )
    info_html = (
        f"""<details class="info-collapse">
          <summary>{len(info_findings)} context item(s) reviewed, nothing confirmed exploitable (click to expand)</summary>
          <div class="info-groups">{info_groups_html}</div>
        </details>"""
        if info_findings
        else ""
    )

    errors_html = (
        "<div class=\"errors\"><strong>" + str(len(error_findings)) + " check(s) could not complete:</strong><ul>"
        + "".join(f"<li>[{_html_escape(f.check_id)}] {_html_escape((f.description or '').splitlines()[0] if f.description else f.title)}</li>" for f in error_findings)
        + "</ul></div>"
        if error_findings
        else ""
    )

    summary_html = "".join(
        f'<span class="badge {_HTML_BADGE_CLASS[c]}">{c.value}: {counts.get(c, 0)}</span>'
        for c in (Confidence.CONFIRMED, Confidence.LIKELY, Confidence.INFO, Confidence.ERROR)
    )

    meta = _gather_meta()
    duration_str = f" · duration: {duration:.1f}s" if duration is not None else ""
    meta_html = (
        f"host: {_html_escape(meta['hostname'])} · user: {_html_escape(meta['user'])} · "
        f"kernel: {_html_escape(meta['kernel'])}{duration_str}"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>confirmesc report</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem 3rem; background:#0f1115; color:#e6e6e6; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1rem; text-transform: uppercase; letter-spacing: 0.04em; color:#9aa0ab; margin: 1.75rem 0 0.75rem; border-bottom: 1px solid #2a2d34; padding-bottom: 0.4rem; }}
  .meta {{ font-size:0.82rem; color:#7d8492; margin-bottom: 0.75rem; }}
  .summary {{ margin: 0.75rem 0 0.5rem; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:5px; font-size:0.8rem; font-weight:700; margin-right:6px; }}
  .badge-confirmed {{ background:#7a1f1f; color:#ffb3b3; }}
  .badge-likely {{ background:#7a5a1f; color:#ffe0a3; }}
  .badge-info {{ background:#1f3a5f; color:#a8c8ff; }}
  .badge-error {{ background:#333; color:#bbb; }}
  .card {{ border-left:3px solid #444; border-radius:6px; margin-bottom:10px; padding:10px 14px; background:#161920; }}
  .card.badge-confirmed {{ border-left-color:#c94b4b; }}
  .card.badge-likely {{ border-left-color:#c99a4b; }}
  .card-head {{ font-weight:600; margin-bottom:6px; }}
  .card-index {{ color:#6b7280; font-weight:400; font-size:0.85rem; }}
  .card-body {{ font-size:0.92rem; line-height:1.55; color:#c7cad1; }}
  .card-body p {{ margin: 0.4rem 0; }}
  .category {{ color:#7d8492; font-size:0.8rem; text-transform:uppercase; letter-spacing:0.03em; }}
  .cve {{ color:#ff9d9d; font-size:0.85rem; font-weight:600; }}
  .fix {{ color:#b7e3b0; }}
  .refs {{ font-size:0.8rem; color:#7d8492; }}
  ul.evidence {{ background:#0b0d11; border-radius:4px; padding:8px 8px 8px 22px; margin:0.5rem 0; font-size:0.82rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color:#9fd0ff; }}
  ul.evidence li {{ margin: 2px 0; }}
  .empty {{ color:#8fbf8f; }}
  a {{ color:#8ab4ff; }}
  .info-collapse {{ margin-top: 1rem; border:1px solid #2a2d34; border-radius:6px; padding:10px 14px; background:#13151a; }}
  .info-collapse summary {{ cursor:pointer; color:#9aa0ab; font-size:0.9rem; }}
  .info-groups {{ margin-top:0.75rem; }}
  .info-group {{ margin-bottom:0.6rem; }}
  .info-group-name {{ display:block; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.03em; color:#6b7280; margin-bottom:0.25rem; }}
  .info-item {{ display:inline-block; background:#1a1d24; color:#a9afba; font-size:0.78rem; padding:3px 8px; border-radius:4px; margin:2px 4px 2px 0; }}
  .errors {{ margin-top:1.5rem; color:#bbb; font-size:0.85rem; }}
</style>
</head>
<body>
  <h1>confirmesc report</h1>
  <div class="meta">{meta_html}</div>
  <div class="summary">{summary_html}</div>
  <h2>Actionable findings</h2>
  {actionable_html}
  {info_html}
  {errors_html}
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
