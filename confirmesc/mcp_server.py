"""confirmesc over the Model Context Protocol (MCP).

Exposes passive and active privilege-escalation scanning to any
MCP-compatible client or agent. Live exploitation (the `--poc` mode) is
intentionally NOT exposed here: confirming conditions and returning findings
is safe to automate, but actually running escalation payloads must stay a
deliberate, operator-driven step.

The scan logic lives in plain functions (`run_scan`, `available_checks`) that
need no MCP dependency, so they are unit-testable on their own; `build_server`
is the thin wrapper that turns them into MCP tools.
"""
from __future__ import annotations

from typing import Optional

from .checks import ALL_CHECKS
from .core.base import Confidence
from .core.runner import run_checks
from .report import build_report_payload

_ORDER = {
    c.value: i
    for i, c in enumerate([Confidence.CONFIRMED, Confidence.LIKELY, Confidence.INFO, Confidence.ERROR])
}


def run_scan(
    active: bool = False,
    categories: Optional[list[str]] = None,
    min_confidence: Optional[str] = None,
) -> dict:
    """Run a passive (or active) scan and return the JSON report payload.

    Never performs live exploitation (`poc` is always off). `min_confidence`,
    when given, keeps only findings at or above that level (CONFIRMED > LIKELY
    > INFO > ERROR).
    """
    if min_confidence is not None and min_confidence not in _ORDER:
        raise ValueError(
            f"min_confidence must be one of {list(_ORDER)}, got {min_confidence!r}"
        )
    checks = [
        cls(active=active, poc=False)
        for cls in ALL_CHECKS
        if not categories or cls.category in categories
    ]
    result = run_checks(checks)
    if min_confidence is not None:
        threshold = _ORDER[min_confidence]
        result.findings = [f for f in result.findings if _ORDER[f.confidence.value] <= threshold]
    return build_report_payload(result)


def available_checks() -> list[dict]:
    """The privesc checks this build ships, grouped by category."""
    groups: dict[str, dict] = {}
    for cls in ALL_CHECKS:
        g = groups.setdefault(cls.category, {"category": cls.category, "checks": []})
        g["checks"].append(cls.id)
    return list(groups.values())


def build_server():
    """Build the MCP server exposing `scan` and `list_privesc_checks`.

    Works with both the current `mcp` SDK (2.x, `MCPServer`) and the older 1.x
    line (`FastMCP`); both expose a compatible `.tool()` decorator and `.run()`.
    """
    try:  # mcp >= 2.0
        from mcp.server.mcpserver import MCPServer as _Server
    except ModuleNotFoundError:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as _Server

    server = _Server("confirmesc")

    @server.tool(
        description=(
            "Run a passive (or active) Linux privilege-escalation scan of the "
            "local system and return structured findings. Each CONFIRMED "
            "SUID/sudo/capability finding includes a ready-to-run exploit "
            "command. This tool never performs live exploitation."
        )
    )
    def scan(
        active: bool = False,
        categories: Optional[list[str]] = None,
        min_confidence: Optional[str] = None,
    ) -> dict:
        return run_scan(active=active, categories=categories, min_confidence=min_confidence)

    @server.tool(
        description="List the available privilege-escalation checks, grouped by category."
    )
    def list_privesc_checks() -> list[dict]:
        return available_checks()

    return server


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
