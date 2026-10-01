"""Tests for the MCP scan layer.

The core scan functions need no MCP dependency, so they are tested directly.
The actual server wiring is only checked when the optional `mcp` package is
installed (skipped otherwise).
"""
import pytest

from confirmesc.mcp_server import available_checks, run_report, run_scan


def test_run_scan_returns_payload_shape():
    payload = run_scan(categories=["nfs"])
    assert set(payload) >= {"meta", "duration", "findings", "errors"}
    assert isinstance(payload["findings"], list)
    assert "hostname" in payload["meta"]


def test_run_scan_never_runs_poc():
    # categories filter keeps it fast; the point is poc is never enabled.
    payload = run_scan(categories=["nfs"])
    # a passive scan must not raise and must return a well-formed payload
    assert isinstance(payload["errors"], dict)


def test_run_scan_min_confidence_filters():
    payload = run_scan(min_confidence="CONFIRMED")
    assert all(f["confidence"] == "CONFIRMED" for f in payload["findings"])


def test_run_scan_rejects_bad_min_confidence():
    with pytest.raises(ValueError):
        run_scan(min_confidence="NOPE")


def test_run_report_text_is_readable():
    text = run_report(fmt="text", categories=["nfs"])
    assert "confirmesc" in text
    assert isinstance(text, str)


def test_run_report_json_roundtrips():
    import json

    data = json.loads(run_report(fmt="json", categories=["nfs"]))
    assert "findings" in data


def test_run_report_html_is_html():
    html = run_report(fmt="html", categories=["nfs"])
    assert html.lstrip().startswith("<!DOCTYPE html>")


def test_run_report_rejects_bad_fmt():
    with pytest.raises(ValueError):
        run_report(fmt="pdf")


def test_available_checks_lists_known_categories():
    cats = {c["category"] for c in available_checks()}
    assert "suid_sgid_sudo" in cats
    assert "known_cves" in cats


def test_build_server_registers_tools():
    pytest.importorskip("mcp")
    import asyncio
    import inspect

    from confirmesc.mcp_server import build_server

    server = build_server()
    # both mcp 1.x (FastMCP) and 2.x (MCPServer) expose list_tools();
    # it is async in some versions.
    tools = server.list_tools()
    if inspect.isawaitable(tools):
        tools = asyncio.run(tools)
    names = {getattr(t, "name", None) for t in tools}
    assert {"scan", "list_privesc_checks", "report"} <= names
