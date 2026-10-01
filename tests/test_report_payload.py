"""Tests for the push/exfil report path: JSON payload roundtrip, meta
override in rendering, and the SSH-only `build_executor` wiring."""
import pytest

from confirmesc.cli import build_executor
from confirmesc.core.base import Confidence, Finding
from confirmesc.core.executor import LocalExecutor, SSHExecutor
from confirmesc.core.runner import RunResult
from confirmesc.report import (
    build_report_payload,
    render_text,
    result_from_payload,
)


def _sample_result() -> RunResult:
    result = RunResult()
    result.findings.append(
        Finding(
            check_id="suid_sudo",
            category="suid_sgid_sudo",
            title="Exploitable SUID binary: /usr/bin/find",
            confidence=Confidence.CONFIRMED,
            description="demo",
            evidence={"path": "/usr/bin/find", "suid": True},
            exploit_command="/usr/bin/find . -maxdepth 0 -exec /bin/bash -p ; -quit",
        )
    )
    result.errors = {"nfs": "boom"}
    return result


# -- payload roundtrip ------------------------------------------------------


def test_payload_roundtrips_findings_and_errors():
    original = _sample_result()
    payload = build_report_payload(original, duration=1.23)

    assert payload["duration"] == 1.23
    assert "meta" in payload and "hostname" in payload["meta"]

    rebuilt = result_from_payload(payload)
    assert len(rebuilt.findings) == 1
    f = rebuilt.findings[0]
    assert f.confidence is Confidence.CONFIRMED  # rebuilt as the enum, not a bare string
    assert f.title == original.findings[0].title
    assert f.exploit_command == original.findings[0].exploit_command
    assert rebuilt.errors == {"nfs": "boom"}


# -- meta override in rendering ---------------------------------------------


def test_render_text_uses_supplied_meta():
    result = _sample_result()
    meta = {"hostname": "victim-box", "user": "www-data", "kernel": "5.15.0"}
    text = render_text(result, use_color=False, duration=2.0, meta=meta)
    assert "victim-box" in text
    assert "www-data" in text


# -- build_executor wiring --------------------------------------------------


def test_build_executor_defaults_to_local():
    assert isinstance(build_executor(None), LocalExecutor)


def test_build_executor_parses_ssh():
    ex = build_executor("ssh://op@10.0.0.5:2222")
    assert isinstance(ex, SSHExecutor)
    assert ex.host == "10.0.0.5"
    assert ex.user == "op"
    assert ex.port == 2222


def test_build_executor_rejects_removed_shell_scheme():
    # raw-shell transport was removed; shell:// must no longer be accepted.
    with pytest.raises(SystemExit):
        build_executor("shell://0.0.0.0:4444")


def test_build_executor_rejects_unknown_scheme():
    with pytest.raises(SystemExit):
        build_executor("http://example.com")
