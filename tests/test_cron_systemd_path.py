import os
from unittest.mock import patch

from confirmesc.checks.cron_systemd_path import CronSystemdPathCheck
from confirmesc.core.base import Confidence


def test_check_target_writable_file_is_confirmed(tmp_path):
    script = tmp_path / "backup.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    os.chmod(script, 0o666)  # world-writable

    check = CronSystemdPathCheck()
    findings = check._check_target(str(script), "test context")

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].evidence["check"] == "file writable"


def test_check_target_not_writable_but_dir_writable(tmp_path):
    script = tmp_path / "backup.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    os.chmod(script, 0o444)  # read-only file
    os.chmod(tmp_path, 0o777)  # but writable directory

    check = CronSystemdPathCheck()
    findings = check._check_target(str(script), "test context")

    assert len(findings) == 1
    assert findings[0].evidence["check"] == "directory writable"


def test_check_target_neither_writable_is_clean(tmp_path):
    script = tmp_path / "backup.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    os.chmod(script, 0o444)
    os.chmod(tmp_path, 0o555)

    check = CronSystemdPathCheck()
    findings = check._check_target(str(script), "test context")

    assert findings == []


def test_check_target_skips_dev_and_container_noise():
    check = CronSystemdPathCheck()
    assert check._check_target("/dev/null", "ctx") == []
    assert check._check_target("/var/lib/docker/overlay2/abc/diff/usr/bin/x", "ctx") == []


def test_parse_crontab_commands_ignores_redirection_target(tmp_path):
    cron_file = tmp_path / "cron.d-fake"
    cron_file.write_text("* * * * * root somecommand > /dev/null 2>&1\n")

    check = CronSystemdPathCheck()
    findings = check._parse_crontab_commands(str(cron_file))

    # /dev/null is skipped by _check_target's noise filter, and
    # 'somecommand' isn't an absolute path, so nothing should fire here.
    assert findings == []


def test_parse_crontab_commands_finds_real_writable_script(tmp_path):
    script = tmp_path / "job.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    os.chmod(script, 0o666)
    cron_file = tmp_path / "cron.d-fake"
    cron_file.write_text(f"* * * * * root {script}\n")

    check = CronSystemdPathCheck()
    findings = check._parse_crontab_commands(str(cron_file))

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED


def test_path_check_flags_empty_entry_classic_bug(monkeypatch):
    """Regression test: PATH='/usr/bin::' (a trailing empty entry) is the
    single most classic PATH hijack misconfiguration - it must be detected,
    not silently skipped."""
    check = CronSystemdPathCheck()
    monkeypatch.setenv("PATH", "/usr/bin::/bin")
    with patch.object(check, "_run"):
        findings = check._check_path()
    assert any("Relative/current directory" in f.title for f in findings)


def test_path_check_flags_literal_dot(monkeypatch):
    check = CronSystemdPathCheck()
    monkeypatch.setenv("PATH", "/usr/bin:.:/bin")
    findings = check._check_path()
    assert any("Relative/current directory" in f.title for f in findings)


def test_path_check_only_reports_dot_finding_once(monkeypatch):
    check = CronSystemdPathCheck()
    monkeypatch.setenv("PATH", "/usr/bin::.:/bin")
    findings = check._check_path()
    dot_findings = [f for f in findings if "Relative/current directory" in f.title]
    assert len(dot_findings) == 1
