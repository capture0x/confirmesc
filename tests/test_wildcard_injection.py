from confirmesc.checks.wildcard_injection import WildcardInjectionCheck
from confirmesc.core.base import Confidence


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    return str(path)


def test_crontab_style_cd_does_not_leak_into_next_independent_job(tmp_path):
    """Regression test: /etc/cron.d-style files list independently scheduled
    jobs, one per line - a `cd` on one line must never be treated as the
    working directory for a completely unrelated job on the next line."""
    check = WildcardInjectionCheck()
    content = (
        "* * * * * root cd /tmp\n"
        "* * * * * root tar czf /var/backups/x.tar.gz *\n"
    )
    path = _write(tmp_path, "cron.d-fake", content)

    findings = check._scan_file(path, is_crontab_style=True)

    tar_findings = [f for f in findings if f.evidence.get("command") == "tar"]
    assert tar_findings, "expected the tar wildcard to be detected"
    # must NOT have inherited "/tmp" from the unrelated previous line
    assert tar_findings[0].evidence["working_directory"] is None
    assert tar_findings[0].confidence == Confidence.LIKELY


def test_script_style_cd_persists_across_lines_in_same_script(tmp_path):
    """A cron.daily/etc file is one real sequential shell script - `cd`
    legitimately carries forward to later lines in the same file."""
    check = WildcardInjectionCheck()
    content = "#!/bin/sh\ncd /tmp\ntar czf backup.tar.gz *\n"
    path = _write(tmp_path, "daily-fake", content)

    findings = check._scan_file(path, is_crontab_style=False)

    tar_findings = [f for f in findings if f.evidence.get("command") == "tar"]
    assert tar_findings
    assert tar_findings[0].evidence["working_directory"] == "/tmp"
    # /tmp is always world-writable, so this should resolve to CONFIRMED
    assert tar_findings[0].confidence == Confidence.CONFIRMED


def test_strip_crontab_schedule_handles_at_special_and_short_lines():
    strip = WildcardInjectionCheck._strip_crontab_schedule
    assert strip("* * * * * root tar czf x *") == "tar czf x *"
    assert strip("@daily root tar czf x *") == "tar czf x *"
    assert strip("* * * *") == ""  # too short to contain a real command
