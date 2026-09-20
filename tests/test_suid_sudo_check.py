import subprocess
from unittest.mock import patch

from confirmesc.checks.suid_sudo import SuidSudoCheck
from confirmesc.core.base import Confidence


def _cp(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_sudo_l_unrestricted_all_is_confirmed():
    check = SuidSudoCheck(active=False)
    with patch.object(check, "_run") as mocked_run:
        # first call: find (suid/sgid) -> nothing; second call: sudo -l
        mocked_run.side_effect = [
            _cp(stdout="", returncode=0),
            _cp(stdout="Matching Defaults entries...\n\nUser foo may run:\n    (ALL : ALL) ALL\n", returncode=0),
        ]
        findings = check.run()

    confirmed = [f for f in findings if f.confidence == Confidence.CONFIRMED]
    assert any("Unrestricted sudo access" in f.title for f in confirmed)


def test_sudo_l_gtfobins_match_confirmed():
    check = SuidSudoCheck(active=False)
    with patch.object(check, "_run") as mocked_run:
        mocked_run.side_effect = [
            _cp(stdout="", returncode=0),
            _cp(stdout="User foo may run:\n    (root) NOPASSWD: /usr/bin/vim\n", returncode=0),
        ]
        findings = check.run()

    confirmed = [f for f in findings if f.confidence == Confidence.CONFIRMED]
    assert any("/usr/bin/vim" in f.title for f in confirmed)


def test_sudo_l_unknown_binary_is_info_not_confirmed():
    check = SuidSudoCheck(active=False)
    with patch.object(check, "_run") as mocked_run:
        mocked_run.side_effect = [
            _cp(stdout="", returncode=0),
            _cp(stdout="User foo may run:\n    (root) /opt/custom/internal_tool\n", returncode=0),
        ]
        findings = check.run()

    assert not any(f.confidence == Confidence.CONFIRMED for f in findings)
    assert any(f.confidence == Confidence.INFO for f in findings)


def test_sudo_l_password_required_no_findings():
    check = SuidSudoCheck(active=False)
    with patch.object(check, "_run") as mocked_run:
        mocked_run.side_effect = [
            _cp(stdout="", returncode=0),
            _cp(stdout="", returncode=1, stderr="a password is required"),
        ]
        findings = check.run()

    assert not any(f.confidence == Confidence.CONFIRMED for f in findings)
