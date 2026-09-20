import subprocess
from unittest.mock import patch

from confirmesc.checks import poc as poc_engine
from confirmesc.checks.suid_sudo import SuidSudoCheck
from confirmesc.core.base import Confidence


def _cp(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_poc_upgrades_title_on_real_root_confirmation():
    check = SuidSudoCheck(active=False, poc=True)
    with patch.object(check, "_run") as mocked_run, patch.object(
        poc_engine, "attempt_suid_poc"
    ) as mocked_poc:
        mocked_run.side_effect = [
            _cp(stdout="/usr/bin/find\n", returncode=0),  # find -perm listing
            _cp(stdout="", returncode=1),  # sudo -n -l (no rules)
        ]
        mocked_poc.return_value = poc_engine.PocResult(
            attempted=True, success=True, observed_uid="0", argv=["/usr/bin/find", "."]
        )
        findings = check.run()

    suid_findings = [f for f in findings if "find" in f.title.lower()]
    assert any(f.confidence == Confidence.CONFIRMED for f in suid_findings)
    assert any("ROOT CONFIRMED" in f.title for f in suid_findings)
    assert any(f.evidence.get("poc_success") is True for f in suid_findings)


def test_poc_notes_failed_attempt_without_downgrading():
    check = SuidSudoCheck(active=False, poc=True)
    with patch.object(check, "_run") as mocked_run, patch.object(
        poc_engine, "attempt_suid_poc"
    ) as mocked_poc:
        mocked_run.side_effect = [
            _cp(stdout="/usr/bin/find\n", returncode=0),
            _cp(stdout="", returncode=1),
        ]
        mocked_poc.return_value = poc_engine.PocResult(
            attempted=True, success=False, observed_uid="1000", argv=["/usr/bin/find", "."]
        )
        findings = check.run()

    suid_findings = [f for f in findings if "find" in f.title.lower()]
    # still CONFIRMED by condition (real suid bit + known GTFOBins binary),
    # PoC failing doesn't get to override that, but the discrepancy is noted.
    assert any(f.confidence == Confidence.CONFIRMED for f in suid_findings)
    assert any("did not succeed" in f.description or "instead of 0" in f.description for f in suid_findings)
