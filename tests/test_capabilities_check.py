import subprocess
from unittest.mock import patch

from confirmesc.checks.capabilities_files import CapabilitiesAndCriticalFilesCheck
from confirmesc.core.base import Confidence


def _cp(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_getcap_multi_capability_operator_only_on_last_entry():
    """Regression test: `getcap -r /` prints operator suffix (+ep/=ep) only
    on the LAST capability in a comma-separated list, e.g.
    'cap_setgid,cap_setuid=ep' - not on each entry. A naive split on '+'
    alone fails to strip the '=ep' suffix from 'cap_setuid=ep', silently
    losing the match against the dangerous-capability set."""
    check = CapabilitiesAndCriticalFilesCheck(poc=False)
    with patch.object(check, "_run") as mocked_run:
        mocked_run.return_value = _cp(stdout="/opt/vulnapp/python3 cap_setgid,cap_setuid=ep\n")
        findings = check.run()

    confirmed = [f for f in findings if f.confidence == Confidence.CONFIRMED]
    assert confirmed, "expected the cap_setuid capability to be recognized as dangerous"
    assert "cap_setuid" in confirmed[0].title
