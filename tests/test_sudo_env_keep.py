import subprocess
from unittest.mock import patch

from confirmesc.checks.sudo_env_keep import SudoEnvKeepCheck


def _cp(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_defaults_line_alone_is_not_counted_as_a_rule():
    """Regression test: the 'Matching Defaults entries' settings line
    (which is where env_keep itself appears) must not be mistaken for an
    actual authorized command rule - only a real '(runas) command' line
    counts."""
    check = SudoEnvKeepCheck()
    stdout = (
        "Matching Defaults entries for user on host:\n"
        '    env_reset, env_keep+="LD_PRELOAD LD_LIBRARY_PATH"\n'
        "User user may run the following commands on host:\n"
    )
    with patch.object(check, "_run", return_value=_cp(stdout=stdout)):
        findings = check.run()
    assert findings == []


def test_real_rule_plus_env_keep_is_confirmed():
    check = SudoEnvKeepCheck()
    stdout = (
        "Matching Defaults entries for user on host:\n"
        '    env_reset, env_keep+="LD_PRELOAD LD_LIBRARY_PATH"\n'
        "User user may run the following commands on host:\n"
        "    (root) NOPASSWD: /usr/bin/whatever\n"
    )
    with patch.object(check, "_run", return_value=_cp(stdout=stdout)):
        findings = check.run()
    assert len(findings) == 1
    assert "LD_PRELOAD" in findings[0].title
