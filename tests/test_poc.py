import os
import stat
import textwrap

from confirmesc.checks import poc


def _make_script(tmp_path, name: str, prints: str) -> str:
    path = tmp_path / name
    path.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        echo "{prints}"
        """))
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return str(path)


def test_extract_uid_finds_digit_line():
    assert poc._extract_uid("some banner\n0\ntrailing") == "0"
    assert poc._extract_uid("no digits here") is None


def test_attempt_suid_poc_success(tmp_path):
    script = _make_script(tmp_path, "fake_root_binary", "0")
    result = poc.attempt_suid_poc(script, [])
    assert result.attempted is True
    assert result.success is True
    assert result.observed_uid == "0"


def test_attempt_suid_poc_failure(tmp_path):
    script = _make_script(tmp_path, "fake_unpriv_binary", "1000")
    result = poc.attempt_suid_poc(script, [])
    assert result.attempted is True
    assert result.success is False
    assert result.observed_uid == "1000"


def test_attempt_suid_poc_missing_binary_does_not_raise():
    result = poc.attempt_suid_poc("/nonexistent/binary/path", ["-c", "id -u"])
    assert result.attempted is True
    assert result.success is None
    assert result.error
