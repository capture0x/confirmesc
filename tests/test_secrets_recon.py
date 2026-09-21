import os

from confirmesc.checks.secrets_recon import SecretsReconCheck
from confirmesc.core.base import Confidence


def test_ssh_key_owned_by_current_user_is_not_flagged(tmp_path):
    key = tmp_path / "id_rsa"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END-----\n")

    check = SecretsReconCheck()
    my_uid = os.getuid()
    findings = check._check_ssh_keys(my_uid, globs=[str(tmp_path / "*")])

    assert findings == []  # it's our own file - reading it isn't a finding


def test_ssh_key_owned_by_another_uid_but_readable_is_confirmed(tmp_path, monkeypatch):
    key = tmp_path / "id_rsa"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END-----\n")

    check = SecretsReconCheck()
    my_uid = os.getuid()

    real_stat = os.stat

    class FakeStat:
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            if name == "st_uid":
                return my_uid + 1  # pretend it belongs to someone else
            return getattr(self._real, name)

    monkeypatch.setattr(os, "stat", lambda path: FakeStat(real_stat(path)))
    monkeypatch.setattr(os, "access", lambda path, mode: True)

    findings = check._check_ssh_keys(my_uid, globs=[str(tmp_path / "*")])

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].evidence["owner_uid"] == my_uid + 1


def test_pub_key_is_never_flagged(tmp_path):
    (tmp_path / "id_rsa.pub").write_text("ssh-rsa AAAA...\n")
    check = SecretsReconCheck()
    findings = check._check_ssh_keys(os.getuid(), globs=[str(tmp_path / "*")])
    assert findings == []


def test_history_file_own_user_not_flagged_even_with_secrets(tmp_path):
    # Note: bare '*' doesn't match dotfiles under Python's glob (same as a
    # shell), so pass the exact path - this is also how the real
    # "/home/*/.bash_history" patterns work: '.bash_history' is a literal
    # path component, not something a wildcard expands into.
    hist = tmp_path / ".bash_history"
    hist.write_text("export password=hunter2\nls -la\n")
    check = SecretsReconCheck()
    findings = check._check_history_files(os.getuid(), globs=[str(hist)])
    assert findings == []
