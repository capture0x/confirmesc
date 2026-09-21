import subprocess
from unittest.mock import patch

from confirmesc.checks import group_escalation
from confirmesc.checks.group_escalation import GroupEscalationCheck
from confirmesc.core.base import Confidence


def _cp(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_not_in_docker_group_no_finding():
    check = GroupEscalationCheck()
    with patch.object(check, "_run", return_value=_cp(stdout="kali sudo users\n")):
        findings = check.run()
    assert not any("docker" in f.title.lower() for f in findings)


def test_docker_group_with_accessible_socket_is_confirmed(monkeypatch):
    check = GroupEscalationCheck()
    monkeypatch.setattr(group_escalation.os.path, "exists", lambda p: p == "/var/run/docker.sock")
    monkeypatch.setattr(group_escalation.os, "access", lambda p, mode: True)
    with patch.object(check, "_run") as mocked_run:
        mocked_run.side_effect = [
            _cp(stdout="kali docker sudo\n"),  # id -nG
        ]
        findings = check._check_docker({"kali", "docker", "sudo"})
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].evidence["socket_accessible"] is True


def test_docker_group_without_socket_is_info_only(monkeypatch):
    check = GroupEscalationCheck()
    monkeypatch.setattr(group_escalation.os.path, "exists", lambda p: False)
    findings = check._check_docker({"kali", "docker"})
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.INFO


def test_lxd_group_with_working_lxc_is_confirmed():
    check = GroupEscalationCheck()
    with patch.object(check, "_run", return_value=_cp(returncode=0)):
        findings = check._check_lxd({"kali", "lxd"})
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED


def test_lxd_group_without_working_lxc_is_info():
    check = GroupEscalationCheck()
    with patch.object(check, "_run", return_value=_cp(returncode=1)):
        findings = check._check_lxd({"kali", "lxd"})
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.INFO


def test_disk_group_with_accessible_device_is_confirmed(monkeypatch):
    check = GroupEscalationCheck()
    monkeypatch.setattr(group_escalation.os, "listdir", lambda d: ["sda", "tty0"])
    monkeypatch.setattr(group_escalation.os, "access", lambda p, mode: p.endswith("sda"))
    findings = check._check_disk({"kali", "disk"})
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].evidence["accessible_devices"] == ["/dev/sda"]


def test_no_relevant_groups_returns_nothing():
    check = GroupEscalationCheck()
    with patch.object(check, "_run", return_value=_cp(stdout="kali sudo users\n")):
        findings = check.run()
    assert findings == []
