import subprocess
from unittest.mock import patch

from confirmesc.core.executor import LocalExecutor, SSHExecutor, StatInfo


def _cp(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# -- LocalExecutor ---------------------------------------------------------


def test_local_stat_roundtrips_mode_bits(tmp_path):
    path = tmp_path / "f"
    path.write_text("hi")
    fs = LocalExecutor()
    info = fs.stat(str(path))
    assert isinstance(info, StatInfo)
    assert info.st_size == 2


def test_local_stat_missing_path_returns_none():
    assert LocalExecutor().stat("/nonexistent/path/xyz") is None


def test_local_glob(tmp_path):
    (tmp_path / "a.txt").write_text("")
    (tmp_path / "b.txt").write_text("")
    fs = LocalExecutor()
    found = fs.glob(str(tmp_path / "*.txt"))
    assert len(found) == 2


# -- SSHExecutor ------------------------------------------------------------


def test_ssh_run_wraps_argv_and_parses_result():
    fs = SSHExecutor(host="10.0.0.5", user="op")
    with patch("confirmesc.core.executor.subprocess.run") as mocked_run:
        mocked_run.return_value = _cp(stdout="hello\n", returncode=0)
        result = fs.run(["echo", "hello"], timeout=5)

    assert result.returncode == 0
    assert result.stdout == "hello\n"
    called_cmd = mocked_run.call_args[0][0]
    assert called_cmd[0] == "ssh"
    assert "op@10.0.0.5" in called_cmd
    assert "echo hello" in called_cmd


def test_ssh_stat_parses_hex_mode():
    fs = SSHExecutor(host="10.0.0.5")
    with patch.object(fs, "run") as mocked_run:
        mocked_run.return_value = _cp(stdout="81ed 0 0 123\n", returncode=0)
        info = fs.stat("/etc/passwd")

    assert info.st_uid == 0
    assert info.st_size == 123


def test_ssh_exists_uses_test_dash_e():
    fs = SSHExecutor(host="10.0.0.5")
    with patch.object(fs, "run") as mocked_run:
        mocked_run.return_value = _cp(returncode=0)
        assert fs.exists("/etc/shadow") is True
        assert mocked_run.call_args[0][0] == ["test", "-e", "/etc/shadow"]


def test_ssh_glob_dir_star():
    fs = SSHExecutor(host="10.0.0.5")
    with patch.object(fs, "run") as mocked_run:
        mocked_run.return_value = _cp(stdout="/etc/cron.d/a\n/etc/cron.d/b\n", returncode=0)
        found = fs.glob("/etc/cron.d/*")

    assert found == ["/etc/cron.d/a", "/etc/cron.d/b"]
    argv = mocked_run.call_args[0][0]
    assert argv[0] == "find" and "/etc/cron.d" in argv


def test_ssh_connection_failure_does_not_raise():
    fs = SSHExecutor(host="unreachable.invalid")
    with patch("confirmesc.core.executor.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=5)):
        result = fs.run(["id", "-u"], timeout=5)
    assert result.returncode == -1
