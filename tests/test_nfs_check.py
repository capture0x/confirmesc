import os

from confirmesc.checks.nfs import NfsCheck
from confirmesc.core.base import Confidence


def test_export_with_no_root_squash_and_writable_dir_is_confirmed(tmp_path):
    export_dir = tmp_path / "share"
    export_dir.mkdir()
    exports_file = tmp_path / "exports"
    exports_file.write_text(f"{export_dir} *(rw,sync,no_root_squash)\n")

    check = NfsCheck()
    findings = check._check_exports(exports_path=str(exports_file))

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].evidence["locally_writable"] is True


def test_export_without_no_root_squash_is_ignored(tmp_path):
    export_dir = tmp_path / "share"
    export_dir.mkdir()
    exports_file = tmp_path / "exports"
    exports_file.write_text(f"{export_dir} *(rw,sync,root_squash)\n")

    check = NfsCheck()
    findings = check._check_exports(exports_path=str(exports_file))

    assert findings == []


def test_export_no_root_squash_but_not_locally_writable_is_likely(tmp_path, monkeypatch):
    export_dir = tmp_path / "share"
    export_dir.mkdir()
    monkeypatch.setattr(os, "access", lambda path, mode: False)
    exports_file = tmp_path / "exports"
    exports_file.write_text(f"{export_dir} *(rw,no_root_squash)\n")

    check = NfsCheck()
    findings = check._check_exports(exports_path=str(exports_file))

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.LIKELY


def test_missing_exports_file_returns_nothing(tmp_path):
    check = NfsCheck()
    findings = check._check_exports(exports_path=str(tmp_path / "does-not-exist"))
    assert findings == []


def test_client_nfs_mount_is_info_only(tmp_path):
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    mounts_file = tmp_path / "mounts"
    mounts_file.write_text(f"server:/export {mountpoint} nfs4 rw,relatime 0 0\n")

    check = NfsCheck()
    findings = check._check_client_mounts(mounts_path=str(mounts_file))

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.INFO


def test_non_nfs_mount_is_ignored(tmp_path):
    mounts_file = tmp_path / "mounts"
    mounts_file.write_text("/dev/sda1 / ext4 rw,relatime 0 0\n")

    check = NfsCheck()
    findings = check._check_client_mounts(mounts_path=str(mounts_file))

    assert findings == []
