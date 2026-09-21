"""NFS no_root_squash exposure.

Two distinct, honestly-different-confidence situations:
  - This host is itself exporting a share with no_root_squash and a
    writable directory (/etc/exports, directly parsed) - CONFIRMED, this is
    a real, directly observed server misconfiguration.
  - This host has mounted a remote NFS share and the client-side mount
    options happen to surface a root-squash-related flag - LIKELY, because
    the authoritative setting lives on the server and we can't verify it
    from the client alone (mount option strings don't always reflect it
    faithfully).
"""
from __future__ import annotations

import os
import re

from ..core.base import Check, Confidence, Finding

_EXPORTS_LINE_RE = re.compile(r"^\s*(/\S+)\s+(.+)$")


class NfsCheck(Check):
    id = "nfs"
    category = "nfs"
    supports_active = False
    supports_poc = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_exports())
        findings.extend(self._check_client_mounts())
        return findings

    def _check_exports(self) -> list[Finding]:
        if not os.path.isfile("/etc/exports"):
            return []
        try:
            with open("/etc/exports", "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            return []

        findings: list[Finding] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = _EXPORTS_LINE_RE.match(line)
            if not match:
                continue
            export_path, options = match.groups()
            if "no_root_squash" not in options:
                continue
            writable = os.path.isdir(export_path) and os.access(export_path, os.W_OK)
            findings.append(
                self.finding(
                    title=f"NFS export with no_root_squash: {export_path}",
                    confidence=Confidence.CONFIRMED if writable else Confidence.LIKELY,
                    description=(
                        f"/etc/exports directly configures '{export_path}' with no_root_squash "
                        + (
                            "and os.access() confirms the current user can already write to it "
                            "locally - any client mounting this share as root can create a SUID "
                            "root binary that this user can then execute."
                            if writable
                            else "- exploitability from a remote client depends on that client "
                            "having root and mount access; verify manually."
                        )
                    ),
                    evidence={"export_path": export_path, "options": options, "locally_writable": writable},
                    remediation=f"Remove no_root_squash from the export of {export_path} in /etc/exports, or restrict client IPs.",
                )
            )
        return findings

    def _check_client_mounts(self) -> list[Finding]:
        try:
            with open("/proc/mounts", "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            return []

        findings: list[Finding] = []
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]
            if not fstype.startswith("nfs"):
                continue
            writable = os.path.isdir(mountpoint) and os.access(mountpoint, os.W_OK)
            findings.append(
                self.finding(
                    title=f"NFS mount detected: {mountpoint} ({device})",
                    confidence=Confidence.INFO,
                    description=(
                        f"'{mountpoint}' is an NFS mount ({fstype}). Root-squash status is a "
                        "server-side setting not reliably visible from the client - check the "
                        "server's /etc/exports, or test by mounting from a host you control as "
                        "root and attempting to create a SUID binary."
                    ),
                    evidence={"mountpoint": mountpoint, "device": device, "options": options, "locally_writable": writable},
                )
            )
        return findings
