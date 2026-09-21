"""Group-membership escalation vectors: docker, lxd/lxc, disk.

These are CONFIRMED-by-condition (no extra caveat needed, unlike the CVE
checks) because group membership + a directly-verified accessible socket or
device *is* the exploitable condition - there's no extra runtime factor that
could block it once both are true. We deliberately don't PoC these:
  - docker/lxd: the "proof" is spinning up a real container that bind-mounts
    the host filesystem - that's genuine state creation (an image pull, a
    running container), not a read-only probe, so it stays condition-only.
  - disk: the "proof" would be reading a live block device, which is already
    what we're confirming access to - attempting it doesn't tell us more than
    os.access() already did, and reading raw sectors of /dev/sda is not
    something to do casually even read-only.
"""
from __future__ import annotations

import os

from ..core.base import Check, Confidence, Finding

_DEVICE_PREFIXES = ("sd", "vd", "nvme", "xvd", "hd")


class GroupEscalationCheck(Check):
    id = "group_escalation"
    category = "group_membership"
    supports_active = False
    supports_poc = False

    def run(self) -> list[Finding]:
        groups = self._current_groups()
        if groups is None:
            return [
                self.finding(
                    title="Could not determine current group membership",
                    confidence=Confidence.ERROR,
                    description="`id -nG` failed.",
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._check_docker(groups))
        findings.extend(self._check_lxd(groups))
        findings.extend(self._check_disk(groups))
        return findings

    def _current_groups(self) -> set[str] | None:
        proc = self._run(["id", "-nG"])
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return set(proc.stdout.split())

    # -- docker ------------------------------------------------------------
    def _check_docker(self, groups: set[str]) -> list[Finding]:
        if "docker" not in groups:
            return []
        sock = "/var/run/docker.sock"
        if not os.path.exists(sock):
            sock = "/run/docker.sock"
        accessible = os.path.exists(sock) and os.access(sock, os.R_OK | os.W_OK)
        return [
            self.finding(
                title="Member of the 'docker' group with an accessible docker socket",
                confidence=Confidence.CONFIRMED if accessible else Confidence.INFO,
                description=(
                    "The current user is in the 'docker' group"
                    + (
                        f" and os.access() confirms '{sock}' is directly read/write-able. "
                        "This is root-equivalent: `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` "
                        "mounts the host filesystem into a container you control and gives a root shell "
                        "on the host."
                        if accessible
                        else f", but the docker socket ('{sock}') was not found or is not accessible - "
                        "docker may not be running, or use a different socket path."
                    )
                ),
                evidence={"groups": sorted(groups), "socket": sock, "socket_accessible": accessible},
                remediation="Remove the user from the 'docker' group unless required; the docker group is equivalent to root.",
                references=["https://gtfobins.github.io/gtfobins/docker/"],
            )
        ]

    # -- lxd/lxc -------------------------------------------------------------
    def _check_lxd(self, groups: set[str]) -> list[Finding]:
        matched_group = next((g for g in ("lxd", "lxc") if g in groups), None)
        if not matched_group:
            return []
        proc = self._run(["lxc", "list"])
        usable = proc.returncode == 0
        return [
            self.finding(
                title=f"Member of the '{matched_group}' group",
                confidence=Confidence.CONFIRMED if usable else Confidence.INFO,
                description=(
                    f"The current user is in the '{matched_group}' group"
                    + (
                        " and `lxc list` succeeds, confirming working LXD access. This is "
                        "root-equivalent: create a privileged container with a host filesystem "
                        "mount to escalate (classic LXD group escalation)."
                        if usable
                        else ", but `lxc list` failed - LXD may not be installed/running, or "
                        "the socket is inaccessible."
                    )
                ),
                evidence={"groups": sorted(groups), "lxc_list_succeeded": usable},
                remediation=f"Remove the user from the '{matched_group}' group unless required.",
                references=["https://gtfobins.github.io/gtfobins/lxd/"],
            )
        ]

    # -- disk ----------------------------------------------------------------
    def _check_disk(self, groups: set[str]) -> list[Finding]:
        if "disk" not in groups:
            return []
        dev_dir = "/dev"
        accessible_devices = []
        try:
            for name in os.listdir(dev_dir):
                if not name.startswith(_DEVICE_PREFIXES):
                    continue
                path = os.path.join(dev_dir, name)
                if os.access(path, os.R_OK | os.W_OK):
                    accessible_devices.append(path)
        except OSError:
            pass

        return [
            self.finding(
                title="Member of the 'disk' group with read/write access to a raw block device",
                confidence=Confidence.CONFIRMED if accessible_devices else Confidence.INFO,
                description=(
                    "The current user is in the 'disk' group"
                    + (
                        f" and os.access() confirms direct read/write access to: {', '.join(accessible_devices)}. "
                        "Raw block device access is root-equivalent - the whole filesystem, including "
                        "/etc/shadow, can be read or patched with a tool like debugfs."
                        if accessible_devices
                        else ", but no raw block device under /dev was directly accessible."
                    )
                ),
                evidence={"groups": sorted(groups), "accessible_devices": accessible_devices},
                remediation="Remove the user from the 'disk' group unless required.",
            )
        ]
