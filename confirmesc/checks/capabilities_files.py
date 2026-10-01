"""Linux capabilities on binaries, and writable critical system files.

Both sub-checks resolve to CONFIRMED because both are directly observed,
verifiable facts: `getcap` reports the exact capability set the kernel will
grant on exec, and os.access() directly tests write permission against the
real file - no inference either way.
"""
from __future__ import annotations

import os
import re

from ..core.base import Check, Confidence, Finding
from ..core.data_loader import load_gtfobins
from . import poc as poc_engine

# Capabilities that alone are enough for a straightforward root escalation
# when present on a binary that can read/write/execute arbitrary files or
# assume arbitrary uid/gid.
_DANGEROUS_CAPS = {
    "cap_setuid",
    "cap_setgid",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_chown",
    "cap_fowner",
}

_CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ld.so.preload",
    "/etc/gshadow",
]
_CRITICAL_GLOB_DIRS = ["/etc/sudoers.d"]


class CapabilitiesAndCriticalFilesCheck(Check):
    id = "capabilities_and_critical_files"
    category = "capabilities_and_critical_files"
    supports_active = False
    supports_poc = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_capabilities())
        findings.extend(self._check_critical_files())
        return findings

    # -- capabilities --------------------------------------------------
    def _check_capabilities(self) -> list[Finding]:
        proc = self._run(["getcap", "-r", "/"], timeout=60)
        if proc.returncode == -1 and "No such file" in (proc.stderr or ""):
            return [
                self.finding(
                    title="getcap not installed",
                    confidence=Confidence.ERROR,
                    description="`getcap` (from libcap2-bin / libcap) is not available - capability check skipped.",
                )
            ]

        gtfo = load_gtfobins()
        findings: list[Finding] = []
        for line in filter(None, proc.stdout.splitlines()):
            # Format: "/usr/bin/python3.11 cap_setuid,cap_setgid+ep" - note the
            # +ep/=ep operator suffix is only attached to the LAST capability
            # in a comma-separated list, not to each one individually.
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            path, caps_raw = parts
            caps_raw = caps_raw.strip()
            cap_names = {re.sub(r"[+=].*$", "", c).strip().lower() for c in caps_raw.split(",")}
            dangerous = cap_names & _DANGEROUS_CAPS
            if not dangerous:
                continue

            basename = os.path.basename(path)
            gtfo_entry = gtfo.get(basename)
            known_vector = bool(gtfo_entry and gtfo_entry.get("capability"))

            title = f"Dangerous capability on {path}: {', '.join(sorted(dangerous))}"
            description = (
                f"`getcap -r /` directly reports '{path}' holds {caps_raw}. "
                + (
                    f"'{basename}' is a known GTFOBins capability-abuse vector "
                    "(e.g. python3 with cap_setuid can spawn a root shell directly)."
                    if known_vector
                    else "This binary is not in the curated GTFOBins capability table - "
                    "review manually to confirm an abuse primitive exists for it."
                )
            )
            evidence = {"path": path, "capabilities": caps_raw, "gtfobins_known_vector": known_vector}

            cap_poc_args = gtfo_entry.get("cap_poc_args") if gtfo_entry else None
            if self.poc and cap_poc_args and "cap_setuid" in dangerous:
                result = poc_engine.attempt_capability_poc(path, cap_poc_args)
                evidence.update(result.as_evidence())
                if result.success:
                    title = f"ROOT CONFIRMED via capability exploitation: {path}"
                    description += (
                        f" PoC executed: `{' '.join(result.argv)}` actually returned "
                        f"euid {result.observed_uid} - root access was live-verified."
                    )
                elif result.success is False:
                    description += (
                        f" PoC attempted (`{' '.join(result.argv)}`) but returned uid "
                        f"{result.observed_uid!r} instead of 0."
                    )

            exploit_command = None
            if "cap_setuid" in dangerous and gtfo_entry:
                # Same template used for the SUID case works here too: it
                # calls setuid(0) explicitly, which is exactly the ability
                # cap_setuid grants (unlike a real SUID bit, capabilities
                # don't elevate euid automatically at exec - the binary has
                # to call setuid() itself).
                template = gtfo_entry.get("suid_shell_cmd")
                if template:
                    exploit_command = template.replace("<BIN>", path)

            findings.append(
                self.finding(
                    title=title,
                    confidence=Confidence.CONFIRMED,
                    description=description,
                    evidence=evidence,
                    remediation=f"Remove the capability if not required: setcap -r {path}",
                    references=(
                        [f"https://gtfobins.github.io/gtfobins/{basename}/"] if known_vector else []
                    ),
                    exploit_command=exploit_command,
                )
            )
        return findings

    # -- critical files --------------------------------------------------
    def _check_critical_files(self) -> list[Finding]:
        findings: list[Finding] = []
        targets = list(_CRITICAL_FILES)
        for d in _CRITICAL_GLOB_DIRS:
            if os.path.isdir(d):
                try:
                    names = os.listdir(d)
                except OSError:
                    continue  # unreadable directory (e.g. root-only /etc/sudoers.d): nothing to enumerate
                targets.extend(os.path.join(d, name) for name in names)

        for path in targets:
            if not os.path.exists(path):
                continue
            if os.access(path, os.W_OK):
                findings.append(
                    self.finding(
                        title=f"Critical system file is writable: {path}",
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"os.access() confirms the current user can write to '{path}'. "
                            "This directly allows privilege escalation (e.g. appending a "
                            "root-equivalent line to /etc/passwd or /etc/sudoers)."
                        ),
                        evidence={"path": path},
                        remediation=f"Fix ownership/permissions on {path} (root:root, restrictive mode).",
                    )
                )
        return findings
