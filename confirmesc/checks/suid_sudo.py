"""SUID/SGID binaries and `sudo -l` entries, cross-referenced against GTFOBins.

Why this "confirms" rather than just lists:
  - We re-`stat()` every SUID/SGID candidate `find` returns, so the perm bit is
    a directly observed fact, not something we infer from a stale listing.
  - We only call something CONFIRMED when the observed binary basename is
    present in the curated GTFOBins table *for that specific technique*
    (suid vs. sudo), not just "any SUID file" like plain LinEnum-style tools.
  - For sudo, `sudo -l -n` (non-interactive) only succeeds if the invoking
    user's own credentials already grant that rule, so a match there is
    already-authorized, real access - not a guess.
  - With --active, we additionally execute the binary with a harmless
    `--version`/`--help` probe to confirm it's a real, runnable binary and not
    a dangling symlink or a busybox alias that doesn't actually behave like
    the GTFOBins entry assumes.
  - With --poc (separate, more invasive flag), we go one step further and
    actually run the real GTFOBins escalation payload for binaries we have a
    curated recipe for, and check that the resulting process really has
    euid 0. This is live exploitation, not just condition-checking - see
    checks/poc.py for exactly what runs and why it's safe (read-only,
    no shell, no persistence).
"""
from __future__ import annotations

import os
import re
import stat

from ..core.base import Check, Confidence, Finding
from ..core.data_loader import load_gtfobins
from . import poc as poc_engine

_SAFE_PROBE_FLAGS = ("--version", "-V", "--help")
_SUDO_RULE_RE = re.compile(r"^\s*\(([^)]+)\)\s*((?:NOPASSWD:|PASSWD:)\s*)?(.+)$")
# Container image layers on disk aren't the live root filesystem - a SUID bit
# baked into a container image layer isn't a host privesc vector by itself.
_NOISE_SUBSTRINGS = ("/containers/storage/", "/docker/overlay2/")


class SuidSudoCheck(Check):
    id = "suid_sudo"
    category = "suid_sgid_sudo"
    supports_active = True
    supports_poc = True

    def run(self) -> list[Finding]:
        gtfo = load_gtfobins()
        findings: list[Finding] = []
        findings.extend(self._check_suid_sgid(gtfo))
        findings.extend(self._check_sudo_l(gtfo))
        return findings

    # -- SUID / SGID -----------------------------------------------------
    def _check_suid_sgid(self, gtfo: dict) -> list[Finding]:
        proc = self._run(
            [
                "find", "/",
                "-path", "/proc", "-prune", "-o",
                "-path", "/sys", "-prune", "-o",
                "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
                "-type", "f", "-print",
            ],
            timeout=90,
        )
        if proc.returncode not in (0, 1):  # 1 = some dirs unreadable, still usable
            return [
                self.finding(
                    title="Could not enumerate SUID/SGID binaries",
                    confidence=Confidence.ERROR,
                    description=proc.stderr.strip() or "find failed",
                )
            ]

        findings: list[Finding] = []
        for path in filter(None, proc.stdout.splitlines()):
            if any(n in path for n in _NOISE_SUBSTRINGS):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue  # vanished between find and stat - not a stable finding
            is_suid = bool(st.st_mode & stat.S_ISUID)
            is_sgid = bool(st.st_mode & stat.S_ISGID)
            basename = os.path.basename(path)
            entry = gtfo.get(basename)

            if entry and entry.get("suid"):
                evidence = {
                    "path": path,
                    "owner_uid": st.st_uid,
                    "suid": is_suid,
                    "sgid": is_sgid,
                    "gtfobins_technique": "suid",
                }
                if self.active:
                    evidence["active_probe"] = self._probe_binary(path)

                title = f"Exploitable SUID/SGID binary: {path}"
                description = (
                    f"'{basename}' is set{'uid' if is_suid else ''}"
                    f"{'/setgid' if is_sgid else ''} and is a known GTFOBins "
                    "SUID escalation vector. Directly observed on disk with "
                    f"os.stat(): mode={oct(st.st_mode)}, owner uid={st.st_uid}."
                )
                poc_args = entry.get("poc_args")
                if self.poc and poc_args:
                    result = poc_engine.attempt_suid_poc(path, poc_args)
                    evidence.update(result.as_evidence())
                    if result.success:
                        title = f"ROOT CONFIRMED via SUID exploitation: {path}"
                        description += (
                            f" PoC executed: `{' '.join(result.argv)}` actually returned "
                            f"euid {result.observed_uid} - this is not a condition match, "
                            "root access was live-verified."
                        )
                    elif result.success is False:
                        description += (
                            f" PoC attempted (`{' '.join(result.argv)}`) but returned uid "
                            f"{result.observed_uid!r} instead of 0 - conditions looked right but "
                            "live exploitation did not succeed here (binary may behave "
                            "differently than the GTFOBins reference, or be patched/wrapped)."
                        )

                exploit_command = None
                template = entry.get("suid_shell_cmd")
                if template:
                    exploit_command = template.replace("<BIN>", path)

                findings.append(
                    self.finding(
                        title=title,
                        confidence=Confidence.CONFIRMED,
                        description=description,
                        evidence=evidence,
                        remediation=f"Remove the setuid/setgid bit if not required: chmod -s {path}",
                        references=[f"https://gtfobins.github.io/gtfobins/{basename}/"],
                        exploit_command=exploit_command,
                    )
                )
            else:
                findings.append(
                    self.finding(
                        title=f"Unclassified SUID/SGID binary: {path}",
                        confidence=Confidence.INFO,
                        description=(
                            "SUID/SGID bit directly observed but binary is not in the "
                            "curated GTFOBins table - review manually, it may still be "
                            "exploitable (custom binary, or GTFOBins entry not yet added)."
                        ),
                        evidence={"path": path, "owner_uid": st.st_uid, "suid": is_suid, "sgid": is_sgid},
                    )
                )
        return findings

    # -- sudo -l -----------------------------------------------------------
    def _check_sudo_l(self, gtfo: dict) -> list[Finding]:
        proc = self._run(["sudo", "-n", "-l"])
        if proc.returncode != 0:
            return [
                self.finding(
                    title="sudo -l unavailable",
                    confidence=Confidence.INFO,
                    description=(
                        "`sudo -n -l` failed (password required, or no sudo rules for "
                        "this user). Not itself a finding."
                    ),
                    evidence={"stderr": proc.stderr.strip()},
                )
            ]

        findings: list[Finding] = []
        for line in proc.stdout.splitlines():
            match = _SUDO_RULE_RE.match(line)
            if not match:
                continue
            runas, nopasswd_marker, cmdspec = match.groups()
            cmdspec = cmdspec.strip()
            nopasswd = bool(nopasswd_marker and "NOPASSWD" in nopasswd_marker)

            runs_as_root = bool(re.search(r"\b(root|ALL)\b", runas))

            if cmdspec == "ALL":
                evidence = {"runas": runas, "nopasswd": nopasswd, "raw_line": line.strip()}
                title = f"Unrestricted sudo access as ({runas})"
                description = (
                    "`sudo -n -l` reports this user may run ANY command as "
                    f"({runas}). This is directly authorized, real access - "
                    "trivially gives a root shell via `sudo /bin/sh`."
                )
                if self.poc and runs_as_root:
                    result = poc_engine.attempt_sudo_all_poc()
                    evidence.update(result.as_evidence())
                    if result.success:
                        title = "ROOT CONFIRMED via unrestricted sudo"
                        description += f" PoC executed: `{' '.join(result.argv)}` actually returned euid {result.observed_uid}."
                findings.append(
                    self.finding(
                        title=title,
                        confidence=Confidence.CONFIRMED,
                        description=description,
                        evidence=evidence,
                        remediation="Restrict the sudoers entry to specific commands.",
                        exploit_command="sudo /bin/bash" if runs_as_root else None,
                    )
                )
                continue

            for cmd_entry in cmdspec.split(","):
                cmd_entry = cmd_entry.strip()
                if not cmd_entry:
                    continue
                binary_path = cmd_entry.split()[0]
                basename = os.path.basename(binary_path)
                entry = gtfo.get(basename)
                if entry and entry.get("sudo"):
                    evidence = {
                        "runas": runas,
                        "nopasswd": nopasswd,
                        "rule": cmd_entry,
                        "gtfobins_technique": "sudo",
                    }
                    if self.active:
                        evidence["active_probe"] = self._probe_binary(binary_path)

                    title = f"Exploitable sudo rule: {cmd_entry}"
                    description = (
                        f"`sudo -n -l` confirms this user is authorized to run "
                        f"'{cmd_entry}' as ({runas}){' without a password' if nopasswd else ''}, "
                        f"and '{basename}' is a known GTFOBins sudo escalation vector. "
                        "This authorization was directly verified, not inferred."
                    )
                    poc_args = entry.get("poc_args")
                    if self.poc and poc_args and runs_as_root:
                        result = poc_engine.attempt_sudo_poc(binary_path, poc_args)
                        evidence.update(result.as_evidence())
                        if result.success:
                            title = f"ROOT CONFIRMED via sudo exploitation: {cmd_entry}"
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
                    template = entry.get("sudo_shell_cmd")
                    if template and runs_as_root:
                        exploit_command = template.replace("<BIN>", binary_path)

                    findings.append(
                        self.finding(
                            title=title,
                            confidence=Confidence.CONFIRMED,
                            description=description,
                            evidence=evidence,
                            remediation=f"Remove or tighten the sudoers rule for '{binary_path}'",
                            references=[f"https://gtfobins.github.io/gtfobins/{basename}/"],
                            exploit_command=exploit_command,
                        )
                    )
                else:
                    findings.append(
                        self.finding(
                            title=f"Unclassified sudo rule: {cmd_entry}",
                            confidence=Confidence.INFO,
                            description=(
                                "Rule directly observed via `sudo -n -l` but binary is not "
                                "in the curated GTFOBins table - review manually."
                            ),
                            evidence={"runas": runas, "nopasswd": nopasswd, "rule": cmd_entry},
                        )
                    )
        return findings

    # -- active, non-destructive confirmation -----------------------------
    def _probe_binary(self, path: str) -> dict:
        """Run the binary with a harmless flag to confirm it's a real, live
        executable. Never writes, never spawns a shell, always time-boxed."""
        for flag in _SAFE_PROBE_FLAGS:
            proc = self._run([path, flag], timeout=3)
            if proc.returncode == 0 or proc.stdout or proc.stderr:
                return {
                    "flag_used": flag,
                    "exit_code": proc.returncode,
                    "output_snippet": (proc.stdout or proc.stderr)[:200],
                }
        return {"note": "binary did not respond to any safe probe flag"}
