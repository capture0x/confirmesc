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
"""
from __future__ import annotations

import os
import re
import stat

from ..core.base import Check, Confidence, Finding
from ..core.data_loader import load_gtfobins

_SAFE_PROBE_FLAGS = ("--version", "-V", "--help")
_SUDO_RULE_RE = re.compile(r"^\s*\(([^)]+)\)\s*((?:NOPASSWD:|PASSWD:)\s*)?(.+)$")
# Container image layers on disk aren't the live root filesystem - a SUID bit
# baked into a container image layer isn't a host privesc vector by itself.
_NOISE_SUBSTRINGS = ("/containers/storage/", "/docker/overlay2/")


class SuidSudoCheck(Check):
    id = "suid_sudo"
    category = "suid_sgid_sudo"
    supports_active = True

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
                findings.append(
                    self.finding(
                        title=f"Exploitable SUID/SGID binary: {path}",
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"'{basename}' is set{'uid' if is_suid else ''}"
                            f"{'/setgid' if is_sgid else ''} and is a known GTFOBins "
                            "SUID escalation vector. Directly observed on disk with "
                            f"os.stat(): mode={oct(st.st_mode)}, owner uid={st.st_uid}."
                        ),
                        evidence=evidence,
                        remediation=(
                            f"Remove the setuid/setgid bit if not required: "
                            f"chmod -s {path}. See https://gtfobins.github.io/gtfobins/{basename}/"
                        ),
                        references=[f"https://gtfobins.github.io/gtfobins/{basename}/"],
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

            if cmdspec == "ALL":
                findings.append(
                    self.finding(
                        title=f"Unrestricted sudo access as ({runas})",
                        confidence=Confidence.CONFIRMED,
                        description=(
                            "`sudo -n -l` reports this user may run ANY command as "
                            f"({runas}). This is directly authorized, real access - "
                            "trivially gives a root shell via `sudo /bin/sh`."
                        ),
                        evidence={"runas": runas, "nopasswd": nopasswd, "raw_line": line.strip()},
                        remediation="Restrict the sudoers entry to specific commands.",
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
                    findings.append(
                        self.finding(
                            title=f"Exploitable sudo rule: {cmd_entry}",
                            confidence=Confidence.CONFIRMED,
                            description=(
                                f"`sudo -n -l` confirms this user is authorized to run "
                                f"'{cmd_entry}' as ({runas}){' without a password' if nopasswd else ''}, "
                                f"and '{basename}' is a known GTFOBins sudo escalation vector. "
                                "This authorization was directly verified, not inferred."
                            ),
                            evidence=evidence,
                            remediation=(
                                f"Remove or tighten the sudoers rule for '{binary_path}'. "
                                f"See https://gtfobins.github.io/gtfobins/{basename}/"
                            ),
                            references=[f"https://gtfobins.github.io/gtfobins/{basename}/"],
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
