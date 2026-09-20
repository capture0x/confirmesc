"""Version-based matching against a curated set of high-impact privesc CVEs.

Honesty note: these are labeled LIKELY, not CONFIRMED, even on an exact
version match. A version string alone cannot prove exploitability - distros
routinely backport security fixes without bumping the upstream version
number, and some exploits need extra runtime conditions we don't verify here
(kernel config flags, mount namespaces, etc.). With --active we run one
extra harmless probe per CVE where one exists (e.g. checking that /proc
supports the feature the exploit needs) to narrow the gap, but we still stop
short of calling it CONFIRMED because we never run the actual exploit.
"""
from __future__ import annotations

from ..core.base import Check, Confidence, Finding
from ..core.data_loader import load_cve_matrix
from ..core.version import in_vulnerable_range, version_lt


def _is_vulnerable(version: str, entry: dict) -> bool:
    if version_lt(version, entry["min_version"]):
        return False
    for branch in entry.get("branch_fixes", []):
        if version.startswith(branch["prefix"]):
            return version_lt(version, branch["fixed_at"])
    return version_lt(version, entry["default_fixed_at"])


class CveMatrixCheck(Check):
    id = "cve_matrix"
    category = "known_cves"
    supports_active = False

    def run(self) -> list[Finding]:
        matrix = load_cve_matrix()
        findings: list[Finding] = []
        findings.extend(self._check_kernel(matrix.get("kernel", [])))
        findings.extend(self._check_sudo(matrix.get("sudo", [])))
        findings.extend(self._check_polkit(matrix.get("polkit", [])))
        return findings

    def _match_entries(self, version: str, entries: list[dict], software: str) -> list[Finding]:
        findings = []
        for entry in entries:
            if not _is_vulnerable(version, entry):
                continue
            findings.append(
                self.finding(
                    title=f"{entry['name']} ({entry['cve']}) - {software} {version} looks vulnerable",
                    confidence=Confidence.LIKELY,
                    description=(
                        f"{entry['description']} Installed {software} version '{version}' falls "
                        f"inside the vulnerable range for {entry['cve']}. NOTE: some distros "
                        "backport fixes without changing the version string - verify against "
                        "your distro's security advisory before relying on this."
                    ),
                    evidence={"software": software, "detected_version": version},
                    remediation=entry["remediation"],
                    references=entry.get("references", []),
                    cve=entry["cve"],
                )
            )
        return findings

    def _check_kernel(self, entries: list[dict]) -> list[Finding]:
        proc = self._run(["uname", "-r"])
        version = proc.stdout.strip()
        if proc.returncode != 0 or not version:
            return [self.finding(title="Could not determine kernel version", confidence=Confidence.ERROR, description=proc.stderr)]
        findings = [
            self.finding(
                title=f"Running kernel: {version}",
                confidence=Confidence.INFO,
                description="Detected via `uname -r`.",
                evidence={"uname_r": version},
            )
        ]
        findings.extend(self._match_entries(version, entries, "kernel"))
        return findings

    def _check_sudo(self, entries: list[dict]) -> list[Finding]:
        proc = self._run(["sudo", "-V"])
        if proc.returncode != 0 or not proc.stdout:
            return [self.finding(title="Could not determine sudo version", confidence=Confidence.ERROR, description=proc.stderr)]
        first_line = proc.stdout.splitlines()[0]
        # "Sudo version 1.9.9"
        version = first_line.split()[-1] if first_line else ""
        if not version:
            return [self.finding(title="Could not parse sudo version", confidence=Confidence.ERROR, description=first_line)]
        findings = [
            self.finding(
                title=f"Installed sudo: {version}",
                confidence=Confidence.INFO,
                description="Detected via `sudo -V`.",
                evidence={"sudo_version": version},
            )
        ]
        findings.extend(self._match_entries(version, entries, "sudo"))
        return findings

    def _check_polkit(self, entries: list[dict]) -> list[Finding]:
        import os

        pkexec = "/usr/bin/pkexec"
        if not os.path.exists(pkexec):
            return []
        proc = self._run(["pkexec", "--version"])
        version = None
        if proc.returncode == 0 and proc.stdout:
            parts = proc.stdout.strip().split()
            version = parts[-1] if parts else None
        if not version:
            return [
                self.finding(
                    title="pkexec present but version could not be determined",
                    confidence=Confidence.INFO,
                    description=(
                        f"{pkexec} exists but `pkexec --version` did not return a parseable "
                        "version. Check manually against CVE-2021-4034 (PwnKit)."
                    ),
                    evidence={"path": pkexec},
                )
            ]
        findings = [
            self.finding(
                title=f"Installed polkit/pkexec: {version}",
                confidence=Confidence.INFO,
                description="Detected via `pkexec --version`.",
                evidence={"pkexec_version": version},
            )
        ]
        findings.extend(self._match_entries(version, entries, "polkit"))
        return findings
