"""Cron wildcard injection (the classic GTFOBins "Wildcards" technique).

When a root cron job runs `tar`/`rsync`/`chown`/`chmod`/`zip`/`7z` with an
unquoted `*` inside a directory the current user can write to, planting a
file named like a command-line flag (e.g. `--checkpoint=1`,
`--checkpoint-action=exec=sh script.sh` for tar) makes the shell's glob
expansion hand that "filename" to the command as an option, which several of
these tools can turn into arbitrary code execution running as root.

CONFIRMED requires both facts to be directly verified: the vulnerable
command+wildcard pattern in a real root-run script, AND os.access() proving
the relevant directory is actually writable by the current user. If we can't
determine the working directory with confidence, we still report the pattern
but at LIKELY, since we can't confirm the second half of the condition.
"""
from __future__ import annotations

import glob
import os
import re

from ..core.base import Check, Confidence, Finding

_VULNERABLE_COMMANDS = ("tar", "rsync", "chown", "chmod", "zip", "7z")
_CD_RE = re.compile(r"^\s*cd\s+(\S+)")
# /etc/crontab and /etc/cron.d/* use the crontab table format
# ('min hour dom mon dow user command...' or '@special user command...') -
# each LINE is an independently-scheduled, independently-executed job, so a
# `cd` on one line must never leak into the next line's working directory.
_CRONTAB_STYLE_SOURCES = ["/etc/crontab", "/etc/cron.d/*"]
# run-parts style: each file *is* one sequential shell script, so `cd`
# legitimately persists across lines within the same file.
_SCRIPT_SOURCES = [
    "/etc/cron.hourly/*",
    "/etc/cron.daily/*",
    "/etc/cron.weekly/*",
    "/etc/cron.monthly/*",
]


def _split_statements(line: str) -> list[str]:
    # Good enough for cron/shell scripts: split on statement separators.
    # Not a full shell parser - quoted ';'/'&&' inside strings would confuse
    # it, but that's rare in these scripts and we'd rather under- than
    # over-report.
    return re.split(r"&&|\|\||;", line)


class WildcardInjectionCheck(Check):
    id = "wildcard_injection"
    category = "wildcard_injection"
    supports_active = False
    supports_poc = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        crontab_files: list[str] = []
        for pattern in _CRONTAB_STYLE_SOURCES:
            crontab_files.extend(glob.glob(pattern))
        for path in crontab_files:
            if os.path.isfile(path):
                findings.extend(self._scan_file(path, is_crontab_style=True))

        script_files: list[str] = []
        for pattern in _SCRIPT_SOURCES:
            script_files.extend(glob.glob(pattern))
        for path in script_files:
            if os.path.isfile(path):
                findings.extend(self._scan_file(path, is_crontab_style=False))

        return findings

    @staticmethod
    def _strip_crontab_schedule(line: str) -> str:
        """Drop the 'min hour dom mon dow user' (or '@special user') prefix
        so command detection looks at the actual command, not schedule
        digits or the username."""
        tokens = line.split()
        if not tokens:
            return line
        if tokens[0].startswith("@"):
            return " ".join(tokens[2:])  # @daily user command...
        if len(tokens) < 7:  # 5 schedule fields + user + at least 1 command token
            return ""
        return " ".join(tokens[6:])

    def _scan_file(self, path: str, is_crontab_style: bool) -> list[Finding]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            return []

        findings: list[Finding] = []
        cwd_context: str | None = None

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if is_crontab_style:
                # Each crontab line is its own independent job/shell - never
                # let a previous line's `cd` leak into this one.
                cwd_context = None
                stripped = self._strip_crontab_schedule(stripped)
                if not stripped:
                    continue

            for statement in _split_statements(stripped):
                statement = statement.strip()
                if not statement:
                    continue

                cd_match = _CD_RE.match(statement)
                if cd_match:
                    cwd_context = cd_match.group(1)
                    continue

                tokens = statement.split()
                if not tokens:
                    continue
                command = os.path.basename(tokens[0])
                if command not in _VULNERABLE_COMMANDS:
                    continue

                wildcard_token = next((t for t in tokens[1:] if "*" in t), None)
                if not wildcard_token:
                    continue

                target_dir = cwd_context
                if "/" in wildcard_token:
                    candidate = wildcard_token.rsplit("/", 1)[0]
                    if candidate:
                        target_dir = candidate

                writable = bool(target_dir) and os.path.isdir(target_dir) and os.access(target_dir, os.W_OK)
                findings.append(
                    self.finding(
                        title=f"Cron wildcard injection risk: '{command}' in {path}",
                        confidence=Confidence.CONFIRMED if (target_dir and writable) else Confidence.LIKELY,
                        description=(
                            f"{path} runs `{statement.strip()}` - '{command}' with an unquoted "
                            f"wildcard ('{wildcard_token}') is vulnerable to the classic GTFOBins "
                            "wildcard injection technique (planting a file named like a CLI flag "
                            "to hijack the command). "
                            + (
                                f"os.access() confirms the working directory '{target_dir}' is "
                                "writable by the current user - directly exploitable."
                                if target_dir and writable
                                else "Could not confirm the working directory is writable "
                                "(no clear 'cd' context found) - verify manually before relying on this."
                            )
                        ),
                        evidence={
                            "cron_file": path,
                            "statement": statement.strip(),
                            "command": command,
                            "wildcard_token": wildcard_token,
                            "working_directory": target_dir,
                            "writable": writable,
                        },
                        remediation=(
                            f"Quote/escape the wildcard or use `--` before it in {path} "
                            f"(e.g. `tar czf archive.tar.gz -- *` still isn't fully safe; prefer "
                            "explicit file lists), and avoid running such commands from "
                            "world/group-writable directories."
                        ),
                        references=["https://gtfobins.github.io/gtfobins/tar/#wildcard"],
                    )
                )
        return findings
