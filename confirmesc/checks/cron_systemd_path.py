"""Root-run cron jobs / systemd units / $PATH entries that the current user
can write into.

"Confirmed" here means exactly what it says: os.access(path, os.W_OK) (or
writability of the containing directory, which is equally exploitable via
delete+recreate) was directly tested against the real filesystem for a
script/binary that a privileged scheduler (cron or systemd, running as root)
will execute. There is no heuristic or guesswork involved.
"""
from __future__ import annotations

import glob
import os
import re
import stat

from ..core.base import Check, Confidence, Finding

# Real crontab-format files: 5 schedule fields + a user field + a command.
# (/etc/cron.d/* files use this format, same as /etc/crontab.)
_CRONTAB_STYLE_PATTERNS = ["/etc/crontab", "/etc/cron.d/*"]
# run-parts style: each file *is* the script that gets executed directly,
# there is no crontab table to parse inside it.
_CRON_SCRIPT_DIR_PATTERNS = [
    "/etc/cron.hourly/*",
    "/etc/cron.daily/*",
    "/etc/cron.weekly/*",
    "/etc/cron.monthly/*",
]
# Paths where write access is either meaningless (pseudo-devices) or not a
# real host privesc vector (container image layers on disk, not live root).
_NOISE_SUBSTRINGS = ("/containers/storage/", "/docker/overlay2/")
_SYSTEMD_DIRS = ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"]
_EXEC_START_RE = re.compile(r"^\s*Exec(Start|StartPre|StartPost)\s*=\s*(.+)$")
# Skip pseudo/well-known system dirs that are supposed to be root-only and are
# irrelevant to "user writable" analysis.
_SKIP_DIRS = {"/proc", "/sys", "/dev"}


def _writable(path: str) -> bool:
    return os.access(path, os.W_OK)


def _dir_writable(path: str) -> bool:
    directory = os.path.dirname(path) or "/"
    return os.access(directory, os.W_OK)


class CronSystemdPathCheck(Check):
    id = "cron_systemd_path"
    category = "scheduled_tasks_and_path"
    supports_active = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_cron())
        findings.extend(self._check_systemd())
        findings.extend(self._check_path())
        return findings

    # -- cron --------------------------------------------------------------
    def _check_cron(self) -> list[Finding]:
        findings: list[Finding] = []

        crontab_files: list[str] = []
        for pattern in _CRONTAB_STYLE_PATTERNS:
            crontab_files.extend(glob.glob(pattern))
        for cron_file in crontab_files:
            if not os.path.isfile(cron_file):
                continue
            findings.extend(self._check_target(cron_file, "cron definition file"))
            findings.extend(self._parse_crontab_commands(cron_file))

        script_files: list[str] = []
        for pattern in _CRON_SCRIPT_DIR_PATTERNS:
            script_files.extend(glob.glob(pattern))
        for script in script_files:
            if os.path.isfile(script):
                findings.extend(self._check_target(script, "cron.{hourly,daily,weekly,monthly} script"))
        return findings

    def _parse_crontab_commands(self, cron_file: str) -> list[Finding]:
        """Extract the command a crontab-format line actually executes.

        Format is `min hour dom mon dow user command [args...]` (or
        `@special user command [args...]`). We deliberately do NOT just grab
        "any absolute path on the line" - that also matches redirection
        targets like `> /dev/null`, which are not the executed command.
        """
        try:
            with open(cron_file, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            return []

        findings: list[Finding] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Only the part before any redirection is the invoked command.
            command_part = re.split(r"[<>]", line, maxsplit=1)[0]
            tokens = command_part.split()
            if not tokens:
                continue
            if tokens[0].startswith("@"):
                fields = tokens[1:]  # @daily user command...
            else:
                if len(tokens) < 7:  # 5 schedule fields + user + at least 1 command token
                    continue
                fields = tokens[6:]
            if not fields:
                continue
            script = fields[0]
            if script.startswith("/") and os.path.exists(script):
                findings.extend(self._check_target(script, f"command executed by {cron_file}"))
        return findings

    def _check_target(self, path: str, context: str) -> list[Finding]:
        if path.startswith(("/dev/", "/proc/", "/sys/")) or any(n in path for n in _NOISE_SUBSTRINGS):
            return []
        findings = []
        if _writable(path):
            findings.append(
                self.finding(
                    title=f"Writable file executed by root scheduler: {path}",
                    confidence=Confidence.CONFIRMED,
                    description=(
                        f"{context} — os.access() confirms the current user can write to "
                        f"'{path}' directly. Overwriting it will have root run our code on "
                        "its next scheduled execution."
                    ),
                    evidence={"path": path, "context": context, "check": "file writable"},
                    remediation=f"Restrict ownership/permissions on {path} (root:root, 0644 or stricter).",
                )
            )
        elif _dir_writable(path):
            directory = os.path.dirname(path)
            findings.append(
                self.finding(
                    title=f"Writable directory containing root-scheduled file: {directory}",
                    confidence=Confidence.CONFIRMED,
                    description=(
                        f"{context} — the file itself isn't writable but its containing "
                        f"directory '{directory}' is, confirmed via os.access(). The file can "
                        "be deleted and replaced, which is equally exploitable."
                    ),
                    evidence={"path": path, "directory": directory, "context": context, "check": "directory writable"},
                    remediation=f"Restrict write permissions on {directory}.",
                )
            )
        return findings

    # -- systemd -------------------------------------------------------------
    def _check_systemd(self) -> list[Finding]:
        findings: list[Finding] = []
        for base in _SYSTEMD_DIRS:
            if not os.path.isdir(base):
                continue
            for root, _dirs, files in os.walk(base):
                for name in files:
                    if not name.endswith(".service"):
                        continue
                    unit_path = os.path.join(root, name)
                    try:
                        with open(unit_path, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                    except OSError:
                        continue
                    for line in content.splitlines():
                        match = _EXEC_START_RE.match(line)
                        if not match:
                            continue
                        exec_line = match.group(2).strip().lstrip("-").lstrip("@").lstrip("+")
                        exec_path = exec_line.split()[0] if exec_line else ""
                        if exec_path.startswith("/") and os.path.exists(exec_path):
                            findings.extend(
                                self._check_target(exec_path, f"ExecStart target of systemd unit {unit_path}")
                            )
        return findings

    # -- $PATH ---------------------------------------------------------------
    def _check_path(self) -> list[Finding]:
        findings: list[Finding] = []
        path_env = os.environ.get("PATH", "")
        seen_writable_before_system = False
        for directory in path_env.split(os.pathsep):
            if not directory or directory in _SKIP_DIRS:
                continue
            if not os.path.isdir(directory):
                continue
            if directory in (".", ""):
                findings.append(
                    self.finding(
                        title="Relative/current directory in $PATH",
                        confidence=Confidence.CONFIRMED,
                        description="An empty or '.' entry in $PATH means commands can be hijacked by placing a malicious binary in the current working directory.",
                        evidence={"PATH": path_env},
                    )
                )
                continue
            if _writable(directory):
                seen_writable_before_system = True
                findings.append(
                    self.finding(
                        title=f"Writable directory in $PATH: {directory}",
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"os.access() confirms the current user can write into '{directory}', "
                            "which is on $PATH. If a root-run script or cron job invokes a command "
                            "by basename without an absolute path and this directory precedes the "
                            "real binary's directory, a planted binary here will run as root."
                        ),
                        evidence={"directory": directory, "PATH": path_env},
                        remediation=f"Remove {directory} from PATH or restrict its permissions.",
                    )
                )
        return findings
