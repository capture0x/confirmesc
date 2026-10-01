"""Core data types shared by every check."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Confidence(str, Enum):
    """How strongly a finding is backed by directly-observed facts.

    CONFIRMED - the exploitable condition itself was directly observed on the
                 system (a real writable file, a real SUID bit + known GTFOBins
                 binary, a real capability on a real binary, ...). No guessing.
    LIKELY    - a strong indicator was observed (e.g. a version string) that is
                 *usually* exploitable, but something else could stop it
                 (distro backport, missing dependency, disabled feature) and we
                 could not directly verify that extra condition.
    INFO      - informational; not itself an escalation path but useful context.
    ERROR     - the check could not complete (permission denied, tool missing).
    """

    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INFO = "INFO"
    ERROR = "ERROR"


# Sort order for reporting, most actionable first.
_CONFIDENCE_ORDER = {
    Confidence.CONFIRMED: 0,
    Confidence.LIKELY: 1,
    Confidence.INFO: 2,
    Confidence.ERROR: 3,
}


def confidence_sort_key(finding: "Finding") -> tuple:
    return (_CONFIDENCE_ORDER[finding.confidence], finding.category, finding.title)


@dataclass
class Finding:
    check_id: str
    category: str
    title: str
    confidence: Confidence
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cve: Optional[str] = None
    #: A ready-to-run command that gets an actual interactive root shell,
    #: only ever populated on CONFIRMED findings we have a verified-reliable
    #: recipe for. Never executed automatically - printed for the operator
    #: to run themselves. Deliberately avoids known shell privilege-drop
    #: pitfalls (dash/bash silently drop euid-!=-ruid privileges unless
    #: bypassed - see checks/suid_sudo.py and data/gtfobins.json for details)
    #: rather than reproducing a GTFOBins one-liner that may not actually
    #: work on the target's default shell.
    exploit_command: Optional[str] = None


class Check:
    """Base class every privesc check implements."""

    id: str = "base"
    category: str = "generic"
    #: True if this check ever performs an active (but non-destructive) probe
    #: such as running `<binary> --version`. Only done when active=True.
    supports_active: bool = False

    #: True if this check can attempt a real, live exploitation PoC
    #: (running the actual escalation payload and proving euid 0), gated
    #: behind the separate, more invasive --poc flag.
    supports_poc: bool = False

    def __init__(self, active: bool = False, poc: bool = False, timeout: int = 20):
        self.active = active
        self.poc = poc
        self.timeout = timeout

    def run(self) -> list[Finding]:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError

    # -- shared helpers -------------------------------------------------
    def _run(self, args: list[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        """Run a command, never raising on non-zero exit or missing binary."""
        try:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return subprocess.CompletedProcess(args, returncode=-1, stdout="", stderr=str(exc))

    def finding(self, **kwargs) -> Finding:
        kwargs.setdefault("check_id", self.id)
        kwargs.setdefault("category", self.category)
        return Finding(**kwargs)
