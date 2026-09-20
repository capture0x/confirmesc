"""Real, active exploitation-confirmation ("PoC") primitives.

This is the strongest and most invasive confirmation tier `confirmesc` offers,
gated behind the explicit `--poc` flag (never on by default, never implied by
`--active`). For each GTFOBins vector that has a curated `poc_args`/
`cap_poc_args` payload, we actually invoke the real binary with a payload
whose *only* effect is to print the resulting effective UID (`id -u`) and
immediately exit. Nothing is written to disk, no shell is spawned, no
persistence is created - the only "damage" a failed attempt can do is print
"1000" instead of "0".

This turns a CONFIRMED-by-condition finding (permissions/authorization look
right) into a CONFIRMED-by-execution finding (we actually got euid 0).
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Optional

_TIMEOUT = 6


@dataclass
class PocResult:
    attempted: bool
    success: Optional[bool] = None  # None = attempted but result inconclusive
    observed_uid: Optional[str] = None
    argv: list[str] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""

    def as_evidence(self) -> dict:
        return {
            "poc_attempted": self.attempted,
            "poc_success": self.success,
            "poc_observed_uid": self.observed_uid,
            "poc_argv": self.argv,
            "poc_raw_output": self.raw_output[:200] if self.raw_output else "",
            "poc_error": self.error,
        }


def _extract_uid(output: str) -> Optional[str]:
    for line in output.splitlines():
        line = line.strip()
        if line.isdigit():
            return line
    return None


def _run_argv(argv: list[str], timeout: int = _TIMEOUT) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return subprocess.CompletedProcess(argv, returncode=-1, stdout="", stderr=str(exc))


def attempt_suid_poc(binary_path: str, poc_args: list[str]) -> PocResult:
    """Run the SUID binary itself with its curated payload.

    The kernel already grants euid 0 at exec() because the setuid bit is set
    on this exact file - no sudo, no wrapper.
    """
    argv = [binary_path] + poc_args
    proc = _run_argv(argv)
    if proc.returncode == -1:
        return PocResult(attempted=True, success=None, argv=argv, error=proc.stderr)
    uid = _extract_uid(proc.stdout)
    return PocResult(
        attempted=True,
        success=(uid == "0"),
        observed_uid=uid,
        argv=argv,
        raw_output=proc.stdout,
        error=proc.stderr.strip() if proc.returncode != 0 and not uid else "",
    )


def attempt_sudo_poc(binary_path: str, poc_args: list[str]) -> PocResult:
    """Run the binary via `sudo -n`, using the exact rule the user is
    authorized for. Only ever invoked for a binary/args combination that
    `sudo -n -l` already confirmed is authorized without a password prompt
    hanging - `-n` guarantees we never block waiting for input.
    """
    argv = ["sudo", "-n", binary_path] + poc_args
    proc = _run_argv(argv)
    if proc.returncode == -1:
        return PocResult(attempted=True, success=None, argv=argv, error=proc.stderr)
    uid = _extract_uid(proc.stdout)
    return PocResult(
        attempted=True,
        success=(uid == "0"),
        observed_uid=uid,
        argv=argv,
        raw_output=proc.stdout,
        error=proc.stderr.strip() if proc.returncode != 0 and not uid else "",
    )


def attempt_sudo_all_poc() -> PocResult:
    """PoC for an unrestricted `(ALL : ALL) ALL` sudo rule."""
    argv = ["sudo", "-n", "id", "-u"]
    proc = _run_argv(argv)
    if proc.returncode == -1:
        return PocResult(attempted=True, success=None, argv=argv, error=proc.stderr)
    uid = _extract_uid(proc.stdout)
    return PocResult(attempted=True, success=(uid == "0"), observed_uid=uid, argv=argv, raw_output=proc.stdout)


def attempt_capability_poc(binary_path: str, cap_poc_args: list[str]) -> PocResult:
    """Run the binary directly - its capability set (e.g. cap_setuid+ep) is
    attached to the file itself, so no sudo/setuid wrapper is needed; the
    payload calls os.setuid(0) itself before printing the resulting uid.
    """
    argv = [binary_path] + cap_poc_args
    proc = _run_argv(argv)
    if proc.returncode == -1:
        return PocResult(attempted=True, success=None, argv=argv, error=proc.stderr)
    uid = _extract_uid(proc.stdout)
    return PocResult(
        attempted=True,
        success=(uid == "0"),
        observed_uid=uid,
        argv=argv,
        raw_output=proc.stdout,
        error=proc.stderr.strip() if proc.returncode != 0 and not uid else "",
    )
