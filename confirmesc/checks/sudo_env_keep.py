"""sudo env_keep exposing LD_PRELOAD / LD_LIBRARY_PATH / PYTHONPATH.

If sudoers keeps one of these env vars across `sudo`, and the current user
has ANY sudo rule at all (even to one specific, otherwise-harmless binary),
they can preload a malicious shared object that runs as root the moment that
binary is invoked via sudo.

Condition-only by design: proving it live would mean compiling a shared
object and writing it to disk, which breaks the "never writes to disk, even
under --poc" guarantee every other PoC in this tool holds to. Documented as
a known limitation instead of silently faking that guarantee.
"""
from __future__ import annotations

import re

from ..core.base import Check, Confidence, Finding

_DANGEROUS_ENV_VARS = ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PERL5LIB")
_ENV_KEEP_RE = re.compile(r"env_keep\s*\+?=\s*\"?([^\n\"]+)\"?", re.IGNORECASE)


class SudoEnvKeepCheck(Check):
    id = "sudo_env_keep"
    category = "sudo_env_keep"
    supports_active = False
    supports_poc = False

    def run(self) -> list[Finding]:
        proc = self._run(["sudo", "-n", "-l"])
        if proc.returncode != 0:
            return []  # no sudo access at all - sudo -l unavailable, nothing to leverage

        has_any_rule = any(
            line.strip() and not line.strip().startswith(("Matching", "User", "Sudoers"))
            for line in proc.stdout.splitlines()
        )
        if not has_any_rule:
            return []

        kept_vars: set[str] = set()
        for match in _ENV_KEEP_RE.finditer(proc.stdout):
            kept_vars.update(v.strip() for v in match.group(1).split())

        dangerous = kept_vars & set(_DANGEROUS_ENV_VARS)
        if not dangerous:
            return []

        return [
            self.finding(
                title=f"sudo env_keep preserves {', '.join(sorted(dangerous))}",
                confidence=Confidence.CONFIRMED,
                description=(
                    f"`sudo -n -l` directly shows env_keep includes {', '.join(sorted(dangerous))}, "
                    "and this user is authorized for at least one sudo rule. Any sudo-run command "
                    "can be hijacked by preloading a malicious shared object "
                    "(`sudo LD_PRELOAD=/path/evil.so <allowed-command>`) to get a root shell."
                ),
                evidence={"kept_vars": sorted(dangerous), "raw_sudo_l": proc.stdout.strip()},
                remediation=f"Remove {', '.join(sorted(dangerous))} from env_keep in sudoers.",
                references=["https://gtfobins.github.io/gtfobins/sudo/#shell"],
            )
        ]
