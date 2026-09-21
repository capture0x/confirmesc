"""Credential recon: files that leak secrets across user boundaries.

Not privilege escalation by itself, but the single most common path INTO
one (a reused password, an API token, another user's private key). Every
finding here resolves to CONFIRMED via exactly one directly-observed fact:
the file belongs to a different uid than the current process AND
os.access() confirms the current user can read it anyway. Reading your own
files is never reported - that's not a misconfiguration.

Deliberately scoped to common, well-known locations rather than a slow
filesystem-wide grep - this stays fast enough to run as one check among many.
"""
from __future__ import annotations

import glob
import os
import re

from ..core.base import Check, Confidence, Finding

_SSH_KEY_BASENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
_SSH_SEARCH_GLOBS = ["/home/*/.ssh/*", "/root/.ssh/*"]

_CREDENTIAL_FILE_GLOBS = [
    "/home/*/.git-credentials",
    "/home/*/.netrc",
    "/home/*/.my.cnf",
    "/home/*/.pgpass",
    "/root/.git-credentials",
    "/root/.netrc",
    "/root/.my.cnf",
    "/root/.pgpass",
    "/var/www/*/wp-config.php",
    "/var/www/*/*/wp-config.php",
    "/var/www/*/.env",
    "/var/www/*/*/.env",
    "/srv/*/.env",
    "/opt/*/.env",
]

_HISTORY_GLOBS = [
    "/home/*/.bash_history",
    "/home/*/.zsh_history",
    "/home/*/.mysql_history",
    "/root/.bash_history",
    "/root/.zsh_history",
    "/root/.mysql_history",
]
_SECRET_KEYWORD_RE = re.compile(r"(password|passwd|secret|api[_-]?key|token)\s*[=:]", re.IGNORECASE)


class SecretsReconCheck(Check):
    id = "secrets_recon"
    category = "secrets_recon"
    supports_active = False
    supports_poc = False

    def run(self) -> list[Finding]:
        my_uid = os.getuid()
        findings: list[Finding] = []
        findings.extend(self._check_ssh_keys(my_uid))
        findings.extend(self._check_credential_files(my_uid))
        findings.extend(self._check_history_files(my_uid))
        return findings

    def _cross_user_readable(self, path: str, my_uid: int) -> tuple[bool, int | None]:
        try:
            st = os.stat(path)
        except OSError:
            return False, None
        if st.st_uid == my_uid:
            return False, st.st_uid  # our own file - not a finding
        return os.access(path, os.R_OK), st.st_uid

    def _check_ssh_keys(self, my_uid: int, globs: list[str] | None = None) -> list[Finding]:
        findings = []
        for pattern in (globs if globs is not None else _SSH_SEARCH_GLOBS):
            for path in glob.glob(pattern):
                basename = os.path.basename(path)
                if basename.endswith(".pub") or basename not in _SSH_KEY_BASENAMES:
                    continue
                readable, owner_uid = self._cross_user_readable(path, my_uid)
                if not readable:
                    continue
                findings.append(
                    self.finding(
                        title=f"Readable private SSH key belonging to another user: {path}",
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"'{path}' is owned by uid {owner_uid} (not the current user, uid {my_uid}) "
                            "but os.access() confirms it is readable anyway. This directly leaks that "
                            "user's SSH private key, which may grant lateral or root access if it's used "
                            "for a root-owned account or another host."
                        ),
                        evidence={"path": path, "owner_uid": owner_uid},
                        remediation=f"chmod 600 {path} and chown it to only the owning user.",
                    )
                )
        return findings

    def _check_credential_files(self, my_uid: int, globs: list[str] | None = None) -> list[Finding]:
        findings = []
        for pattern in (globs if globs is not None else _CREDENTIAL_FILE_GLOBS):
            for path in glob.glob(pattern):
                if not os.path.isfile(path):
                    continue
                readable, owner_uid = self._cross_user_readable(path, my_uid)
                if not readable:
                    continue
                findings.append(
                    self.finding(
                        title=f"Readable credential file belonging to another user: {path}",
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"'{path}' is owned by uid {owner_uid} but os.access() confirms it is "
                            "readable by the current user - likely contains plaintext credentials "
                            "(git, database, or application secrets)."
                        ),
                        evidence={"path": path, "owner_uid": owner_uid},
                        remediation=f"Restrict permissions on {path} (owner-only read).",
                    )
                )
        return findings

    def _check_history_files(self, my_uid: int, globs: list[str] | None = None) -> list[Finding]:
        findings = []
        for pattern in (globs if globs is not None else _HISTORY_GLOBS):
            for path in glob.glob(pattern):
                if not os.path.isfile(path):
                    continue
                readable, owner_uid = self._cross_user_readable(path, my_uid)
                if not readable:
                    continue
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        matches = [line.strip() for line in fh if _SECRET_KEYWORD_RE.search(line)]
                except OSError:
                    continue
                if not matches:
                    continue
                findings.append(
                    self.finding(
                        title=f"Readable shell history with credential-like entries: {path}",
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"'{path}' is owned by uid {owner_uid} but readable by the current user, "
                            f"and contains {len(matches)} line(s) matching password/secret/token "
                            "patterns - likely a credential typed on the command line."
                        ),
                        evidence={"path": path, "owner_uid": owner_uid, "match_count": len(matches), "sample": matches[0][:120]},
                        remediation=f"Restrict permissions on {path}; avoid typing secrets directly on the command line.",
                    )
                )
        return findings
