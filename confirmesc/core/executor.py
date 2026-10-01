"""Executor abstraction: where a check's commands and file reads actually run.

Every check talks to "the system" only through a `Check.fs` (an `Executor`)
plus the thin `Check._run`/`Check._stat`/... wrappers around it. This is
what makes remote mode possible: swap `LocalExecutor` (the default - runs
everything on this machine, today's exact behavior) for `SSHExecutor` and
the *same* check code runs entirely against a target reached over SSH, with
zero code ever touching the target's disk.
"""
from __future__ import annotations

import glob as _glob_module
import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class StatInfo:
    """Subset of `os.stat_result` that checks actually use.

    `st_mode` is the raw POSIX mode bits (same encoding `os.stat` uses, so
    existing `stat.S_ISUID`/`S_ISGID` checks work unchanged regardless of
    which Executor produced it).
    """

    st_mode: int
    st_uid: int
    st_gid: int
    st_size: int


class Executor:
    """Base interface. Subclasses implement each primitive for one transport."""

    def run(self, argv: list[str], timeout: float) -> subprocess.CompletedProcess:
        raise NotImplementedError

    def read_text(self, path: str) -> Optional[str]:
        raise NotImplementedError

    def stat(self, path: str) -> Optional[StatInfo]:
        raise NotImplementedError

    def exists(self, path: str) -> bool:
        raise NotImplementedError

    def is_file(self, path: str) -> bool:
        raise NotImplementedError

    def is_dir(self, path: str) -> bool:
        raise NotImplementedError

    def can_read(self, path: str) -> bool:
        raise NotImplementedError

    def can_write(self, path: str) -> bool:
        raise NotImplementedError

    def can_execute(self, path: str) -> bool:
        raise NotImplementedError

    def listdir(self, path: str) -> list[str]:
        raise NotImplementedError

    def walk_files(self, root: str) -> list[str]:
        """All regular files under `root`, recursively, as absolute paths."""
        raise NotImplementedError

    def getenv(self, name: str) -> str:
        """The named environment variable *of the system being checked* -
        never the operator's own local shell, which matters once `fs` is a
        remote executor (e.g. $PATH must be the target's, not ours)."""
        raise NotImplementedError

    def getuid(self) -> int:
        """The uid of the user being checked - the target's, not the
        operator's own, once `fs` is a remote executor."""
        raise NotImplementedError

    def glob(self, pattern: str) -> list[str]:
        """Expand a shell-style glob where each `*` matches within a single
        path component (never across `/`) - exactly `glob.glob`'s semantics,
        the only kind every check actually needs (e.g. `/home/*/.ssh/*`,
        `/etc/cron.d/*`). No `**`, `?`, or `[...]` support required."""
        raise NotImplementedError


class LocalExecutor(Executor):
    """Runs everything on this machine - today's exact behavior."""

    def run(self, argv: list[str], timeout: float) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return subprocess.CompletedProcess(argv, returncode=-1, stdout="", stderr=str(exc))

    def read_text(self, path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read()
        except OSError:
            return None

    def stat(self, path: str) -> Optional[StatInfo]:
        try:
            st = os.stat(path)
        except OSError:
            return None
        return StatInfo(st_mode=st.st_mode, st_uid=st.st_uid, st_gid=st.st_gid, st_size=st.st_size)

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def is_file(self, path: str) -> bool:
        return os.path.isfile(path)

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(path)

    def can_read(self, path: str) -> bool:
        return os.access(path, os.R_OK)

    def can_write(self, path: str) -> bool:
        return os.access(path, os.W_OK)

    def can_execute(self, path: str) -> bool:
        return os.access(path, os.X_OK)

    def listdir(self, path: str) -> list[str]:
        try:
            return os.listdir(path)
        except OSError:
            return []

    def walk_files(self, root: str) -> list[str]:
        files: list[str] = []
        for base, _dirs, names in os.walk(root):
            files.extend(os.path.join(base, name) for name in names)
        return files

    def getenv(self, name: str) -> str:
        return os.environ.get(name, "")

    def getuid(self) -> int:
        return os.getuid()

    def glob(self, pattern: str) -> list[str]:
        return sorted(_glob_module.glob(pattern))


class _RemoteShellMixin(Executor):
    """Implements every primitive except `run()` in terms of one POSIX
    command each, so a subclass only has to implement how a command's
    argv gets executed and how stdout/stderr/exit-code come back.

    This is what lets `SSHExecutor` reuse all the `stat`/`test`/`find`
    command construction below - a future transport only has to implement
    `run`.
    """

    default_timeout: float = 15.0

    def read_text(self, path: str) -> Optional[str]:
        proc = self.run(["cat", "--", path], self.default_timeout)
        return proc.stdout if proc.returncode == 0 else None

    def stat(self, path: str) -> Optional[StatInfo]:
        proc = self.run(["stat", "-c", "%f %u %g %s", "--", path], self.default_timeout)
        if proc.returncode != 0:
            return None
        try:
            hex_mode, uid, gid, size = proc.stdout.split()
            return StatInfo(st_mode=int(hex_mode, 16), st_uid=int(uid), st_gid=int(gid), st_size=int(size))
        except ValueError:
            return None

    def exists(self, path: str) -> bool:
        return self.run(["test", "-e", path], self.default_timeout).returncode == 0

    def is_file(self, path: str) -> bool:
        return self.run(["test", "-f", path], self.default_timeout).returncode == 0

    def is_dir(self, path: str) -> bool:
        return self.run(["test", "-d", path], self.default_timeout).returncode == 0

    def can_read(self, path: str) -> bool:
        return self.run(["test", "-r", path], self.default_timeout).returncode == 0

    def can_write(self, path: str) -> bool:
        return self.run(["test", "-w", path], self.default_timeout).returncode == 0

    def can_execute(self, path: str) -> bool:
        return self.run(["test", "-x", path], self.default_timeout).returncode == 0

    def listdir(self, path: str) -> list[str]:
        proc = self.run(["find", path, "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\\n"], self.default_timeout)
        return [line for line in proc.stdout.splitlines() if line] if proc.returncode == 0 else []

    def walk_files(self, root: str) -> list[str]:
        proc = self.run(["find", root, "-type", "f"], self.default_timeout)
        return [line for line in proc.stdout.splitlines() if line] if proc.returncode == 0 else []

    def getenv(self, name: str) -> str:
        proc = self.run(["printenv", name], self.default_timeout)
        return proc.stdout.strip() if proc.returncode == 0 else ""

    def getuid(self) -> int:
        proc = self.run(["id", "-u"], self.default_timeout)
        out = proc.stdout.strip()
        return int(out) if proc.returncode == 0 and out.isdigit() else -1

    def glob(self, pattern: str) -> list[str]:
        """`find`-based equivalent of `glob.glob` for `dir/.../*`-style
        patterns - the only kind any check needs. Best-effort: unlike the
        real glob module, `*` is matched via `find -path`'s fnmatch, so a
        literal `/` inside a filename could in principle confuse it - not a
        real-world concern for the fixed patterns checks use."""
        parts = pattern.split("/")
        fixed: list[str] = []
        remaining: list[str] = []
        wildcard_seen = False
        for part in parts:
            if not wildcard_seen and "*" not in part:
                fixed.append(part)
            else:
                wildcard_seen = True
                remaining.append(part)
        if not wildcard_seen:
            return [pattern] if self.exists(pattern) else []
        prefix = "/".join(fixed) or "/"
        depth = len(remaining)
        proc = self.run(
            ["find", prefix, "-mindepth", str(depth), "-maxdepth", str(depth), "-path", pattern],
            self.default_timeout,
        )
        return sorted(line for line in proc.stdout.splitlines() if line) if proc.returncode == 0 else []


class SSHExecutor(_RemoteShellMixin):
    """Drives a target purely through `ssh`, with no code ever placed on its
    disk. Requires the operator to already have (or be able to obtain, e.g.
    after upgrading an initial shell) SSH access."""

    def __init__(self, host: str, user: Optional[str] = None, port: int = 22, identity_file: Optional[str] = None):
        self.host = host
        self.user = user
        self.port = port
        self.identity_file = identity_file

    def _base_cmd(self) -> list[str]:
        target = f"{self.user}@{self.host}" if self.user else self.host
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-p", str(self.port)]
        if self.identity_file:
            cmd += ["-i", self.identity_file]
        cmd.append(target)
        return cmd

    def run(self, argv: list[str], timeout: float) -> subprocess.CompletedProcess:
        remote_cmd = shlex.join(argv)
        full_cmd = self._base_cmd() + [remote_cmd]
        try:
            proc = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout, check=False)
            return subprocess.CompletedProcess(argv, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return subprocess.CompletedProcess(argv, returncode=-1, stdout="", stderr=str(exc))
