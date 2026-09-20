"""All built-in checks, in the order they are run."""
from __future__ import annotations

from ..core.base import Check
from .capabilities_files import CapabilitiesAndCriticalFilesCheck
from .cve_matrix import CveMatrixCheck
from .cron_systemd_path import CronSystemdPathCheck
from .suid_sudo import SuidSudoCheck

ALL_CHECKS: list[type[Check]] = [
    SuidSudoCheck,
    CveMatrixCheck,
    CronSystemdPathCheck,
    CapabilitiesAndCriticalFilesCheck,
]
