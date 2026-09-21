"""All built-in checks, in the order they are run."""
from __future__ import annotations

from ..core.base import Check
from .capabilities_files import CapabilitiesAndCriticalFilesCheck
from .cve_matrix import CveMatrixCheck
from .cron_systemd_path import CronSystemdPathCheck
from .group_escalation import GroupEscalationCheck
from .nfs import NfsCheck
from .secrets_recon import SecretsReconCheck
from .sudo_env_keep import SudoEnvKeepCheck
from .suid_sudo import SuidSudoCheck
from .wildcard_injection import WildcardInjectionCheck

ALL_CHECKS: list[type[Check]] = [
    SuidSudoCheck,
    CveMatrixCheck,
    CronSystemdPathCheck,
    CapabilitiesAndCriticalFilesCheck,
    GroupEscalationCheck,
    NfsCheck,
    WildcardInjectionCheck,
    SudoEnvKeepCheck,
    SecretsReconCheck,
]
