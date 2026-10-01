# Changelog

## v0.1.0

First release.

### Added

- Confirm-based Linux privilege-escalation enumeration with honest confidence
  levels: `CONFIRMED` / `LIKELY` / `INFO` / `ERROR`.
- A ready-to-run root shell command for every `CONFIRMED` SUID / sudo /
  capability vector, built to work around the `dash`/`bash` privilege drop.
- Checks: SUID/SGID + `sudo -l`, 14 curated kernel/sudo/polkit CVEs,
  cron/systemd/`$PATH`, cron wildcard injection, capabilities, critical-file
  writability, group escalation (docker/lxd/disk), NFS `no_root_squash`,
  sudo `env_keep`, credential recon.
- Scan modes: passive (default), `--active`, and `--poc` (live `euid 0` proof).
- Output formats: text, json, and html.
- Remote reporting: `--send` and the `confirmesc-recv` listener.
- AI agent integration: an MCP server (`scan` / `report` / `list_privesc_checks`)
  and 14 agent skills.
- Portable single-file build (`confirmesc.pyz`).
