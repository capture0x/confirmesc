# confirmesc

A Linux privilege-escalation enumerator built around one idea: **don't just
list suspicious things — confirm whether they're actually exploitable.**

Tools like LinEnum and linpeas dump every SUID binary, every cron job, every
kernel version on the box and leave it to you to figure out which of the 200
lines actually matter. `confirmesc` re-verifies each candidate directly
against the running system (real file permissions, real capabilities, real
`sudo -l` authorization, exact version-range matches) and assigns it an
honest confidence level, so you can jump straight to what's actionable.

## Confidence levels

| Level       | Meaning |
|-------------|---------|
| `CONFIRMED` | The exploitable condition itself was directly observed (a real writable root-cron file, a real SUID bit on a known GTFOBins binary, a real dangerous capability, an authorized `sudo -l` rule). Not a guess. |
| `LIKELY`    | A strong indicator matched (typically a version string against a known-CVE range), but distro backports or extra runtime conditions could still block it — verify manually. |
| `INFO`      | Context worth knowing, not itself an escalation path (e.g. an unclassified SUID binary not in the curated GTFOBins table — flagged for manual review, not asserted exploitable). |
| `ERROR`     | The check itself could not complete (missing tool, permission denied). |

## What it checks (v0.1)

- **SUID/SGID + `sudo -l`**, cross-referenced against a curated [GTFOBins](https://gtfobins.github.io/) table
- **Known high-impact CVEs** (Dirty Pipe, Dirty COW, OverlayFS, Sudo Baron Samedit, sudo `-1` uid bypass, PwnKit) via exact, branch-aware version comparison
- **Cron / systemd / `$PATH`** entries writable by the current user that a root-run scheduler will execute
- **Capabilities** (`getcap -r /`) and **critical file** (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, ...) writability

## Three confirmation tiers: passive → active → PoC

By default `confirmesc` is **fully passive** — it only reads file metadata,
runs read-only commands (`find`, `getcap`, `sudo -n -l`, `uname -r`, ...),
and never writes to disk or executes an exploit.

**`--active`** allows one additional, still non-destructive step per
finding: running a suspected binary with a harmless flag (`--version`,
`--help`) to confirm it's a real, live executable rather than a dangling
symlink. This never spawns a shell, never writes a file, and is always
time-boxed (3s).

**`--poc`** goes further and is genuinely invasive: for every SUID / sudo /
capability vector we have a curated payload for (`find`, `python`/`python2`/
`python3`, `perl`, `ruby`, `php`, `node`, `lua`, `awk`/`gawk`, `bash`, and
unrestricted `sudo ALL` rules), it **actually runs the real GTFOBins
escalation payload** and checks whether the resulting process really has
`euid == 0`. That flips a finding from "the conditions for exploitation are
real" (CONFIRMED-by-condition) to "we actually got root, right now"
(CONFIRMED-by-execution) — the strongest claim a privesc tool can make
without leaving state behind.

Every `--poc` payload is deliberately a single read-only `id -u` proof
(e.g. `find . -maxdepth 0 -exec /usr/bin/id -u ;`, `python3 -c "import os;
os.system('id -u')"`, `bash -p -c "id -u"`) — no interactive shell is ever
spawned, no file is written, nothing persists. A failed attempt only ever
prints an unprivileged uid instead of `0`; it does not downgrade the
CONFIRMED-by-condition finding, it just notes the discrepancy so you know
live exploitation didn't line up with the GTFOBins reference on this box.

Not every vector has a `--poc` recipe yet (editors/pagers like `vim`/`less`
that need a TTY, and cron/systemd writable-file findings that would require
waiting for a scheduler to fire, are intentionally left as condition-only —
see "Known limitations" below).

**Only use `--poc` against systems you are explicitly authorized to test**
(your own systems, a CTF, or an engagement with signed authorization). It
will attempt real privilege escalation.

## Install & run

```bash
git clone <this repo>
cd confirmesc
python3 -m pip install -e .
confirmesc                       # passive scan, text report
confirmesc --active              # + harmless binary probes
confirmesc --poc                 # + real exploitation proof (authorized systems only)
confirmesc --format json -o out.json
confirmesc --category suid_sgid_sudo --min-confidence LIKELY
```

Or without installing:

```bash
python3 -m confirmesc.cli
```

Exit code is `1` if any `CONFIRMED` finding exists, `0` otherwise — useful in CI/CTF automation.

## Known limitations

- `--poc` only covers vectors with a curated non-interactive payload (see list above). Editor/pager GTFOBins entries (`vim`, `less`, `man`, ...) need a TTY and are condition-only for now.
- Writable cron/systemd targets are confirmed by write-access, not by actually waiting for the scheduler to fire and observing root execution — that would require a real (if reversible) wait/trigger step and isn't implemented yet.
- Kernel/sudo/polkit CVE matches are version-string based (`LIKELY`); a distro can backport a fix without changing the version string, so always cross-check against your distro's advisory before relying on one.
- The GTFOBins and CVE tables are curated subsets, not a full scrape — extend them as you hit binaries/CVEs they don't cover yet.

## Extending

- Add binaries to `confirmesc/data/gtfobins.json` (`{"suid": bool, "sudo": bool, "capability": bool, "poc_args": [...], "cap_poc_args": [...]}`). `poc_args`/`cap_poc_args` are optional argv lists appended after the binary path — keep payloads read-only (print a uid, nothing else).
- Add CVEs to `confirmesc/data/cve_matrix.json` (`min_version`, optional `branch_fixes`, `default_fixed_at`).
- Add a new check by subclassing `confirmesc.core.base.Check` and registering it in `confirmesc/checks/__init__.py`.

## Project design rules

- **General-purpose, target-agnostic**: no check may hardcode a hostname, IP, username, or CTF-specific path. Every check must work against any Linux box.
- **No destructive actions ever**, even under `--active`. If a proposed check needs to modify system state to confirm something, it stays passive/heuristic (labeled `LIKELY`/`INFO`) instead.

## License

MIT — see [LICENSE](LICENSE).
