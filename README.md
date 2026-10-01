# confirmesc

A Linux privilege-escalation enumerator built around one idea: **don't just
list suspicious things — confirm whether they're actually exploitable.**

Tools like LinEnum and linpeas dump every SUID binary, every cron job, every
kernel version on the box and leave it to you to figure out which of the 200
lines actually matter. `confirmesc` re-verifies each candidate directly
against the running system (real file permissions, real capabilities, real
`sudo -l` authorization, exact version-range matches) and assigns it an
honest confidence level, so you can jump straight to what's actionable.

It also goes one step further than a reference link. Every GTFOBins-style
tool tells you "this binary is on the list, go look it up" - but a lot of
the classic one-liners on GTFOBins silently fail on a modern Debian/Kali box,
because `/bin/sh` is `dash`, and both `dash` and `bash` (without `-p`)
**actively drop root privileges the instant they detect `euid != ruid`** -
a real, verified Linux shell hardening behavior, not a bug. `confirmesc`
generates the exploit command *knowing this*: it either calls `setuid(0)`
explicitly before ever touching a shell, uses `bash -p`, or bypasses the
shell entirely via a direct `exec()`. Every `CONFIRMED` finding with a
verified-reliable recipe gets a **ready-to-run command that actually spawns
an interactive root shell** - not just a link, and not just an `id -u`
probe. This was verified end-to-end in the `testlab/` sandbox: both the
generated SUID and sudo commands were run for real and produced
`uid=0(root)`.

## Confidence levels

| Level       | Meaning |
|-------------|---------|
| `CONFIRMED` | The exploitable condition itself was directly observed (a real writable root-cron file, a real SUID bit on a known GTFOBins binary, a real dangerous capability, an authorized `sudo -l` rule). Not a guess. |
| `LIKELY`    | A strong indicator matched (typically a version string against a known-CVE range), but distro backports or extra runtime conditions could still block it — verify manually. |
| `INFO`      | Context worth knowing, not itself an escalation path (e.g. an unclassified SUID binary not in the curated GTFOBins table — flagged for manual review, not asserted exploitable). |
| `ERROR`     | The check itself could not complete (missing tool, permission denied). |

## What it checks

- **SUID/SGID + `sudo -l`**, cross-referenced against a curated [GTFOBins](https://gtfobins.github.io/) table
- **14 curated high-impact CVEs** (Dirty Pipe, Dirty COW, two OverlayFS bugs, Netfilter/nf_tables x2 including the widely-weaponized CVE-2024-1086, PTRACE_TRACEME, io_uring, Sudo Baron Samedit, sudo `-1` uid bypass, sudoedit EDITOR escape, PwnKit, polkit D-Bus bypass) via exact, branch-aware version comparison
- **Cron / systemd / `$PATH`** entries writable by the current user that a root-run scheduler will execute
- **Cron wildcard injection** - `tar`/`rsync`/`chown`/`chmod`/`zip`/`7z` run with an unquoted `*` from a directory you can write into (the classic GTFOBins "Wildcards" technique)
- **Capabilities** (`getcap -r /`) and **critical file** (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, ...) writability
- **Group-membership escalation**: `docker`/`lxd`/`lxc`/`disk` group membership combined with actually-verified socket/device access
- **NFS `no_root_squash`** exports (server-side, parsed from `/etc/exports`) and NFS client mounts worth a manual look
- **sudo `env_keep`** exposing `LD_PRELOAD`/`LD_LIBRARY_PATH`/`PYTHONPATH`/`PERL5LIB` to an authorized sudo rule
- **Credential recon**: SSH private keys, `.git-credentials`/`.netrc`/`.my.cnf`/`.pgpass`/`wp-config.php`/`.env`, and shell history files that belong to another user but are readable by you anyway

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

## Ready-to-run exploit commands

Independent of `--poc`, every `CONFIRMED` SUID/sudo/capability finding for a
binary we have a verified-reliable recipe for (`find`, `bash`, `python`/
`python2`/`python3`, `perl`, `ruby`) carries an `exploit_command` field - a
command you can copy and run yourself to get an actual interactive root
shell. **`confirmesc` never runs it for you**, in any mode, including
`--poc` - it's printed for the operator to decide on, the same way a manual
pentest report would suggest a PoC. It shows up as a highlighted "🔑 root
shell:" line in the text report, a green box in the HTML report, and the
`exploit_command` key in JSON.

## Install & run

```bash
git clone <this repo>
cd confirmesc
python3 -m pip install -e .
confirmesc                       # passive scan, text report
confirmesc --active              # + harmless binary probes
confirmesc --poc                 # + real exploitation proof (authorized systems only)
confirmesc --format json -o out.json
confirmesc --format html -o report.html   # shareable, collapsible HTML report
confirmesc --category suid_sgid_sudo --min-confidence LIKELY
confirmesc --quiet               # suppress the "[*] <check> done (Ns)" progress lines
```

Checks run concurrently (thread pool, I/O-bound), so a full scan is typically
dominated by the single slowest check (usually the SUID/SGID `find /` walk
or `getcap -r /`) rather than the sum of all of them.

Or without installing:

```bash
python3 -m confirmesc.cli
```

Or as a single portable file to drop on a target (no pip install needed there):

```bash
python3 -m zipapp confirmesc -m "confirmesc.cli:main" -o confirmesc.pyz -p "/usr/bin/env python3"
# transfer confirmesc.pyz to the target, then:
python3 confirmesc.pyz --no-color
```

See `testlab/` for a local Docker-based vulnerable sandbox to see `--poc` actually gain root, without needing an external target like HTB.

Exit code is `1` if any `CONFIRMED` finding exists, `0` otherwise — useful in CI/CTF automation.

## Known limitations

- `--poc` only covers vectors with a curated non-interactive payload (see list above). Editor/pager GTFOBins entries (`vim`, `less`, `man`, ...) need a TTY and are condition-only for now.
- Writable cron/systemd targets are confirmed by write-access, not by actually waiting for the scheduler to fire and observing root execution — that would require a real (if reversible) wait/trigger step and isn't implemented yet.
- Kernel/sudo/polkit CVE matches are version-string based (`LIKELY`); a distro can backport a fix without changing the version string, so always cross-check against your distro's advisory before relying on one. Fixed-version numbers for the less common CVEs are best-effort from public writeups and may be off by a point release on some branches.
- `docker`/`lxd` group escalation and `sudo env_keep` findings are condition-only by design: proving them live would mean spinning up a real container or compiling and writing a shared object to disk, which breaks the "never writes to disk / never leaves running state" guarantee every other PoC in this tool holds to.
- Cron wildcard injection detection uses a lightweight statement splitter, not a real shell parser - quoted `;`/`&&` inside strings, or wildcards built up across multiple variables, can be missed or (rarely) misattributed to the wrong working directory.
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
