# Local test lab (no HTB/CTF needed)

A deliberately vulnerable Debian container to see `confirmesc --poc` actually
gain root, without needing an external target. Builds three real vectors:

1. **SUID python3** at `/opt/vulnapp/python3` (classic GTFOBins SUID vector)
2. **Passwordless sudo** on `/usr/bin/find` for user `lowpriv` (classic GTFOBins sudo vector)
3. **`cap_setuid`/`cap_setgid` capability** on a python3 copy at `/opt/vulnapp2/python3` (classic GTFOBins capability vector)

Plus a negative control: `mount`/`umount` are setuid by default in the base
image and must NOT be flagged as CONFIRMED (they need a permissive fstab
entry, not just the bit).

## Usage

```bash
# from the repo root
python3 -m zipapp confirmesc -m "confirmesc.cli:main" -o confirmesc.pyz
cp confirmesc.pyz testlab/confirmesc.pyz
cd testlab
docker build -t confirmesc-lab .

# passive - see the conditions
docker run --rm --user lowpriv confirmesc-lab python3 confirmesc.pyz --no-color

# --poc - see it actually get euid 0 for each vector
docker run --rm --user lowpriv confirmesc-lab python3 confirmesc.pyz --poc --no-color
```

Look for `"poc_success": true` and `"poc_observed_uid": "0"` in the evidence,
and titles prefixed `ROOT CONFIRMED via ...` - that means live exploitation
was verified, not just a permission/condition match.
