#!/usr/bin/env bash
#
# Build the deliberately-vulnerable lab container, run confirmesc against it,
# and ASSERT that every planted vector is detected (and the negative control
# is not). Exits non-zero if any assertion fails, so it doubles as a smoke
# test / CI gate.
#
# Usage:
#   bash testlab/run.sh              # build + passive + --poc assertions
#   SEND_TEST=1 bash testlab/run.sh  # also exercise --send -> confirmesc-recv
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Building confirmesc.pyz"
# zipapp on a package DIR archives its *contents* at the zip root, which makes
# `confirmesc` un-importable (`confirmesc.cli:main` -> ModuleNotFoundError).
# Stage the package under a parent dir so `confirmesc/` is a subdir in the zip.
rm -rf build/pyz confirmesc.pyz
mkdir -p build/pyz
cp -r confirmesc build/pyz/confirmesc
python3 -m zipapp build/pyz -m "confirmesc.cli:main" -o confirmesc.pyz -p "/usr/bin/env python3"
cp confirmesc.pyz testlab/confirmesc.pyz

echo "==> docker build"
docker build -t confirmesc-lab testlab/

fail=0
assert_has() {
    if printf '%s' "$1" | grep -qF -- "$2"; then
        echo "  [PASS] found: $2"
    else
        echo "  [FAIL] MISSING: $2"
        fail=1
    fi
}
assert_absent() {
    if printf '%s' "$1" | grep -qF -- "$2"; then
        echo "  [FAIL] UNEXPECTED: $2"
        fail=1
    else
        echo "  [PASS] absent (negative control): $2"
    fi
}

echo
echo "==> Passive scan (text report)"
# confirmesc exits 1 when CONFIRMED findings exist, so tolerate nonzero exit.
passive="$(docker run --rm --user lowpriv confirmesc-lab python3 confirmesc.pyz --no-color --quiet 2>&1 || true)"
echo "$passive"

echo
echo "==> Asserting each planted vector is CONFIRMED"
assert_has "$passive" "Exploitable SUID/SGID binary: /opt/vulnapp/python3"
assert_has "$passive" "Exploitable sudo rule: /usr/bin/find"
assert_has "$passive" "Dangerous capability on /opt/vulnapp2/python3"
assert_has "$passive" "Critical system file is writable: /etc/passwd"
assert_has "$passive" "Writable file executed by root scheduler: /etc/cron.d/maint"
assert_has "$passive" "Cron wildcard injection risk: 'tar'"
assert_has "$passive" "NFS export with no_root_squash: /srv/share"
assert_has "$passive" "sudo env_keep preserves LD_PRELOAD"
assert_has "$passive" "Writable directory in \$PATH: /usr/local/writablebin"
assert_has "$passive" "Readable private SSH key belonging to another user"
assert_has "$passive" "Readable credential file belonging to another user"

echo
echo "==> Negative control: default-SUID mount must NOT be CONFIRMED-exploitable"
assert_absent "$passive" "Exploitable SUID/SGID binary: /usr/bin/mount"

echo
echo "==> --poc scan (JSON) - live root proof for the executable vectors"
poc="$(docker run --rm --user lowpriv confirmesc-lab python3 confirmesc.pyz --poc --format json --quiet 2>&1 || true)"
poc_success_count="$(printf '%s' "$poc" | grep -c '"poc_success": true' || true)"
echo "  poc_success:true count = ${poc_success_count}"
if [ "${poc_success_count:-0}" -ge 3 ]; then
    echo "  [PASS] at least 3 vectors live-verified euid 0 (SUID + sudo + capability)"
else
    echo "  [FAIL] expected >=3 live-verified PoCs, got ${poc_success_count}"
    fail=1
fi

if [ "${SEND_TEST:-0}" = "1" ]; then
    echo
    echo "==> --send end-to-end (requires 'pip install -e .' so confirmesc-recv is on PATH)"
    if command -v confirmesc-recv >/dev/null 2>&1; then
        tmp="$(mktemp -d)"
        confirmesc-recv --host 127.0.0.1 --port 8000 --save-dir "$tmp" --save-format json >/dev/null 2>&1 &
        recv_pid=$!
        sleep 1
        docker run --rm --network host --user lowpriv confirmesc-lab \
            python3 confirmesc.pyz --send http://127.0.0.1:8000 --no-color >/dev/null 2>&1 || true
        sleep 1
        kill "$recv_pid" 2>/dev/null || true
        if ls "$tmp"/confirmesc-*.json >/dev/null 2>&1; then
            echo "  [PASS] receiver saved a pushed report in $tmp"
        else
            echo "  [FAIL] no report received by confirmesc-recv"
            fail=1
        fi
    else
        echo "  [SKIP] confirmesc-recv not on PATH - run 'pip install -e .' first"
    fi
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "===================  ALL ASSERTIONS PASSED  ==================="
else
    echo "===================  SOME ASSERTIONS FAILED  =================="
fi
exit "$fail"
