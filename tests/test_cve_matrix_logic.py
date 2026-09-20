from confirmesc.checks.cve_matrix import _is_vulnerable


def test_dirty_pipe_branch_fix_5_10():
    entry = {
        "min_version": "5.8.0",
        "branch_fixes": [
            {"prefix": "5.10.", "fixed_at": "5.10.102"},
            {"prefix": "5.15.", "fixed_at": "5.15.25"},
        ],
        "default_fixed_at": "5.16.11",
    }
    assert _is_vulnerable("5.10.90", entry) is True
    assert _is_vulnerable("5.10.110", entry) is False
    assert _is_vulnerable("5.15.10", entry) is True
    assert _is_vulnerable("5.15.30", entry) is False
    # unlisted branch (e.g. 5.13.x) falls back to default_fixed_at
    assert _is_vulnerable("5.13.0", entry) is True
    assert _is_vulnerable("5.17.0", entry) is False
    # below min_version entirely -> not vulnerable
    assert _is_vulnerable("5.4.0", entry) is False


def test_sudo_baron_samedit_branches():
    entry = {
        "min_version": "1.8.2",
        "branch_fixes": [{"prefix": "1.9.", "fixed_at": "1.9.5p2"}],
        "default_fixed_at": "1.8.31p3",
    }
    assert _is_vulnerable("1.8.31", entry) is True
    assert _is_vulnerable("1.8.31p3", entry) is False
    assert _is_vulnerable("1.9.4", entry) is True
    assert _is_vulnerable("1.9.5p2", entry) is False
