from confirmesc.core.version import in_vulnerable_range, parse_version, version_lt


def test_parse_version_basic():
    assert parse_version("1.8.31") == (1, 8, 31)


def test_parse_version_kernel_suffix():
    assert parse_version("5.15.0-91-generic") == (5, 15, 0)


def test_parse_version_patch_letter():
    assert parse_version("1.8.31p2") == (1, 8, 31, 2)


def test_version_lt():
    assert version_lt("1.8.2", "1.8.31p3") is True
    assert version_lt("1.9.5p2", "1.9.5p2") is False
    assert version_lt("1.9.6", "1.9.5p2") is False


def test_in_vulnerable_range():
    assert in_vulnerable_range("5.10.90", "5.8.0", "5.10.102") is True
    assert in_vulnerable_range("5.10.110", "5.8.0", "5.10.102") is False
    assert in_vulnerable_range("5.7.0", "5.8.0", "5.10.102") is False
