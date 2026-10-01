"""Validate the bundled agent skills: present, well-formed frontmatter, and
free of the content this project forbids.

The forbidden-token pattern is assembled from pieces and escapes on purpose,
so this test file itself contains none of the literal tokens it looks for.
"""
import pathlib
import re

SKILLS_DIR = pathlib.Path(__file__).resolve().parent.parent / "skills"

_FORBIDDEN = re.compile(
    "|".join(
        [
            chr(0x2014),                    # em dash, via unicode escape (no literal dash here)
            "powered " + "by " + "ai",
            "cl" + "aude",
            "son" + "net",
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",  # any email address
        ]
    ),
    re.IGNORECASE,
)


def _skill_files():
    return sorted(SKILLS_DIR.glob("*/SKILL.md"))


def test_skills_exist():
    files = _skill_files()
    assert files, "no SKILL.md files found under skills/"


def test_each_skill_has_name_and_description():
    for path in _skill_files():
        text = path.read_text(encoding="utf-8")
        assert text.startswith("---"), f"{path} missing frontmatter"
        frontmatter = text.split("---", 2)[1]
        assert re.search(r"^name:\s*\S+", frontmatter, re.MULTILINE), f"{path} missing name"
        assert re.search(r"^description:\s*\S+", frontmatter, re.MULTILINE), f"{path} missing description"


def test_skills_have_no_forbidden_content():
    for path in _skill_files():
        hit = _FORBIDDEN.search(path.read_text(encoding="utf-8"))
        assert hit is None, f"forbidden content in {path}: {hit.group(0)!r}"
