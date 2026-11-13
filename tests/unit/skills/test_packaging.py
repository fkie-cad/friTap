"""The skills (SKILL.md + references/*.md) must ship in the wheel and sdist."""

from __future__ import annotations

import ast
from pathlib import Path, PurePosixPath

from setuptools import find_packages

REPO = Path(__file__).resolve().parents[3]


def _friTap_package_data() -> list[str]:
    tree = ast.parse((REPO / "setup.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "package_data":
            return ast.literal_eval(node.value)["friTap"]
    raise AssertionError("setup.py has no package_data")


def _covered(relative: str, globs: list[str]) -> bool:
    return any(PurePosixPath(relative).match(pattern) for pattern in globs)


def test_package_data_covers_skill_files():
    globs = _friTap_package_data()
    assert _covered("skills/some-skill/SKILL.md", globs)
    assert _covered("skills/some-skill/references/guide.md", globs)


def test_package_data_covers_every_shipped_skill_markdown():
    globs = _friTap_package_data()
    pkg = REPO / "friTap"
    for doc in (pkg / "skills").rglob("*.md"):
        relative = doc.relative_to(pkg).as_posix()
        assert _covered(relative, globs), f"{relative} would not ship in the wheel"


def test_skills_is_a_package():
    assert "friTap.skills" in find_packages(where=str(REPO))


def test_manifest_includes_skills():
    manifest = (REPO / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include friTap/skills" in manifest
