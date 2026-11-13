"""Fixtures: a fake skills root so loader/CLI tests never depend on real skill content."""

from __future__ import annotations

from pathlib import Path

import pytest

import friTap.skills as skills_pkg


def write_skill(root: Path, name: str, description: str = "Does things.\nMore detail.",
                body: str = "# Body\n", frontmatter_name: str | None = None) -> Path:
    """Create ``root/<name>/SKILL.md`` (+ a reference file) and return the dir."""
    skill_dir = root / name
    (skill_dir / "references").mkdir(parents=True)
    desc_lines = "\n".join("  " + line for line in description.splitlines())
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {frontmatter_name or name}\ndescription: |\n{desc_lines}\n---\n{body}",
        encoding="utf-8")
    (skill_dir / "references" / "guide.md").write_text("# Guide\n", encoding="utf-8")
    return skill_dir


@pytest.fixture
def fake_root(tmp_path, monkeypatch):
    """An empty skills root patched in place of the packaged one."""
    root = tmp_path / "skills_root"
    root.mkdir()
    monkeypatch.setattr(skills_pkg, "skills_root", lambda: root)
    return root


@pytest.fixture
def two_skills(fake_root):
    write_skill(fake_root, "zeta-skill")
    write_skill(fake_root, "alpha-skill", description="Alpha first line.\nSecond line.")
    (fake_root / "not-a-skill").mkdir()
    return fake_root
