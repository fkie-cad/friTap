"""Tests for the friTap.skills loader (fake skills root, no real content)."""

from __future__ import annotations

import pytest

from friTap import skills
from friTap.skills import (
    MAX_DESCRIPTION_CHARS,
    SkillFormatError,
    get_skill,
    install_skills,
    list_skills,
    parse_skill_text,
    validate_frontmatter,
)

from .conftest import write_skill

# -- frontmatter parsing ------------------------------------------------------

def test_parse_simple_key_values_and_body():
    meta, body = parse_skill_text("---\nname: x\ndescription: 'Quoted: yes'\n---\n\n# B\n")
    assert meta == {"name": "x", "description": "Quoted: yes"}
    assert body == "# B\n" or body == "# B"


def test_parse_literal_and_folded_block_scalars():
    text = "---\nname: x\ndescription: >\n  one\n  two\nnotes: |\n  a\n  b\n---\n"
    meta, _ = parse_skill_text(text)
    assert meta["description"] == "one two"
    assert meta["notes"] == "a\nb"


def test_parse_nested_mapping_and_comments():
    meta, _ = parse_skill_text("---\n# c\nname: x\nmetadata:\n  version: \"1\"\n  author: a\n---\n")
    assert meta["metadata"] == {"version": "1", "author": "a"}


@pytest.mark.parametrize("text", [
    "no frontmatter",
    "---\nname: x\n",
    "---\nnot a pair\n---\n",
    "---\n  indented: first\n---\n",
    "---\nname: x\n  stray: y\n---\n",
])
def test_parse_rejects_malformed_frontmatter(text):
    with pytest.raises(SkillFormatError):
        parse_skill_text(text)


# -- validation ---------------------------------------------------------------

def test_validate_accepts_matching_name():
    validate_frontmatter({"name": "a", "description": "d"}, "a")


@pytest.mark.parametrize("meta", [
    {"name": "b", "description": "d"},
    {"description": "d"},
    {"name": "a", "description": "   "},
    {"name": "a"},
    {"name": "a", "description": "x" * (MAX_DESCRIPTION_CHARS + 1)},
])
def test_validate_rejects_bad_frontmatter(meta):
    with pytest.raises(SkillFormatError):
        validate_frontmatter(meta, "a")


def test_validate_accepts_max_length_description():
    validate_frontmatter({"name": "a", "description": "x" * MAX_DESCRIPTION_CHARS}, "a")


# -- listing / lookup ---------------------------------------------------------

def test_list_skills_sorted_and_skips_dirs_without_skill_md(two_skills):
    names = [s.name for s in list_skills()]
    assert names == ["alpha-skill", "zeta-skill"]


def test_list_skills_empty_root(fake_root):
    assert list_skills() == []


def test_get_skill_fields(two_skills):
    skill = get_skill("alpha-skill")
    assert skill.description.startswith("Alpha first line.")
    assert skill.body == "# Body\n" or skill.body == "# Body"
    assert skill.path.name == "alpha-skill"
    assert skill.markdown().startswith("---\nname: alpha-skill")


def test_get_skill_unknown_raises_key_error(two_skills):
    with pytest.raises(KeyError):
        get_skill("missing")


def test_name_mismatch_is_rejected(fake_root):
    write_skill(fake_root, "dir-name", frontmatter_name="other-name")
    with pytest.raises(SkillFormatError):
        list_skills()


def test_real_skills_root_is_the_package():
    assert skills.skills_root().joinpath("__init__.py").is_file()


# -- installation -------------------------------------------------------------

def test_install_all_copies_references(two_skills, tmp_path):
    target = tmp_path / "out"
    installed = install_skills(target)
    assert installed == [target / "alpha-skill", target / "zeta-skill"]
    assert (target / "alpha-skill" / "SKILL.md").is_file()
    assert (target / "alpha-skill" / "references" / "guide.md").read_text() == "# Guide\n"


def test_install_selected_names(two_skills, tmp_path):
    installed = install_skills(tmp_path / "out", names=["zeta-skill"])
    assert [p.name for p in installed] == ["zeta-skill"]
    assert not (tmp_path / "out" / "alpha-skill").exists()


def test_install_unknown_name_raises(two_skills, tmp_path):
    with pytest.raises(KeyError):
        install_skills(tmp_path / "out", names=["nope"])


def test_install_refuses_existing_dir_without_force(two_skills, tmp_path):
    target = tmp_path / "out"
    (target / "zeta-skill").mkdir(parents=True)
    with pytest.raises(FileExistsError):
        install_skills(target)
    assert not (target / "alpha-skill").exists()  # nothing copied


def test_install_force_replaces_existing_dir(two_skills, tmp_path):
    target = tmp_path / "out"
    stale = target / "zeta-skill" / "stale.md"
    stale.parent.mkdir(parents=True)
    stale.write_text("old")
    install_skills(target, force=True)
    assert not stale.exists()
    assert (target / "zeta-skill" / "SKILL.md").is_file()
