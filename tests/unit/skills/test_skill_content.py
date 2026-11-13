"""Drift checks over the REAL shipped skills (pass with zero skills, grow automatically).

(a) frontmatter valid, name == directory, description <= 1024 chars;
(b) every ``fritap q <tool>`` names a registered agent tool;
(c) every ``--long-option`` on a ``fritap ...`` line in a fenced block exists in
    the argparse parser of that command (``# noqa-flag`` opts a line out).
"""

from __future__ import annotations

import pytest

from friTap.agent_api.registry import registry
from friTap.skills import SKILL_FILE, load_skill, skills_root

from ._skill_lint import markdown_files, referenced_tools, unknown_options


def _shipped_skill_dirs():
    return sorted((entry for entry in skills_root().iterdir()
                   if entry.is_dir() and entry.joinpath(SKILL_FILE).is_file()),
                  key=lambda entry: entry.name)


def _shipped_markdown():
    return [(f"{skill_dir.name}/{doc.name}", doc.read_text(encoding="utf-8"))
            for skill_dir in _shipped_skill_dirs() for doc in markdown_files(skill_dir)]


SKILL_DIRS = _shipped_skill_dirs()
MARKDOWN = _shipped_markdown()


@pytest.mark.parametrize("skill_dir", SKILL_DIRS, ids=lambda d: d.name)
def test_frontmatter_is_valid(skill_dir):
    skill = load_skill(skill_dir)  # raises SkillFormatError on any violation
    assert skill.name == skill_dir.name


@pytest.mark.parametrize("label, text", MARKDOWN, ids=[label for label, _ in MARKDOWN])
def test_referenced_agent_tools_exist(label, text):
    missing = sorted(referenced_tools(text) - set(registry.names()))
    assert not missing, f"{label}: unknown agent tools {missing}"


@pytest.mark.parametrize("label, text", MARKDOWN, ids=[label for label, _ in MARKDOWN])
def test_cli_long_options_exist(label, text):
    problems = unknown_options(text)
    assert not problems, f"{label}: unknown options " + "; ".join(
        f"{option} in `{command}`" for command, option in problems)


def test_shipped_skills_list_cleanly():
    from friTap.skills import list_skills
    assert [s.name for s in list_skills()] == [d.name for d in SKILL_DIRS]
