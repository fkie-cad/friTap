"""
Agent skills shipped with friTap (Agent Skills format).

Each skill is a directory ``friTap/skills/<name>/`` holding a ``SKILL.md``
(YAML frontmatter with ``name`` and ``description``, then a Markdown body) and
optional supporting files such as ``references/*.md``. Directories without a
``SKILL.md`` are ignored.

    from friTap.skills import list_skills, get_skill, install_skills
    install_skills(".claude/skills")          # copy every skill
    install_skills("dir", names=["x"], force=True)

The skills are read through :mod:`importlib.resources`, so they work from a
source checkout, an installed wheel or a zip import alike.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Iterable, Optional

try:  # Python >= 3.11
    from importlib.resources.abc import Traversable
except ImportError:  # pragma: no cover - Python 3.10
    from importlib.abc import Traversable

SKILL_FILE = "SKILL.md"
MAX_DESCRIPTION_CHARS = 1024
_FRONTMATTER_DELIMITER = "---"
_BLOCK_SCALAR_MARKERS = (">", ">-", "|", "|-")
_SKIPPED_ENTRIES = ("__pycache__",)


class SkillFormatError(ValueError):
    """A ``SKILL.md`` whose frontmatter is missing or invalid."""


@dataclass(frozen=True)
class Skill:
    """One packaged skill: its frontmatter fields, Markdown body and directory."""

    name: str
    description: str
    body: str
    path: Traversable
    frontmatter: dict = field(default_factory=dict, compare=False)

    def markdown(self) -> str:
        """The complete ``SKILL.md`` text (frontmatter and body)."""
        return self.path.joinpath(SKILL_FILE).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Frontmatter parsing (minimal YAML subset: PyYAML is not a friTap dependency)
# ---------------------------------------------------------------------------

def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _split_frontmatter(text: str) -> tuple[list[str], str]:
    """Return (frontmatter lines, body) or raise :class:`SkillFormatError`."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != _FRONTMATTER_DELIMITER:
        raise SkillFormatError("SKILL.md must start with a '---' frontmatter line")
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == _FRONTMATTER_DELIMITER:
            return lines[1:index], "\n".join(lines[index + 1:]).lstrip("\n")
    raise SkillFormatError("SKILL.md frontmatter has no closing '---' line")


def _join_block(marker: str, block: list[str]) -> str:
    stripped = [line.strip() for line in block]
    joined = "\n".join(stripped) if marker.startswith("|") else " ".join(s for s in stripped if s)
    return joined.strip()


def _parse_entry(key: str, raw: str, block: list[str]):
    """Value of one top-level key: scalar, block scalar or nested mapping."""
    if raw in _BLOCK_SCALAR_MARKERS:
        return _join_block(raw, block)
    if raw == "" and block:
        return parse_frontmatter_lines(line.strip() for line in block)
    if block:
        raise SkillFormatError(f"unexpected indented lines after '{key}'")
    return _unquote(raw)


def _group_entries(lines: Iterable[str]) -> list[tuple[str, list[str]]]:
    """Group frontmatter lines into (top-level line, indented continuation lines)."""
    groups: list[tuple[str, list[str]]] = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] in " \t":
            if not groups:
                raise SkillFormatError("frontmatter starts with an indented line")
            groups[-1][1].append(line)
        else:
            groups.append((line, []))
    return groups


def parse_frontmatter_lines(lines: Iterable[str]) -> dict:
    """Parse ``key: value`` lines (plus ``>``/``|`` blocks and one nesting level)."""
    result: dict = {}
    for head, block in _group_entries(lines):
        key, sep, raw = head.partition(":")
        if not sep or not key.strip():
            raise SkillFormatError(f"invalid frontmatter line: {head!r}")
        result[key.strip()] = _parse_entry(key.strip(), raw.strip(), block)
    return result


def parse_skill_text(text: str) -> tuple[dict, str]:
    """Split a ``SKILL.md`` into (frontmatter dict, Markdown body)."""
    lines, body = _split_frontmatter(text)
    return parse_frontmatter_lines(lines), body


# ---------------------------------------------------------------------------
# Validation and loading
# ---------------------------------------------------------------------------

def validate_frontmatter(frontmatter: dict, dir_name: str) -> None:
    """Raise :class:`SkillFormatError` unless name/description follow the spec."""
    name = frontmatter.get("name")
    if name != dir_name:
        raise SkillFormatError(f"skill name {name!r} does not match its directory {dir_name!r}")
    description = frontmatter.get("description")
    if not isinstance(description, str) or not description.strip():
        raise SkillFormatError(f"skill {dir_name!r} has an empty description")
    if len(description) > MAX_DESCRIPTION_CHARS:
        raise SkillFormatError(
            f"skill {dir_name!r} description has {len(description)} chars "
            f"(max {MAX_DESCRIPTION_CHARS})")


def load_skill(directory: Traversable) -> Skill:
    """Load and validate the skill stored in ``directory``."""
    text = directory.joinpath(SKILL_FILE).read_text(encoding="utf-8")
    frontmatter, body = parse_skill_text(text)
    validate_frontmatter(frontmatter, directory.name)
    return Skill(name=frontmatter["name"], description=frontmatter["description"],
                 body=body, path=directory, frontmatter=frontmatter)


def skills_root() -> Traversable:
    """The resource directory holding the skill directories (patched in tests)."""
    return resources.files(__name__)


def _skill_dirs() -> list[Traversable]:
    return [entry for entry in skills_root().iterdir()
            if entry.is_dir() and entry.joinpath(SKILL_FILE).is_file()]


def list_skills() -> list[Skill]:
    """Every packaged skill, sorted by name."""
    return sorted((load_skill(directory) for directory in _skill_dirs()),
                  key=lambda skill: skill.name)


def get_skill(name: str) -> Skill:
    """The skill called ``name``; raises :class:`KeyError` when there is none."""
    for directory in _skill_dirs():
        if directory.name == name:
            return load_skill(directory)
    raise KeyError(name)


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

def _copy_tree(source: Traversable, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for entry in source.iterdir():
        if entry.name in _SKIPPED_ENTRIES:
            continue
        if entry.is_dir():
            _copy_tree(entry, destination / entry.name)
        else:
            (destination / entry.name).write_bytes(entry.read_bytes())


def _select_skills(names: Optional[Iterable[str]]) -> list[Skill]:
    if names is None:
        return list_skills()
    return [get_skill(name) for name in names]


def _refuse_existing(skills: list[Skill], target: Path) -> None:
    existing = [str(target / skill.name) for skill in skills if (target / skill.name).exists()]
    if existing:
        raise FileExistsError(
            "skill directory already exists (use force=True / --force): " + ", ".join(existing))


def _clear_destination(destination: Path) -> None:
    """Remove an existing install so ``force`` leaves no stale files behind."""
    if destination.is_dir() and not destination.is_symlink():
        shutil.rmtree(destination)
    elif destination.exists() or destination.is_symlink():
        destination.unlink()


def install_skills(target_dir, names: Optional[Iterable[str]] = None,
                   force: bool = False) -> list[Path]:
    """Copy skills (whole directories, incl. ``references/``) into ``target_dir``.

    ``names=None`` installs every skill; an unknown name raises :class:`KeyError`.
    Nothing is copied when a destination directory exists and ``force`` is false
    (:class:`FileExistsError`); with ``force`` the existing directory is replaced.
    Returns the installed skill directories.
    """
    target = Path(target_dir)
    skills = _select_skills(names)
    if not force:
        _refuse_existing(skills, target)
    installed = []
    for skill in skills:
        _clear_destination(target / skill.name)
        _copy_tree(skill.path, target / skill.name)
        installed.append(target / skill.name)
    return installed


__all__ = [
    "MAX_DESCRIPTION_CHARS",
    "SKILL_FILE",
    "Skill",
    "SkillFormatError",
    "get_skill",
    "install_skills",
    "list_skills",
    "load_skill",
    "parse_skill_text",
    "skills_root",
    "validate_frontmatter",
]
