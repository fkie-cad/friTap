"""
``fritap skills`` — list, show and install the agent skills shipped with friTap.

    fritap skills list [--json]
    fritap skills show <name>
    fritap skills install [names...] [--target DIR] [--force]

Skills follow the Agent Skills format (``<name>/SKILL.md`` plus optional
``references/``); ``install`` copies them into ``./.claude/skills`` by default.

Dispatch guard (see ``friTap.friTap._dispatch_special_mode``): ``skills`` is
only this subcommand when it stands alone or is followed by one of its actions
or ``-h``/``--help``, so ``fritap skills -k keys.log`` still captures a process
named ``skills``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence, TextIO

from friTap.exit_codes import EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_USAGE_ERROR

SKILLS_COMMAND = "skills"
SKILL_ACTIONS = ("list", "show", "install")
DEFAULT_INSTALL_TARGET = "./.claude/skills"
_HELP_FLAGS = ("-h", "--help")


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser of ``fritap skills``."""
    parser = argparse.ArgumentParser(prog="fritap skills",
                                     description="Agent skills shipped with friTap.")
    actions = parser.add_subparsers(dest="action", metavar="{list,show,install}")
    list_parser = actions.add_parser("list", help="List the skills.")
    list_parser.add_argument("--json", action="store_true", help="Print the skills as a JSON array.")
    show_parser = actions.add_parser("show", help="Print a skill's SKILL.md.")
    show_parser.add_argument("name", help="Skill name.")
    install_parser = actions.add_parser("install", help="Copy skills into a skills directory.")
    install_parser.add_argument("names", nargs="*", help="Skills to install (default: all).")
    install_parser.add_argument("--target", default=DEFAULT_INSTALL_TARGET,
                                help=f"Destination directory (default: {DEFAULT_INSTALL_TARGET}).")
    install_parser.add_argument("--force", action="store_true",
                                help="Replace skill directories that already exist.")
    return parser


def is_skills_invocation(argv: Sequence[str]) -> bool:
    """True when ``argv`` (``sys.argv``) selects ``fritap skills`` (see module docstring)."""
    if len(argv) < 2 or argv[1] != SKILLS_COMMAND:
        return False
    return len(argv) == 2 or argv[2] in SKILL_ACTIONS + _HELP_FLAGS


def first_line(text: str) -> str:
    """The first non-empty line of ``text`` (stripped)."""
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def _list(as_json: bool, out: TextIO) -> int:
    from friTap.skills import list_skills

    skills = list_skills()
    if as_json:
        rows = [{"name": s.name, "description": s.description} for s in skills]
        out.write(json.dumps(rows, indent=2) + "\n")
        return EXIT_OK
    width = max((len(s.name) for s in skills), default=0)
    for skill in skills:
        out.write(f"{skill.name.ljust(width)}  {first_line(skill.description)}\n")
    return EXIT_OK


def _show(name: str, out: TextIO, err: TextIO) -> int:
    from friTap.skills import get_skill

    try:
        out.write(get_skill(name).markdown())
    except KeyError:
        err.write(f"Unknown skill: {name}\n")
        return EXIT_USAGE_ERROR
    return EXIT_OK


def _install(ns: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from friTap.skills import install_skills

    try:
        installed = install_skills(ns.target, names=ns.names or None, force=ns.force)
    except KeyError as exc:
        err.write(f"Unknown skill: {exc.args[0]}\n")
        return EXIT_USAGE_ERROR
    except FileExistsError as exc:
        err.write(f"{exc}\n")
        return EXIT_RUNTIME_ERROR
    for path in installed:
        out.write(f"installed {path}\n")
    return EXIT_OK


def run_skills_cli(tokens: Sequence[str], out: TextIO | None = None,
                   err: TextIO | None = None) -> int:
    """Run ``fritap skills <tokens>``; returns the process exit code."""
    out = out or sys.stdout
    err = err or sys.stderr
    ns = build_parser().parse_args(list(tokens) or ["list"])
    if ns.action == "show":
        return _show(ns.name, out, err)
    if ns.action == "install":
        return _install(ns, out, err)
    return _list(getattr(ns, "json", False), out)
