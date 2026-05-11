#!/usr/bin/env python3
"""Install a legacy friTap release with era-matched frida / frida-tools.

friTap 1.x releases on PyPI carry floor-only dependency pins, so a plain
`pip install fritap==X.Y.Z.W` today resolves to whatever frida is latest
(currently 17.x), breaking legacy agents compiled against frida 15.x or
16.x. This script reads `compat.yml`'s `era_boundaries` section, picks
the right friTap version + constraints file for the requested frida
major, and runs the corresponding `pip install`.

Usage:
    python dev/install_legacy.py --frida-major 16
    python dev/install_legacy.py --frida-major 16 --fritap-version 1.3.4.0
    python dev/install_legacy.py --frida-major 17 --dry-run

See constraints/README.md for the equivalent raw-pip recipes.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
COMPAT = REPO_ROOT / "compat.yml"


def die(msg: str) -> None:
    print(f"install_legacy: error: {msg}", file=sys.stderr)
    sys.exit(1)


def load_legacy_eras() -> list[dict]:
    """Era rows that have a constraints file (i.e. excludes the open-ended current era)."""
    compat = yaml.safe_load(COMPAT.read_text()) or {}
    return [
        era for era in (compat.get("era_boundaries") or [])
        if era.get("constraints_file")
    ]


def main() -> None:
    eras = load_legacy_eras()
    valid_majors = sorted({e["frida_major"] for e in eras})

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--frida-major",
        type=int,
        required=True,
        choices=valid_majors,
        help="frida-server major version installed on your target device.",
    )
    parser.add_argument(
        "--fritap-version",
        help=(
            "Override the friTap version to install. Defaults to the top of "
            "the era (latest legacy release that supports this frida major)."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the pip command without executing it.",
    )
    args = parser.parse_args()

    matching = [e for e in eras if e["frida_major"] == args.frida_major]
    if len(matching) != 1:
        die(
            f"Expected exactly one legacy era for frida-major "
            f"{args.frida_major}, found {len(matching)}."
        )
    era = matching[0]

    version = args.fritap_version or era["fritap_last"]
    constraints = REPO_ROOT / era["constraints_file"]
    if not constraints.is_file():
        die(f"Constraints file not found: {constraints}")

    # sys.executable + -m pip guarantees we install into the same interpreter
    # running this script — `pip` on PATH may belong to a different venv.
    cmd = [
        sys.executable, "-m", "pip", "install",
        f"fritap=={version}", "-c", str(constraints),
    ]
    if args.dry_run:
        cmd.append("--dry-run")

    print("$ " + " ".join(cmd))
    sys.exit(subprocess.run(cmd).returncode)


if __name__ == "__main__":
    main()
