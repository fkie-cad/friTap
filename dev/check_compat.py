#!/usr/bin/env python3
"""Cross-file version-guard for friTap.

Asserts the invariants that prevent silent frida-major bumps (issue #63):

  1. friTap MAJOR (friTap/about.py) and frida lower-bound major
     (requirements.txt) are listed in compat.yml.
  2. The frida pin shape is `frida>=N.x.y,<(N+1).0.0` (strict cap).
  3. If this commit changed the frida major in requirements.txt
     without changing the friTap major in about.py, the script fails.

Designed to be invoked by CI (.github/workflows/ci.yml: version-guard job).
Exit 0 = OK, exit 1 = invariant violated (with a clear message).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
ABOUT = REPO_ROOT / "friTap" / "about.py"
REQUIREMENTS = REPO_ROOT / "requirements.txt"
COMPAT = REPO_ROOT / "compat.yml"


_VERSION_RE = re.compile(r'__version__\s*=\s*"([^"]+)"')
_FRIDA_PIN_RE = re.compile(
    r"^frida\s*>=\s*(\d+)\.\d+\.\d+\s*,\s*<\s*(\d+)\.\d+\.\d+\s*$",
    re.MULTILINE,
)
_FRIDA_LOWER_RE = re.compile(r"^frida\s*>=\s*(\d+)\.", re.MULTILINE)


def _major_from_about(text: str) -> int:
    m = _VERSION_RE.search(text)
    if not m:
        die(f"Could not find __version__ in {ABOUT}")
    return int(m.group(1).split(".")[0])


def _frida_bounds_from_requirements(text: str) -> tuple[int, int]:
    """Return (lower_major, upper_major) parsed from a strict-cap pin.

    Fails loudly if the pin shape isn't `frida>=N.x.y,<M.x.y` — uncapped
    pins are exactly the failure mode this guard exists to prevent.
    """
    m = _FRIDA_PIN_RE.search(text)
    if not m:
        die(
            f"requirements.txt frida pin must use strict-cap shape "
            f"`frida>=N.x.y,<(N+1).0.0`. See RELEASING.md."
        )
    return int(m.group(1)), int(m.group(2))


def _frida_lower_only(text: str) -> int | None:
    """Best-effort lower-bound extraction even when the pin is uncapped.

    Used only on HEAD~1 (historical content) so we can detect drift
    against pre-2.0.0 releases that legitimately had no upper bound.
    """
    m = _FRIDA_LOWER_RE.search(text)
    return int(m.group(1)) if m else None


def _git_show(rev: str, path: Path) -> str | None:
    try:
        rel = path.relative_to(REPO_ROOT)
    except ValueError:
        return None
    try:
        out = subprocess.run(
            ["git", "show", f"{rev}:{rel.as_posix()}"],
            capture_output=True, text=True, cwd=REPO_ROOT, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def die(msg: str) -> None:
    print(f"version-guard: error: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    about_text = ABOUT.read_text()
    req_text = REQUIREMENTS.read_text()
    compat_rows = (yaml.safe_load(COMPAT.read_text()) or {}).get("fritap_majors") or []

    fritap_major = _major_from_about(about_text)
    lower, upper = _frida_bounds_from_requirements(req_text)

    if upper != lower + 1:
        die(
            f"frida pin upper bound must be exactly lower+1 "
            f"(got >={lower}.x,<{upper}.x). See RELEASING.md."
        )

    row = next(
        (r for r in compat_rows if r.get("fritap_major") == fritap_major),
        None,
    )
    if row is None:
        die(
            f"friTap major {fritap_major} not listed in compat.yml. "
            f"Add a row in the same PR that bumped friTap/about.py."
        )

    fmin, fmax = row.get("frida_major_min"), row.get("frida_major_max")
    if fmin is None or fmax is None:
        die(f"compat.yml row for friTap {fritap_major} is missing frida_major_min/max.")
    if not (fmin <= lower <= fmax):
        die(
            f"requirements.txt has frida>={lower}.x but compat.yml says "
            f"friTap {fritap_major} supports frida {fmin}..{fmax}."
        )

    # Drift check vs HEAD~1 — only meaningful when both files exist there.
    prev_about = _git_show("HEAD~1", ABOUT)
    prev_req = _git_show("HEAD~1", REQUIREMENTS)
    if prev_about and prev_req:
        try:
            prev_fritap_major = _major_from_about(prev_about)
        except SystemExit:
            prev_fritap_major = fritap_major
        prev_lower = _frida_lower_only(prev_req)
        if (
            prev_lower is not None
            and prev_lower != lower
            and prev_fritap_major == fritap_major
        ):
            die(
                f"requirements.txt frida major changed "
                f"({prev_lower} -> {lower}) but friTap/about.py major did not "
                f"({prev_fritap_major}). Bump friTap MAJOR per RELEASING.md."
            )

    print(f"version-guard: OK (friTap {fritap_major}, frida {lower}.x)")


if __name__ == "__main__":
    main()
