#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scrub_public_tree.py — neutralize SUBSTANTIVE Signal-E2E reveals in a
throwaway public tree (friTap tiering §E publish scrubber).

Operates on a COPY of the tree (built by publish_public.sh: publishable set minus
private.txt paths). NEVER edits shared source in place. Idempotent.

Scope (deliberately conservative — see the user stance: operational privacy,
"tiny reveals acceptable", token scan is a guide):
  * setup.py        — drop the ``signal`` extras_require key (a PyPI-page leak;
                      also the §E half of the §F dist rule). mtproto/mtproto-fast
                      stay (Telegram is public).
  * mkdocs.yml      — drop the nav entry for the (stripped) protocols/signal.md so
                      ``mkdocs --strict`` doesn't choke on a dangling page.
  * CHANGELOG.md    — drop list items that match the name-free reveal-token
                      denylist (scripts/denylist.hashes — digests only, never the
                      cleartext, so this scrubber names no private token itself).
  * *.md (§G)       — drop ``@scrub:signal-e2e`` marker regions: Signal-E2E prose
                      embedded in otherwise-public pages (android.md Signal section,
                      offline-quickstart Signal tip, example/README) plus the links
                      to the stripped protocols/signal.md, so the scrubbed tree's
                      ``mkdocs --strict`` stays green.

NOT scrubbed here (accepted per the §F-strict decision, 2026-06):
  * functional bare-"signal" coupling in friTap/api.py and friTap/tui/** plus the
    shared keylog-format identifier string. These keep the leak guard at exit 2
    BY DESIGN — the HARD structural/dist rules are the contract, the token scan is
    a guide (operational-privacy stance). Public Signal-coupled tests SKIP cleanly
    when signal is stripped (a stripped-tree pytest gate in publish_public.sh
    enforces it).

Usage: python3 scripts/scrub_public_tree.py <tree_dir>
"""
from __future__ import annotations
import importlib.util
import os
import re
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_denylist_matcher():
    """Load the shared n-gram hasher + the name-free denylist digests.

    Lets this scrubber detect Signal-E2E reveal-tokens WITHOUT carrying any
    cleartext token of its own — only the SHA-256 digests ship public (see
    scripts/denylist.hashes; scripts/denylist_tokens.py does the normalization).
    Avoids the "the scrubber tells you exactly what's hidden" self-reveal.
    """
    spec = importlib.util.spec_from_file_location(
        "denylist_tokens", os.path.join(_SCRIPT_DIR, "denylist_tokens.py"))
    dt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dt)
    deny: set[str] = set()
    with open(os.path.join(_SCRIPT_DIR, "denylist.hashes"), "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                deny.add(line.split()[0])
    return dt.candidate_hashes, deny


_candidate_hashes, _DENY = _load_denylist_matcher()


def _has_reveal_token(text: str) -> bool:
    """True if *text* contains any denylisted reveal-token (name-free match)."""
    return any(h in _DENY for h, _ in _candidate_hashes(text))

# §G doc-scrub markers. A public Markdown file keeps its Signal-E2E prose for the
# FULL (private) build wrapped in these HTML comments (which never render); the
# published tree drops everything between them, inclusive. This beats regex-on-prose:
# the boundaries are explicit, the full build is unchanged, and new E2E doc blocks
# just need wrapping. Markers must be the only non-whitespace on their line.
_SCRUB_START = "<!-- @scrub:signal-e2e:start -->"
_SCRUB_END = "<!-- @scrub:signal-e2e:end -->"


def _read(path: str) -> list[str] | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.readlines()
    except OSError:
        return None


def _write(path: str, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def scrub_setup_py(tree: str) -> str:
    """Remove the ``"signal": [ ... ],`` extras entry and its leading comment."""
    path = os.path.join(tree, "setup.py")
    lines = _read(path)
    if lines is None:
        return "setup.py: absent (skip)"
    sig = next((i for i, l in enumerate(lines) if re.match(r'\s*"signal"\s*:\s*\[', l)), None)
    if sig is None:
        return "setup.py: no signal extra (already clean)"
    end = sig
    while end < len(lines) and lines[end].strip() != "],":
        end += 1
    start = sig
    while start - 1 >= 0 and lines[start - 1].lstrip().startswith("#"):
        start -= 1
    del lines[start:end + 1]
    _write(path, lines)
    return f"setup.py: removed signal extra (lines {start + 1}-{end + 1})"


def scrub_mkdocs(tree: str) -> str:
    """Drop nav entries pointing at the stripped protocols/signal.md."""
    path = os.path.join(tree, "mkdocs.yml")
    lines = _read(path)
    if lines is None:
        return "mkdocs.yml: absent (skip)"
    kept = [l for l in lines if "protocols/signal.md" not in l]
    if len(kept) == len(lines):
        return "mkdocs.yml: no signal.md nav entry (already clean)"
    _write(path, kept)
    return f"mkdocs.yml: removed {len(lines) - len(kept)} signal.md nav line(s)"


def scrub_changelog(tree: str) -> str:
    """Remove Markdown list items whose text describes the Signal-E2E scheme.

    A list item = a line matching ``^\\s*[-*] `` plus its continuation lines
    (blank lines or lines indented deeper than the marker), up to the next item.
    """
    path = os.path.join(tree, "CHANGELOG.md")
    lines = _read(path)
    if lines is None:
        return "CHANGELOG.md: absent (skip)"
    out: list[str] = []
    i = 0
    removed = 0
    bullet = re.compile(r"^(\s*)[-*]\s")
    while i < len(lines):
        m = bullet.match(lines[i])
        if not m:
            out.append(lines[i]); i += 1; continue
        indent = len(m.group(1))
        block = [lines[i]]; j = i + 1
        while j < len(lines):
            if bullet.match(lines[j]):
                nxt = bullet.match(lines[j])
                if len(nxt.group(1)) <= indent:
                    break
            elif lines[j].strip() and (len(lines[j]) - len(lines[j].lstrip())) <= indent:
                break
            block.append(lines[j]); j += 1
        if _has_reveal_token("".join(block)):
            removed += 1
        else:
            out.extend(block)
        i = j
    if removed == 0:
        return "CHANGELOG.md: no Signal-E2E list items (already clean)"
    _write(path, out)
    return f"CHANGELOG.md: removed {removed} Signal-E2E list item(s)"


def scrub_doc_markers(tree: str) -> str:
    """Strip ``@scrub:signal-e2e`` marker regions (inclusive) from every ``*.md``.

    Removes each block delimited by :data:`_SCRUB_START` / :data:`_SCRUB_END`,
    plus the marker lines themselves. Idempotent: a file with no markers is left
    byte-for-byte untouched. Fails LOUD on an unbalanced/unterminated region
    (raises ``SystemExit``) — a malformed marker must abort the publish, never
    silently leak the block or silently delete the rest of a file.
    """
    changed = 0
    scanned = 0
    for root, dirs, files in os.walk(tree):
        if ".git" in dirs:
            dirs.remove(".git")
        for fn in files:
            if not fn.endswith(".md"):
                continue
            path = os.path.join(root, fn)
            lines = _read(path)
            if lines is None:
                continue
            scanned += 1
            out: list[str] = []
            depth = 0
            removed = 0
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped == _SCRUB_START:
                    depth += 1
                    removed += 1
                    continue
                if stripped == _SCRUB_END:
                    if depth == 0:
                        raise SystemExit(
                            f"scrub: unbalanced @scrub:signal-e2e:end at {path}:{lineno}"
                        )
                    depth -= 1
                    removed += 1
                    continue
                if depth:
                    removed += 1
                else:
                    out.append(line)
            if depth != 0:
                raise SystemExit(
                    f"scrub: unterminated @scrub:signal-e2e region in {path}"
                )
            if removed:
                _write(path, out)
                changed += 1
    return f"doc markers: scrubbed {changed} of {scanned} .md file(s)"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__); return 1
    tree = argv[1]
    if not os.path.isdir(tree):
        print(f"ERROR: not a directory: {tree}", file=sys.stderr); return 2
    for report in (scrub_setup_py(tree), scrub_mkdocs(tree), scrub_changelog(tree), scrub_doc_markers(tree)):
        print(f"  scrub: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
