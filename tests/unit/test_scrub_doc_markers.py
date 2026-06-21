"""§G publish scrubber: the @scrub:signal-e2e marker pass over Markdown.

scrub_public_tree.py operates on a THROWAWAY public tree. scrub_doc_markers drops
every region between the start/end markers (inclusive) from each *.md, so a public
page can keep its Signal-E2E prose for the full (private) build while the published
tree drops it atomically. These tests pin: partial removal, idempotency, no-op when
markers are absent, and fail-loud on an unbalanced/unterminated region.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

# Load the standalone script as a module (it lives under scripts/, not a pkg).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SCRIPT_PATH = os.path.join(_REPO_ROOT, "scripts", "scrub_public_tree.py")


def _load_scrub_module():
    spec = importlib.util.spec_from_file_location("scrub_public_tree", _SCRIPT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


scrub = _load_scrub_module()

START = "<!-- @scrub:signal-e2e:start -->"
END = "<!-- @scrub:signal-e2e:end -->"


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_removes_region_keeps_surrounding(tmp_path):
    page = _write(
        tmp_path,
        "page.md",
        f"# Title\n\nPublic intro.\n\n{START}\n## Private bit\n\nsecret prose.\n{END}\n\n## Public outro\n",
    )
    scrub.scrub_doc_markers(str(tmp_path))
    out = page.read_text(encoding="utf-8")
    assert "Public intro." in out
    assert "## Public outro" in out
    assert "Private bit" not in out
    assert "secret prose." not in out
    assert START not in out and END not in out


def test_idempotent(tmp_path):
    text = f"keep\n{START}\ndrop\n{END}\nkeep2\n"
    page = _write(tmp_path, "page.md", text)
    scrub.scrub_doc_markers(str(tmp_path))
    first = page.read_text(encoding="utf-8")
    scrub.scrub_doc_markers(str(tmp_path))
    assert page.read_text(encoding="utf-8") == first
    assert first == "keep\nkeep2\n"


def test_no_markers_untouched(tmp_path):
    text = "# Doc\n\nNothing to scrub here.\n"
    page = _write(tmp_path, "page.md", text)
    scrub.scrub_doc_markers(str(tmp_path))
    assert page.read_text(encoding="utf-8") == text


def test_non_markdown_ignored(tmp_path):
    text = f"{START}\nx\n{END}\n"
    other = _write(tmp_path, "page.txt", text)
    scrub.scrub_doc_markers(str(tmp_path))
    assert other.read_text(encoding="utf-8") == text  # not a .md → untouched


def test_unterminated_region_fails_loud(tmp_path):
    _write(tmp_path, "page.md", f"keep\n{START}\ndrop forever\n")
    with pytest.raises(SystemExit):
        scrub.scrub_doc_markers(str(tmp_path))


def test_unbalanced_end_fails_loud(tmp_path):
    _write(tmp_path, "page.md", f"keep\n{END}\nmore\n")
    with pytest.raises(SystemExit):
        scrub.scrub_doc_markers(str(tmp_path))
