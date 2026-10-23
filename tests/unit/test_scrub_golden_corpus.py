"""Publish scrubber: golden-corpus pass over dev/golden/corpus.json.

scrub_public_tree.py operates on a THROWAWAY public tree from which private
paths were already stripped. scrub_golden_corpus drops corpus entries whose
``dev/golden/baseline/<id>.json`` snapshot is gone, so the golden runner never
references a stripped baseline. These tests pin: missing baseline dropped,
existing kept, other fields untouched, idempotency, skip when the corpus or the
baseline dir is absent.
"""
from __future__ import annotations

import importlib.util
import json
import os

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

ENTRIES = [
    {"id": "fx_public_a", "tier": "fixture", "pcap": "tests/fixtures/a.pcap", "args": {}},
    {"id": "fx_private_x", "tier": "fixture", "pcap": "tests/fixtures/x.pcap", "args": {}},
    {"id": "rs_public_b", "tier": "research", "pcap": "b.pcap", "args": {"keylog_path": "b.log"}},
]


def _make_tree(tmp_path, baselines=("fx_public_a", "rs_public_b"), with_baseline_dir=True) -> str:
    golden = tmp_path / "dev" / "golden"
    golden.mkdir(parents=True)
    (golden / "corpus.json").write_text(
        json.dumps({"entries": ENTRIES}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    if with_baseline_dir:
        (golden / "baseline").mkdir()
        for bid in baselines:
            (golden / "baseline" / f"{bid}.json").write_text("{}\n", encoding="utf-8")
    return str(tmp_path)


def _corpus_path(tmp_path):
    return tmp_path / "dev" / "golden" / "corpus.json"


def test_missing_baseline_dropped_existing_kept(tmp_path):
    tree = _make_tree(tmp_path)
    report = scrub.scrub_golden_corpus(tree)
    assert "dropped 1" in report
    data = json.loads(_corpus_path(tmp_path).read_text(encoding="utf-8"))
    assert [e["id"] for e in data["entries"]] == ["fx_public_a", "rs_public_b"]
    assert data["entries"][1] == ENTRIES[2]  # untouched fields


def test_preserves_indent_and_trailing_newline(tmp_path):
    tree = _make_tree(tmp_path)
    scrub.scrub_golden_corpus(tree)
    text = _corpus_path(tmp_path).read_text(encoding="utf-8")
    assert text.startswith('{\n "entries": [\n  {\n')
    assert text.endswith("}\n")


def test_idempotent(tmp_path):
    tree = _make_tree(tmp_path)
    scrub.scrub_golden_corpus(tree)
    first = _corpus_path(tmp_path).read_bytes()
    report = scrub.scrub_golden_corpus(tree)
    assert "already clean" in report
    assert _corpus_path(tmp_path).read_bytes() == first


def test_all_baselines_present_not_rewritten(tmp_path):
    tree = _make_tree(tmp_path, baselines=[e["id"] for e in ENTRIES])
    before = _corpus_path(tmp_path).read_bytes()
    assert "already clean" in scrub.scrub_golden_corpus(tree)
    assert _corpus_path(tmp_path).read_bytes() == before


def test_no_baseline_dir_keeps_everything(tmp_path):
    tree = _make_tree(tmp_path, with_baseline_dir=False)
    before = _corpus_path(tmp_path).read_bytes()
    assert "skip" in scrub.scrub_golden_corpus(tree)
    assert _corpus_path(tmp_path).read_bytes() == before


def test_absent_corpus_skips(tmp_path):
    assert scrub.scrub_golden_corpus(str(tmp_path)) == "dev/golden/corpus.json: absent (skip)"
