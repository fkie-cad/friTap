"""Golden regression test: fixture-tier pcap->tap conversions must not drift.

Each fixture-tier entry of dev/golden/corpus.json is converted in a fresh
interpreter (PYTHONHASHSEED=0, inputs copied to a temp dir) exactly as
dev/golden/run_golden.py does, and the canonical JSON is compared byte-for-byte
against tests/fixtures/golden/<id>.json.

Re-baseline after an INTENDED behaviour change with:
    env/bin/python dev/golden/run_golden.py --record tests/fixtures/golden --tier fixture
"""

from __future__ import annotations

import os
import shutil
import sys

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_GOLDEN_TOOL_DIR = os.path.join(_REPO_ROOT, "dev", "golden")
_GOLDEN_DIR = os.path.join(_REPO_ROOT, "tests", "fixtures", "golden")

sys.path.insert(0, _GOLDEN_TOOL_DIR)
import run_golden  # noqa: E402

_TSHARK = shutil.which("tshark") or (
    "/opt/homebrew/bin/tshark" if os.path.exists("/opt/homebrew/bin/tshark") else None)

pytestmark = pytest.mark.skipif(_TSHARK is None, reason="tshark not installed")

# The corpus manifest and its golden snapshots are local-only (gitignored), so a
# checkout without them collects zero jobs instead of erroring.
_JOBS = (run_golden.convert_jobs("fixture")
         if os.path.isfile(run_golden.CORPUS_PATH) else [])


def _inputs_present(job: run_golden.Job) -> bool:
    return all(os.path.isfile(os.path.join(_REPO_ROOT, p))
               for p in run_golden.entry_input_paths(job.entry))


@pytest.mark.parametrize("job", _JOBS, ids=[j.id for j in _JOBS])
def test_fixture_conversion_matches_golden(job: run_golden.Job) -> None:
    if not _inputs_present(job):
        pytest.skip(f"corpus inputs for {job.id} are not present")
    golden_path = run_golden.golden_path(_GOLDEN_DIR, job.id)
    if not os.path.isfile(golden_path):
        pytest.skip(f"golden snapshot for {job.id} is not present")
    with open(golden_path, encoding="utf-8") as fh:
        expected = fh.read()

    actual = run_golden.produce_golden(job)

    assert actual == expected, run_golden.diff_text(expected, actual, job.id)[:20000]
