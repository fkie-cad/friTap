#!/usr/bin/env python3
"""Golden regression harness for friTap's offline pcap->tap pipeline and parsers.

Record a baseline from the current code, then compare after a refactor:

    env/bin/python dev/golden/run_golden.py --record  dev/golden/baseline --tier all
    env/bin/python dev/golden/run_golden.py --compare dev/golden/baseline --tier all

Tiers: ``fixture`` / ``research`` (conversions from corpus.json), ``read`` (every
.tap on disk in repo root, demo/, research/** read back through TapReader), and
``all``. Each job runs in a fresh interpreter with PYTHONHASHSEED=0 on inputs
copied into a private temp dir, so nothing is written next to the source files
and no process-wide state (e.g. scapy's TLS binding) leaks between entries.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
CORPUS_PATH = os.path.join(HERE, "corpus.json")
CHILD = os.path.join(HERE, "golden_child.py")
READ_ROOTS = (".", "demo", "research")
READ_MAX_BYTES = 50 * 1024 * 1024
JOB_TIMEOUT_S = 1800
CONVERT_TIERS = ("fixture", "research")


@dataclass
class Job:
    """One golden output: a corpus conversion or a .tap read-back."""
    id: str
    tier: str
    entry: dict | None = None   # conversion jobs
    tap_path: str | None = None  # read jobs


# ---------------------------------------------------------------------------
# Job discovery
# ---------------------------------------------------------------------------

def load_corpus(path: str = CORPUS_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["entries"]


def convert_jobs(tier: str) -> list[Job]:
    return [Job(e["id"], e["tier"], entry=e) for e in load_corpus() if e["tier"] == tier]


def _iter_tap_files():
    for root in READ_ROOTS:
        base = os.path.join(REPO_ROOT, root)
        if root == ".":
            names = sorted(os.listdir(base))
            yield from (os.path.join(base, n) for n in names if n.endswith(".tap"))
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames.sort()
            yield from (os.path.join(dirpath, n) for n in sorted(filenames) if n.endswith(".tap"))


def path_slug(rel_path: str) -> str:
    return rel_path.replace(os.sep, "__").replace(" ", "_")


def read_jobs() -> list[Job]:
    jobs = []
    for path in _iter_tap_files():
        if os.path.isfile(path) and os.path.getsize(path) <= READ_MAX_BYTES:
            rel = os.path.relpath(path, REPO_ROOT)
            jobs.append(Job("read__" + path_slug(rel), "read", tap_path=path))
    return jobs


def select_jobs(tier: str, only: str | None) -> list[Job]:
    tiers = ("fixture", "research", "read") if tier == "all" else (tier,)
    jobs = [j for t in tiers for j in (read_jobs() if t == "read" else convert_jobs(t))]
    if only:
        jobs = [j for j in jobs if j.id == only]
    return jobs


# ---------------------------------------------------------------------------
# Running one job in a fresh interpreter
# ---------------------------------------------------------------------------

def entry_input_paths(entry: dict) -> list[str]:
    """Repo-relative paths of the pcap and every keylog/sidecar the entry names."""
    args = entry.get("args", {})
    paths = [entry["pcap"]]
    paths += [v for v in args.values() if isinstance(v, str)]
    paths += list(args.get("protocol_keylogs", {}).values())
    return list(dict.fromkeys(paths))


def stage_inputs(entry: dict, work_dir: str) -> None:
    """Copy inputs into *work_dir* under their original basenames."""
    for rel in entry_input_paths(entry):
        shutil.copy2(os.path.join(REPO_ROOT, rel), os.path.join(work_dir, os.path.basename(rel)))


def child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = "0"
    env["FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY"] = "1"
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["PATH"] = os.pathsep.join(
        [os.path.dirname(sys.executable), "/opt/homebrew/bin", env.get("PATH", "")])
    return env


def _run_child(argv: list[str], out_path: str) -> str:
    """Run golden_child.py; return its canonical JSON (or a crash/timeout golden)."""
    try:
        proc = subprocess.run([sys.executable, CHILD, *argv], cwd=REPO_ROOT, env=child_env(),
                              capture_output=True, text=True, timeout=JOB_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": {"type": "Timeout", "seconds": JOB_TIMEOUT_S}}) + "\n"
    if proc.returncode != 0 or not os.path.isfile(out_path):
        tail = proc.stderr.strip().splitlines()[-1:] or [""]
        return json.dumps({"error": {"type": "ChildCrash", "returncode": proc.returncode,
                                     "last_stderr_line": tail[0]}}, indent=1) + "\n"
    with open(out_path, encoding="utf-8") as fh:
        return fh.read()


def produce_golden(job: Job) -> str:
    """Canonical JSON text for *job*."""
    with tempfile.TemporaryDirectory(prefix="fritap_golden_") as tmp:
        out_path = os.path.join(tmp, "out.json")
        if job.tap_path is not None:
            return _run_child(["read", job.tap_path, out_path], out_path)
        work_dir = os.path.join(tmp, "work")
        os.mkdir(work_dir)
        stage_inputs(job.entry, work_dir)
        entry_path = os.path.join(tmp, "entry.json")
        with open(entry_path, "w", encoding="utf-8") as fh:
            json.dump(job.entry, fh)
        return _run_child(["convert", entry_path, work_dir, out_path], out_path)


# ---------------------------------------------------------------------------
# Record / compare
# ---------------------------------------------------------------------------

def golden_path(out_dir: str, job_id: str) -> str:
    return os.path.join(out_dir, job_id + ".json")


def diff_text(expected: str, actual: str, job_id: str) -> str:
    return "".join(difflib.unified_diff(
        expected.splitlines(keepends=True), actual.splitlines(keepends=True),
        fromfile=f"golden/{job_id}", tofile=f"actual/{job_id}", n=3))


def short_status(text: str) -> str:
    """One-line description of a golden (error type or flow count)."""
    data = json.loads(text)
    if "error" in data:
        return f"ERROR {data['error'].get('type')}"
    tap = data.get("tap") or {}
    return f"{tap.get('flow_count', 0)} flows"


def record_job(job: Job, out_dir: str) -> tuple[bool, str]:
    text = produce_golden(job)
    with open(golden_path(out_dir, job.id), "w", encoding="utf-8") as fh:
        fh.write(text)
    return True, short_status(text)


def compare_job(job: Job, out_dir: str) -> tuple[bool, str]:
    path = golden_path(out_dir, job.id)
    if not os.path.isfile(path):
        return False, "MISSING golden"
    with open(path, encoding="utf-8") as fh:
        expected = fh.read()
    actual = produce_golden(job)
    if actual == expected:
        return True, short_status(actual)
    return False, "MISMATCH\n" + diff_text(expected, actual, job.id)


def run_jobs(jobs: list[Job], action, out_dir: str, workers: int) -> list[str]:
    """Run *action* over *jobs*; print per-job and per-tier timing; return failures."""
    os.makedirs(out_dir, exist_ok=True)
    failures, tier_seconds = [], {}

    def timed(job: Job):
        start = time.monotonic()
        ok, msg = action(job, out_dir)
        return job, ok, msg, time.monotonic() - start

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for job, ok, msg, secs in pool.map(timed, jobs):
            tier_seconds[job.tier] = tier_seconds.get(job.tier, 0.0) + secs
            print(f"[{'ok' if ok else 'FAIL'}] {job.id} ({secs:.1f}s): {msg}", flush=True)
            if not ok:
                failures.append(job.id)
    for tier, secs in tier_seconds.items():
        print(f"tier {tier}: {secs:.1f}s cumulative job time")
    return failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--record", metavar="DIR")
    mode.add_argument("--compare", metavar="DIR")
    parser.add_argument("--tier", default="all", choices=("fixture", "research", "read", "all"))
    parser.add_argument("--only", metavar="ID")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    jobs = select_jobs(args.tier, args.only)
    if not jobs:
        print("no jobs selected")
        return 2
    out_dir = args.record or args.compare
    action = record_job if args.record else compare_job
    start = time.monotonic()
    failures = run_jobs(jobs, action, out_dir, args.jobs)
    print(f"{len(jobs) - len(failures)}/{len(jobs)} ok in {time.monotonic() - start:.1f}s wall")
    if failures:
        print("failed: " + ", ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
