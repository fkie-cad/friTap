"""Compare scoped Perfetto Binder metadata and fixture clock observations."""
import argparse
import csv
from decimal import Decimal
import json
import re
import subprocess
import time

from . import SCHEMA, lead_time_bounds


def binder_edges(rows, process_names):
    """Yield IPC evidence with trace-local process lifetime identities."""
    names = frozenset(process_names)
    for row in rows:
        if row["client_process"] not in names or row["server_process"] not in names:
            continue
        try:
            endpoints = {
                side: {"name": row[f"{side}_process"],
                       **{key: int(row[f"{side}_{key}"]) for key in ("pid", "upid", "ts")}}
                for side in ("client", "server")
            }
        except (TypeError, ValueError):
            continue
        yield {"schema": SCHEMA, "type": "binder_edge", "clock": "perfetto_trace_ns",
               **endpoints, "action_attribution": "unresolved"}


def sample_clock(serial):
    """Bracket Android boot time using the precision exposed by proc uptime."""
    before = time.monotonic_ns()
    output = subprocess.run(
        ["adb", "-s", serial, "shell", "cat /proc/uptime"],
        text=True, capture_output=True, timeout=5, check=True,
    ).stdout
    after = time.monotonic_ns()
    match = re.match(r"^(\d+\.(\d{1,9}))\s", output)
    if not match:
        raise ValueError("Unexpected Android uptime format")
    return {"clock_host_before_ns": before, "clock_host_after_ns": after,
            "clock_device_ns": int(Decimal(match[1]) * 1_000_000_000),
            "clock_resolution_ns": 10 ** (9 - len(match[2]))}


def compare_timing(record):
    """Score one fixture trial using a bracketed device clock reading."""
    candidate = record["candidate_host_ns"]
    handshake = record["handshake_device_ns"]
    result = {"id": record["id"], "schema": SCHEMA, "type": "timing"}
    if handshake is None or candidate is None:
        status = "no_handshake" if handshake is None else "candidate_missed"
        return dict(result, status=status)
    before, after = record["clock_host_before_ns"], record["clock_host_after_ns"]
    device = record["clock_device_ns"]
    readiness = record["readiness_ns"]
    resolution = record.get("clock_resolution_ns", 0)
    if readiness < 0 or resolution < 0 or before > after:
        raise ValueError("Invalid clock bracket or readiness duration")
    lower, upper = lead_time_bounds(candidate, handshake, device - after,
                                    device + resolution - before)
    if lower >= readiness:
        status = "sufficient_lead"
    elif upper < readiness:
        status = "insufficient_lead"
    else:
        status = "clock_ambiguous"
    return dict(result, status=status, lead_min_ns=lower, lead_max_ns=upper)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    binder = modes.add_parser("binder")
    binder.add_argument("csv")
    binder.add_argument("--process", action="append", required=True)
    timing = modes.add_parser("timing")
    timing.add_argument("jsonl")
    clock = modes.add_parser("clock")
    clock.add_argument("--device", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "binder":
            with open(args.csv, newline="", encoding="utf-8") as source:
                for edge in binder_edges(csv.DictReader(source), args.process):
                    print(json.dumps(edge))
        elif args.mode == "clock":
            print(json.dumps(sample_clock(args.device)))
        else:
            with open(args.jsonl, encoding="utf-8") as source:
                for line in source:
                    print(json.dumps(compare_timing(json.loads(line))))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"tlshunter offline: {exc}\n")


if __name__ == "__main__":
    main()
