"""One golden job, run in a fresh interpreter by run_golden.py.

Usage (internal):
    golden_child.py convert <entry.json> <work_dir> <out.json>
    golden_child.py read    <tap_path>              <out.json>

``convert`` expects the inputs to be already copied into *work_dir* under their
original basenames; the entry's ``args`` hold those basenames. A conversion that
raises is recorded as its golden ``{"error": ...}`` instead of failing the job.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import canonicalize  # noqa: E402

PATH_ARGS = ("keylog_path", "mtproto_keylog", "tls_midstream_secrets")
TUPLE_ARGS = ("tls_ports", "quic_ports", "extra_decode_as")


def build_convert_kwargs(args: dict, work_dir: str) -> dict:
    """Map corpus ``args`` (input basenames) onto convert_pcap_to_tap kwargs."""
    kwargs: dict = {"run_scan": False}
    for name in PATH_ARGS:
        if args.get(name):
            kwargs[name] = os.path.join(work_dir, os.path.basename(args[name]))
    for name in TUPLE_ARGS:
        if args.get(name):
            kwargs[name] = tuple(args[name])
    if args.get("protocol_keylogs"):
        kwargs["protocol_keylogs"] = {
            proto: os.path.join(work_dir, os.path.basename(path))
            for proto, path in args["protocol_keylogs"].items()
        }
    for name in ("heuristic", "resync_search_depth"):
        if name in args:
            kwargs[name] = args[name]
    return kwargs


def run_convert(entry: dict, work_dir: str) -> dict:
    from friTap.offline.pcap_to_tap import convert_pcap_to_tap

    pcap = os.path.join(work_dir, os.path.basename(entry["pcap"]))
    tap = os.path.join(work_dir, os.path.splitext(os.path.basename(pcap))[0] + ".tap")
    try:
        result = convert_pcap_to_tap(pcap, tap_path=tap,
                                     **build_convert_kwargs(entry.get("args", {}), work_dir))
    except Exception as exc:  # noqa: BLE001 - a failure IS the golden behaviour
        return canonicalize.canonical_error(exc)
    out = {"result": result.to_dict()}
    out["tap"] = canonicalize.canonical_tap(tap) if os.path.isfile(tap) else None
    return out


def run_read(tap_path: str) -> dict:
    try:
        return {"tap": canonicalize.canonical_tap(tap_path)}
    except Exception as exc:  # noqa: BLE001
        return canonicalize.canonical_error(exc)


def main(argv: list[str]) -> int:
    mode = argv[0]
    if mode == "convert":
        entry_path, work_dir, out_path = argv[1:4]
        with open(entry_path, encoding="utf-8") as fh:
            entry = json.load(fh)
        work_dirs = [os.path.realpath(work_dir), work_dir]
        data = canonicalize.replace_work_dirs(run_convert(entry, work_dir), work_dirs)
    elif mode == "read":
        tap_path, out_path = argv[1:3]
        data = run_read(tap_path)
    else:
        raise SystemExit(f"unknown mode {mode!r}")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(canonicalize.dumps(data))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
