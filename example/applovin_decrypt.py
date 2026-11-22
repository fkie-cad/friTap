#!/usr/bin/env python3
"""Batch-decrypt AppLovin MAX ``/1.0/mediate`` payloads from friTap .tap captures.

Usage:
    python applovin_decrypt.py capture.tap --sdk-key KEY --salt HEX
    python applovin_decrypt.py a.tap b.tap --app-bundle app.apk --out-dir decrypted/
    python applovin_decrypt.py capture.tap --jsonl > mediate.jsonl

For every mediate envelope one summary line is printed (to stderr with
``--jsonl``, else stdout): flow id, time, host, decrypted?/reason, payload
timestamp. Decrypted JSON is written per envelope to ``--out-dir`` or, with
``--jsonl``, as one JSON object per line on stdout.

Key material is also read from ``FRITAP_APPLOVIN_SDK_KEY``,
``FRITAP_APPLOVIN_SALT`` and ``FRITAP_APPLOVIN_BUNDLE``.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

# Allow standalone execution from the example/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from friTap.analysis.applovin_mediate import find_mediate_envelope, variant_label
from friTap.flow.tap_reader import TapReader
from friTap.parsers.app_ciphers.applovin_keyring import AppLovinKeyring


@dataclass
class EnvelopeRecord:
    """One mediate envelope found in a capture, decrypted or not."""

    tap: str
    flow_id: str
    started: float
    host: str
    protocol_id: str
    reason: str = ""
    timestamp_ms: int | None = None
    variant: str | None = None
    payload: Any = None

    @property
    def decrypted(self) -> bool:
        return not self.reason


def _iso(epoch: float) -> str:
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return "?"


def _host(flow) -> str:
    return (flow.request.host if flow.request else "") or flow.dst_addr or "?"


def _decrypt_flow(tap: str, flow, keyring: AppLovinKeyring) -> EnvelopeRecord | None:
    envelope = find_mediate_envelope(flow)
    if envelope is None:
        return None
    record = EnvelopeRecord(tap=tap, flow_id=flow.flow_id, started=flow.started,
                            host=_host(flow), protocol_id=envelope.protocol_id)
    result, reason = keyring.try_decrypt(envelope)
    if result is None:
        record.reason = reason or "decryption failed"
        return record
    record.timestamp_ms = result.timestamp_ms
    record.variant = variant_label(result)
    record.payload = result.json if result.json is not None else \
        result.plaintext.decode("utf-8", "replace")
    return record


def iter_envelopes(tap_path: str, keyring: AppLovinKeyring) -> Iterator[EnvelopeRecord]:
    """Yield an :class:`EnvelopeRecord` for every mediate envelope in *tap_path*."""
    with TapReader(tap_path) as reader:
        for _ordinal, _summary, flow in reader.iter_flows():
            record = _decrypt_flow(tap_path, flow, keyring)
            if record is not None:
                yield record


def summary_line(record: EnvelopeRecord) -> str:
    status = "decrypted" if record.decrypted else f"NOT decrypted ({record.reason})"
    ts = f" ts={_iso(record.timestamp_ms / 1000)}" if record.timestamp_ms else ""
    return f"{record.flow_id}  {_iso(record.started)}  {record.host}  {status}{ts}"


def to_json_object(record: EnvelopeRecord) -> dict:
    obj = {"tap": record.tap, "flow_id": record.flow_id, "host": record.host,
           "protocol_id": record.protocol_id, "decrypted": record.decrypted}
    if record.decrypted:
        obj.update(timestamp_ms=record.timestamp_ms, variant=record.variant, json=record.payload)
    else:
        obj["reason"] = record.reason
    return obj


def write_payload(record: EnvelopeRecord, out_dir: Path) -> Path:
    path = out_dir / f"{Path(record.tap).stem}_{record.flow_id}.json"
    path.write_text(json.dumps(record.payload, indent=2, ensure_ascii=False) + "\n")
    return path


def emit(record: EnvelopeRecord, args: argparse.Namespace) -> None:
    print(summary_line(record), file=sys.stderr if args.jsonl else sys.stdout)
    if args.jsonl:
        print(json.dumps(to_json_object(record), ensure_ascii=False, default=str))
    elif args.out_dir and record.decrypted:
        write_payload(record, args.out_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decrypt AppLovin MAX /1.0/mediate payloads in friTap .tap captures.")
    parser.add_argument("tap_files", nargs="+", help="One or more .tap capture files")
    parser.add_argument("--sdk-key", "--applovin-sdk-key", dest="sdk_key", action="append", default=[], help="AppLovin SDK key (repeatable)")
    parser.add_argument("--salt", "--applovin-salt", dest="salt", action="append", default=[], help="Cipher salt as hex (repeatable)")
    parser.add_argument("--app-bundle", action="append", default=[],
                        help="APK/IPA to mine SDK key and salt from (repeatable)")
    parser.add_argument("--out-dir", type=Path, help="Write each decrypted payload as JSON here")
    parser.add_argument("--jsonl", action="store_true",
                        help="Print one JSON object per envelope to stdout (summaries go to stderr)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    missing = [p for p in args.tap_files if not Path(p).is_file()]
    if missing:
        print(f"Error: file not found: {', '.join(missing)}", file=sys.stderr)
        return 1
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
    keyring = AppLovinKeyring.from_sources(args.sdk_key, args.salt, args.app_bundle)
    total = decrypted = 0
    for tap in args.tap_files:
        for record in iter_envelopes(tap, keyring):
            emit(record, args)
            total += 1
            decrypted += record.decrypted
    print(f"{total} envelope(s), {decrypted} decrypted.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
