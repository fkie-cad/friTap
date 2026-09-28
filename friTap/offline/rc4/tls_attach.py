"""Post-collection RC4-in-TLS attach: one flow carrying [TLS (owned), RC4 (chunks)].

A nested RC4 capture yields two collector flows over the SAME connection: the
``tls`` flow holding the decrypted TLS plaintext (= the RC4 ciphertext, framed)
and the ``rc4`` flow holding the RC4 plaintext (keyed apart by the RC4 session
token). This pass folds them into the RC4 flow's layer stack::

    TlsLayer(depth 0, owned = the per-direction TLS plaintext that carried the
             flow's RC4 records; version/SNI/cipher/ALPN from the TLS flow)
      -> Rc4Layer(depth 1, chunks = RC4 plaintext; source/key_len/direction/
                  message_count/framing/records filled from the provenance)

When the RC4 records of a connection cover ALL of its TLS plaintext (prefix +
ciphertext of every record, both directions), the standalone TLS flow carries
nothing the RC4 flow does not, and is absorbed (not written). Otherwise it is
kept. Inputs are the writer state's ``tls_spans`` (see
:mod:`friTap.offline.tls_spans`) and ``rc4_provenance`` (per canonical 4-tuple,
records tagged with ``_chunk_key``).
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Set

from friTap.connection_index import canonical_4tuple
from friTap.offline.tls_spans import spans_covering

# Metadata of each RC4 record exposed on ``Rc4Layer.records``; the provenance
# additionally carries key identity/framing, which lands on the layer itself.
_LAYER_RECORD_FIELDS = ("direction", "length", "tls_frames", "timestamp",
                        "cipher_offset", "frame_header_len")
_TLS_META_FIELDS = ("library", "version", "sni", "alpn", "cipher")


def _flow_key(flow) -> str:
    return canonical_4tuple(flow.src_addr, flow.src_port,
                            flow.dst_addr, flow.dst_port)


def _record_range(record: dict) -> tuple:
    """``[start, end)`` of a record (length prefix + ciphertext) in its direction."""
    start = record.get("cipher_offset", 0) - record.get("frame_header_len", 0)
    return max(start, 0), record.get("cipher_offset", 0) + record.get("length", 0)


def _scoped_rc4_records(flow, prov: dict) -> List[dict]:
    """The provenance records of *flow*'s connection whose chunk landed in *flow*
    (``_chunk_key`` stripped), reusing the Telegram message scoping."""
    from friTap.offline.pcap_to_tap import _scope_messages_to_flow

    return _scope_messages_to_flow(flow, prov.get(_flow_key(flow)) or [])


def _covered_spans(spans: list, records: Iterable[dict]) -> list:
    """The spans holding any byte of *records*, once each, in capture order."""
    wanted: Set[int] = set()
    for record in records:
        lo, hi = _record_range(record)
        wanted.update(id(span) for span in spans_covering(spans, lo, hi))
    return [span for span in spans if id(span) in wanted]


def _tls_owned_for(records: List[dict], spans_by_dir: Dict[str, list]) -> dict:
    """``{"write": bytes, "read": bytes}``: per direction, the concatenated TLS
    plaintext of the spans covering *records* (each frame contributed once)."""
    owned = {}
    for direction in ("write", "read"):
        mine = [r for r in records if r.get("direction") == direction]
        spans = _covered_spans(spans_by_dir.get(direction) or [], mine)
        owned[direction] = b"".join(span.data for span in spans)
    return owned


def _covers(intervals: List[tuple], total: int) -> bool:
    """True when the union of ``[lo, hi)`` *intervals* covers ``[0, total)``."""
    reach = 0
    for lo, hi in sorted(intervals):
        if lo > reach:
            return False
        reach = max(reach, hi)
    return reach >= total


def _tls_fully_consumed(spans_by_dir: Dict[str, list], records: List[dict]) -> bool:
    """True when *records* cover every TLS plaintext byte of every direction.

    No spans at all (no single-pass provenance) is never "consumed".
    """
    if not any(spans_by_dir.get(d) for d in ("write", "read")):
        return False
    for direction in ("write", "read"):
        total = sum(len(s.data) for s in spans_by_dir.get(direction) or [])
        ranges = [_record_range(r) for r in records
                  if r.get("direction") == direction]
        if total and not _covers(ranges, total):
            return False
    return True


def _build_tls_carrier(tls_meta, owned: dict):
    """A TLS layer owning the carried plaintext, with *tls_meta*'s handshake
    fields (the TLS flow's layer; ``None`` leaves them empty)."""
    from friTap.flow.layers import LayerData, TlsLayer

    layer = TlsLayer()
    for name in _TLS_META_FIELDS:
        setattr(layer, name, getattr(tls_meta, name, "") or "")
    layer.data = LayerData()
    layer.data.set_owned(read=owned.get("read", b""), write=owned.get("write", b""))
    return layer


def _layer_direction(records: List[dict]) -> str:
    directions = {r.get("direction") for r in records}
    if {"write", "read"} <= directions:
        return "both"
    return next(iter(directions), "") or ""


def _set_if_present(layer, name: str, value) -> None:
    """Set *name* only on a layer class that declares it (tolerates older layers)."""
    if hasattr(layer, name):
        setattr(layer, name, value)


def _fill_rc4_layer(layer, records: List[dict]) -> None:
    """Stamp key identity, direction, count, framing and records on *layer*."""
    if not records:
        return
    first = records[0]
    layer.source = first.get("source", "") or ""
    layer.key_len = first.get("key_len", 0) or 0
    layer.direction = _layer_direction(records)
    layer.message_count = len(records)
    _set_if_present(layer, "framing", first.get("framing", "") or "")
    _set_if_present(layer, "records", [
        {name: r.get(name) for name in _LAYER_RECORD_FIELDS} for r in records
    ])


def _rebuild_stack(flow, tls_layer) -> None:
    """Replace *flow*'s stack with ``[tls_layer, rc4 (chunks)]``."""
    inner = flow.layer("rc4") or getattr(flow, "rc4")
    inner.metadata_only = False
    flow.layers = []
    flow.add_layer(tls_layer)
    flow.add_layer(inner)


def _tls_layers_by_key(flows) -> dict:
    """First TLS layer of each ``tls`` flow, by canonical 4-tuple."""
    found: dict = {}
    for flow in flows:
        if getattr(flow, "transport", "") == "tls" and flow.layer("tls") is not None:
            found.setdefault(_flow_key(flow), flow.layer("tls"))
    return found


def _attach_one(flow, state, tls_meta) -> None:
    records = _scoped_rc4_records(flow, state.rc4_provenance)
    spans_by_dir = state.tls_spans.get(_flow_key(flow)) or {}
    if spans_by_dir:
        owned = _tls_owned_for(records, spans_by_dir)
        _rebuild_stack(flow, _build_tls_carrier(tls_meta, owned))
    _fill_rc4_layer(flow.layer("rc4") or getattr(flow, "rc4"), records)


def _absorbed_tls_flow_ids(flows, state) -> Set[str]:
    """``flow_id`` of every TLS flow whose connection RC4 fully consumed."""
    absorbed: Set[str] = set()
    for flow in flows:
        if getattr(flow, "transport", "") != "tls":
            continue
        key = _flow_key(flow)
        records = state.rc4_provenance.get(key) or []
        if records and _tls_fully_consumed(state.tls_spans.get(key) or {}, records):
            absorbed.add(flow.flow_id)
    return absorbed


def attach_rc4_in_tls_layers(flows, state) -> Set[str]:
    """Build the [TLS, RC4] stack on every RC4 flow; return absorbed TLS flow ids.

    Must run on the LIVE flows before ``flush()`` (like the Signal attach).
    Standalone RC4 flows (no TLS spans) only get their RC4 metadata filled.
    """
    flows = list(flows)
    tls_by_key = _tls_layers_by_key(flows)
    for flow in flows:
        if getattr(flow, "transport", "") == "rc4":
            _attach_one(flow, state, tls_by_key.get(_flow_key(flow)))
    return _absorbed_tls_flow_ids(flows, state)
