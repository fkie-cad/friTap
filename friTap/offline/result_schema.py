"""Frozen v1 schema of the offline conversion summary (``ConvertResult``).

A leaf module naming the counter layout of ``ConvertResult.to_dict()`` JSON so
the pipeline, CLI and TUI derive behaviour from one place. Both tables are the
published v1 shape (golden files and API callers depend on it byte for byte):
never reorder, rename or remove an entry; new counters arrive via ``record_protocol(**counters)``.
"""

# Keys every ``per_protocol[<prefix>]`` bucket starts with, in order; record_protocol deep-copies this so the mutable ``{}`` default is never shared.
V1_BUCKET_DEFAULTS = {
    "messages": 0,
    "streams": 0,
    "undecryptable": 0,
    "degraded": 0,
    "degraded_non_mtproto": 0,
    "partial": 0,
    "recovered_via_obf": 0,
    "degraded_unrecovered": 0,
    "short": 0,
    "unsupported_framing": 0,
    "e2e_only": False,
    "unknown_key_ids": {},
}

# Flat v1 counters ``(flat_name, prefix, bucket_key)``: read-only views of ``per_protocol[prefix][bucket_key]`` (0 when absent), serialized in this order before ``per_protocol``.
V1_FLAT_COUNTERS = (
    ("mtproto_messages", "mtproto", "messages"),
    ("mtproto_streams", "mtproto", "streams"),
    ("mtproto_records_undecryptable", "mtproto", "undecryptable"),
    ("mtproto_streams_degraded", "mtproto", "degraded"),
)
