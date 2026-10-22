"""Frozen v1 schema of the offline conversion summary (``ConvertResult``).

A leaf module with NO imports: it only names the counter layout that the
serialized ``ConvertResult.to_dict()`` JSON has always carried, so readers (the
pipeline, the CLI, the TUI) can derive behavior from one place without naming
any protocol in code.

FROZEN: both tables describe the published v1 JSON shape (golden files and the
web/API callers depend on it byte-for-byte). Never reorder, rename or remove an
entry; a new counter only ever appears through ``record_protocol(**counters)``.
"""

# The keys every ``per_protocol[<prefix>]`` bucket starts with, in insertion
# order, with their initial values. ``ConvertResult.record_protocol`` deep-copies
# this for each new bucket, so the mutable ``{}`` default is never shared.
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

# Legacy flat counters of the v1 JSON: ``(flat_name, prefix, bucket_key)``. Each
# flat name is a read-only view of ``per_protocol[prefix][bucket_key]`` (0 when
# the bucket is absent) and is serialized, in this order, right before
# ``per_protocol``.
V1_FLAT_COUNTERS = (
    ("mtproto_messages", "mtproto", "messages"),
    ("mtproto_streams", "mtproto", "streams"),
    ("mtproto_records_undecryptable", "mtproto", "undecryptable"),
    ("mtproto_streams_degraded", "mtproto", "degraded"),
)
