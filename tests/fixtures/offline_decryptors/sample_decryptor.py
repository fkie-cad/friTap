"""Sample drop-in offline decryptor used by the discovery tests.

It opts in via the module-level ``is_fritap_offline_decryptor`` marker and
exposes one :class:`OfflineDecryptorEntry`. The emitter is a no-op: it does not
actually decrypt anything, it just needs to be discoverable and registrable.
"""

from __future__ import annotations

from friTap.flow.layers import AppLayer
from friTap.offline.registry import OfflineDecryptorEntry

is_fritap_offline_decryptor = True


def _sample_emitter(
    *,
    pcap_path,
    proto_keylog,
    tls_keylog_path,
    tshark_bin,
    tls_ports,
    bus,
    state,
    result,
):
    """No-op emitter: record an empty protocol result and return."""
    result.record_protocol("sampleproto", messages=0, streams=0)


SAMPLE_ENTRY = OfflineDecryptorEntry(
    protocol_name="sampleproto",
    cli_flag="--sampleproto-keylog",
    cli_dest="sampleproto_keylog",
    requires_tls_strip=False,
    emitter=_sample_emitter,
    layer_cls=AppLayer,
    counter_prefix="sampleproto",
    cli_help="Sample plugin decryptor.",
)
