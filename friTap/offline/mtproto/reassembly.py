"""MTProto view of the shared sequence-indexed TCP reassembly.

The generic reassembler lives in :mod:`friTap.offline.net.tcp_reassembly`.
This module adds the one MTProto-specific rule: a conversation is ``degraded``
when its client direction lacks the 64-byte obfuscation init block, because
MTProto's obfuscated transport is AES-CTR keyed from that block. The old
private names are re-exported so existing imports keep working.
"""

from __future__ import annotations

from typing import Dict, Tuple

# Re-exported for old imports (decrypt.py, tests).
from ..net.tcp_reassembly import (  # noqa: F401
    ConvBuilder,
    TcpStreamPair,
    TcpStreamReassembler,
)
from ..net.tcp_reassembly import (
    reassemble_pcap as _reassemble_tcp_pcap,
)
from .transport import _INIT_LEN

# 64-byte obfuscation init block — a stream missing this cannot be de-obfuscated.
INIT_BLOCK_LEN = _INIT_LEN


class StreamPair(TcpStreamPair):
    """Both directions of one MTProto conversation.

    ``client`` is the client->server direction (carries the obfuscation init
    block); ``server`` is server->client. ``client_addr``/``server_addr`` are the
    normalized endpoint tuples.
    """

    @property
    def degraded(self) -> bool:
        """A stream is degraded if the client direction lacks the first 64 bytes."""
        if self.client.degraded:
            return True
        return len(self.client.contiguous_bytes()) < INIT_BLOCK_LEN


class _ConvBuilder(ConvBuilder):
    """:class:`ConvBuilder` that finalizes into an MTProto :class:`StreamPair`."""

    def __init__(self, family: str, server_ports: Tuple[int, ...]):
        super().__init__(family, server_ports, StreamPair)


def reassemble_pcap(
    pcap_path: str,
    *,
    server_ports: Tuple[int, ...] = (443, 80, 5222),
) -> Dict[Tuple[str, int, str, int], StreamPair]:
    """Reassemble all TCP conversations in ``pcap_path`` into MTProto stream pairs.

    Same as :func:`friTap.offline.net.tcp_reassembly.reassemble_pcap` (see there
    for the client-orientation rule) but with MTProto's default server ports and
    :class:`StreamPair` values.
    """
    return _reassemble_tcp_pcap(
        pcap_path, server_ports=server_ports, pair_cls=StreamPair
    )
