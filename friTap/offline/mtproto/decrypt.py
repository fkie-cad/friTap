"""Top-level orchestrator: pcap -> decrypted MTProto messages.

Ties together TCP reassembly (:mod:`.reassembly`), transport de-obfuscation
(:mod:`.transport`), and record decryption (:mod:`.crypto`). Streams that are not
MTProto-obfuscated are silently skipped (false-positive guard); unsupported
transports (padded-intermediate, full, Fake-TLS) and degraded streams are counted
and logged with an actionable hint, mirroring friTap's keyless-skip logging.

The crypto backend is imported lazily; a :class:`MtprotoDependencyError` is
re-raised so the parent offline driver can catch it and skip MTProto cleanly.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterator, Optional, Tuple

from ...protocols.mtproto_keylog_spec import MtprotoAuthKey
from . import MtprotoCryptoError, MtprotoDependencyError
from .records import DecryptedMessage, MtprotoStats
from .reassembly import INIT_BLOCK_LEN, StreamPair, reassemble_pcap
from .transport import ObfuscationCipher, detect_transport, iter_frames

logger = logging.getLogger(__name__)


def iter_decrypted_messages(
    pcap_path: str,
    keymap: Dict[bytes, MtprotoAuthKey],
    *,
    server_ports: Tuple[int, ...] = (443, 80, 5222),
    stats: Optional[MtprotoStats] = None,
) -> Iterator[DecryptedMessage]:
    """Yield every decryptable MTProto message from ``pcap_path``.

    For each reassembled conversation:
      * de-obfuscate the first 64 client bytes and detect the transport tag; a
        ``None`` result means the stream is not MTProto — skip it silently;
      * CTR-decrypt both directions and split into outer records via
        :func:`iter_frames`;
      * decrypt each record with the auth_key looked up by ``outer[0:8]``.

    Unknown key, msg_key-verify failure -> ``records_undecryptable``. Unsupported
    framing (padded/full) and degraded streams -> ``streams_degraded`` (logged).
    A :class:`MtprotoDependencyError` from the backend is re-raised.
    """
    # Lazy backend check: surface a missing crypto dep to the parent immediately.
    from . import MTPROTO_DEPENDENCY_HINT, crypto

    if not crypto.backend_available():
        raise MtprotoDependencyError(MTPROTO_DEPENDENCY_HINT)

    if stats is None:
        stats = MtprotoStats()

    streams = reassemble_pcap(pcap_path, server_ports=server_ports)
    for pair in streams.values():
        stats.add_stream()
        yield from _process_stream(pair, keymap, stats)


def _process_stream(
    pair: StreamPair,
    keymap: Dict[bytes, MtprotoAuthKey],
    stats: MtprotoStats,
) -> Iterator[DecryptedMessage]:
    if pair.degraded:
        stats.add_degraded()
        logger.info(
            "Skipping MTProto stream %s<->%s: client direction missing the first "
            "%d obfuscation bytes (capture started mid-flow or has a gap). "
            "Capture from connection start to decrypt this stream.",
            pair.client_addr,
            pair.server_addr,
            INIT_BLOCK_LEN,
        )
        return

    client_bytes = pair.client.contiguous_bytes()
    cipher = ObfuscationCipher(client_bytes[:INIT_BLOCK_LEN])

    # Decrypt the init block (first 64 client bytes) to read the transport tag.
    decrypted_init = cipher.decrypt_out(client_bytes[:INIT_BLOCK_LEN])
    transport_type = detect_transport(decrypted_init)
    if transport_type is None:
        return  # not MTProto-obfuscated — false-positive guard, skip silently

    # Continue the keystream over the rest of each direction.
    client_payload = cipher.decrypt_out(client_bytes[INIT_BLOCK_LEN:])
    server_payload = cipher.decrypt_in(pair.server.contiguous_bytes())

    try:
        yield from _decrypt_direction(
            transport_type, client_payload, "write", pair, keymap, stats
        )
        yield from _decrypt_direction(
            transport_type, server_payload, "read", pair, keymap, stats
        )
    except NotImplementedError:
        stats.add_degraded()
        logger.info(
            "Skipping MTProto stream %s<->%s: %r transport framing is not yet "
            "supported (only abridged/intermediate are). Counted, not decrypted.",
            pair.client_addr,
            pair.server_addr,
            transport_type,
        )
        return


def _decrypt_direction(
    transport_type: str,
    payload: bytes,
    direction: str,
    pair: StreamPair,
    keymap: Dict[bytes, MtprotoAuthKey],
    stats: MtprotoStats,
) -> Iterator[DecryptedMessage]:
    from . import crypto

    if direction == "write":
        src_addr, src_port = pair.client_addr
        dst_addr, dst_port = pair.server_addr
    else:
        src_addr, src_port = pair.server_addr
        dst_addr, dst_port = pair.client_addr

    for frame in iter_frames(transport_type, payload):
        if len(frame) < 8:
            stats.add_undecryptable()
            continue
        auth_key_id = frame[0:8]
        entry = keymap.get(auth_key_id)
        if entry is None:
            stats.add_undecryptable()
            continue
        try:
            record = crypto.decrypt_record(entry.auth_key, frame, direction)
        except MtprotoCryptoError:
            stats.add_undecryptable()
            continue
        stats.add_message()
        yield DecryptedMessage(
            src_addr=src_addr,
            src_port=src_port,
            dst_addr=dst_addr,
            dst_port=dst_port,
            ss_family=pair.ss_family,
            direction=direction,
            message=record.envelope.message,
            dc_id=entry.dc_id,
            transport=transport_type,
            obfuscated=True,
            auth_key_id_hex=auth_key_id.hex(),
        )
