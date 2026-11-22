"""Transport messages -> decrypted secret-chat messages.

Scans the decrypted MTProto transport messages from
:func:`friTap.offline.mtproto.decrypt.iter_decrypted_messages` for
TL-``bytes``-framed E2E blobs keyed by a known fingerprint, peels off the second
AES-IGE layer, and yields the inner TL payloads. A
:class:`MtprotoDependencyError` from the transport decryptor propagates so the
offline driver can skip cleanly.
"""

from __future__ import annotations

from typing import Dict, Iterable, Iterator, Optional, Set, Tuple

from ....protocols.mtproto_keylog_spec import MtprotoSecretChatKey
from .. import MtprotoCryptoError, crypto
from ..records import DecryptedMessage
from .records import SecretChatMessage, SecretChatStats

# TL ``bytes`` framing: a single length byte when the payload is < 254 bytes,
# otherwise a 0xFE marker followed by a 3-byte little-endian length.
_TL_SHORT_MAX = 254
_TL_LONG_MARKER = 0xFE


def iter_e2e_blobs(data: bytes, fingerprints: Set[bytes]) -> Iterator[Tuple[bytes, bytes]]:
    """Yield ``(fingerprint, blob)`` for every TL-``bytes``-framed E2E blob in ``data``.

    A known-fingerprint match anchors each candidate; the TL ``bytes`` length
    just before it must describe a valid E2E blob (``>= header + one AES
    block``, block-aligned body, in bounds), then the scan resumes past it.

    Unknown fingerprints cannot be reported: anchoring on a plausible TL length
    instead would accept about one random byte in 18 (short-form lengths
    ``40, 56, ... 248``). That needs a TL-aware ``encryptedMessage`` walk.
    """
    fp_len = crypto.E2E_FINGERPRINT_LEN
    hits = {fp: -1 for fp in fingerprints if len(fp) == fp_len}
    if not hits:
        return
    data = bytes(data)
    p = 0
    n = len(data)
    while True:
        p = _next_fingerprint_hit(data, hits, p)
        if p < 0:
            return
        fp = data[p : p + fp_len]
        length = _read_tl_bytes_length(data, p)
        if (
            length is not None
            and length >= crypto.E2E_HEADER_LEN + crypto.AES_BLOCK
            and (length - crypto.E2E_HEADER_LEN) % crypto.AES_BLOCK == 0
            and p + length <= n
        ):
            yield fp, data[p : p + length]
            p += length
            continue
        p += 1


def _next_fingerprint_hit(data: bytes, hits: Dict[bytes, int], start: int) -> int:
    """Smallest offset >= *start* holding any known fingerprint, or -1.

    *hits* caches each fingerprint's next occurrence (``-1`` = not searched yet,
    ``-2`` = none left) so each one is located with ``bytes.find`` instead of probing
    every offset; there are only a handful of fingerprints per capture.
    """
    best = -1
    for fp, hit in hits.items():
        if hit < start and hit != -2:
            hit = data.find(fp, start)
            hits[fp] = hit if hit >= 0 else -2  # -2: no further occurrence
        if hit >= 0 and (best < 0 or hit < best):
            best = hit
    return best


def _read_tl_bytes_length(data: bytes, p: int) -> Optional[int]:
    """Decode the TL ``bytes`` length stored immediately before index ``p``."""
    if p >= 1 and data[p - 1] < _TL_SHORT_MAX:
        return data[p - 1]
    if p >= 4 and data[p - 4] == _TL_LONG_MARKER:
        return int.from_bytes(data[p - 3 : p], "little")
    return None


def iter_secret_chat_messages(
    transport_messages: Iterable[DecryptedMessage],
    keymap: Dict[bytes, MtprotoSecretChatKey],
    *,
    stats: Optional[SecretChatStats] = None,
) -> Iterator[SecretChatMessage]:
    """Yield every decryptable secret-chat message embedded in ``transport_messages``.

    For each transport message, every embedded E2E blob keyed by a known
    fingerprint is decrypted with the per-chat shared key and unframed into its
    TL payload. Unknown fingerprints are invisible here (see
    :func:`iter_e2e_blobs`). A blob whose msg_key fails to verify or whose
    framing is bad counts as ``records_undecryptable``. Addressing and direction
    are copied from the carrying transport message.
    """
    if stats is None:
        stats = SecretChatStats()

    fingerprints = set(keymap)
    for msg in transport_messages:
        for fp, blob in iter_e2e_blobs(msg.message, fingerprints):
            stats.add_blob()
            key = keymap[fp]
            try:
                plaintext = crypto.decrypt_secret_chat_blob(key.shared_key, blob)
                payload = crypto.parse_secret_chat_plaintext(plaintext)
            except MtprotoCryptoError:
                stats.add_undecryptable()
                continue
            stats.add_message()
            yield SecretChatMessage(
                src_addr=msg.src_addr,
                src_port=msg.src_port,
                dst_addr=msg.dst_addr,
                dst_port=msg.dst_port,
                ss_family=msg.ss_family,
                direction=msg.direction,
                message=payload,
                chat_id=key.chat_id,
                key_fingerprint_hex=fp.hex(),
                origin="decrypted",
                msg_key_hex=_blob_msg_key_hex(blob),
                timestamp=getattr(msg, "timestamp", 0.0) or 0.0,
                peer_user_id=getattr(key, "peer_user_id", 0) or 0,
            )


def _blob_msg_key_hex(blob: bytes) -> str:
    """Hex of an E2E blob's 16-byte msg_key (after the 8-byte fingerprint)."""
    return blob[crypto.E2E_FINGERPRINT_LEN:crypto.E2E_HEADER_LEN].hex()


def iter_decrypted_secret_chats(
    pcap_path: str,
    auth_keymap: Dict[bytes, object],
    secret_keymap: Dict[bytes, MtprotoSecretChatKey],
    *,
    server_ports: Tuple[int, ...] = (443, 80, 5222),
    stats: Optional[SecretChatStats] = None,
    tstats: Optional[object] = None,
) -> Iterator[SecretChatMessage]:
    """pcap -> transport messages -> decrypted secret-chat messages.

    ``tstats`` collects transport-level counters; ``stats`` the secret-chat ones.
    """
    from ..decrypt import iter_decrypted_messages

    transport_messages = iter_decrypted_messages(
        pcap_path, auth_keymap, server_ports=server_ports, stats=tstats
    )
    yield from iter_secret_chat_messages(transport_messages, secret_keymap, stats=stats)
