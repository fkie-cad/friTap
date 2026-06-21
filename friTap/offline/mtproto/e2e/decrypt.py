"""Top-level orchestrator: transport messages -> decrypted secret-chat messages.

Secret-chat E2E blobs are TL-``bytes``-framed payloads embedded inside the
already-decrypted MTProto transport messages produced by
:func:`friTap.offline.mtproto.decrypt.iter_decrypted_messages`. This module scans
those transport messages for E2E blobs keyed by a known fingerprint, peels off
the second AES-IGE layer (:mod:`friTap.offline.mtproto.crypto`), and yields the
inner TL payloads. Deeper TL parsing is left to a downstream parser.

The crypto backend is imported lazily; a :class:`MtprotoDependencyError` from the
transport decryptor propagates so the parent offline driver can skip cleanly.
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

    Scans for any 8-byte window equal to a known fingerprint. At a candidate
    position ``p`` the immediately preceding TL ``bytes`` length is read (a single
    byte when ``< 254``, else the 0xFE + 3-byte-LE long form). The match is
    accepted only when the framed length describes a valid E2E blob
    (``>= header + one AES block``, block-aligned body, in bounds); the blob is
    then yielded and the scan resumes past it.
    """
    if not fingerprints:
        return
    fp_len = crypto.E2E_FINGERPRINT_LEN
    p = 0
    n = len(data)
    while p + fp_len <= n:
        fp = data[p : p + fp_len]
        if fp not in fingerprints:
            p += 1
            continue
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
    TL payload. An unknown fingerprint is ignored; a blob whose msg_key fails to
    verify (or whose framing is bad) counts as ``records_undecryptable``. The
    address/port/family/direction are copied from the carrying transport message.
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
            )


def iter_decrypted_secret_chats(
    pcap_path: str,
    auth_keymap: Dict[bytes, object],
    secret_keymap: Dict[bytes, MtprotoSecretChatKey],
    *,
    server_ports: Tuple[int, ...] = (443, 80, 5222),
    stats: Optional[SecretChatStats] = None,
    tstats: Optional[object] = None,
) -> Iterator[SecretChatMessage]:
    """Convenience: pcap -> transport messages -> decrypted secret-chat messages.

    Runs the transport decryptor (:func:`friTap.offline.mtproto.decrypt.\
iter_decrypted_messages`) over ``pcap_path`` with ``auth_keymap`` and pipes its
    output into :func:`iter_secret_chat_messages` keyed by ``secret_keymap``.
    ``tstats`` collects transport-level counters; ``stats`` the secret-chat ones.
    The transport decryptor is imported lazily.
    """
    from ..decrypt import iter_decrypted_messages

    transport_messages = iter_decrypted_messages(
        pcap_path, auth_keymap, server_ports=server_ports, stats=tstats
    )
    yield from iter_secret_chat_messages(transport_messages, secret_keymap, stats=stats)
