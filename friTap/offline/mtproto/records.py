"""Dataclasses for offline MTProto decryption results and run statistics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

#: Distinct unknown auth_key_ids remembered per run. The ids are read from the
#: wire (8 attacker-chosen bytes per record), so the set must not grow without
#: bound; records naming further ids only bump ``unknown_key_ids_overflow``.
MAX_UNKNOWN_KEY_IDS = 256


@dataclass
class DecryptedMessage:
    """One successfully decrypted MTProto record (its TL payload)."""

    src_addr: str
    src_port: int
    dst_addr: str
    dst_port: int
    ss_family: str  # "AF_INET" | "AF_INET6"
    direction: str  # "read" (server->client) | "write" (client->server)
    message: bytes  # the TL-serialized payload
    dc_id: int
    transport: str  # "abridged" | "intermediate" | ...
    obfuscated: bool
    auth_key_id_hex: str
    # Envelope msg_id (unique per auth key + direction); 0 = unknown. Dedup key.
    msg_id: int = 0
    # Capture timestamp of the carrying packet (epoch seconds); 0.0 = unknown.
    timestamp: float = 0.0
    # Remaining envelope fields (forensic); defaults mean unknown.
    salt: bytes = b""
    session_id: bytes = b""
    seq_no: int = 0
    msg_len: int = 0
    padding_len: int = 0
    # Length of the outer transport frame (auth_key_id + msg_key + ciphertext).
    frame_len: int = 0


@dataclass
class MtprotoStats:
    """Counters for one ``iter_decrypted_messages`` run.

    ``records_undecryptable`` is the read-only sum of three buckets:

      * ``records_malformed``: frame shorter than the 8-byte auth_key_id.
      * ``records_unknown_key``: auth_key_id not in the keymap. Recoverable: the
        id is cleartext, so it can seed a key hunt
        (``mtproto_secret_scan.py --known-auth-key-id <id>``); kept in
        ``unknown_key_ids``.
      * ``records_crypto_failed``: key in hand but msg_key/padding failed.
    """

    streams: int = 0
    messages: int = 0
    # Streams missing the 64-byte obfuscation init. ``streams_degraded`` counts
    # only those with MTProto evidence (decrypt._has_mtproto_evidence); foreign
    # traffic goes to ``streams_degraded_non_mtproto``. The TUI reads the former.
    streams_degraded: int = 0
    streams_degraded_non_mtproto: int = 0
    # Valid init but a later gap: the pre-gap records are decrypted.
    streams_partial: int = 0
    # Contiguous client run never reached the 64-byte init (start gap or too little data).
    streams_short: int = 0
    # Init captured but framing unsupported (padded-intermediate, full, Fake-TLS).
    streams_unsupported_framing: int = 0
    # Mid-stream obfuscation-key recovery (decrypt._process_recovered_stream):
    # init-less streams are retried with a de-obfuscation cipher seeded from
    # MTPROTO_OBF_KEY entries. Counters: keys loaded, streams recovered, streams
    # tried but unaligned, (stream, key) trials, trials with no alignment.
    obf_keys_loaded: int = 0
    streams_recovered_via_obf: int = 0
    streams_degraded_unrecovered: int = 0
    obf_trials: int = 0
    obf_alignment_failed: int = 0
    records_malformed: int = 0
    records_unknown_key: int = 0
    records_crypto_failed: int = 0
    # hex auth_key_id -> record count (stray record vs whole unreadable session).
    unknown_key_ids: Dict[str, int] = field(default_factory=dict)
    # Records whose (new) auth_key_id did not fit in ``unknown_key_ids``.
    unknown_key_ids_overflow: int = 0

    def add_stream(self) -> None:
        self.streams += 1

    def add_message(self) -> None:
        self.messages += 1

    @property
    def records_undecryptable(self) -> int:
        """Records that did not open: the sum of the three failure buckets."""
        return (
            self.records_malformed
            + self.records_unknown_key
            + self.records_crypto_failed
        )

    def add_malformed_record(self) -> None:
        """A frame too short to even carry an auth_key_id."""
        self.records_malformed += 1

    def add_unknown_key(self, auth_key_id_hex: str) -> None:
        """A record naming an auth_key_id not in the keymap (recoverable)."""
        self.records_unknown_key += 1
        known = auth_key_id_hex in self.unknown_key_ids
        if not known and len(self.unknown_key_ids) >= MAX_UNKNOWN_KEY_IDS:
            self.unknown_key_ids_overflow += 1
            return
        self.unknown_key_ids[auth_key_id_hex] = (
            self.unknown_key_ids.get(auth_key_id_hex, 0) + 1
        )

    def add_crypto_failure(self) -> None:
        """The key was in hand and decryption still failed."""
        self.records_crypto_failed += 1

    def add_degraded(self) -> None:
        """A degraded (missing-init) stream with positive MTProto evidence."""
        self.streams_degraded += 1

    def add_degraded_non_mtproto(self) -> None:
        """A degraded stream not tied to MTProto (foreign/empty/handshake-only)."""
        self.streams_degraded_non_mtproto += 1

    def add_partial(self) -> None:
        """A stream whose valid init allowed decrypting only the pre-gap records."""
        self.streams_partial += 1

    def add_short_stream(self) -> None:
        """A short/lossy stream whose client run never reached the 64-byte init."""
        self.streams_short += 1

    def add_unsupported_framing(self) -> None:
        """A stream with a valid init but a known-but-unsupported transport framing."""
        self.streams_unsupported_framing += 1

    def set_obf_keys_loaded(self, count: int) -> None:
        """Record how many MTPROTO_OBF_KEY entries were supplied for recovery."""
        self.obf_keys_loaded = count

    def add_recovered_stream(self) -> None:
        """A degraded stream re-obfuscated from recovered live CTR state and decrypted."""
        self.streams_recovered_via_obf += 1

    def add_degraded_unrecovered(self) -> None:
        """A degraded stream recovery was attempted on, but no obf key aligned."""
        self.streams_degraded_unrecovered += 1

    def add_obf_trial(self, *, aligned: bool) -> None:
        """One (stream, obf key) alignment attempt; ``aligned`` False bumps the miss count."""
        self.obf_trials += 1
        if not aligned:
            self.obf_alignment_failed += 1
