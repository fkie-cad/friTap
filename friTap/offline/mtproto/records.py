"""Dataclasses for offline MTProto decryption results and run statistics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


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
    # MTProto envelope msg_id (unique per auth key + direction); 0 = unknown.
    # Used by the offline emitter to skip a record already emitted.
    msg_id: int = 0
    # Capture timestamp of the carrying packet (epoch seconds); 0.0 = unknown.
    timestamp: float = 0.0
    # Remaining MTProto envelope fields (forensic per-packet metadata); the
    # defaults mean "unknown" so hand-built messages (tests, plugins) still work.
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

    ``records_undecryptable`` is the grand total, derived as the sum of the
    three buckets below. Those buckets split the total by *why* the record did
    not open, because only one of the three reasons is actionable:

      * ``records_malformed`` -- the frame was shorter than the 8-byte
        auth_key_id, so there is no id to report and nothing to recover.
      * ``records_unknown_key`` -- the record named an auth_key_id that is not in
        the keymap. **This is the recoverable one**: the id travels in the clear
        in the first 8 bytes of every record, so it can be fed straight back into
        a key hunt (``mtproto_secret_scan.py --known-auth-key-id <id>``) to go
        looking for the key we are missing. ``unknown_key_ids`` keeps those ids.
      * ``records_crypto_failed`` -- we HAD the key and decryption still failed
        (msg_key mismatch, bad padding). Reporting that id would be a dead end:
        the key is already in hand, so the fault is elsewhere.

    The three sum to the total by construction: the total is a read-only
    property over them, so there is no way to bump it without naming a reason.
    """

    streams: int = 0
    messages: int = 0
    # Degraded streams split by whether they are *evidently* MTProto. A stream
    # missing its 64-byte obfuscation init cannot be de-obfuscated here, but not
    # every such stream is Telegram: plain TCP captured mid-flow and TLS/handshake
    # -only connections also arrive init-less. ``streams_degraded`` therefore keeps
    # its original name but now counts ONLY degraded streams with positive MTProto
    # evidence (see decrypt._has_mtproto_evidence), so the number the user sees is
    # not inflated by foreign traffic. Non-evidently-MTProto degraded streams go to
    # ``streams_degraded_non_mtproto`` instead. (The TUI reads a helper that depends
    # on ``streams_degraded`` and its ``add_degraded()`` method — both kept.)
    streams_degraded: int = 0
    streams_degraded_non_mtproto: int = 0
    # A stream with a valid init block but a LATER gap: we decrypt the contiguous
    # records BEFORE the gap and count the stream here rather than discarding it.
    streams_partial: int = 0
    # A stream whose contiguous client run never even reached the 64-byte
    # obfuscation init block (a start gap swallowed the opening bytes, or the
    # connection carried too little client data). This is NOT "started
    # mid-connection" — the SYN was often seen — so it is counted here, under an
    # accurate label, instead of inflating ``streams_degraded`` (which the TUI/CLI
    # report as "started mid-connection").
    streams_short: int = 0
    # A stream that de-obfuscated to a KNOWN-but-unsupported transport framing
    # (e.g. padded-intermediate / full / Fake-TLS). The connection start WAS
    # captured; only the framing is not yet decodable — so it is its own reason,
    # kept out of the mid-connection ``streams_degraded`` figure.
    streams_unsupported_framing: int = 0
    # Workstream F — mid-stream obfuscation-key recovery. When MTPROTO_OBF_KEY
    # entries are supplied, an init-less stream that would otherwise be counted
    # ``streams_degraded`` is re-attempted by seeding the de-obfuscation cipher from
    # the recovered live CTR state (see decrypt._process_recovered_stream):
    #   * ``obf_keys_loaded``            how many MTPROTO_OBF_KEY entries are in hand.
    #   * ``streams_recovered_via_obf``  degraded streams re-obfuscated + decrypted.
    #   * ``streams_degraded_unrecovered`` degraded streams recovery was tried on but
    #                                    no key aligned (they still could not decrypt).
    #   * ``obf_trials``                 how many (stream, key) alignment attempts ran.
    #   * ``obf_alignment_failed``       how many of those attempts found no alignment.
    obf_keys_loaded: int = 0
    streams_recovered_via_obf: int = 0
    streams_degraded_unrecovered: int = 0
    obf_trials: int = 0
    obf_alignment_failed: int = 0
    records_malformed: int = 0
    records_unknown_key: int = 0
    records_crypto_failed: int = 0
    # hex auth_key_id -> how many records named it. A dict rather than a set
    # because the count is what tells a one-off stray record apart from a whole
    # session we cannot read, and that decides whether a key hunt is worth it.
    unknown_key_ids: Dict[str, int] = field(default_factory=dict)

    def add_stream(self) -> None:
        self.streams += 1

    def add_message(self) -> None:
        self.messages += 1

    @property
    def records_undecryptable(self) -> int:
        """How many records did not open, whatever the reason.

        Derived, not stored: every record that fails lands in exactly one of the
        three buckets, so the total is their sum and cannot drift away from them.
        """
        return (
            self.records_malformed
            + self.records_unknown_key
            + self.records_crypto_failed
        )

    def add_malformed_record(self) -> None:
        """A frame too short to even carry an auth_key_id."""
        self.records_malformed += 1

    def add_unknown_key(self, auth_key_id_hex: str) -> None:
        """A record naming an auth_key_id we do not hold -- the recoverable kind."""
        self.records_unknown_key += 1
        self.unknown_key_ids[auth_key_id_hex] = (
            self.unknown_key_ids.get(auth_key_id_hex, 0) + 1
        )

    def add_crypto_failure(self) -> None:
        """We had the key and decryption still failed -- a different bug entirely."""
        self.records_crypto_failed += 1

    def add_degraded(self) -> None:
        """A degraded (missing-init) stream WITH positive MTProto evidence."""
        self.streams_degraded += 1

    def add_degraded_non_mtproto(self) -> None:
        """A degraded stream we cannot tie to MTProto (foreign/empty/handshake-only).

        Kept separate so ``streams_degraded`` reflects real Telegram streams only.
        """
        self.streams_degraded_non_mtproto += 1

    def add_partial(self) -> None:
        """A stream whose valid init let us decrypt only the pre-gap record prefix."""
        self.streams_partial += 1

    def add_short_stream(self) -> None:
        """A stream whose contiguous client run never reached the 64-byte init.

        Distinct from ``add_degraded``: this is a short/lossy stream (start gap or
        too little client data), NOT a connection captured mid-flow, so it must not
        be reported as "started mid-connection".
        """
        self.streams_short += 1

    def add_unsupported_framing(self) -> None:
        """A stream with a valid init but a known-but-unsupported transport framing.

        Distinct from ``add_degraded``: the connection start was captured; only the
        framing (padded-intermediate / full / Fake-TLS) is not yet decodable.
        """
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
