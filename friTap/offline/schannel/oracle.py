"""In-Python trial-decryption oracle for the Schannel correlator (PUBLIC).

The correlator joins secrets to connections by trial decryption, one tshark pass
per trial (:mod:`.correlate`). This oracle answers the easy cases in pure Python
so tshark runs only on the rest; anything it is unsure about is ``None`` ("ask
tshark"). It answers True/False only for a clean stream it fully understands:

  * exactly one captured conversation carries that client random,
  * its ClientHello is record 0 of one direction and a real (non-HRR) ServerHello
    is in the other,
  * neither direction is degraded (no start/mid gap),
  * the negotiated suite is one it can decrypt, and
  * (TLS 1.3) its anchor search is conclusive: the secret decrypts a record at seq
    0 within the first 32 encrypted records, or the search covered every place the
    label's anchor can sit (:meth:`_anchor_window`).

Any internal error (malformed record, e.g. ChaCha20 on an OpenSSL without it)
also gives ``None``, so a failure is never confidently wrong. Version comes from
the ServerHello (``supported_versions``, else legacy_version): a TLS 1.3
connection answers ``False`` for a TLS 1.2 master (tshark ignores ``CLIENT_RANDOM``
lines for 1.3), a TLS 1.2 one ``False`` for TLS 1.3 labels, TLS 1.0/1.1 ``None``.

``FRITAP_SCHANNEL_ORACLE=0`` disables it (``from_pcap`` returns ``None``).
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional, Tuple

from ..tls import records as rec
from ..tls import tls12
from ..tls.records import CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE
from ..tls.stream import iter_app_data_records
from ..tls.tls13 import (
    SUITE_BY_ID,
    inner_content_type,
    next_traffic_secret,
    suites_for_secret,
    try_decrypt,
)

logger = logging.getLogger(__name__)

ORACLE_ENV = "FRITAP_SCHANNEL_ORACLE"

_HS_ENCRYPTED_EXTENSIONS = 8     # SERVER_HANDSHAKE_TRAFFIC_SECRET anchor
_HS_FINISHED = 20                # CLIENT_HANDSHAKE_TRAFFIC_SECRET anchor
_HS_KEY_UPDATE = 24              # TLS 1.3 post-handshake KeyUpdate

_V_TLS10, _V_TLS11, _V_TLS12, _V_TLS13 = 0x0301, 0x0302, 0x0303, 0x0304

# TLS 1.3 clean-stream bound: a correct secret anchors at the first encrypted record or the first app-data record after the handshake, so 32 is generous. A miss is conclusive only if the window covered every place the anchor can sit (TrialOracle._anchor_window), else ``None``.
_MAX_ANCHOR_RECORDS = 32

# Subsets of the keylog labels on purpose: only those this oracle can confirm by decryption, and the direction each lives on.
_SERVER_LABELS = ("SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0")
_CLIENT_LABELS = ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0")
_HANDSHAKE_LABELS = ("SERVER_HANDSHAKE_TRAFFIC_SECRET",
                     "CLIENT_HANDSHAKE_TRAFFIC_SECRET")


Record = Tuple[int, bytes, bytes]  # (content_type, header5, fragment)


class _Stream:
    """One analyzed, clean TLS conversation, indexed by its client random."""

    __slots__ = ("client_records", "server_records", "client_random",
                 "server_hello", "version", "offered_early_data")

    def __init__(self, client_records: List[Record], server_records: List[Record],
                 client_random: str, server_hello: rec.ServerHelloInfo,
                 offered_early_data: Optional[bool] = None):
        self.client_records = client_records
        self.server_records = server_records
        self.client_random = client_random
        self.server_hello = server_hello
        self.version = server_hello.version
        # ``None`` = unknown (ClientHello split across records). Early-data
        # records precede the client handshake secret's first record.
        self.offered_early_data = offered_early_data


def _direction_records(reassembler) -> List[Record]:
    """Parse one direction's contiguous reassembled bytes into TLS records."""
    try:
        data = reassembler.contiguous_bytes()
    except Exception:  # noqa: BLE001 - a malformed stream is simply not analyzable
        return []
    return rec.parse_records(data)


def _handshake_bytes_before_ccs(records: List[Record]) -> bytes:
    """Concatenate handshake-record fragments up to the first CCS (TLS 1.2 coalesces and may split hello messages across records)."""
    out = bytearray()
    for ctype, _hdr, frag in records:
        if ctype == CT_CHANGE_CIPHER_SPEC:
            break
        if ctype == CT_HANDSHAKE:
            out += frag
    return bytes(out)


def _first_record_after_ccs(records: List[Record]) -> Optional[Record]:
    """The record immediately following the first ChangeCipherSpec, or ``None``."""
    for i, (ctype, _hdr, _frag) in enumerate(records):
        if ctype == CT_CHANGE_CIPHER_SPEC and i + 1 < len(records):
            return records[i + 1]
    return None


def _analyze_pair(pair) -> Optional[_Stream]:
    """A :class:`_Stream` for a clean conversation (record 0 a ClientHello, a real non-HRR ServerHello in the other direction, neither degraded), else ``None``."""
    if pair.client.degraded or pair.server.degraded:
        return None
    client_records = _direction_records(pair.client)
    server_records = _direction_records(pair.server)
    if not client_records or not server_records:
        return None
    c0_type, _c0_hdr, c0_frag = client_records[0]
    if c0_type != CT_HANDSHAKE:
        return None
    client_random = rec.client_random_from_clienthello(c0_frag)
    if client_random is None:
        return None
    sh = rec.server_hello_info(_handshake_bytes_before_ccs(server_records))
    if sh is None or sh.is_hrr:
        return None
    extensions = rec.client_hello_extensions(c0_frag)
    offered_early_data = (None if extensions is None
                          else rec.EXT_EARLY_DATA in extensions)
    return _Stream(client_records, server_records, client_random, sh,
                   offered_early_data)


class TrialOracle:
    """Answers "does this secret belong to this client random?" in pure Python."""

    def __init__(self, streams_by_cr: Dict[str, List[_Stream]]):
        self._by_cr = streams_by_cr

    @classmethod
    def from_pcap(cls, pcap: str) -> Optional["TrialOracle"]:
        """Build an oracle from *pcap*, or ``None`` (tshark does everything) when :data:`ORACLE_ENV` disables it, ``cryptography`` is missing, or parsing fails."""
        if os.environ.get(ORACLE_ENV, "1") == "0":
            return None
        try:
            from ..tls.backend import backend_available
            if not backend_available():
                return None
            from ..net.tcp_reassembly import reassemble_pcap
            pairs = reassemble_pcap(pcap)
        except Exception:  # noqa: BLE001 - no oracle is always a safe fallback
            logger.debug("Schannel oracle: pcap parse failed; using tshark only",
                         exc_info=True)
            return None
        by_cr: Dict[str, List[_Stream]] = {}
        for pair in pairs.values():
            try:
                stream = _analyze_pair(pair)
            except Exception:  # noqa: BLE001
                continue
            if stream is not None:
                by_cr.setdefault(stream.client_random, []).append(stream)
        return cls(by_cr)

    def _clean_stream(self, cr: str) -> Optional[_Stream]:
        """The single clean stream for *cr*, or ``None`` when absent/duplicated."""
        streams = self._by_cr.get(cr)
        if streams is None or len(streams) != 1:
            return None
        return streams[0]

    def tls12_match(self, cr: str, master: str) -> Optional[bool]:
        """Does *master* decrypt the connection with client random *cr*?

        Mirrors tshark's ``tls.handshake.type==20``: the first record after each side's
        ChangeCipherSpec is decrypted at seq 0; a match in either direction means yes. The
        key block is derived once for both. A direction the peel cannot judge (backend
        error) makes a "no" inconclusive: ``None``.
"""
        stream = self._clean_stream(cr)
        if stream is None:
            return None
        if stream.version in (_V_TLS10, _V_TLS11):
            return None
        if stream.version == _V_TLS13:
            return False  # tshark ignores CLIENT_RANDOM masters for a 1.3 connection
        suite_id = stream.server_hello.cipher_suite
        is_aead = tls12.suite_supported(suite_id)
        is_cbc = tls12.cbc_suite_supported(suite_id)
        if not (is_aead or is_cbc):
            return None
        try:
            master_b = bytes.fromhex(master)
            cr_b = bytes.fromhex(cr)
        except ValueError:
            return None
        server_random = stream.server_hello.random
        uses_etm = stream.server_hello.uses_etm
        # AEAD derives the key block once for both directions; CBC derives its
        # own (different-layout) block inside finished_decrypts.
        try:
            keys = (tls12.key_block(master_b, server_random, cr_b,
                                    tls12.AEAD_SUITES[suite_id])
                    if is_aead else None)
        except Exception:  # noqa: BLE001 - cannot tell, ask tshark
            return None
        verdict: Optional[bool] = False
        for records, from_client in ((stream.client_records, True),
                                     (stream.server_records, False)):
            after = _first_record_after_ccs(records)
            if after is None:
                continue
            ctype, hdr, frag = after
            hit = tls12.finished_decrypts(master_b, cr_b, server_random, suite_id,
                                          ctype, hdr[1:3], frag,
                                          from_client=from_client, keys=keys,
                                          uses_etm=uses_etm)
            if hit:
                return True
            if hit is None:
                verdict = None
        return verdict

    def tls13_probe(self, cr: str, label: str, secret: str) -> Optional[bool]:
        """Does *secret*, tried under *label*, decrypt the *cr* connection?

        True/False for a clean TLS 1.3 stream with a known suite and matching secret
        length; ``None`` otherwise (including an inconclusive anchor search or an error).
"""
        stream = self._clean_stream(cr)
        if stream is None:
            return None
        if stream.version in (_V_TLS10, _V_TLS11):
            return None
        if stream.version == _V_TLS12:
            return False  # a 1.2 connection never carries TLS 1.3 traffic secrets
        suite = SUITE_BY_ID.get(stream.server_hello.cipher_suite)
        if suite is None:
            return None
        try:
            secret_b = bytes.fromhex(secret)
        except ValueError:
            return None
        # A secret whose length does not match the suite's hash can never be this
        # connection's traffic secret — a definitive no.
        if suite not in suites_for_secret(secret_b):
            return False
        if label in _SERVER_LABELS:
            records = stream.server_records
        elif label in _CLIENT_LABELS:
            records = stream.client_records
        else:
            return None  # EXPORTER_SECRET / unknown: placed by elimination, not here
        try:
            return self._shows_label_evidence(records, secret_b, suite, label,
                                              self._anchor_window(stream, label))
        except Exception:  # noqa: BLE001 - e.g. AEAD unsupported: ask tshark
            logger.debug("Schannel oracle: TLS 1.3 probe failed; asking tshark",
                         exc_info=True)
            return None

    @staticmethod
    def _anchor_window(stream: _Stream, label: str) -> int:
        """How many leading encrypted records can hold *label*'s anchor.

        Nothing encrypted precedes EncryptedExtensions, so a server handshake secret's
        anchor is record 0, likewise the client Finished flight unless the ClientHello
        offered 0-RTT; searching that one record is exhaustive. Traffic secrets follow a
        flight of unknown length, so they get :data:`_MAX_ANCHOR_RECORDS`.
"""
        if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET":
            return 1
        if (label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
                and stream.offered_early_data is False):
            return 1
        return _MAX_ANCHOR_RECORDS

    @staticmethod
    def _encrypted_records(records: List[Record]) -> List[Tuple[bytes, bytes]]:
        """The ``(header5, fragment)`` of the decryptable application_data records."""
        return [(hdr, frag) for _ctype, hdr, frag in iter_app_data_records(records)]

    @classmethod
    def _shows_label_evidence(cls, records: List[Record], secret: bytes,
                              suite: str, label: str,
                              window: int = _MAX_ANCHOR_RECORDS) -> Optional[bool]:
        """Does decrypting *records* under (*secret*, *suite*) show *label*'s evidence?

        Evidence: EncryptedExtensions (8) for SHTS, client Finished (20) for CHTS, an
        inner application_data record (23) for the traffic secrets. No anchor in the
        first *window* records is a definite ``False`` only when the window covered every
        place the anchor can sit; otherwise ``None``.
"""
        encrypted = cls._encrypted_records(records)
        anchor = cls._find_anchor(encrypted[:window], secret, suite)
        if anchor is None:
            exhaustive = window < _MAX_ANCHOR_RECORDS or len(encrypted) <= window
            return False if exhaustive else None
        return cls._scan_from_anchor(encrypted, anchor, secret, suite,
                                     label in _HANDSHAKE_LABELS, label)

    @staticmethod
    def _find_anchor(encrypted: List[Tuple[bytes, bytes]], secret: bytes,
                     suite: str) -> Optional[int]:
        """Index of the first record of *encrypted* that decrypts at seq 0."""
        for i, (hdr, frag) in enumerate(encrypted):
            pt = try_decrypt(secret, suite, 0, hdr, frag)
            if pt is not None and inner_content_type(pt) is not None:
                return i
        return None

    @classmethod
    def _scan_from_anchor(cls, encrypted: List[Tuple[bytes, bytes]], anchor: int,
                          secret: bytes, suite: str, want_handshake: bool,
                          label: str) -> bool:
        """Decrypt sequentially from *anchor* (seq advances even on failure, as :func:`decrypt_stream`) and look for the label's signal.

        Each complete handshake message is acted on once: a KeyUpdate rolls the secret and resets the seq a single time."""
        target = (_HS_ENCRYPTED_EXTENSIONS
                  if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" else _HS_FINISHED)
        cur = secret
        seq = 0
        handshake = bytearray()
        seen_messages = 0
        for hdr, frag in encrypted[anchor:]:
            pt = try_decrypt(cur, suite, seq, hdr, frag)
            seq += 1
            if pt is None:
                continue
            ctype = inner_content_type(pt)
            if ctype == CT_APPLICATION_DATA:
                if not want_handshake:
                    return True
            elif ctype == CT_HANDSHAKE:
                # Inner plaintext is handshake_bytes || type || zeros; drop the
                # trailing zeros and the single content-type byte.
                handshake += pt.rstrip(b"\x00")[:-1]
                messages = rec.iter_handshake_messages(bytes(handshake))
                new_types = [t for t, _body in messages[seen_messages:]]
                seen_messages = len(messages)
                if want_handshake and target in new_types:
                    return True
                for _ in range(new_types.count(_HS_KEY_UPDATE)):
                    cur = next_traffic_secret(cur, suite)
                    seq = 0
        return False


__all__ = ["TrialOracle", "ORACLE_ENV"]
