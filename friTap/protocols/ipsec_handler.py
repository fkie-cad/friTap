#!/usr/bin/env python3

"""IPsec (IKEv2 / ESP) protocol handler.

friTap hooks strongSwan to recover IKE_SA and CHILD_SA (ESP) key material and
writes it as the two Wireshark UAT decryption tables, ``ikev2_decryption_table``
and ``esp_sa``. The row formats and the algorithm-name maps below are copied
verbatim from strongSwan's own ``save-keys`` plugin
(``save_keys_listener.c``) — that file is the ground truth tshark consumes, so
the exact Wireshark strings must match byte-for-byte.

Unlike the TLS/SSH formatters this one does NOT emit NSS keylog lines: it emits
CSV rows for two separate files. The output factory therefore wires it to the
dedicated :class:`~friTap.output.ipsec_decryption_tables.IPsecDecryptionTableHandler`
instead of the generic :class:`~friTap.output.keylog_handler.KeylogOutputHandler`;
the ``writes_decryption_tables`` marker on the formatter selects that path.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ..backends.base import BackendName
from ..output.keylog_format import (
    KeylogFormatter,
    is_hex_field,
    warn_dropped_keylog_line,
)
from .base import BackendSupport, ProtocolHandler

IPSEC_LIBRARY_PATTERNS = [
    "libcharon", "libstrongswan", "charon", "strongswan",
]

# Wireshark UAT file names (Wireshark's canonical names; must not change).
IKEV2_TABLE = "ikev2_decryption_table"
ESP_TABLE = "esp_sa"

# ---------------------------------------------------------------------------
# IANA transform ids (mirror strongSwan's ENCR_*/AUTH_* enum values, which use
# the IANA IKEv2 transform numbers directly). AUTH_UNDEFINED is strongSwan's
# internal "no integrity" marker used for AEAD ciphers.
# ---------------------------------------------------------------------------
ENCR_AES_GCM_ICV8 = 18
ENCR_AES_GCM_ICV12 = 19
ENCR_AES_GCM_ICV16 = 20
AUTH_UNDEFINED = 1024

# Encryption transform ids whose ESP/IKE mode is AEAD (no separate integrity
# transform): AES-CCM (14/15/16), AES-GCM (18/19/20), ChaCha20-Poly1305 (28).
_AEAD_ENC_ALGS = frozenset({14, 15, 16, 18, 19, 20, 28})

# Per-GCM-variant ESP ICV length (bits) for the AUTH_UNDEFINED lookup — the
# ``esp_names`` switch in save_keys_listener.c (GCM_ICV8->64, 12->96, 16->128).
_GCM_ICV_BITS = {ENCR_AES_GCM_ICV8: 64, ENCR_AES_GCM_ICV12: 96, ENCR_AES_GCM_ICV16: 128}


# ---------------------------------------------------------------------------
# Algorithm-name maps — copied VERBATIM from save_keys_listener.c. Each entry
# is ``(alg_id, key_len_bits, wireshark_name)``; ``key_len_bits == -1`` matches
# any key length (see :func:`_algo_name`, mirroring the plugin's ``algo_name``).
# ---------------------------------------------------------------------------
_IKE_ENCR: Tuple[Tuple[int, int, str], ...] = (
    (3,   -1, "3DES [RFC2451]"),
    (11,  -1, "NULL [RFC2410]"),
    (12, 128, "AES-CBC-128 [RFC3602]"),
    (12, 192, "AES-CBC-192 [RFC3602]"),
    (12, 256, "AES-CBC-256 [RFC3602]"),
    (13, 128, "AES-CTR-128 [RFC5930]"),
    (13, 192, "AES-CTR-192 [RFC5930]"),
    (13, 256, "AES-CTR-256 [RFC5930]"),
    (18, 128, "AES-GCM-128 with 8 octet ICV [RFC5282]"),
    (18, 192, "AES-GCM-192 with 8 octet ICV [RFC5282]"),
    (18, 256, "AES-GCM-256 with 8 octet ICV [RFC5282]"),
    (19, 128, "AES-GCM-128 with 12 octet ICV [RFC5282]"),
    (19, 192, "AES-GCM-192 with 12 octet ICV [RFC5282]"),
    (19, 256, "AES-GCM-256 with 12 octet ICV [RFC5282]"),
    (20, 128, "AES-GCM-128 with 16 octet ICV [RFC5282]"),
    (20, 192, "AES-GCM-192 with 16 octet ICV [RFC5282]"),
    (20, 256, "AES-GCM-256 with 16 octet ICV [RFC5282]"),
    (14, 128, "AES-CCM-128 with 8 octet ICV [RFC5282]"),
    (14, 192, "AES-CCM-192 with 8 octet ICV [RFC5282]"),
    (14, 256, "AES-CCM-256 with 8 octet ICV [RFC5282]"),
    (15, 128, "AES-CCM-128 with 12 octet ICV [RFC5282]"),
    (15, 192, "AES-CCM-192 with 12 octet ICV [RFC5282]"),
    (15, 256, "AES-CCM-256 with 12 octet ICV [RFC5282]"),
    (16, 128, "AES-CCM-128 with 16 octet ICV [RFC5282]"),
    (16, 192, "AES-CCM-192 with 16 octet ICV [RFC5282]"),
    (16, 256, "AES-CCM-256 with 16 octet ICV [RFC5282]"),
)

_IKE_INTEG: Tuple[Tuple[int, int, str], ...] = (
    (1,    -1, "HMAC_MD5_96 [RFC2403]"),
    (2,    -1, "HMAC_SHA1_96 [RFC2404]"),
    (6,    -1, "HMAC_MD5_128 [RFC4595]"),
    (7,    -1, "HMAC_SHA1_160 [RFC4595]"),
    (12,   -1, "HMAC_SHA2_256_128 [RFC4868]"),
    (13,   -1, "HMAC_SHA2_384_192 [RFC4868]"),
    (14,   -1, "HMAC_SHA2_512_256 [RFC4868]"),
    (1026, -1, "HMAC_SHA2_256_96 [draft-ietf-ipsec-ciph-sha-256-00]"),
    (AUTH_UNDEFINED, -1, "NONE [RFC4306]"),
)

_ESP_ENCR: Tuple[Tuple[int, int, str], ...] = (
    (11, -1, "NULL"),
    (3,  -1, "TripleDes-CBC [RFC2451]"),
    (12, -1, "AES-CBC [RFC3602]"),
    (13, -1, "AES-CTR [RFC3686]"),
    (2,  -1, "DES-CBC [RFC2405]"),
    (6,  -1, "CAST5-CBC [RFC2144]"),
    (7,  -1, "BLOWFISH-CBC [RFC2451]"),
    (1027, -1, "TWOFISH-CBC"),
    (18, -1, "AES-GCM [RFC4106]"),
    (19, -1, "AES-GCM [RFC4106]"),
    (20, -1, "AES-GCM [RFC4106]"),
)

_ESP_INTEG: Tuple[Tuple[int, int, str], ...] = (
    (2,    -1, "HMAC-SHA-1-96 [RFC2404]"),
    (1,    -1, "HMAC-MD5-96 [RFC2403]"),
    (12,   -1, "HMAC-SHA-256-128 [RFC4868]"),
    (13,   -1, "HMAC-SHA-384-192 [RFC4868]"),
    (14,   -1, "HMAC-SHA-512-256 [RFC4868]"),
    (1026, -1, "HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00]"),
    (1027, -1, "ANY 256 bit authentication [no checking]"),
    (AUTH_UNDEFINED, 64,  "ANY 64 bit authentication [no checking]"),
    (AUTH_UNDEFINED, 96,  "ANY 96 bit authentication [no checking]"),
    (AUTH_UNDEFINED, 128, "ANY 128 bit authentication [no checking]"),
    (AUTH_UNDEFINED, 192, "ANY 192 bit authentication [no checking]"),
    (AUTH_UNDEFINED, 256, "ANY 256 bit authentication [no checking]"),
    (AUTH_UNDEFINED, -1,  "NULL"),
)

# A src/dst endpoint value: ``*`` (wildcard) or an IPv4/IPv6 literal. No commas,
# quotes or control characters so an agent-supplied value can never break out of
# its CSV cell or inject a second row.
_ENDPOINT_RE = re.compile(r"\*|[0-9A-Fa-f:.]{1,45}")


def _algo_name(table: Tuple[Tuple[int, int, str], ...],
               alg: Optional[int], key_len: int) -> Optional[str]:
    """Wireshark name for *alg*/*key_len*, or ``None`` (mirrors ``algo_name``).

    Iterates the table in order and returns the first entry whose id matches and
    whose key length is wildcard (``-1``) or equal to *key_len*.
    """
    if alg is None:
        return None
    for entry_alg, entry_len, name in table:
        if entry_alg == alg and (entry_len == -1 or entry_len == key_len):
            return name
    return None


def ike_names(enc_alg: Optional[int], enc_key_len_bits: int,
              int_alg: Optional[int]) -> Tuple[Optional[str], Optional[str]]:
    """(encryption name, integrity name) for an IKE_SA — mirrors ``ike_names``.

    For an AEAD cipher the integrity transform is forced to ``AUTH_UNDEFINED``
    (rendered as ``"NONE [RFC4306]"``), exactly like the save_keys plugin.
    """
    enc = _algo_name(_IKE_ENCR, enc_alg, enc_key_len_bits)
    if enc_alg in _AEAD_ENC_ALGS:
        int_alg = AUTH_UNDEFINED
    integ = _algo_name(_IKE_INTEG, int_alg, -1)
    return enc, integ


def esp_names(enc_alg: Optional[int], int_alg: Optional[int]
              ) -> Tuple[Optional[str], Optional[str]]:
    """(encryption name, integrity name) for a CHILD_SA — mirrors ``esp_names``.

    When there is no separate integrity transform (AEAD cipher, i.e. *int_alg*
    is absent / ``0`` / ``AUTH_UNDEFINED``) the integrity name comes from the
    AUTH_UNDEFINED rows keyed by the derived ICV length (GCM-8/12/16 ->
    64/96/128 bit), and any other AEAD falls through to ``"NULL"``.
    """
    enc = _algo_name(_ESP_ENCR, enc_alg, -1)
    if int_alg in (None, 0, AUTH_UNDEFINED):
        # AEAD cipher (GCM/CCM): there is no separate integrity transform.
        # strongSwan's save_keys plugin writes "ANY <N> bit authentication
        # [no checking]" here, but current Wireshark (confirmed 4.2.2) REFUSES
        # such an esp_sa row for AES-GCM/CCM — it errors "AES-GCM encryption can
        # only be used with NULL authentication" and decrypts nothing. Emit the
        # exact "NULL" the dissector requires so the row actually decrypts; the
        # ICV length is implied by the GCM/CCM encryption transform itself.
        integ = "NULL"
    else:
        integ = _algo_name(_ESP_INTEG, int_alg, -1)
    return enc, integ


def _is_endpoint(value: str) -> bool:
    """True for a safe src/dst cell value (``*`` or an IP literal)."""
    return isinstance(value, str) and bool(_ENDPOINT_RE.fullmatch(value))


def _opt_int(value) -> Optional[int]:
    """Coerce an agent-supplied algorithm id to ``int``, or ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return None


class IPsecKeylogFormatter(KeylogFormatter):
    """Builds Wireshark UAT rows for IKEv2 / ESP from :class:`KeylogEvent`.

    This formatter produces CSV table rows, not NSS keylog lines, so it carries
    the ``writes_decryption_tables`` marker and :meth:`format` returns no lines.
    The output factory routes it to
    :class:`~friTap.output.ipsec_decryption_tables.IPsecDecryptionTableHandler`,
    which calls :meth:`format_rows` and appends each row to the matching file.

    Every field originates in an untrusted target process: SPIs/keys must be hex
    and endpoints must be ``*`` or an IP literal, else the whole row is dropped
    with a once-per-reason warning (no partial/forged row is ever written).
    """

    #: Marks this formatter as writing Wireshark UAT files (two CSV tables),
    #: not NSS keylog lines — the factory wires it to the dedicated UAT handler.
    writes_decryption_tables: bool = True

    @property
    def protocol(self) -> str:
        return "ipsec"

    def format(self, event) -> List[str]:  # noqa: D401 - no keylog lines
        """IPsec emits UAT table rows, not keylog lines (see :meth:`format_rows`)."""
        return []

    def format_rows(self, event) -> List[Tuple[str, str]]:
        """Return ``[(table_file_name, csv_row), ...]`` for *event*.

        One row per event in practice; an empty list when the record is missing
        or malformed.
        """
        payload = event.payload or {}
        record = payload.get("record")
        if record == "ike":
            return self._ike_rows(payload)
        if record == "esp":
            return self._esp_rows(payload)
        return []

    def _ike_rows(self, payload: dict) -> List[Tuple[str, str]]:
        spi_i = str(payload.get("spi_i", ""))
        spi_r = str(payload.get("spi_r", ""))
        sk_ei = str(payload.get("sk_ei", ""))
        sk_er = str(payload.get("sk_er", ""))
        sk_ai = str(payload.get("sk_ai", ""))
        sk_ar = str(payload.get("sk_ar", ""))
        enc, integ = ike_names(
            _opt_int(payload.get("enc_alg")),
            _opt_int(payload.get("enc_key_len_bits")) or -1,
            _opt_int(payload.get("int_alg")),
        )
        if enc is None or integ is None:
            warn_dropped_keylog_line("ipsec ike", "unknown enc/integ algorithm")
            return []
        if not all(is_hex_field(v) for v in (spi_i, spi_r, sk_ei, sk_er, sk_ai, sk_ar)):
            warn_dropped_keylog_line("ipsec ike", "spi and keys must be hex")
            return []
        row = (f'{spi_i},{spi_r},{sk_ei},{sk_er},"{enc}",'
               f'{sk_ai},{sk_ar},"{integ}"')
        return [(IKEV2_TABLE, row)]

    def _esp_rows(self, payload: dict) -> List[Tuple[str, str]]:
        spi = str(payload.get("spi", ""))
        src = str(payload.get("src", "*"))
        dst = str(payload.get("dst", "*"))
        family = str(payload.get("family", "IPv4"))
        enc_key = str(payload.get("enc_key", ""))
        int_key = str(payload.get("int_key", ""))
        enc, integ = esp_names(
            _opt_int(payload.get("enc_alg")),
            _opt_int(payload.get("int_alg")),
        )
        if enc is None or integ is None:
            warn_dropped_keylog_line("ipsec esp", "unknown enc/integ algorithm")
            return []
        if family not in ("IPv4", "IPv6") or not _is_endpoint(src) or not _is_endpoint(dst):
            warn_dropped_keylog_line("ipsec esp", "invalid family/endpoint")
            return []
        # enc_key is always present; the ESP integrity key is empty for AEAD
        # ciphers (rendered as a bare "0x", matching save_keys' %+B on an empty
        # chunk). A non-empty int_key must be valid hex.
        if not is_hex_field(spi) or not is_hex_field(enc_key) \
                or (int_key and not is_hex_field(int_key)):
            warn_dropped_keylog_line("ipsec esp", "spi and keys must be hex")
            return []
        row = (f'"{family}","{src}","{dst}","0x{spi}","{enc}",'
               f'"0x{enc_key}","{integ}","0x{int_key}"')
        return [(ESP_TABLE, row)]


class IPSecHandler(ProtocolHandler):
    """Handler for IPsec (IKEv2 / ESP) key material from strongSwan."""

    library_patterns = IPSEC_LIBRARY_PATTERNS

    @property
    def name(self) -> str:
        return "ipsec"

    @property
    def display_name(self) -> str:
        return "IPsec"

    @property
    def description(self) -> str:
        return "IKEv2 / ESP key extraction (strongSwan) for Wireshark"

    def get_keylog_format(self) -> str:
        return "Wireshark IPsec decryption tables (ikev2_decryption_table, esp_sa)"

    def get_wireshark_protocol_preference(self) -> str:
        return "isakmp.decryption_table"  # Wireshark IKEv2 decryption UAT

    def get_display_filter_template(self) -> str:
        return "ip.addr == {src} && ip.addr == {dst} && (isakmp || esp)"

    def keylog_formatter(self) -> Optional[KeylogFormatter]:
        return IPsecKeylogFormatter()

    @property
    def supported_backends(self) -> dict[str, str]:
        return {
            BackendName.FRIDA: BackendSupport.FULL,
        }
