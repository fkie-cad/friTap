#!/usr/bin/env python3

"""Schannel offline decryptor: correlate + derive NSS keylog + decrypt (PUBLIC).

The Schannel mem-scan engine recovers TLS secrets from lsass but cannot read the
ClientHello random (it is not memory-resident), so it writes them UNPAIRED to a
``.schannel.unpaired`` sidecar. This decryptor closes that gap OFFLINE:

  1. parse the sidecar (:mod:`.unpaired`),
  2. trial-decrypt each secret against the pcap to find its client_random
     (:mod:`.correlate`, TLS 1.2 AND 1.3), producing a STANDARD NSS keylog
     (``CLIENT_RANDOM``/``*_TRAFFIC_SECRET_0``/…),
  3. write that derived keylog next to the sidecar, and
  4. feed its lines that the primary ``--keylog`` does not already hold into the
     SAME TLS single-pass that the ``--keylog`` path uses, so the recovered TLS
     flows are decrypted and reconstructed exactly like any other — once (a
     session whose exact lines the primary keylog already carries is decrypted
     by the primary TLS pass, not a second time here).

INTEGRATION CHOICE — option (a): emit a standard NSS keylog and let the existing
TLS single-pass consume it, rather than (b) emitting ``DatalogEvent``s directly.
Producing a standard NSS keylog is the whole point of the correlation — it is what
makes the secrets Wireshark-/tshark-loadable — and reusing the TLS single pass
(the one-run ``run_tls_combined_pass``) means the decrypted Schannel flows get the
exact same TLS layer, SNI/cipher/ALPN metadata, direction tracking and
reconstruction as a normal ``--keylog`` capture, with no bespoke event plumbing
to keep in sync.

The entry registers ``requires_tls_strip=False`` (an INDEPENDENT emitter): it does
not consume tshark's already-decrypted bytes; it supplies its OWN derived keylog
and drives a fresh TLS pass over it. The derived keylog is written to disk in full
(a real, reusable artifact) at ``<sidecar-with-.unpaired-stripped>.nss.keylog``.
Secrets that could not be placed are counted (``undecryptable``) and summarized
in one warning.
"""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Iterable, List, Optional

from friTap.offline.registry import OfflineDecryptorEntry
from friTap.offline.schannel.unpaired import looks_like_unpaired
from friTap.offline.tls.keylog import parse_strict_nss_line

logger = logging.getLogger(__name__)


def _derived_keylog_path(sidecar_path: str) -> str:
    """Where the correlated NSS keylog is written (next to the sidecar).

    ``keys.memscan.schannel.unpaired`` -> ``keys.memscan.schannel.nss.keylog``.
    """
    if sidecar_path.endswith(".unpaired"):
        base = sidecar_path[: -len(".unpaired")]
    else:
        base = os.path.splitext(sidecar_path)[0]
    return base + ".nss.keylog"


def _schannel_offline_emitter(
    *, pcap_path, proto_keylog, tls_keylog_path, tshark_bin, tls_ports,
    bus, state, result,
) -> None:
    """Correlate the ``.schannel.unpaired`` sidecar and decrypt the paired TLS.

    Never raises for a recoverable problem (missing sidecar, no tshark match, empty
    correlation) — per the offline-emitter contract it logs and returns instead, so
    a capture that yields no Schannel pairing still converts cleanly.

    *proto_keylog* is the ``.schannel.unpaired`` sidecar path (``protocol_keylogs``
    maps ``--schannel-unpaired`` -> ``schannel``). *tls_keylog_path* is the primary
    TLS keylog (may be None): derived lines it already holds verbatim are left to
    the primary TLS pass, so passing both for the same sessions does not
    duplicate their flows.
    """
    from .correlate import correlate_unpaired_detailed
    from .unpaired import parse_unpaired, tls12_masters, tls13_groups, tls13_secrets

    try:
        with open(proto_keylog, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        logger.warning("Schannel unpaired sidecar %s unreadable; skipping", proto_keylog)
        return

    records = parse_unpaired(text)
    masters = tls12_masters(records)
    secrets13 = tls13_secrets(records)
    groups13 = tls13_groups(records)
    if not masters and not secrets13:
        logger.warning(
            "Schannel unpaired sidecar %s held no usable TLS 1.2/1.3 secrets; "
            "nothing to correlate", proto_keylog,
        )
        return

    try:
        correlation = correlate_unpaired_detailed(tshark_bin, pcap_path, masters,
                                                  secrets13, tls13_groups=groups13)
    except Exception:  # noqa: BLE001 - correlation must never abort the conversion
        logger.warning("Schannel offline correlation failed; skipping", exc_info=True)
        return
    lines = correlation.lines

    if not lines:
        logger.warning(
            "Schannel: none of %d master(s) / %d TLS 1.3 secret(s) paired to a "
            "client_random in %s (secrets may be from a different capture, or the "
            "connections carried no decryptable records)",
            len(masters), len(secrets13), os.path.basename(pcap_path),
        )
        result.record_protocol("schannel", messages=0,
                               streams=0, undecryptable=len(masters) + len(secrets13))
        return

    derived_keylog = _derived_keylog_path(proto_keylog)
    try:
        with open(derived_keylog, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
    except OSError:
        logger.warning("Could not write derived Schannel keylog %s; skipping",
                       derived_keylog, exc_info=True)
        return
    logger.info("Schannel: wrote %d correlated NSS keylog line(s) -> %s",
                len(lines), derived_keylog)
    _report_unplaced(correlation, result)

    new_lines = _lines_not_in_keylog(lines, tls_keylog_path)
    if not new_lines:
        logger.info("Schannel: every correlated line is already in %s; its TLS "
                    "pass decrypts those sessions", tls_keylog_path)
    elif len(new_lines) == len(lines):
        _decrypt_with_derived_keylog(
            pcap_path, derived_keylog, tshark_bin, tls_ports,
            bus=bus, state=state, result=result,
        )
    else:
        logger.info("Schannel: %d of %d correlated line(s) are already in %s; "
                    "decrypting with the other %d", len(lines) - len(new_lines),
                    len(lines), tls_keylog_path, len(new_lines))
        _decrypt_with_lines(pcap_path, new_lines, tshark_bin, tls_ports,
                            bus=bus, state=state, result=result)
    result.record_protocol("schannel", messages=len(lines))


def _report_unplaced(correlation, result) -> None:
    """Count the secrets correlation could not place and warn once about them."""
    unplaced = correlation.unplaced_masters + correlation.unplaced_tls13
    if not unplaced:
        return
    logger.warning(
        "Schannel: %d secret(s) could not be paired to a connection in the "
        "capture (%d TLS 1.2 master(s), %d TLS 1.3 secret(s)); they may belong "
        "to connections outside it (an EXPORTER_SECRET decrypts nothing and is "
        "placed only via the sidecar's group column)", unplaced,
        correlation.unplaced_masters, correlation.unplaced_tls13,
    )
    result.record_protocol("schannel", undecryptable=unplaced)


def _nss_line_key(line: str) -> Optional[tuple]:
    """``(LABEL, client_random, secret)`` of an NSS line, case-normalized."""
    entry = parse_strict_nss_line(line)
    if entry is None:
        return None
    return entry.label.upper(), entry.client_random, entry.secret


def _lines_not_in_keylog(lines: Iterable[str],
                         keylog_path: Optional[str]) -> List[str]:
    """The derived *lines* whose exact (label, client_random, secret) the
    primary keylog does not already hold; all of them when it is absent or
    unreadable."""
    lines = list(lines)
    if not keylog_path:
        return lines
    try:
        with open(keylog_path, "r", encoding="utf-8", errors="replace") as fh:
            known = {_nss_line_key(raw) for raw in fh}
    except OSError:
        return lines
    known.discard(None)
    return [line for line in lines if _nss_line_key(line) not in known]


def _decrypt_with_lines(pcap_path, lines, tshark_bin, tls_ports, *,
                        bus, state, result) -> None:
    """:func:`_decrypt_with_derived_keylog` over a temp keylog holding *lines*."""
    with tempfile.NamedTemporaryFile("w", suffix=".keylog", delete=False,
                                     encoding="utf-8") as fh:
        fh.writelines(lines)
        keylog_path = fh.name
    try:
        _decrypt_with_derived_keylog(pcap_path, keylog_path, tshark_bin, tls_ports,
                                     bus=bus, state=state, result=result)
    finally:
        os.unlink(keylog_path)


def _decrypt_with_derived_keylog(
    pcap_path, derived_keylog, tshark_bin, tls_ports, *, bus, state, result,
) -> None:
    """Drive the standard TLS single-pass over the derived keylog (option a).

    One combined tshark run (:func:`~friTap.offline.pipeline_api.
    run_tls_combined_pass`) reads the handshake metadata and the decrypted
    application data together, exactly as the ``has_keys`` branch of
    :func:`convert_pcap_to_tap` does: the recovered Schannel flows are decrypted
    and reconstructed as ordinary TLS flows.
    """
    from friTap.offline.pipeline_api import (
        StreamDirectionTracker,
        run_tls_combined_pass,
    )

    run_tls_combined_pass(
        tshark_bin, pcap_path, derived_keylog,
        tls_ports=tls_ports, extra_decode_as=(), heuristic=False,
        bus=bus, state=state, result=result,
        tracker=StreamDirectionTracker(server_ports=tls_ports),
    )


def build_schannel_offline_decryptor_entry() -> OfflineDecryptorEntry:
    """Build the Schannel :class:`OfflineDecryptorEntry`.

    The decrypted output is standard TLS (the derived keylog drives the normal TLS
    pass), so the flow layer is :class:`~friTap.flow.layers.TlsLayer`.
    """
    from friTap.flow.layers import TlsLayer

    return OfflineDecryptorEntry(
        protocol_name="schannel",
        cli_flag="--schannel-unpaired",
        cli_dest="schannel_unpaired",
        requires_tls_strip=False,
        emitter=_schannel_offline_emitter,
        layer_cls=TlsLayer,
        counter_prefix="schannel",
        cli_help=(
            "Schannel mem-scan '.schannel.unpaired' sidecar. friTap trial-decrypts "
            "each recovered TLS 1.2/1.3 secret against the pcap to find its "
            "client_random, writes a derived NSS keylog next to the sidecar, and "
            "decrypts the paired TLS flows. Use when Schannel secrets were recovered "
            "from lsass but carry no client_random."
        ),
        picker_group="tls",
        accepts_keylog=looks_like_unpaired,
    )
