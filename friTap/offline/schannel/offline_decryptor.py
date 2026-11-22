#!/usr/bin/env python3

"""Schannel offline decryptor: correlate + derive NSS keylog + decrypt (PUBLIC).

The Schannel mem-scan engine writes lsass secrets UNPAIRED to a
``.schannel.unpaired`` sidecar (no client_random). This decryptor, offline:

  1. parses the sidecar (:mod:`.unpaired`),
  2. trial-decrypts each secret against the pcap to find its client_random
     (:mod:`.correlate`), yielding a standard NSS keylog,
  3. writes that keylog next to the sidecar
     (``<sidecar-with-.unpaired-stripped>.nss.keylog``), and
  4. feeds the lines the primary ``--keylog`` does not already hold into the same
     TLS single pass (``run_tls_combined_pass``), so the flows get the normal TLS
     layer and metadata. Sessions the primary keylog already carries are decrypted
     only by the primary pass.

The entry registers ``requires_tls_strip=False``: it supplies its own derived
keylog and drives a fresh TLS pass. Unplaced secrets are counted
(``undecryptable``) and summarized in one warning.
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
    """``keys.memscan.schannel.unpaired`` -> ``keys.memscan.schannel.nss.keylog``."""
    if sidecar_path.endswith(".unpaired"):
        base = sidecar_path[: -len(".unpaired")]
    else:
        base = os.path.splitext(sidecar_path)[0]
    return base + ".nss.keylog"


def _schannel_offline_emitter(
    *, pcap_path, proto_keylog, tls_keylog_path, tshark_bin, tls_ports,
    bus, state, result,
) -> None:
    """Correlate the sidecar and decrypt the paired TLS.

    Logs and returns on any recoverable problem (offline-emitter contract).
    *proto_keylog* is the sidecar path; *tls_keylog_path* is the primary TLS keylog
    (may be None), whose already-held lines are left to the primary pass so their
    flows are not duplicated.
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
    """The *lines* whose (label, client_random, secret) the primary keylog lacks.

    All of them when the keylog is absent or unreadable.
    """
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
    """Run the standard TLS single pass over the derived keylog.

    Mirrors the ``has_keys`` branch of :func:`convert_pcap_to_tap`.
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
    """Build the Schannel entry; output is standard TLS, so the layer is ``TlsLayer``."""
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
