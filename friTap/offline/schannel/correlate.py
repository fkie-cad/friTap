"""Pair memory-recovered Schannel secrets to their client_random (PUBLIC).

Port of ``research/memory_scan_lsass/tools/schannel_correlate.py``. Schannel never
stores the ClientHello random next to the key object, so the mem-scan engine emits
every recovered secret UNPAIRED (see :mod:`.unpaired`). What is unknown is only the
MAPPING: which recovered secret belongs to which captured connection. This module
discovers that mapping by TRIAL DECRYPTION against the pcap — the one correlation
method that needs nothing from lsass beyond the secrets already recovered.

TLS 1.2
  Every TLS 1.2 ClientHello in the pcap carries its client_random in the clear.
  For each candidate 48-byte master, a keylog pairing it with EVERY stream's
  client_random is written and tshark asked which streams then dissect a decrypted
  Finished (handshake type 20 — encrypted, so only dissectable once the master is
  right). Those streams are the ones whose real master is that candidate. That is
  O(number of masters) tshark runs, not O(masters x streams). The resulting NSS
  line is ``CLIENT_RANDOM <client_random> <master>``.

TLS 1.3
  A connection has a SET of secrets sharing one client_random; the keylog is keyed
  by label. Each recovered secret is trial-placed by decryption, which both LABELS
  it and identifies its connection:
    * SERVER_HANDSHAKE_TRAFFIC_SECRET decrypts EncryptedExtensions (type 8) — the
      anchor present in every full handshake.
    * CLIENT_HANDSHAKE_TRAFFIC_SECRET decrypts the client Finished (type 20).
    * {SERVER,CLIENT}_TRAFFIC_SECRET_0 decrypt application data (proven by a
      decrypted inner content_type 23); the correct direction/label is the one
      whose AEAD tag verifies.
  A wrong (secret,label) pairing fails its AEAD tag and simply does not match, so
  input labels are hints confirmed by decryption. EXPORTER_SECRET protects no
  records and can never be confirmed by decryption — it is placed only via a
  scanner ``group=`` tag riding along on a connection a sibling secret pinned down.

tshark is driven through the shared hermetic wrapper (:mod:`friTap.offline.tshark`
``_run_capture`` + ``-o tls.keylog_file``); nothing here touches lsass.
"""

from __future__ import annotations

import logging
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, List

logger = logging.getLogger(__name__)

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_SECRET_KV = re.compile(r"secret=([0-9a-fA-F]+)")
_SESSION_KV = re.compile(r"session_id=([0-9a-fA-F]*)")
_LABEL_KV = re.compile(r"label=([A-Za-z0-9_]+)")
_GROUP_KV = re.compile(r"group=(\S+)")

TLS12_MASTER_HEXLEN = 96  # 48 bytes

# TLS 1.3 keylog labels. Every secret of one connection shares that connection's
# ONE client_random. EXPORTER_SECRET protects no records, so it can never be
# confirmed by trial decryption — only placed by riding along on a group.
TLS13_LABELS = (
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
)
# 32 bytes (SHA-256 suites) or 48 bytes (SHA-384 suites).
TLS13_SECRET_HEXLENS = frozenset({64, 96})

# Which label a probe writes, paired with the tshark display filter that proves it
# decrypted. All four messages are ENCRYPTED in TLS 1.3, so they are dissectable
# only once the right secret is supplied — a clean yes/no signal that lets a wrong
# (secret,label) pairing fail silently (its AEAD tag never verifies).
# NOTE on the traffic-secret probes: `tls.app_data` is the *encrypted* payload,
# present on every application record whether or not decryption succeeded, so it
# can NOT prove a (secret,label) pairing. `tls.record.content_type` is the *inner*
# content type — but it is ALSO present on the plaintext handshake records
# (ClientHello/ServerHello carry content_type 22 with no decryption), so bare
# presence still matches every stream regardless of the traffic secret. The clean
# signal is `tls.record.content_type==23`: the INNER *application_data* type, which
# tshark exposes only after a traffic secret AEAD-decrypts an application record.
# A wrong-direction/wrong secret fails the tag and never yields a type-23 inner
# record — giving the same clean yes/no the handshake probes get from the
# (already decryption-gated, encrypted-only) tls.handshake.type==8/==20 filters.
# (Verified against a real TLS 1.3 pcap in
# tests/integration/test_schannel_tls13_correlate_e2e.py.)
# The signal is further anchored to a TLS 1.3 ciphertext record
# (`tls.record.opaque_type==23`): in TLS 1.2 `tls.record.content_type` is the
# OUTER, plaintext record type, so every TLS 1.2 application record carries
# content_type 23 with no decryption at all (e.g. a TLS 1.2 connection whose
# ClientHello merely OFFERED 1.3, or a mid-stream TLS 1.2 connection). TLS 1.2
# records never carry opaque_type, and an undecrypted TLS 1.3 record exposes no
# inner content_type 23, so the conjunction is decryption-gated for both.
TLS13_APP_DATA_SIGNAL = "tls.record.opaque_type==23 && tls.record.content_type==23"
TLS13_PROBE_SIGNAL = {
    "SERVER_HANDSHAKE_TRAFFIC_SECRET": "tls.handshake.type==8",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET": "tls.handshake.type==20",
    "SERVER_TRAFFIC_SECRET_0": TLS13_APP_DATA_SIGNAL,
    "CLIENT_TRAFFIC_SECRET_0": TLS13_APP_DATA_SIGNAL,
}
# Order matters only for tidy logging; the anchor is tried first.
TLS13_TRIAL_LABELS = (
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_TRAFFIC_SECRET_0",
    "CLIENT_TRAFFIC_SECRET_0",
)


# --------------------------------------------------------------------------- #
# Pure parsing (unit-testable without tshark)
# --------------------------------------------------------------------------- #

def parse_secrets(text: str) -> List[str]:
    """Pull candidate 48-byte master secrets out of scanner output.

    Accepts both ``kind=... secret=<hex>`` records and a plain file of one hex
    master per line. De-duplicated, lower-cased, order preserved.
    """
    out: List[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        candidates: List[str] = []
        kv = _SECRET_KV.search(line)
        if kv:
            candidates.append(kv.group(1))
        elif _HEX.match(line):
            candidates.append(line)
        for hexval in candidates:
            h = hexval.lower()
            if len(h) == TLS12_MASTER_HEXLEN and h not in seen:
                seen.add(h)
                out.append(h)
    return out


def parse_session_map(text: str) -> dict[str, str]:
    """session_id(hex) -> master(hex) from scanner records that carry both.

    A record with an empty session_id contributes nothing: an empty id cannot be
    matched to a ClientHello (the documented gap for ticket-resumed sessions).
    """
    mapping: dict[str, str] = {}
    for raw in text.splitlines():
        sec = _SECRET_KV.search(raw)
        sid = _SESSION_KV.search(raw)
        if not sec or not sid:
            continue
        sid_hex, master = sid.group(1).lower(), sec.group(1).lower()
        if sid_hex and len(master) == TLS12_MASTER_HEXLEN:
            mapping[sid_hex] = master
    return mapping


def parse_tshark_fields(output: str, ncols: int) -> List[List[str]]:
    """Split tshark ``-T fields`` tab output into rows of exactly ncols columns."""
    rows: List[List[str]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) < ncols:
            cols += [""] * (ncols - len(cols))
        rows.append(cols[:ncols])
    return rows


def client_randoms_from_rows(rows: Iterable[List[str]]) -> dict[str, str]:
    """stream -> client_random(hex, no colons) from (stream, random) rows."""
    out: dict[str, str] = {}
    for stream, rnd in rows:
        rnd = rnd.replace(":", "").strip().lower()
        stream = stream.strip()
        if stream and len(rnd) == 64 and _HEX.match(rnd):  # 32-byte client random
            out.setdefault(stream, rnd)
    return out


def build_keylog(client_randoms: Iterable[str], master: str) -> str:
    """One ``CLIENT_RANDOM cr master`` line per stream, all sharing one master."""
    return "".join(f"CLIENT_RANDOM {cr} {master}\n" for cr in client_randoms)


def parse_tls13_records(text: str) -> List[dict]:
    """Pull TLS 1.3 secret records out of scanner output.

    Accepts, in order of preference: ``kind=... label=... group=... secret=<hex>``
    key=value records; NSS-style triples ``LABEL <client_random> <hex>`` (the
    client_random is ignored — re-derived); ``LABEL <hex>``; and bare ``<hex>``.
    A record keeps its label only if it names a real TLS 1.3 label. Secrets must be
    32 or 48 bytes. De-duplicated on (label, secret, group), order preserved.
    """
    records: List[dict] = []
    seen: set[tuple] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        secret = None
        label = None
        group = None
        kv = _SECRET_KV.search(line)
        if kv:
            secret = kv.group(1).lower()
            lm = _LABEL_KV.search(line)
            if lm and lm.group(1).upper() in TLS13_LABELS:
                label = lm.group(1).upper()
            gm = _GROUP_KV.search(line)
            if gm:
                group = gm.group(1)
        else:
            toks = line.split()
            if len(toks) == 3 and toks[0].upper() in TLS13_LABELS and _HEX.match(toks[2]):
                label, secret = toks[0].upper(), toks[2].lower()   # NSS triple
            elif len(toks) == 2 and toks[0].upper() in TLS13_LABELS and _HEX.match(toks[1]):
                label, secret = toks[0].upper(), toks[1].lower()
            elif len(toks) == 1 and _HEX.match(toks[0]):
                secret = toks[0].lower()
        if secret is None or len(secret) not in TLS13_SECRET_HEXLENS:
            continue
        key = (label, secret, group)
        if key not in seen:
            seen.add(key)
            records.append({"secret": secret, "label": label, "group": group})
    return records


def unique_secrets(records: Iterable[dict]) -> List[str]:
    """The distinct secret hexes across records, order preserved."""
    out: List[str] = []
    seen: set[str] = set()
    for r in records:
        s = r["secret"]
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def group_connection_map(records: Iterable[dict],
                         secret_to_stream: dict[str, str]) -> dict[str, str]:
    """group -> stream, for groups where any member secret was placed to a stream.

    This lets EXPORTER_SECRET (and any secret that carried no decryptable signal)
    ride along on a connection a sibling secret already identified.
    """
    mapping: dict[str, str] = {}
    for r in records:
        g, s = r["group"], r["secret"]
        if g and s in secret_to_stream:
            mapping.setdefault(g, secret_to_stream[s])
    return mapping


def build_tls13_probe_keylog(label: str, client_randoms: dict[str, str], secret: str) -> str:
    """One ``<label> <client_random> <secret>`` line per stream, one shared secret."""
    return "".join(f"{label} {cr} {secret}\n" for cr in client_randoms.values())


def records_from_secret_lists(masters: Iterable[str],
                              tls13_secrets: Iterable[str]) -> tuple[List[str], List[dict]]:
    """Adapt the :mod:`.unpaired` hex lists into (masters, tls13-record dicts).

    The mem-scan sidecar carries no TLS 1.3 label/group (Schannel keeps neither),
    so each 1.3 secret becomes an unlabeled, ungrouped record — exactly the shape
    :func:`correlate_tls13` trial-places by decryption.
    """
    m = [h.lower() for h in masters if len(h) == TLS12_MASTER_HEXLEN]
    recs = [{"secret": h.lower(), "label": None, "group": None}
            for h in tls13_secrets if len(h) in TLS13_SECRET_HEXLENS]
    return m, recs


# --------------------------------------------------------------------------- #
# tshark orchestration (reuses the shared hermetic wrapper)
# --------------------------------------------------------------------------- #

def _run_fields(tshark_bin: str, pcap: str, display_filter: str,
                fields: Iterable[str], *, keylog: str | None = None) -> str:
    """Run one hermetic ``-T fields`` tshark pass and return its raw stdout.

    Reuses :func:`friTap.offline.tshark._run_capture` (hermetic env) and the same
    ``-o tls.keylog_file`` mechanism the rest of the offline pipeline uses, rather
    than inventing a fresh tshark invocation.
    """
    from friTap.offline.tshark import _run_capture

    cmd = [tshark_bin, "-r", pcap]
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}",
                "-o", "tls.ignore_ssl_mac_failed:FALSE"]
    cmd += ["-Y", display_filter, "-T", "fields"]
    for field_name in fields:
        cmd += ["-e", field_name]
    try:
        return _run_capture(cmd)
    except Exception:  # noqa: BLE001 - a tshark failure yields "no rows", not a crash
        logger.debug("tshark fields pass failed (filter %r)", display_filter, exc_info=True)
        return ""


def read_client_randoms(tshark_bin: str, pcap: str) -> dict[str, str]:
    """Every TLS 1.2 ClientHello in the pcap: tcp.stream -> client_random."""
    out = _run_fields(tshark_bin, pcap, "tls.handshake.type==1",
                      ("tcp.stream", "tls.handshake.random"))
    return client_randoms_from_rows(parse_tshark_fields(out, 2))


def read_tls13_client_randoms(tshark_bin: str, pcap: str) -> dict[str, str]:
    """Every TLS 1.3 ClientHello in the pcap: tcp.stream -> client_random.

    A TLS 1.3 ClientHello still carries legacy_version 0x0303; what marks it 1.3 is
    a supported_versions extension offering 0x0304, the field keyed on here so a
    1.2-only ClientHello in the same capture is not swept in.
    """
    out = _run_fields(
        tshark_bin, pcap,
        "tls.handshake.type==1 && tls.handshake.extensions.supported_version==0x0304",
        ("tcp.stream", "tls.handshake.random"))
    return client_randoms_from_rows(parse_tshark_fields(out, 2))


def streams_that_decrypted(tshark_bin: str, pcap: str, keylog_path: str) -> set[str]:
    """tcp.streams whose TLS 1.2 Finished (type 20) decrypted under this keylog."""
    return streams_matching_filter(tshark_bin, pcap, keylog_path,
                                   "tls.handshake.type==20")


def streams_matching_filter(tshark_bin: str, pcap: str, keylog_path: str,
                            display_filter: str) -> set[str]:
    """tcp.streams for which `display_filter` matches once this keylog is applied."""
    out = _run_fields(tshark_bin, pcap, display_filter, ("tcp.stream",),
                      keylog=keylog_path)
    return {row[0].strip() for row in parse_tshark_fields(out, 1) if row[0].strip()}


@contextmanager
def _temp_keylog(content: str) -> Iterator[str]:
    """Yield the path to a temp NSS keylog holding `content`, unlinking on exit.

    The write-keylog / capture-name / unlink-in-finally dance lives here in one
    place so every trial-decryption call site is leak-safe by construction.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".keylog", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(content)
        keylog_path = fh.name
    try:
        yield keylog_path
    finally:
        Path(keylog_path).unlink(missing_ok=True)


def correlate_by_trial(tshark_bin: str, pcap: str, masters: List[str],
                       client_randoms: dict[str, str]) -> dict[str, str]:
    """Return stream -> master by testing each master against every stream."""
    identified: dict[str, str] = {}
    remaining = dict(client_randoms)
    for i, master in enumerate(masters, 1):
        if not remaining:
            break
        with _temp_keylog(build_keylog(remaining.values(), master)) as keylog_path:
            hit_streams = streams_that_decrypted(tshark_bin, pcap, keylog_path)
        matched = [s for s in list(remaining) if s in hit_streams]
        for s in matched:
            identified[s] = master
            del remaining[s]
        logger.debug("master %d/%d %s… matched %d stream(s); %d unmatched",
                     i, len(masters), master[:16], len(matched), len(remaining))
    return identified


def probe_tls13_label(tshark_bin: str, pcap: str, label: str, secret: str,
                      client_randoms: dict[str, str]) -> set[str]:
    """Streams where `secret`, tried under `label`, produces that label's signal."""
    with _temp_keylog(build_tls13_probe_keylog(label, client_randoms, secret)) as keylog_path:
        return streams_matching_filter(tshark_bin, pcap, keylog_path,
                                       TLS13_PROBE_SIGNAL[label])


def place_tls13_secret(tshark_bin: str, pcap: str, secret: str,
                       client_randoms: dict[str, str]) -> List[tuple[str, str]]:
    """(label, stream) pairs a secret verifiably decrypts, over the trial labels.

    Only streams in *client_randoms* count: a probe filter matching some other
    stream (one the probe keylog never covered) proves nothing about *secret*.
    """
    hits: List[tuple[str, str]] = []
    for label in TLS13_TRIAL_LABELS:
        streams = probe_tls13_label(tshark_bin, pcap, label, secret, client_randoms)
        streams = {s for s in streams if s in client_randoms}
        for stream in streams:
            hits.append((label, stream))
        # A secret matches exactly one label; once one label's probe hits, the
        # remaining probes are guaranteed empty, so skip their tshark runs.
        if streams:
            break
    return hits


# --------------------------------------------------------------------------- #
# High-level correlation (used by the offline emitter)
# --------------------------------------------------------------------------- #

def correlate_tls12(tshark_bin: str, pcap: str, masters: List[str]) -> List[str]:
    """Correlate TLS 1.2 masters -> client_random. Returns NSS keylog lines."""
    masters = [m for m in dict.fromkeys(masters) if len(m) == TLS12_MASTER_HEXLEN]
    if not masters:
        return []
    client_randoms = read_client_randoms(tshark_bin, pcap)
    if not client_randoms:
        logger.info("Schannel TLS 1.2: no ClientHello in the pcap; nothing to pair")
        return []
    identified = correlate_by_trial(tshark_bin, pcap, masters, client_randoms)
    lines: List[str] = []
    for stream, master in sorted(identified.items(),
                                 key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
        lines.append(f"CLIENT_RANDOM {client_randoms[stream]} {master}\n")
    return lines


def correlate_tls13(tshark_bin: str, pcap: str, records: List[dict]) -> List[str]:
    """Correlate a TLS 1.3 secret set -> client_random. Returns NSS keylog lines.

    Trial-place every distinct secret by decryption (which both labels it and
    identifies its connection's client_random), then let any secret carrying no
    decryptable signal ride along on a group a sibling secret already pinned down.
    """
    if not records:
        return []
    client_randoms = read_tls13_client_randoms(tshark_bin, pcap)
    if not client_randoms:
        logger.info("Schannel TLS 1.3: no TLS 1.3 ClientHello in the pcap; nothing to pair")
        return []
    secrets = unique_secrets(records)

    lines: set[str] = set()
    secret_to_stream: dict[str, str] = {}
    placed_secrets: set[str] = set()
    for secret in secrets:
        for label, stream in place_tls13_secret(tshark_bin, pcap, secret, client_randoms):
            lines.add(f"{label} {client_randoms[stream]} {secret}\n")
            secret_to_stream.setdefault(secret, stream)
            placed_secrets.add(secret)

    # Ride-along: place secrets that produced no signal (EXPORTER_SECRET, or a
    # labeled secret for an already-identified connection) via their group.
    group_to_stream = group_connection_map(records, secret_to_stream)
    for r in records:
        secret, label, group = r["secret"], r["label"], r["group"]
        if secret in placed_secrets:
            continue
        stream = group_to_stream.get(group) if group else None
        if stream is not None and label:
            lines.add(f"{label} {client_randoms[stream]} {secret}\n")
            placed_secrets.add(secret)

    return sorted(lines)


def correlate_unpaired(tshark_bin: str, pcap: str, masters: List[str],
                       tls13_secrets: List[str]) -> List[str]:
    """Full correlation for the mem-scan sidecar: TLS 1.2 + TLS 1.3 -> keylog lines.

    Returns the de-duplicated, sorted union of both correlations — a standard NSS
    keylog ready for tshark/Wireshark.
    """
    m, recs = records_from_secret_lists(masters, tls13_secrets)
    lines: List[str] = []
    lines += correlate_tls12(tshark_bin, pcap, m)
    lines += correlate_tls13(tshark_bin, pcap, recs)
    return sorted(dict.fromkeys(lines))


__all__ = [
    "TLS12_MASTER_HEXLEN",
    "TLS13_LABELS",
    "TLS13_SECRET_HEXLENS",
    "TLS13_APP_DATA_SIGNAL",
    "TLS13_PROBE_SIGNAL",
    "TLS13_TRIAL_LABELS",
    "parse_secrets",
    "parse_session_map",
    "parse_tshark_fields",
    "client_randoms_from_rows",
    "build_keylog",
    "parse_tls13_records",
    "unique_secrets",
    "group_connection_map",
    "build_tls13_probe_keylog",
    "records_from_secret_lists",
    "read_client_randoms",
    "read_tls13_client_randoms",
    "streams_that_decrypted",
    "streams_matching_filter",
    "correlate_by_trial",
    "probe_tls13_label",
    "place_tls13_secret",
    "correlate_tls12",
    "correlate_tls13",
    "correlate_unpaired",
]
