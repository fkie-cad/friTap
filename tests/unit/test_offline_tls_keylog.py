"""Characterization tests for the shared NSS keylog line parser and loader loop.

Every NSS keylog reader now delegates to the one strict policy
(:func:`friTap.offline.tls.keylog.parse_strict_nss_line`), and the MTProto loaders
delegate to :func:`friTap.offline.keylog_io.load_keylog_lines`.
These tests pin each caller's accept/reject decision for a set of tricky lines
(rows marked ``CHANGED`` were accepted by the old quirky readers), and check
against a verbatim copy of each pre-refactor implementation that the new policy
only ever tightens: a line accepted now was accepted before, with the same result.
"""

from __future__ import annotations

import itertools
import re

import pytest

from friTap.offline import keylog_coverage as kc
from friTap.offline.keylog_io import load_keylog_lines
from friTap.offline.mtproto.e2e.keylog import load_secret_chat_keylog
from friTap.offline.mtproto.keylog import load_mtproto_keylog, load_mtproto_obf_keylog
from friTap.offline.rc4.crypto import secrets_from_keylog
from friTap.offline.schannel.pidmap import parse_keylog_by_cr
from friTap.offline.schannel.sspi import keylog_secret_map
from friTap.offline.tls.keylog import NssEntry, parse_strict_nss_line
from friTap.protocols.mtproto_keylog_spec import (
    parse_e2e_line,
    parse_line,
    parse_obf_line,
)

CR = "ab" * 32
S32 = "cd" * 32
S48 = "ef" * 48

# --------------------------------------------------------------------------- #
# Verbatim pre-refactor implementations (the characterization oracle)
# --------------------------------------------------------------------------- #

_LEGACY_HEX = re.compile(r"^[0-9a-fA-F]+$")
_LEGACY_CR_HEX = re.compile(r"^[0-9a-f]{64}$")
_LEGACY_SECRET_HEX = re.compile(r"^[0-9a-f]+$")


def _legacy_rc4(text):
    out = []
    for line in text.splitlines():
        p = line.split()
        if len(p) == 3 and not line.startswith("#") and len(p[2]) in (64, 96):
            out.append(p[2].lower())
    return out


def _legacy_sspi(text):
    out = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) == 3 and not line.startswith("#"):
            out[p[2].lower()] = (p[0], p[1].lower())
    return out


def _legacy_pidmap(text):
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        label, cr, secret = parts[0], parts[1].lower(), parts[2].lower()
        if len(cr) == 64 and _LEGACY_HEX.match(cr) and _LEGACY_HEX.match(secret):
            out.setdefault(cr, {})[label] = secret
    return out


def _legacy_coverage_line(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split()
    if len(parts) != 3 or not kc.is_nss_tls_label(parts[0]):
        return None
    client_random, secret = parts[1].lower(), parts[2].lower()
    if not _LEGACY_CR_HEX.match(client_random) or not _LEGACY_SECRET_HEX.match(secret):
        return None
    return parts[0], client_random, secret


def _legacy_triple(line):
    parts = line.strip().split()
    if len(parts) == 3 and kc.is_nss_tls_label(parts[0]):
        return parts[0], parts[1].lower(), parts[2].lower()
    return None


def _per_line(fn):
    return lambda text: [fn(line) for line in text.splitlines()]


# (caller name, current implementation, pre-refactor oracle)
CALLERS = [
    ("rc4.secrets_from_keylog", secrets_from_keylog, _legacy_rc4),
    ("sspi.keylog_secret_map", keylog_secret_map, _legacy_sspi),
    ("pidmap.parse_keylog_by_cr", parse_keylog_by_cr, _legacy_pidmap),
    ("keylog_coverage._parse_keylog_line",
     _per_line(kc._parse_keylog_line), _per_line(_legacy_coverage_line)),
    ("keylog_coverage._line_nss_triple",
     _per_line(kc._line_nss_triple), _per_line(_legacy_triple)),
]

# --------------------------------------------------------------------------- #
# Explicit accept/reject table, per caller
# --------------------------------------------------------------------------- #

# line -> (rc4, sspi, pidmap, coverage, triple) acceptance.
# CHANGED rows: the old acceptance is in the trailing comment (Phase 2 step 5).
TABLE = {
    "valid": (f"CLIENT_RANDOM {CR} {S32}", (1, 1, 1, 1, 1)),
    "upper_hex": (f"CLIENT_RANDOM {CR.upper()} {S32.upper()}", (1, 1, 1, 1, 1)),
    "secret_48": (f"CLIENT_TRAFFIC_SECRET_0 {CR} {S48}", (1, 1, 1, 1, 1)),
    "secret_odd_len": (f"CLIENT_RANDOM {CR} {S32[:-1]}", (0, 0, 0, 0, 0)),  # CHANGED (0,1,1,1,1)
    "short_cr": (f"CLIENT_RANDOM {CR[:-2]} {S32}", (0, 0, 0, 0, 1)),  # CHANGED (1,1,0,0,1); triple = unknown CR
    "non_hex_cr": (f"CLIENT_RANDOM {'zz' * 32} {S32}", (0, 0, 0, 0, 1)),  # CHANGED (1,1,0,0,1); triple = unknown CR
    "unknown_cr": (f"CLIENT_RANDOM ??? {S32}", (1, 1, 0, 0, 1)),
    "unknown_cr_bad_secret": (f"CLIENT_RANDOM ??? {S32[:-1]}", (0, 0, 0, 0, 0)),  # CHANGED (0,1,0,0,1)
    "non_hex_secret": (f"CLIENT_RANDOM {CR} {'zz' * 32}", (0, 0, 0, 0, 0)),  # CHANGED (1,1,0,0,1)
    "unknown_label": (f"FOO {CR} {S32}", (1, 1, 1, 0, 0)),
    "two_fields": (f"CLIENT_RANDOM {CR}", (0, 0, 0, 0, 0)),
    "four_fields": (f"CLIENT_RANDOM {CR} {S32} extra", (0, 0, 0, 0, 0)),
    "tabs": (f"CLIENT_RANDOM\t{CR}\t{S32}", (1, 1, 1, 1, 1)),
    "crlf": (f"CLIENT_RANDOM {CR} {S32}\r", (1, 1, 1, 1, 1)),
    "comment": (f"# {CR} {S32}", (0, 0, 0, 0, 0)),
    "indented_comment": (f"  # {CR} {S32}", (0, 0, 0, 0, 0)),  # CHANGED (1,1,0,0,0)
    "hash_traffic_label": (f"#CLIENT_TRAFFIC_SECRET_0 {CR} {S32}", (0, 0, 0, 0, 0)),  # CHANGED (0,0,0,0,1)
    "blank": ("   ", (0, 0, 0, 0, 0)),
}


def _accepted(impl, line):
    result = impl(line)
    if isinstance(result, list) and result and isinstance(result[0], (tuple, type(None))):
        return any(r is not None for r in result)
    return bool(result)


@pytest.mark.parametrize("case", sorted(TABLE))
@pytest.mark.parametrize("index,caller", [(i, c) for i, c in enumerate(CALLERS)],
                         ids=[c[0] for c in CALLERS])
def test_caller_accept_reject_table(case, index, caller):
    line, expected = TABLE[case]
    _name, impl, _legacy = caller
    assert _accepted(impl, line) is bool(expected[index])


def _corpus():
    labels = ["CLIENT_RANDOM", "CLIENT_TRAFFIC_SECRET_0", "EXPORTER_SECRET",
              "EARLY_EXPORTER_SECRET", "FOO", "#X", "#", "client_random", "MY_TRAFFIC_SECRETX"]
    randoms = [CR, CR.upper(), CR[:-1], CR + "a", "zz" * 32, "???", "İ" + CR[1:], "K" * 64]
    secrets = [S32, S48, S32.upper(), S32[:-1], "zz" * 32, "ab", "İ" * 64,
               "İ" + S32[1:], "0" * 96, "a" * 128]
    lines = [" ".join(t) for t in itertools.product(labels, randoms, secrets)]
    lines += [
        "", " ", "#", f"  # {CR} {S32}", f"\t#X {CR} {S32}", f"CLIENT_RANDOM {CR} {S32}\r\n",
        f"CLIENT_RANDOM\x0b{CR}\x0c{S32}", f"CLIENT_RANDOM {CR} {S32}",
        f"﻿CLIENT_RANDOM {CR} {S32}", f"CLIENT_RANDOM {CR} secret={S32}",
        f"CLIENT_RANDOM {CR} {S32}\nSERVER_TRAFFIC_SECRET_0 {CR.upper()} {S48}\n# c\n"
        f"CLIENT_RANDOM {CR} {S48}",
        f"CLIENT_RANDOM {CR} {S32} CLIENT_RANDOM {CR} {S48}",
    ]
    return lines


@pytest.mark.parametrize("caller", CALLERS, ids=[c[0] for c in CALLERS])
def test_caller_only_tightens_pre_refactor_implementation(caller):
    _name, impl, legacy = caller
    for text in _corpus():
        for line in text.splitlines():
            if _accepted(impl, line):
                assert impl(line) == legacy(line), repr(line)


@pytest.mark.parametrize("caller", CALLERS, ids=[c[0] for c in CALLERS])
def test_caller_matches_pre_refactor_implementation_on_valid_lines(caller):
    _name, impl, legacy = caller
    valid = [f"CLIENT_RANDOM {CR} {S48}", f"CLIENT_TRAFFIC_SECRET_0 {CR.upper()} {S32}",
             f"EXPORTER_SECRET\t{CR}\t{S48}\r", "# header", "", f"SERVER_TRAFFIC_SECRET_0 {CR} {S48}"]
    text = "\n".join(valid)
    assert impl(text) == legacy(text)


# --------------------------------------------------------------------------- #
# parse_strict_nss_line itself
# --------------------------------------------------------------------------- #

def test_parse_strict_nss_line_lowercases_random_and_secret_not_label():
    entry = parse_strict_nss_line(f"client_Random {CR.upper()} {S32.upper()}")
    assert entry == NssEntry("client_Random", CR, S32)


def test_parse_strict_nss_line_policy():
    assert parse_strict_nss_line(f"CLIENT_RANDOM {CR} {S48}") == NssEntry("CLIENT_RANDOM", CR, S48)
    assert parse_strict_nss_line(f"  # {CR} {S32}") is None
    assert parse_strict_nss_line(f"  #X {CR} {S32}") is None
    assert parse_strict_nss_line(f"L {CR} {S32[:-2]}") is None
    assert parse_strict_nss_line(f"L {CR} zz") is None
    assert parse_strict_nss_line(f"L {CR[:-2]} {S32}") is None
    assert parse_strict_nss_line(f"L {'zz' * 32} {S32}") is None
    assert parse_strict_nss_line(f"L {CR} {'a' * 128}") is None
    assert parse_strict_nss_line(f"L ??? {S32}") is None
    assert parse_strict_nss_line(f"L ??? {S32}", allow_unknown_client_random=True).client_random == "???"
    assert parse_strict_nss_line("L ??? zz", allow_unknown_client_random=True) is None
    assert parse_strict_nss_line(f"L {CR} {S32}", label_ok=lambda label: False) is None


# --------------------------------------------------------------------------- #
# load_keylog_lines and the loaders that use it
# --------------------------------------------------------------------------- #

AUTH_A = "MTPROTO_AUTH_KEY 2 " + "11" * 8 + " " + "22" * 256 + " perm"
AUTH_A2 = "MTPROTO_AUTH_KEY 4 " + "11" * 8 + " " + "33" * 256 + " perm"
AUTH_B = "MTPROTO_AUTH_KEY 2 " + "44" * 8 + " " + "55" * 256 + " perm"
E2E_A = "MTPROTO_E2E_KEY " + "66" * 8 + " " + "77" * 256 + " 101"
E2E_A2 = "MTPROTO_E2E_KEY " + "66" * 8 + " " + "88" * 256 + " 102 7"
OBF_A = "MTPROTO_OBF_KEY " + " ".join(["99" * 32, "aa" * 16, "bb" * 32, "cc" * 16, "0", "0", "-"])
OBF_B = "MTPROTO_OBF_KEY " + " ".join(["dd" * 32, "ee" * 16, "ff" * 32, "00" * 16, "3", "5",
                                       "1.2.3.4:443"])


def _legacy_load(path, parse, key=None):
    out = {} if key else []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = parse(line)
            if entry is not None:
                if key:
                    out[key(entry)] = entry
                else:
                    out.append(entry)
    return out


def test_load_keylog_lines_list_keeps_order_and_skips_none(tmp_path):
    path = tmp_path / "k.log"
    path.write_text("b\n\nskip\na\r\nc", encoding="utf-8")
    parse = lambda line: None if line.strip() in ("", "skip") else line  # noqa: E731
    assert load_keylog_lines(str(path), parse) == ["b\n", "a\n", "c"]


def test_load_keylog_lines_dict_last_wins_first_position(tmp_path):
    path = tmp_path / "k.log"
    path.write_text("x1\ny1\nx2\n", encoding="utf-8")
    result = load_keylog_lines(str(path), str.strip, key=lambda e: e[0])
    assert result == {"x": "x2", "y": "y1"}
    assert list(result) == ["x", "y"]


def test_load_keylog_lines_missing_file_raises(tmp_path):
    with pytest.raises(OSError):
        load_keylog_lines(str(tmp_path / "missing"), str.strip)


@pytest.mark.parametrize("loader,parse,key", [
    (load_mtproto_keylog, parse_line, lambda e: e.auth_key_id),
    (load_mtproto_obf_keylog, parse_obf_line, None),
    (load_secret_chat_keylog, parse_e2e_line, lambda e: e.key_fingerprint),
], ids=["mtproto", "mtproto_obf", "secret_chat"])
def test_loaders_match_pre_refactor_loop(tmp_path, loader, parse, key):
    path = tmp_path / "keys.mtproto.keylog"
    body = "\n".join([
        "# header\r", f"{AUTH_A}\r", "", f"{E2E_A}\x0b", f"{OBF_A}\r", "\xff garbage",
        f"{AUTH_B} tail", OBF_B, E2E_A2, f"{AUTH_A2}\r", OBF_A,
    ])
    path.write_bytes(body.encode("utf-8").replace(b"\xc3\xbf", b"\xff"))  # invalid UTF-8
    expected = _legacy_load(str(path), parse, key)
    assert expected  # the fixture must exercise real entries
    result = loader(str(path))
    assert result == expected
    if key is not None:
        assert list(result) == list(expected)


def test_mtproto_loader_duplicate_auth_key_last_wins(tmp_path):
    path = tmp_path / "keys.mtproto.keylog"
    path.write_text(f"{AUTH_A}\n{AUTH_B}\n{AUTH_A2}\n", encoding="utf-8")
    keymap = load_mtproto_keylog(str(path))
    assert len(keymap) == 2
    assert keymap[bytes.fromhex("11" * 8)].auth_key == bytes.fromhex("33" * 256)


# --------------------------------------------------------------------------- #
# Phase 2: consistent validation (the three historical quirks are fixed)
# --------------------------------------------------------------------------- #

QUIRK_LINES = {
    "indented_comment": f"  # {CR} {S32}",
    "hash_traffic_label": f"#CLIENT_TRAFFIC_SECRET_0 {CR} {S32}",
    "garbage_secret": f"CLIENT_RANDOM {CR} {'zz' * 32}",
}


@pytest.mark.parametrize("case", sorted(QUIRK_LINES))
@pytest.mark.parametrize("caller", CALLERS, ids=[c[0] for c in CALLERS])
def test_quirk_lines_rejected_by_every_caller(case, caller):
    _name, impl, _legacy = caller
    assert not _accepted(impl, QUIRK_LINES[case])


def test_tls13_labels_live_in_tls_keylog_and_are_reexported():
    from friTap.offline.schannel import correlate as sc
    from friTap.offline.tls import keylog as kl
    assert sc.TLS13_LABELS is kl.TLS13_LABELS
    assert sc.TLS13_TRIAL_LABELS is kl.TLS13_TRIAL_LABELS
    assert set(kl.TLS13_TRIAL_LABELS) == set(kl.TLS13_LABELS) - {"EXPORTER_SECRET"}
    assert kl.TLS13_TRIAL_LABELS[0] == "SERVER_HANDSHAKE_TRAFFIC_SECRET"
