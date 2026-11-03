"""Bounded keylog line reads and the filtered ``--repair-keylog`` / relabel copy.

* :func:`friTap.offline.keylog_io.iter_bounded_lines` caps each line read, so a
  file with no newlines (binary junk, or a hostile file named by an untrusted
  capture manifest) is drained in bounded chunks instead of becoming one giant
  in-memory line; every keylog / secret-file reader goes through it.
* The repaired / relabeled keylog copies only valid NSS keylog lines of the
  input (like ``keylog_picker.merge_keylogs``) and refuses a non-regular file.
"""

from __future__ import annotations

import io
import json
import logging
import os
import tracemalloc

import pytest

from friTap.offline import keylog_coverage as kc
from friTap.offline import keylog_paths, keylog_picker, keylog_suggest
from friTap.offline.keylog_io import iter_bounded_lines, load_keylog_lines
from friTap.offline.tls_midstream import pipeline as pl

CR_A = "aa" * 32
CR_B = "bb" * 32
CR_C = "cc" * 32
SECRET_48 = "11" * 48
SECRET_32 = "22" * 32

VALID_LINES = [
    f"CLIENT_RANDOM {CR_A} {SECRET_48}",
    f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_B} {SECRET_32}",
]
JUNK_BYTES = 50 * 1024 * 1024
# Far below the 50 MB junk line (and its ~100 MB decoded form): proves the line
# was never held in memory as a whole.
PEAK_LIMIT_BYTES = 8 * 1024 * 1024


def _junk_block() -> bytes:
    """1 MiB of binary junk without any line terminator (``\\n`` / ``\\r``)."""
    block = bytearray(os.urandom(1024 * 1024))
    return bytes(block).replace(b"\n", b"x").replace(b"\r", b"y")


def _write_junk_then(path, tail: str) -> str:
    """Write a 50 MB newline-free junk line, then *tail* (valid lines)."""
    block = _junk_block()
    with open(path, "wb") as fh:
        for _ in range(JUNK_BYTES // len(block)):
            fh.write(block)
        fh.write(b"\n" + tail.encode())
    return str(path)


@pytest.fixture(scope="module")
def junk_keylog(tmp_path_factory) -> str:
    """A 50 MB no-newline junk line followed by valid NSS keylog lines."""
    path = tmp_path_factory.mktemp("junk") / "junk.keylog"
    return _write_junk_then(path, "".join(f"{line}\n" for line in VALID_LINES))


def _peak_bytes(func):
    """``(result, peak traced allocation)`` of calling *func*."""
    tracemalloc.start()
    try:
        result = func()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak


def _overlong_warnings(caplog):
    return [r for r in caplog.records if "over-long line" in r.getMessage()]


# --------------------------------------------------------------------------- #
# iter_bounded_lines
# --------------------------------------------------------------------------- #

def test_text_lines_keep_newlines_like_plain_iteration():
    text = "a\nbb\n\nccc"
    assert list(iter_bounded_lines(io.StringIO(text), max_chars=10)) == list(io.StringIO(text))


def test_overlong_text_line_is_skipped_and_reading_resumes(caplog):
    text = "ok\n" + "x" * 50 + "\nnext\n" + "y" * 11 + "\ntail"
    with caplog.at_level(logging.WARNING):
        lines = list(iter_bounded_lines(io.StringIO(text), max_chars=10, source="k.log"))
    assert lines == ["ok\n", "next\n", "tail"]
    (warning,) = _overlong_warnings(caplog)  # ONE warning per file
    assert "Skipped 2 over-long" in warning.getMessage() and "k.log" in warning.getMessage()


def test_line_length_boundary_counts_content_not_newline():
    exact, over = "e" * 10, "o" * 11
    text = f"{exact}\n{over}\n{exact}"
    assert list(iter_bounded_lines(io.StringIO(text), max_chars=10)) == [f"{exact}\n", exact]
    assert list(iter_bounded_lines(io.StringIO(over), max_chars=10)) == []


def test_binary_handle_is_supported():
    data = b"a\n" + b"z" * 100 + b"\nb\n"
    assert list(iter_bounded_lines(io.BytesIO(data), max_chars=8)) == [b"a\n", b"b\n"]


def test_drain_spans_many_chunks():
    text = "q" * (300 * 1024) + "\nafter\n"
    assert list(iter_bounded_lines(io.StringIO(text), max_chars=16)) == ["after\n"]


def test_no_warning_without_skips(caplog):
    with caplog.at_level(logging.WARNING):
        list(iter_bounded_lines(io.StringIO("a\nb\n")))
    assert not _overlong_warnings(caplog)


def test_warning_is_emitted_when_closed_early(caplog):
    lines = iter_bounded_lines(io.StringIO("w" * 40 + "\nfirst\nsecond\n"), max_chars=10)
    with caplog.at_level(logging.WARNING):
        assert next(lines) == "first\n"
        lines.close()
    assert len(_overlong_warnings(caplog)) == 1


# --------------------------------------------------------------------------- #
# 50 MB newline-free junk: bounded memory, later valid lines still found
# --------------------------------------------------------------------------- #

def test_load_keylog_lines_bounded_memory(junk_keylog):
    def parse(line):
        return line.strip() if line.startswith(("CLIENT_", "SERVER_")) else None

    entries, peak = _peak_bytes(lambda: load_keylog_lines(junk_keylog, parse))
    assert entries == VALID_LINES
    assert peak < PEAK_LIMIT_BYTES, f"peak {peak} bytes"


def test_merge_keylogs_bounded_memory(junk_keylog, tmp_path):
    merged, peak = _peak_bytes(
        lambda: keylog_picker.merge_keylogs([junk_keylog], "tls", out_dir=str(tmp_path)))
    assert merged is not None and merged.key_count == len(VALID_LINES)
    assert open(merged.path, encoding="utf-8").read().splitlines() == VALID_LINES
    assert peak < PEAK_LIMIT_BYTES, f"peak {peak} bytes"


def test_count_distinct_keys_skips_the_junk_line(junk_keylog):
    count, peak = _peak_bytes(lambda: keylog_picker.count_distinct_keys([junk_keylog]))
    assert count == len(VALID_LINES)
    assert peak < PEAK_LIMIT_BYTES, f"peak {peak} bytes"


def test_repair_source_lines_bounded_memory(junk_keylog):
    lines, peak = _peak_bytes(lambda: kc._original_keylog_lines(junk_keylog))
    assert lines == VALID_LINES
    assert peak < PEAK_LIMIT_BYTES, f"peak {peak} bytes"


def test_secret_bundle_sidecar_bounded_memory(tmp_path):
    bundle = {"client_traffic_secret_0": "ab" * 32, "server_traffic_secret_0": "cd" * 32}
    sidecar = _write_junk_then(tmp_path / "s.tls_midstream.secrets.jsonl",
                               json.dumps(bundle) + "\n")
    bundles, peak = _peak_bytes(lambda: pl.load_secret_bundles(sidecar))
    assert bundles == [bundle]
    assert peak < PEAK_LIMIT_BYTES, f"peak {peak} bytes"


def test_sniff_reads_a_bounded_head_only(junk_keylog):
    protocol, peak = _peak_bytes(lambda: keylog_suggest.sniff_keylog_protocol(junk_keylog))
    assert protocol is None  # the records sit past the sniffed head
    assert peak < PEAK_LIMIT_BYTES, f"peak {peak} bytes"


def test_sniff_still_skips_an_overlong_line_inside_the_head(tmp_path):
    path = tmp_path / "k.log"
    path.write_text("#" + "c" * 20000 + "\n" + VALID_LINES[0] + "\n")
    assert keylog_suggest.sniff_keylog_protocol(str(path)) == "tls"


# --------------------------------------------------------------------------- #
# --repair-keylog / relabel copy only valid keylog lines
# --------------------------------------------------------------------------- #

FAKE_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
    "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
    "-----END PRIVATE KEY-----\n"
)
HOSTILE_INPUT = (
    "# SSL/TLS secrets log file, generated by friTap\n"
    f"CLIENT_RANDOM {CR_C} {SECRET_48}\n"
    + FAKE_PEM
    + "some prose: the password is hunter2\n"
    "   # indented comment\n"
    "\n"
    f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {SECRET_32}\n"
)
KEPT_ORIGINALS = [
    f"CLIENT_RANDOM {CR_C} {SECRET_48}",
    f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {SECRET_32}",
]


def _patch_correlators(monkeypatch, tls12_lines=(), tls13_lines=()):
    monkeypatch.setattr("friTap.offline.schannel.correlate.correlate_tls12",
                        lambda _t, _p, _masters: list(tls12_lines))
    monkeypatch.setattr("friTap.offline.schannel.correlate.correlate_tls13",
                        lambda _t, _p, _records: list(tls13_lines))


def _hostile_keylog(tmp_path) -> str:
    path = tmp_path / "keys.log"
    path.write_text(HOSTILE_INPUT)
    return str(path)


def _assert_only_keylog_lines(path: str) -> list:
    content = open(path, encoding="utf-8").read()
    for marker in ("#", "BEGIN", "PRIVATE", "MIIE", "hunter2", "prose"):
        assert marker not in content
    return content.splitlines()


def test_repair_output_holds_no_comment_or_non_keylog_line(tmp_path, monkeypatch, caplog):
    keylog = _hostile_keylog(tmp_path)
    capture = kc.CaptureTls(handshakes=(kc.TlsHandshake("1", CR_B, "", "TLS 1.2"),))
    _patch_correlators(monkeypatch, tls12_lines=[f"CLIENT_RANDOM {CR_B} {SECRET_48}\n"])
    with caplog.at_level(logging.WARNING):
        result = kc.repair_keylog("tshark", "x.pcap", keylog, capture=capture)
    assert result.repaired_path == str(tmp_path / "keys.repaired.keylog")
    lines = _assert_only_keylog_lines(result.repaired_path)
    assert lines == KEPT_ORIGINALS + [f"CLIENT_RANDOM {CR_B} {SECRET_48}"]
    dropped = [r.getMessage() for r in caplog.records if "non-keylog" in r.getMessage()]
    assert len(dropped) == 1 and "skipped 7 " in dropped[0]  # 2 comments + PEM(4) + prose


def test_relabel_output_holds_no_comment_or_non_keylog_line(tmp_path, monkeypatch):
    keylog = _hostile_keylog(tmp_path)
    # Trial decryption says the "handshake" secret is really TRAFFIC_SECRET_0.
    _patch_correlators(monkeypatch, tls13_lines=[
        f"SERVER_TRAFFIC_SECRET_0 {CR_A} {SECRET_32}\n"])
    result = kc.relabel_keylog("tshark", "x.pcap", keylog)
    assert result.repaired_path == str(tmp_path / "keys.relabeled.keylog")
    lines = _assert_only_keylog_lines(result.repaired_path)
    assert lines == [f"CLIENT_RANDOM {CR_C} {SECRET_48}",
                     f"SERVER_TRAFFIC_SECRET_0 {CR_A} {SECRET_32}"]


@pytest.mark.parametrize("repair", [kc.repair_keylog, kc.relabel_keylog])
def test_repair_refuses_a_directory(tmp_path, monkeypatch, repair):
    _patch_correlators(monkeypatch)
    result = repair("tshark", "x.pcap", str(tmp_path), capture=kc.CaptureTls())
    assert result.repaired_path is None and result.tried_secrets == 0
    assert "not a regular file" in result.message


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
@pytest.mark.parametrize("repair", [kc.repair_keylog, kc.relabel_keylog])
def test_repair_never_opens_a_fifo(tmp_path, monkeypatch, repair):
    fifo = tmp_path / "keys.fifo"
    os.mkfifo(fifo)
    _patch_correlators(monkeypatch)
    result = repair("tshark", "x.pcap", str(fifo), capture=kc.CaptureTls())  # must not block
    assert result.repaired_path is None and "not a regular file" in result.message


@pytest.mark.parametrize("repair", [kc.repair_keylog, kc.relabel_keylog])
def test_repair_refuses_an_oversized_keylog(tmp_path, monkeypatch, repair):
    keylog = _hostile_keylog(tmp_path)
    monkeypatch.setattr(keylog_paths, "MANIFEST_FILE_MAX_BYTES", 16)
    _patch_correlators(monkeypatch, tls12_lines=[f"CLIENT_RANDOM {CR_B} {SECRET_48}\n"])
    result = repair("tshark", "x.pcap", keylog, capture=kc.CaptureTls())
    assert result.repaired_path is None and "not a regular file" in result.message
