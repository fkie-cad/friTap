"""WP9: an (untrusted) ``<pcap>.fritap.json`` manifest cannot exfiltrate files.

friTap's own manifests legitimately name absolute paths and CWD-relative paths
(``-k /tmp/k.log -p out/cap.pcap``), so manifest paths are not confined to the
pcap directory. Instead:

* a manifest path must name a bounded regular file (no FIFO/device/directory);
* when manifest-named files are merged into ``<stem>.merged.<proto>.keylog``,
  only well-formed keylog lines are copied — a private key contributes nothing;
* protocol names (used in output file names) must be ``^[a-z0-9_]+$``;
* malformed port lists are ignored instead of aborting.
"""

from __future__ import annotations

import argparse
import json
import os

import pytest

from friTap.offline import cli, keylog_paths
from friTap.offline.keylog_paths import (
    is_bounded_regular_file,
    is_safe_protocol_name,
    validate_manifest_path,
)
from friTap.offline.keylog_picker import merge_keylogs, merge_memory_scan_sidecars
from friTap.output.keylog_format import is_keylog_shaped_line, is_valid_keylog_line_for

CR = "aa" * 32
SECRET = "bb" * 48
TLS_LINE = f"CLIENT_RANDOM {CR} {SECRET}"
FAKE_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
    "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
    "-----END PRIVATE KEY-----\n"
)


@pytest.fixture
def capture(tmp_path):
    """``caps/cap.pcapng`` with an in-dir keylog, plus keylog + PEM outside."""
    caps = tmp_path / "caps"
    caps.mkdir()
    pcap = caps / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    (caps / "keys.log").write_text(TLS_LINE + "\n")
    outside_keylog = tmp_path / "elsewhere_k.log"
    outside_keylog.write_text(TLS_LINE + "\n")
    pem = tmp_path / "id_rsa"
    pem.write_text(FAKE_PEM)
    return caps, pcap, outside_keylog, pem


def _write_manifest(pcap, data) -> None:
    (pcap.parent / (pcap.name + cli.MANIFEST_SUFFIX)).write_text(json.dumps(data))


def _ns(pcap, **kw):
    base = dict(from_pcap=str(pcap), keylog=None, tls_ports=[], quic_ports=[],
                decode_as=[], tls_heuristic=False)
    base.update(kw)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------------- #
# validate_manifest_path
# --------------------------------------------------------------------------- #

def test_relative_path_prefers_manifest_dir(capture):
    caps, _pcap, _k, _pem = capture
    assert validate_manifest_path(str(caps), "keys.log") == str(caps / "keys.log")


def test_absolute_path_outside_manifest_dir_is_accepted(capture):
    caps, _pcap, outside, _pem = capture
    assert validate_manifest_path(str(caps), str(outside)) == str(outside)


def test_cwd_relative_fallback(capture, monkeypatch):
    caps, _pcap, outside, _pem = capture
    monkeypatch.chdir(outside.parent)
    assert validate_manifest_path(str(caps), outside.name) == outside.name


def test_missing_path_returned_unchanged(capture):
    caps, _pcap, _k, _pem = capture
    assert validate_manifest_path(str(caps), "/no/such/k.log") == "/no/such/k.log"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_fifo_is_rejected(capture):
    caps, _pcap, _k, _pem = capture
    os.mkfifo(caps / "pipe.log")
    assert validate_manifest_path(str(caps), "pipe.log") is None
    assert validate_manifest_path(str(caps), str(caps / "pipe.log")) is None
    assert is_bounded_regular_file(str(caps / "pipe.log")) is False


def test_directory_is_rejected(capture):
    caps, _pcap, _k, _pem = capture
    (caps / "adir").mkdir()
    assert validate_manifest_path(str(caps), "adir") is None


def test_oversized_file_is_rejected(capture, monkeypatch):
    caps, _pcap, _k, _pem = capture
    monkeypatch.setattr(keylog_paths, "MANIFEST_FILE_MAX_BYTES", 4)
    assert validate_manifest_path(str(caps), "keys.log") is None


@pytest.mark.parametrize("bad", [None, "", 42, ["keys.log"], "a\x00b"])
def test_non_string_or_nul_paths_are_rejected(capture, bad):
    caps, _pcap, _k, _pem = capture
    assert validate_manifest_path(str(caps), bad) is None


# --------------------------------------------------------------------------- #
# absolute keylog outside the pcap dir works end to end
# --------------------------------------------------------------------------- #

def test_absolute_keylog_outside_pcap_dir_is_used(capture):
    _caps, pcap, outside, _pem = capture
    _write_manifest(pcap, {"keylog": str(outside), "tls_ports": [8443]})
    merged = cli.merge_manifest(_ns(pcap), cli.load_manifest(str(pcap)))
    assert merged["keylog_path"] == str(outside)
    assert merged["tls_ports"] == (8443,)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_load_manifest_nulls_fifo_paths(capture):
    caps, pcap, outside, _pem = capture
    os.mkfifo(caps / "pipe.log")
    _write_manifest(pcap, {
        "keylog": "pipe.log",
        "tls_midstream_secrets": str(caps / "pipe.log"),
        "memory_scan_keylogs": {"tls": "pipe.log", "mtproto": str(outside)},
    })
    loaded = cli.load_manifest(str(pcap))
    assert loaded["keylog"] is None
    assert loaded["tls_midstream_secrets"] is None
    assert loaded["memory_scan_keylogs"] == {"tls": None, "mtproto": str(outside)}


# --------------------------------------------------------------------------- #
# exfil defence at the sink: merge copies only keylog lines
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("protocol", ["tls", "mtproto", "rc4"])
def test_merging_a_private_key_copies_zero_lines(capture, protocol):
    caps, _pcap, _k, pem = capture
    merged = merge_keylogs([str(pem)], protocol, out_dir=str(caps))
    assert merged is not None and merged.key_count == 0
    with open(merged.path, encoding="utf-8") as fh:
        assert fh.read() == ""


def test_manifest_sidecar_pointing_at_private_key_leaks_nothing(capture):
    caps, pcap, _k, pem = capture
    _write_manifest(pcap, {"keylog": "keys.log", "memory_scan_keylogs": {"tls": str(pem)}})
    merged = cli.merge_manifest(_ns(pcap), cli.load_manifest(str(pcap)))
    with open(merged["keylog_path"], encoding="utf-8") as fh:
        assert fh.read() == TLS_LINE + "\n"
    for produced in caps.iterdir():
        if produced.is_file():
            assert "PRIVATE KEY" not in produced.read_text(errors="replace")
            assert "MIIEvQ" not in produced.read_text(errors="replace")


def test_merge_drops_comments_and_free_text(capture):
    caps, _pcap, _k, _pem = capture
    src = caps / "mixed.log"
    src.write_text(f"# header\n{TLS_LINE}\nsome free text here\nCLIENT_RANDOM zz yy\n")
    merged = merge_keylogs([str(src)], "tls", out_dir=str(caps))
    assert merged.key_count == 1
    with open(merged.path, encoding="utf-8") as fh:
        assert fh.read() == TLS_LINE + "\n"


def test_merge_warns_once_about_dropped_lines(capture, caplog):
    caps, _pcap, _k, pem = capture
    with caplog.at_level("WARNING", logger="friTap.offline.keylog_picker"):
        merge_keylogs([str(pem)], "tls", out_dir=str(caps))
    assert len([r for r in caplog.records if "skipped" in r.getMessage()]) == 1


@pytest.mark.parametrize("line", [
    "MTPROTO_AUTH_KEY 2 " + "ab" * 8 + " " + "cd" * 256 + " perm",
    "MTPROTO_E2E_KEY " + "11" * 8 + " " + "22" * 256 + " -1",
    "MTPROTO_OBF_KEY " + " ".join(["aa" * 32, "bb" * 16, "cc" * 32, "dd" * 16])
    + " 0 0 149.154.167.51:443",
    "RC4_KEY 00112233 4 memscan-trial c2s -",
    "WG_KEY YWJjZA==",
])
def test_generic_shape_accepts_real_formats(line):
    assert is_keylog_shaped_line(line)
    assert is_valid_keylog_line_for("mtproto", line)


@pytest.mark.parametrize("line", [
    "-----BEGIN PRIVATE KEY-----",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
    "root:x:0:0:root:/root:/bin/bash",
    "aws_secret_access_key = wJalrXUtnFEMI",
    "ssh-rsa AAAAB3Nza user@host",
    "LABEL",
])
def test_generic_shape_rejects_non_keylog(line):
    assert not is_keylog_shaped_line(line)


def test_tls_merge_requires_nss_lines(capture):
    assert is_valid_keylog_line_for("tls", TLS_LINE)
    assert not is_valid_keylog_line_for("tls", "WG_KEY YWJjZA==")


# --------------------------------------------------------------------------- #
# protocol names / ports
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", ["tls", "mtproto", "rc4", "schannel_unpaired", "p2"])
def test_safe_protocol_names(name):
    assert is_safe_protocol_name(name)


@pytest.mark.parametrize("name", ["../x", "a/b", "TLS", "", "a.b", "a b", None, 3])
def test_unsafe_protocol_names(name):
    assert not is_safe_protocol_name(name)


def test_bad_proto_names_dropped_from_manifest(capture):
    caps, pcap, _k, _pem = capture
    resolved = cli.resolve_manifest_keylog_paths(str(pcap), {
        "../../evil_keylog": "keys.log",
        "mtproto_keylog": "keys.log",
        "keylogs": {"a/b": "keys.log", "mtproto": "keys.log"},
        "memory_scan_keylogs": {"../x": "keys.log", "tls": "keys.log"},
    })
    assert "../../evil_keylog" not in resolved
    assert resolved["mtproto_keylog"] == str(caps / "keys.log")
    assert resolved["keylogs"] == {"mtproto": str(caps / "keys.log")}
    assert resolved["memory_scan_keylogs"] == {"tls": str(caps / "keys.log")}


def test_load_manifest_drops_bad_proto_names(capture):
    _caps, pcap, _k, _pem = capture
    _write_manifest(pcap, {"a/b_keylog": "keys.log", "keylogs": {"../x": "keys.log"}})
    loaded = cli.load_manifest(str(pcap))
    assert "a/b_keylog" not in loaded
    assert loaded["keylogs"] == {}


def test_non_dict_keylog_map_is_dropped(capture):
    _caps, pcap, _k, _pem = capture
    resolved = cli.resolve_manifest_keylog_paths(str(pcap), {"keylogs": ["x"]})
    assert "keylogs" not in resolved


def test_non_string_keylog_value_becomes_none(capture):
    _caps, pcap, _k, _pem = capture
    resolved = cli.resolve_manifest_keylog_paths(str(pcap), {"keylog": ["/etc/passwd"]})
    assert resolved["keylog"] is None


@pytest.mark.parametrize("bad", ["443", [443, "x"], [0], [70000], [True], {"a": 1}, 443])
def test_bad_ports_are_ignored(bad):
    assert cli.manifest_ports({"tls_ports": bad}, "tls_ports") == []


def test_good_ports_are_kept():
    assert cli.manifest_ports({"quic_ports": [443, 8443]}, "quic_ports") == [443, 8443]
    assert cli.manifest_ports({}, "quic_ports") == []


def test_bad_ports_do_not_abort_merge(capture):
    _caps, pcap, _k, _pem = capture
    _write_manifest(pcap, {"tls_ports": "443", "quic_ports": [1, 2, 99999]})
    merged = cli.merge_manifest(_ns(pcap), cli.load_manifest(str(pcap)))
    assert merged["tls_ports"] == ()
    assert merged["quic_ports"] == ()


# --------------------------------------------------------------------------- #
# merge_keylogs input / name guards
# --------------------------------------------------------------------------- #

def test_merge_keylogs_refuses_unsafe_protocol(capture):
    caps, _pcap, _k, _pem = capture
    assert merge_keylogs([str(caps / "keys.log")], "../evil", out_dir=str(caps)) is None
    assert not any(p.name.endswith(".keylog") for p in caps.iterdir())


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_merge_keylogs_skips_fifo_input(capture):
    caps, _pcap, _k, _pem = capture
    os.mkfifo(caps / "pipe.log")
    merged = merge_keylogs(
        [str(caps / "pipe.log"), str(caps / "keys.log")], "tls", out_dir=str(caps))
    assert merged is not None and merged.key_count == 1


def test_memory_scan_sidecar_merge_valid_still_works(capture):
    caps, _pcap, _k, _pem = capture
    (caps / "ms.mtproto.keylog").write_text("MTPROTO_OBF_KEY aa\n")
    result = merge_memory_scan_sidecars(
        {"mtproto": str(caps / "ms.mtproto.keylog")}, lambda _p: None, out_dir=str(caps))
    assert set(result) == {"mtproto"}
    assert os.path.basename(result["mtproto"]).endswith(".merged.mtproto.keylog")
