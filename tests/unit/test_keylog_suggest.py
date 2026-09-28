"""Tests for the pcap keylog suggestion and keylog protocol sniffing helpers."""

from __future__ import annotations

import os
import time
from datetime import datetime

import pytest

from friTap.offline import keylog_suggest as ks
from friTap.protocols.mtproto_keylog_spec import format_line as mtproto_format_line

_BASE_MTIME = 1_700_000_000


def _touch(path, mtime: float, text: str = "") -> str:
    path.write_text(text)
    os.utime(path, (mtime, mtime))
    return str(path)


def _pcap(tmp_path, name: str = "capture.pcap", mtime: float = _BASE_MTIME) -> str:
    return _touch(tmp_path / name, mtime)


# --- timestamp tokens ------------------------------------------------------

@pytest.mark.parametrize(
    "name, expected",
    [
        ("cap_20240131_120000.pcap", datetime(2024, 1, 31, 12, 0, 0)),
        ("cap_20240131-1205.pcap", datetime(2024, 1, 31, 12, 5, 0)),
        ("cap20240131T120530.pcapng", datetime(2024, 1, 31, 12, 5, 30)),
        ("keys_2024-01-31_12-05-30.log", datetime(2024, 1, 31, 12, 5, 30)),
        ("keys_2024-01-31T12:05.log", datetime(2024, 1, 31, 12, 5, 0)),
        ("keys 2024-01-31 12.05.07.log", datetime(2024, 1, 31, 12, 5, 7)),
        (
            "keys_1700000000.log",
            datetime.fromtimestamp(1_700_000_000),  # naive local time
        ),
    ],
)
def test_timestamp_token_variants(name, expected):
    assert ks._timestamp_token(name) == expected


@pytest.mark.parametrize(
    "name",
    [
        "capture.pcap",
        "cap_20241331_120000.pcap",  # month 13
        "cap_20240230_120000.pcap",  # Feb 30
        "keys_0999999999.log",  # epoch below range
        "keys_12345678901.log",  # 11 digits, not standalone 10
    ],
)
def test_timestamp_token_rejects(name):
    assert ks._timestamp_token(name) is None


def test_epoch_token_is_local_time_comparable_with_dashed():
    local = datetime(2024, 1, 31, 12, 5, 30)
    epoch = int(time.mktime(local.timetuple()))
    assert ks._timestamp_token(f"keys_{epoch}.log") == local
    assert ks._timestamp_token(f"keys_{epoch}.log") == ks._timestamp_token(
        "cap_2024-01-31_12-05-30.pcap"
    )


def test_epoch_keylog_matches_dashed_pcap_by_token(tmp_path):
    epoch = int(time.mktime(datetime(2024, 1, 31, 12, 5, 30).timetuple()))
    pcap = _pcap(tmp_path, "cap_2024-01-31_12-05-30.pcap")
    _touch(tmp_path / f"keys_{epoch}.log", _BASE_MTIME + 250)
    _touch(tmp_path / "keylog_other.log", _BASE_MTIME + 1)
    assert ks.suggest_keylog_for_pcap(pcap).endswith(f"keys_{epoch}.log")


@pytest.mark.parametrize(
    "name, expected",
    [
        ("cap_20241331_000000_20240131_120000.pcap", datetime(2024, 1, 31, 12, 0, 0)),
        ("keys_2024-02-30_10-00_2024-01-31_12-05.log", datetime(2024, 1, 31, 12, 5, 0)),
        ("cap_20240230_120000_1700000000.pcap", datetime.fromtimestamp(1_700_000_000)),
    ],
)
def test_timestamp_token_skips_invalid_first_match(name, expected):
    assert ks._timestamp_token(name) == expected


# --- suggestion ------------------------------------------------------------

def test_filename_token_beats_closer_mtime(tmp_path):
    pcap = _pcap(tmp_path, "cap_20240131_120000.pcap")
    _touch(tmp_path / "sslkeys_20240131_120010.log", _BASE_MTIME + 200)
    _touch(tmp_path / "keylog_other.log", _BASE_MTIME + 1)
    assert ks.suggest_keylog_for_pcap(pcap) == os.path.join(
        str(tmp_path), "sslkeys_20240131_120010.log"
    )


def test_closest_filename_token_wins(tmp_path):
    pcap = _pcap(tmp_path, "cap_20240131_120000.pcap")
    _touch(tmp_path / "keys_20240131_120200.log", _BASE_MTIME)
    _touch(tmp_path / "keys_20240131_115950.log", _BASE_MTIME)
    assert ks.suggest_keylog_for_pcap(pcap).endswith("keys_20240131_115950.log")


def test_mtime_within_window_closest_wins(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "a_keys.log", _BASE_MTIME + 100)
    _touch(tmp_path / "b_keys.keylog", _BASE_MTIME - 20)
    assert ks.suggest_keylog_for_pcap(pcap) == os.path.join(str(tmp_path), "b_keys.keylog")


def test_mtime_outside_window_ignored(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "keys.log", _BASE_MTIME + ks.DEFAULT_MAX_DELTA_S + 1)
    assert ks.suggest_keylog_for_pcap(pcap) is None
    assert ks.suggest_keylog_for_pcap(pcap, max_delta_s=ks.DEFAULT_MAX_DELTA_S + 100) is not None


def test_keylog_flushed_minutes_after_capture_is_suggested(tmp_path):
    # Real case: an lsass memory-scan keylog written ~5 min after the pcap.
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "keys_lsass.log", _BASE_MTIME + 302)
    assert ks.suggest_keylog_for_pcap(pcap) == os.path.join(str(tmp_path), "keys_lsass.log")


def test_keylog_written_during_capture_window_beats_later_one(tmp_path, monkeypatch):
    pcap = _pcap(tmp_path)
    # The capture ran from BASE-120 to BASE; a keylog last written inside that
    # span is a closer match than one flushed shortly after it ended.
    monkeypatch.setattr(ks, "_capture_window", lambda _p: (_BASE_MTIME - 120, _BASE_MTIME))
    _touch(tmp_path / "keys_during.log", _BASE_MTIME - 60)
    _touch(tmp_path / "keys_after.log", _BASE_MTIME + 30)
    assert ks.suggest_keylog_for_pcap(pcap) == os.path.join(str(tmp_path), "keys_during.log")


def test_long_lived_keylog_appended_later_is_not_suggested(tmp_path):
    # A keylog appended to across many sessions (last write days later) must not
    # match just because it was created before the capture.
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "mtproto_memscan.mtproto.keylog", _BASE_MTIME + 2 * 86400)
    assert ks.suggest_keylog_for_pcap(pcap) is None


def test_filename_token_outside_window_falls_back_to_mtime(tmp_path):
    pcap = _pcap(tmp_path, "cap_20240131_120000.pcap")
    _touch(tmp_path / "keys_20240131_130000.log", _BASE_MTIME + 5000)
    _touch(tmp_path / "keys_plain.log", _BASE_MTIME + 10)
    assert ks.suggest_keylog_for_pcap(pcap).endswith("keys_plain.log")


def test_non_key_and_non_log_files_ignored(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "capture.log", _BASE_MTIME)
    _touch(tmp_path / "keys.txt", _BASE_MTIME)
    (tmp_path / "keys_dir.log").mkdir()
    assert ks.suggest_keylog_for_pcap(pcap) is None


def test_uppercase_name_matches(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "SSLKEYS.LOG", _BASE_MTIME)
    assert ks.suggest_keylog_for_pcap(pcap).endswith("SSLKEYS.LOG")


def test_exclude_respected(tmp_path):
    pcap = _pcap(tmp_path)
    near = _touch(tmp_path / "keys_near.log", _BASE_MTIME + 1)
    _touch(tmp_path / "keys_far.log", _BASE_MTIME + 50)
    relative_near = os.path.relpath(near)
    result = ks.suggest_keylog_for_pcap(pcap, exclude=[relative_near])
    assert result.endswith("keys_far.log")


def test_pcap_itself_never_suggested(tmp_path):
    pcap = _pcap(tmp_path, "keydump.keylog")
    assert ks.suggest_keylog_for_pcap(pcap) is None


def test_relative_pcap_path_keeps_form(tmp_path, monkeypatch):
    _pcap(tmp_path)
    _touch(tmp_path / "keys.log", _BASE_MTIME)
    monkeypatch.chdir(tmp_path)
    assert ks.suggest_keylog_for_pcap("capture.pcap") == "keys.log"


def test_missing_directory_returns_none(tmp_path):
    assert ks.suggest_keylog_for_pcap(str(tmp_path / "nope" / "capture.pcap")) is None


def test_missing_pcap_with_candidates_returns_none(tmp_path):
    _touch(tmp_path / "keys.log", _BASE_MTIME)
    assert ks.suggest_keylog_for_pcap(str(tmp_path / "missing.pcap")) is None


# --- content (coverage) ranking ------------------------------------------------

_CR_1 = "a1" * 32
_CR_2 = "b2" * 32
_CR_3 = "c3" * 32


def _tls_keylog_text(*client_randoms: str) -> str:
    return "".join(f"CLIENT_RANDOM {cr} {'11' * 48}\r\n" for cr in client_randoms)


def test_coverage_beats_timestamp(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "keys_lsass.log", _BASE_MTIME + 5, _tls_keylog_text("ff" * 32))
    _touch(tmp_path / "keys_power.log", _BASE_MTIME + 5000, _tls_keylog_text(_CR_1, _CR_2))
    crs = {_CR_1, _CR_2}
    assert ks.suggest_keylog_for_pcap(pcap).endswith("keys_lsass.log")
    assert ks.suggest_keylog_for_pcap(pcap, capture_crs=crs).endswith("keys_power.log")
    suggestion = ks.suggest_keylog_with_evidence(pcap, capture_crs=crs)
    assert suggestion == ks.Suggestion(os.path.join(str(tmp_path), "keys_power.log"), 2, 2)


def test_higher_coverage_wins(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "a_keys.log", _BASE_MTIME, _tls_keylog_text(_CR_1))
    _touch(tmp_path / "b_keys.log", _BASE_MTIME + 9000, _tls_keylog_text(_CR_1, _CR_2))
    result = ks.suggest_keylog_with_evidence(pcap, capture_crs={_CR_1, _CR_2, _CR_3})
    assert result.path.endswith("b_keys.log") and (result.covered, result.total) == (2, 3)


def test_coverage_tie_broken_by_time(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "a_keys.log", _BASE_MTIME + 400, _tls_keylog_text(_CR_1))
    _touch(tmp_path / "b_keys.log", _BASE_MTIME + 10, _tls_keylog_text(_CR_1))
    assert ks.suggest_keylog_for_pcap(pcap, capture_crs={_CR_1}).endswith("b_keys.log")


def test_coverage_tie_outside_time_window_still_suggested(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "a_keys.log", _BASE_MTIME + 90000, _tls_keylog_text(_CR_1))
    _touch(tmp_path / "b_keys.log", _BASE_MTIME + 90000, _tls_keylog_text(_CR_1))
    assert ks.suggest_keylog_for_pcap(pcap, capture_crs={_CR_1}).endswith("a_keys.log")


def test_zero_coverage_falls_back_to_time_with_evidence(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "keys_lsass.log", _BASE_MTIME + 302, _tls_keylog_text("ff" * 32))
    suggestion = ks.suggest_keylog_with_evidence(pcap, capture_crs={_CR_1, _CR_2, _CR_3})
    assert suggestion.path.endswith("keys_lsass.log")
    assert (suggestion.covered, suggestion.total) == (0, 3)


def test_evidence_absent_without_capture_crs(tmp_path):
    pcap = _pcap(tmp_path)
    _touch(tmp_path / "keys.log", _BASE_MTIME)
    suggestion = ks.suggest_keylog_with_evidence(pcap)
    assert suggestion.covered is None and suggestion.total is None


def test_rank_keylogs_by_coverage(tmp_path):
    low = _touch(tmp_path / "low_keys.log", _BASE_MTIME, _tls_keylog_text(_CR_1))
    high = _touch(tmp_path / "high_keys.log", _BASE_MTIME, _tls_keylog_text(_CR_1, _CR_2))
    missing = str(tmp_path / "missing_keys.log")
    assert ks.rank_keylogs_by_coverage([low, missing, high], {_CR_1, _CR_2}) == [
        (high, 2), (low, 1), (missing, 0),
    ]


# --- sniffing --------------------------------------------------------------

def _mtproto_line() -> str:
    line = mtproto_format_line(dc_id=2, auth_key_id="11" * 8, auth_key="22" * 256)
    assert line is not None
    return line


@pytest.mark.parametrize(
    "content, expected",
    [
        (f"# SSL keylog\n\nCLIENT_RANDOM {'00' * 32} {'ab' * 48}\n", "tls"),
        (f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {'00' * 32} {'ab' * 32}\n", "tls"),
        (f"SERVER_TRAFFIC_SECRET_0 {'00' * 32} {'ab' * 32}\n", "tls"),
        (f"EXPORTER_SECRET {'00' * 32} {'ab' * 32}\n", "tls"),
        (f"schannel_tls13_secret {'ab' * 32} - 772\n", "tls"),
        ("RC4_KEY 6672697461702d7263342d64656d6f2d6b6579 19 RC4_set_key unknown 4711\n", "custom"),
        ("unknown junk\nmore junk\n", None),
        ("", None),
    ],
)
def test_sniff_keylog_protocol(tmp_path, content, expected):
    path = tmp_path / "keys.log"
    path.write_text(content)
    assert ks.sniff_keylog_protocol(str(path)) == expected


def test_sniff_rc4_spec_line(tmp_path):
    from friTap.protocols.rc4_keylog_spec import format_line as rc4_format_line

    line = rc4_format_line(key="ab" * 16, source="RC4_set_key", direction="out", assoc="7")
    assert line is not None
    path = tmp_path / "rc4_keys.log"
    path.write_text(f"# friTap RC4 keylog\n{line}\n")
    assert ks.sniff_keylog_protocol(str(path)) == "custom"


def test_sniff_malformed_rc4_is_none(tmp_path):
    path = tmp_path / "rc4_keys.log"
    path.write_text("RC4_KEY abcd 5 RC4_set_key out -\n")  # key_len disagrees with hex
    assert ks.sniff_keylog_protocol(str(path)) is None


def test_sniff_mtproto(tmp_path):
    path = tmp_path / "mtproto_keys.log"
    path.write_text(f"# friTap MTProto keylog\n{_mtproto_line()}\n")
    assert ks.sniff_keylog_protocol(str(path)) == "mtproto"


def test_sniff_malformed_mtproto_is_none(tmp_path):
    path = tmp_path / "mtproto_keys.log"
    path.write_text("MTPROTO_AUTH_KEY 2 deadbeef short perm\n")
    assert ks.sniff_keylog_protocol(str(path)) is None


def test_sniff_mtproto_e2e_only(tmp_path):
    """An E2E-only keylog (Telegram Secret-Chat keys) must sniff as mtproto, not
    fall through to None and get mis-filed under TLS by the manifest loader."""
    from friTap.protocols.mtproto_keylog_spec import format_e2e_line
    line = format_e2e_line(key_fingerprint="11" * 8, shared_key="22" * 256, chat_id=-1)
    assert line is not None
    path = tmp_path / "keys_mtprot.log"
    path.write_text(f"# friTap MTProto keylog\n{line}\n")
    assert ks.sniff_keylog_protocol(str(path)) == "mtproto"


def test_sniff_mtproto_obf_only(tmp_path):
    """An obf-key-only keylog (memory-scan MTPROTO_OBF_KEY sidecar) sniffs mtproto."""
    from friTap.protocols.mtproto_keylog_spec import format_obf_line
    line = format_obf_line(
        key_out="aa" * 32, iv_out="bb" * 16, key_in="cc" * 32, iv_in="dd" * 16,
        num_out=0, num_in=0, endpoint="-",
    )
    assert line is not None
    path = tmp_path / "obf.mtproto.keylog"
    path.write_text(f"{line}\n")
    assert ks.sniff_keylog_protocol(str(path)) == "mtproto"


def test_sniff_respects_max_lines(tmp_path):
    path = tmp_path / "keys.log"
    path.write_text("junk\n" * 3 + f"CLIENT_RANDOM {'00' * 32} {'ab' * 48}\n")
    assert ks.sniff_keylog_protocol(str(path), max_lines=2) is None
    assert ks.sniff_keylog_protocol(str(path), max_lines=4) == "tls"


def test_sniff_missing_file_is_none(tmp_path):
    assert ks.sniff_keylog_protocol(str(tmp_path / "nope.log")) is None
