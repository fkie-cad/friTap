"""The MTProto optional-dependency hint surfaces wherever MTProto is requested.

cryptography IS installed in CI, so we simulate the missing-backend state by
monkeypatching the availability probe, and assert the actionable hint is shown.
"""

from __future__ import annotations

import pytest

import friTap.offline.mtproto as mt


def _simulate_missing_backend_and_tshark(monkeypatch):
    """Backend "missing" + find_tshark raising, so the CLI hint prints before
    any tshark work is attempted (the two CLI tests share this setup)."""
    from friTap.offline import cli

    monkeypatch.setattr(mt, "mtproto_backend_available", lambda: False)
    monkeypatch.setattr(
        cli, "find_tshark",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no tshark")),
    )
    return cli


def test_backend_available_true_in_ci():
    # cryptography is a test/runtime dep here.
    pytest.importorskip("cryptography")
    assert mt.mtproto_backend_available() is True


def test_hint_mentions_crypto_install():
    assert "pip install cryptography" in mt.MTPROTO_DEPENDENCY_HINT


def test_backend_unavailable_when_probe_fails(monkeypatch):
    monkeypatch.setattr(mt, "mtproto_backend_available", lambda: False)
    assert mt.mtproto_backend_available() is False


def test_offline_cli_prints_hint_when_backend_missing(tmp_path, monkeypatch, capsys):
    cli = _simulate_missing_backend_and_tshark(monkeypatch)

    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00" * 8)  # isfile() true; content irrelevant (we bail at tshark)
    keys = tmp_path / "tg.keys"
    keys.write_text("# empty\n")

    rc = cli.run_offline_pcap_to_tap([
        "--from-pcap", str(pcap), "--mtproto-keylog", str(keys), "--tap", str(tmp_path / "o.tap"),
    ])
    out = capsys.readouterr().out
    assert "pip install cryptography" in out
    assert "MTProto streams in this capture will be skipped" in out
    assert rc == 3  # tshark-missing exit (the hint already printed before it)


def test_offline_cli_no_hint_without_mtproto_keylog(tmp_path, monkeypatch, capsys):
    cli = _simulate_missing_backend_and_tshark(monkeypatch)
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00" * 8)

    cli.run_offline_pcap_to_tap(["--from-pcap", str(pcap)])
    assert "pip install cryptography" not in capsys.readouterr().out


def test_backend_available_requires_cryptography_not_tgcrypto(monkeypatch):
    """tgcrypto alone is insufficient (it can't do the transport AES-CTR).

    Simulate a tgcrypto-only environment and assert the pipeline gate reports
    UNAVAILABLE and _require_backend raises — so the install hint is shown
    instead of a raw ImportError crashing later in transport CTR.
    """
    pytest.importorskip("cryptography")
    from friTap.offline.mtproto import crypto

    monkeypatch.setattr(crypto, "_BACKEND_RESOLVED", True)
    monkeypatch.setattr(crypto, "_ECB_ENCRYPT", None)   # cryptography "absent"
    monkeypatch.setattr(crypto, "_ECB_DECRYPT", None)
    monkeypatch.setattr(crypto, "_TGCRYPTO", object())  # tgcrypto "present"

    assert crypto.backend_available() is False
    with pytest.raises(crypto.MtprotoDependencyError):
        crypto._require_backend()


def test_transport_ctr_raises_clean_error_without_cryptography(monkeypatch):
    """If CTR is reached without cryptography, it raises MtprotoDependencyError."""
    import sys

    from friTap.offline.mtproto import MtprotoDependencyError
    from friTap.offline.mtproto import transport

    # Hide the cryptography ciphers module so the lazy import inside _ctr_cipher fails.
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.ciphers", None)
    with pytest.raises(MtprotoDependencyError):
        transport._ctr_cipher(b"\x00" * 32, b"\x00" * 16)


def test_tui_protocol_modal_lists_mtproto():
    pytest.importorskip("textual")
    from friTap.tui.modals import protocol_modal

    names = {name for name, _ in protocol_modal._BUILTIN_PROTOCOLS}
    assert "mtproto" in names
