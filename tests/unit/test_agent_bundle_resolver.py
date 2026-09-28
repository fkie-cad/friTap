#!/usr/bin/env python3
"""``_resolve_agent_bundle_path`` prefers an in-sync full bundle when present.

A full agent bundle (``fritap_agent_full.js``) is only auto-loaded while its
sidecar (``fritap_agent_full.js.src``, written by ``dev/compile_agent.sh``)
still holds the sha256 of the shipped public bundle. A stale or unverifiable
full bundle would silently drop recent public fixes, so friTap warns and falls
back to the public bundle instead. ``FRITAP_AGENT_BUNDLE`` always wins.
"""

from __future__ import annotations

import hashlib
import logging
import types

import pytest

from friTap.legacy import ssl_logger_core
from friTap.legacy.ssl_logger_core import SSL_Logger

LOGGER_NAME = "test.bundle_resolver"
PUBLIC_SOURCE = b"// public agent bundle\n"


@pytest.fixture
def bundle_dir(tmp_path, monkeypatch):
    """A fake package dir holding a public and a full bundle, set as ``here``."""
    (tmp_path / "fritap_agent.js").write_bytes(PUBLIC_SOURCE)
    (tmp_path / "fritap_agent_full.js").write_bytes(b"// full agent bundle\n")
    monkeypatch.setattr(ssl_logger_core, "here", str(tmp_path))
    monkeypatch.delenv("FRITAP_AGENT_BUNDLE", raising=False)
    return tmp_path


@pytest.fixture
def logger_obj():
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger(LOGGER_NAME)
    obj._config = types.SimpleNamespace(debug=False, debug_output=False)
    obj.agent_script = "fritap_agent.js"
    obj._discover_agent_bundle = lambda: None
    return obj


def _write_sidecar(bundle_dir, digest):
    (bundle_dir / "fritap_agent_full.js.src").write_text(digest + "\n")


def test_matching_sidecar_loads_full_bundle(bundle_dir, logger_obj, caplog):
    _write_sidecar(bundle_dir, hashlib.sha256(PUBLIC_SOURCE).hexdigest())

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        first = logger_obj._resolve_agent_bundle_path()
        second = logger_obj._resolve_agent_bundle_path()

    assert first == second == str(bundle_dir / "fritap_agent_full.js")
    notices = [r for r in caplog.records if "Loading full agent bundle" in r.getMessage()]
    assert len(notices) == 1, "the full-bundle notice must be logged only once"
    assert notices[0].levelno == logging.INFO


def test_mismatched_sidecar_warns_and_falls_back(bundle_dir, logger_obj, caplog):
    _write_sidecar(bundle_dir, hashlib.sha256(b"an older public bundle").hexdigest())

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        resolved = logger_obj._resolve_agent_bundle_path()

    assert resolved == str(bundle_dir / "fritap_agent.js")
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "older than the public agent" in warnings[0].getMessage()


def test_missing_sidecar_warns_and_falls_back(bundle_dir, logger_obj, caplog):
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        resolved = logger_obj._resolve_agent_bundle_path()

    assert resolved == str(bundle_dir / "fritap_agent.js")
    assert any(
        r.levelno == logging.WARNING and "falling back to the public bundle" in r.getMessage()
        for r in caplog.records
    )


def test_garbled_sidecar_warns_and_falls_back(bundle_dir, logger_obj, caplog):
    # Non-UTF-8 bytes raise UnicodeDecodeError (a ValueError, not an OSError):
    # must be treated as out of sync instead of crashing startup.
    (bundle_dir / "fritap_agent_full.js.src").write_bytes(b"\xff\xfe\x80garbled\n")

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        resolved = logger_obj._resolve_agent_bundle_path()

    assert resolved == str(bundle_dir / "fritap_agent.js")
    assert any(
        r.levelno == logging.WARNING and "falling back to the public bundle" in r.getMessage()
        for r in caplog.records
    )


def test_env_override_wins_over_full_bundle(bundle_dir, logger_obj, monkeypatch, tmp_path):
    _write_sidecar(bundle_dir, hashlib.sha256(PUBLIC_SOURCE).hexdigest())
    override = tmp_path / "custom_bundle.js"
    monkeypatch.setenv("FRITAP_AGENT_BUNDLE", str(override))

    assert logger_obj._resolve_agent_bundle_path() == str(override)


def test_resolution_is_cached_per_instance(bundle_dir, logger_obj, monkeypatch):
    _write_sidecar(bundle_dir, hashlib.sha256(PUBLIC_SOURCE).hexdigest())
    calls = []
    real_sha256_file = ssl_logger_core.sha256_file
    monkeypatch.setattr(
        ssl_logger_core, "sha256_file",
        lambda path: calls.append(path) or real_sha256_file(path),
    )

    first = logger_obj._resolve_agent_bundle_path()
    second = logger_obj._resolve_agent_bundle_path()

    assert first == second == str(bundle_dir / "fritap_agent_full.js")
    assert len(calls) == 1, "the public bundle must be hashed only once per instance"


def test_env_override_wins_over_cached_resolution(bundle_dir, logger_obj, monkeypatch, tmp_path):
    cached = logger_obj._resolve_agent_bundle_path()
    override = tmp_path / "custom_bundle.js"
    monkeypatch.setenv("FRITAP_AGENT_BUNDLE", str(override))

    assert logger_obj._resolve_agent_bundle_path() == str(override)
    monkeypatch.delenv("FRITAP_AGENT_BUNDLE")
    assert logger_obj._resolve_agent_bundle_path() == cached


def test_sha256_file_matches_hashlib(tmp_path):
    from friTap.fritap_utility import sha256_file

    payload = b"x" * ((1 << 20) + 17)  # spans more than one chunk
    target = tmp_path / "blob.bin"
    target.write_bytes(payload)
    assert sha256_file(target) == hashlib.sha256(payload).hexdigest()
    assert sha256_file(target, chunk_size=7) == hashlib.sha256(payload).hexdigest()


def test_no_full_bundle_uses_public_bundle_silently(bundle_dir, logger_obj, caplog):
    (bundle_dir / "fritap_agent_full.js").unlink()

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        resolved = logger_obj._resolve_agent_bundle_path()

    assert resolved == str(bundle_dir / "fritap_agent.js")
    assert not caplog.records
