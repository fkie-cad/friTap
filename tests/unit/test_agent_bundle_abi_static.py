#!/usr/bin/env python3
"""The shipped agent bundle must declare the ABI this friTap expects.

``friTap/fritap_agent.js`` is a *pre-compiled* bundle: nothing rebuilds
``agent/*.ts`` at run time, so a checked-in bundle that predates a change to
the JS<->Python boundary silently exercises the old contract. That is not a
hypothetical — friTap discussion #65's reporter patched `agent/*.ts`, never
rebuilt, and concluded the fix did not work.

``AGENT_ABI_VERSION`` versions that boundary (``config_batch`` fields,
ContentTypes, ``rpc.exports``). These tests pin two things:

1. the bundle in the repo really carries the host's ABI — i.e. whoever bumped
   the constant also ran ``python dev/generate_agent_types.py`` **and**
   ``./dev/compile_agent.sh``;
2. the static, pre-load check reads that constant correctly and stays
   non-fatal for bundles that do not carry it.
"""

from __future__ import annotations

import logging
import re
import types
from pathlib import Path

import pytest

from friTap.constants import AGENT_ABI_VERSION
from friTap.legacy.ssl_logger_core import SSL_Logger

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_PATH = REPO_ROOT / "friTap" / "fritap_agent.js"
GENERATED_CONSTANTS = REPO_ROOT / "agent" / "shared" / "generated_constants.ts"


def _make_logger(bundle_path="/tmp/fritap_agent.js"):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.abi_static")
    # debug / debug_output are read-only properties over the config.
    obj._config = types.SimpleNamespace(debug=False, debug_output=False)
    obj._resolve_agent_bundle_path = lambda: bundle_path
    return obj


# ---------------------------------------------------------------------------
# the shipped artefacts agree
# ---------------------------------------------------------------------------

def test_generated_constants_match_the_host_abi():
    """dev/generate_agent_types.py mirrors constants.py into the agent tree."""
    text = GENERATED_CONSTANTS.read_text(encoding="utf-8")
    match = re.search(r"AGENT_ABI_VERSION\s*=\s*(\d+)", text)
    assert match, "generated_constants.ts carries no AGENT_ABI_VERSION"
    assert int(match.group(1)) == AGENT_ABI_VERSION, (
        "agent/shared/generated_constants.ts is stale — "
        "run `python dev/generate_agent_types.py`"
    )


def test_generated_message_schema_matches_the_python_schema():
    """agent/schemas/messages.ts mirrors friTap/schemas/agent_messages.py.

    A field added to a Pydantic agent message (e.g. DatalogMessage.direction /
    quic_payload / library) must also land in the TS interface the agent
    compiles against.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "dev" / "generate_agent_types.py"), "--check"],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        "generated TS schema/constants are stale — run "
        f"`python dev/generate_agent_types.py`:\n{result.stdout}{result.stderr}"
    )


def test_shipped_bundle_matches_the_host_abi():
    """The single check that catches "bumped the constant, forgot to rebuild"."""
    source = BUNDLE_PATH.read_text(encoding="utf-8", errors="replace")
    bundle_abi = SSL_Logger._check_agent_abi_static(source)
    assert bundle_abi is not None, (
        f"{BUNDLE_PATH} declares no AGENT_ABI_VERSION — was it built from "
        "agent/shared/generated_constants.ts?"
    )
    assert bundle_abi == AGENT_ABI_VERSION, (
        f"{BUNDLE_PATH} was built for ABI {bundle_abi} but friTap expects "
        f"{AGENT_ABI_VERSION} — run `./dev/compile_agent.sh` and commit the bundle"
    )


# ---------------------------------------------------------------------------
# the static reader itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("source,expected", [
    ("const AGENT_ABI_VERSION = 2;", 2),
    ("AGENT_ABI_VERSION=17", 17),
    ("x.AGENT_ABI_VERSION  =  3 ;", 3),
    ("var a=1;const AGENT_ABI_VERSION = 42;var b=2;", 42),
])
def test_reads_the_constant_in_its_various_emitted_shapes(source, expected):
    assert SSL_Logger._check_agent_abi_static(source) == expected


@pytest.mark.parametrize("source", ["", "no constant here", "AGENT_ABI_VERSION = x"])
def test_returns_none_when_the_constant_is_absent(source):
    assert SSL_Logger._check_agent_abi_static(source) is None


def test_non_string_source_is_tolerated():
    """A backend may hand back something unexpected; never raise on the way in."""
    assert SSL_Logger._check_agent_abi_static(None) is None
    assert SSL_Logger._check_agent_abi_static(b"AGENT_ABI_VERSION = 2") is None


# ---------------------------------------------------------------------------
# the warning path
# ---------------------------------------------------------------------------

def test_mismatch_warns_and_names_the_bundle_and_the_rebuild_command(caplog):
    obj = _make_logger(bundle_path="/somewhere/fritap_agent.js")
    stale = f"const AGENT_ABI_VERSION = {AGENT_ABI_VERSION + 1};"

    with caplog.at_level(logging.WARNING, logger="test.abi_static"):
        obj._warn_on_stale_agent_bundle(stale)

    message = "\n".join(r.getMessage() for r in caplog.records)
    assert "/somewhere/fritap_agent.js" in message
    assert "./dev/compile_agent.sh" in message
    assert str(AGENT_ABI_VERSION) in message


def test_matching_abi_is_silent(caplog):
    obj = _make_logger()
    with caplog.at_level(logging.WARNING, logger="test.abi_static"):
        obj._warn_on_stale_agent_bundle(f"const AGENT_ABI_VERSION = {AGENT_ABI_VERSION};")
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_absent_constant_does_not_warn(caplog):
    """A standalone / hand-built bundle is a legitimate case, not an error."""
    obj = _make_logger()
    with caplog.at_level(logging.WARNING, logger="test.abi_static"):
        obj._warn_on_stale_agent_bundle("// a hand written agent")
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_the_check_never_raises():
    """It runs on the instrumentation path; a bad read must not abort capture."""
    obj = _make_logger()
    obj._resolve_agent_bundle_path = lambda: (_ for _ in ()).throw(OSError("gone"))
    # A matching bundle never needs the path, so this must still be silent.
    obj._warn_on_stale_agent_bundle(f"AGENT_ABI_VERSION = {AGENT_ABI_VERSION}")


# ---------------------------------------------------------------------------
# entry-point bundle skipping is now visible
# ---------------------------------------------------------------------------

def test_abi_mismatched_entry_point_bundle_warns_instead_of_vanishing(caplog, monkeypatch):
    """An ABI bump makes private-bundle skips likely; they must not be silent."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.abi_static")
    obj._config = types.SimpleNamespace(debug=False, debug_output=False)

    contribution = types.SimpleNamespace(
        AGENT_ABI_VERSION=AGENT_ABI_VERSION - 1,
        AGENT_BUNDLE_PATH="/private/agent.js",
    )
    entry_point = types.SimpleNamespace(name="acme-full", load=lambda: contribution)
    monkeypatch.setattr(
        "importlib.metadata.entry_points", lambda **kwargs: [entry_point]
    )

    with caplog.at_level(logging.WARNING, logger="test.abi_static"):
        assert obj._discover_agent_bundle() is None

    message = "\n".join(r.getMessage() for r in caplog.records)
    assert "acme-full" in message
    assert str(AGENT_ABI_VERSION) in message
