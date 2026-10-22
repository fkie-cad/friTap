"""The side-effect-free MTProto backend leaf (``friTap.protocols.mtproto_backend``).

Covers the leaf itself, its re-export from ``friTap.offline.mtproto``, and the
dependency-direction contract: the live handlers' ``validate_cli_intent`` must
not import ``friTap.offline`` (whose import self-registers offline decryptors),
and the offline registry order stays unchanged when it IS imported afterwards.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from friTap.protocols import mtproto_backend

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_fresh(code: str) -> str:
    """Run *code* in a fresh interpreter from the repo root; return its stdout."""
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip().splitlines()[-1]


def test_hint_mentions_crypto_install():
    assert "pip install cryptography" in mtproto_backend.MTPROTO_DEPENDENCY_HINT


def test_backend_available_true_with_cryptography():
    pytest.importorskip("cryptography")
    assert mtproto_backend.mtproto_backend_available() is True


def test_backend_unavailable_without_cryptography(monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.ciphers", None)
    assert mtproto_backend.mtproto_backend_available() is False


def test_offline_package_reexports_same_objects():
    import friTap.offline.mtproto as mt

    assert mt.MTPROTO_DEPENDENCY_HINT is mtproto_backend.MTPROTO_DEPENDENCY_HINT
    assert mt.mtproto_backend_available is mtproto_backend.mtproto_backend_available


def test_importing_leaf_does_not_import_offline():
    out = _run_fresh("""
        import sys
        import friTap.protocols.mtproto_backend
        print(any(m.startswith("friTap.offline") for m in sys.modules))
    """)
    assert out == "False"


_VALIDATE_ALL_HANDLERS = """
    import sys
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from friTap.protocols.registry import create_default_registry

    registry = create_default_registry(HANDLERS)
    parsed = SimpleNamespace(spawn=False, memory_scan=False, keylog="k.log",
                             pcap=None, full_capture=False)
    for name in HANDLERS:
        registry.get(name).validate_cli_intent(parsed, MagicMock(), MagicMock())
"""


def validate_handlers_code(handlers) -> str:
    """Fresh-interpreter prelude running ``validate_cli_intent`` of *handlers*."""
    return f"HANDLERS = {list(handlers)!r}\n" + textwrap.dedent(_VALIDATE_ALL_HANDLERS)


def test_validate_cli_intent_does_not_import_offline():
    out = _run_fresh(validate_handlers_code(["mtproto", "telegram"]) + """
print(any(m.startswith("friTap.offline") for m in sys.modules))
""")
    assert out == "False"


def test_offline_registry_order_unchanged_after_validate_cli_intent():
    out = _run_fresh(validate_handlers_code(["mtproto", "telegram"]) + """
import friTap.offline
from friTap.offline.registry import get_offline_decryptor_registry
print(",".join(get_offline_decryptor_registry().names()))
""")
    assert out.split(",")[:4] == ["mtproto", "telegram", "rc4", "schannel"]
