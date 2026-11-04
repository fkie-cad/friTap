"""§F leak guard (scripts/check_public_denylist.sh): STRUCTURAL 2 protocol allowlist.

The guard refuses to publish when ``--protocol`` offers a name missing from its
fail-closed allowlist. Every PUBLIC protocol must therefore be listed there:
the built-ins of ``friTap.protocols.registry`` and every ``protocols/_ext`` shim
that private.txt does not strip. These tests pin that contract so a new public
protocol fails here (fast, in CI) instead of at ``make publish-public``.
"""
from __future__ import annotations

import ast
import fnmatch
import os
import re

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_GUARD = os.path.join(_REPO_ROOT, "scripts", "check_public_denylist.sh")
_PRIVATE_TXT = os.path.join(_REPO_ROOT, "private.txt")
_EXT_DIR = os.path.join(_REPO_ROOT, "friTap", "protocols", "_ext")
_ALLOWLIST_RE = re.compile(r"^allowed = (\{[^}]*\})$", re.MULTILINE)
_REGISTER_RE = re.compile(r"register_protocol_handler\(\s*[\"']([A-Za-z0-9_]+)[\"']")


def _guard_allowlist() -> set[str]:
    with open(_GUARD, encoding="utf-8") as fh:
        match = _ALLOWLIST_RE.search(fh.read())
    assert match, "protocol allowlist literal not found in check_public_denylist.sh"
    return set(ast.literal_eval(match.group(1)))


def _private_patterns() -> list[str]:
    """private.txt entries (comments stripped); empty in the public repo."""
    if not os.path.isfile(_PRIVATE_TXT):
        return []
    with open(_PRIVATE_TXT, encoding="utf-8") as fh:
        entries = (line.split("#", 1)[0].strip() for line in fh)
        return [entry for entry in entries if entry]


def _is_stripped(rel_path: str, patterns: list[str]) -> bool:
    return any(
        rel_path.startswith(p) if p.endswith("/") else fnmatch.fnmatch(rel_path, p)
        for p in patterns
    )


def _public_extension_protocols() -> set[str]:
    """Names registered by the ``protocols/_ext`` shims that ship publicly."""
    patterns = _private_patterns()
    names: set[str] = set()
    for filename in sorted(os.listdir(_EXT_DIR)):
        rel_path = f"friTap/protocols/_ext/{filename}"
        if filename.startswith("_") or not filename.endswith(".py") or _is_stripped(rel_path, patterns):
            continue
        with open(os.path.join(_EXT_DIR, filename), encoding="utf-8") as fh:
            names.update(_REGISTER_RE.findall(fh.read()))
    return names


def _builtin_protocols() -> set[str]:
    from friTap.protocols import registry

    registry._register_builtin_handler_factories()
    return set(registry._BUILTIN_HANDLER_FACTORIES)


def test_allowlist_covers_every_builtin_protocol():
    missing = _builtin_protocols() - _guard_allowlist()
    assert not missing, f"add {sorted(missing)} to the allowlist in scripts/check_public_denylist.sh"


def test_allowlist_covers_every_public_extension_protocol():
    missing = _public_extension_protocols() - _guard_allowlist()
    assert not missing, f"add {sorted(missing)} to the allowlist in scripts/check_public_denylist.sh"


def test_public_extension_scan_finds_rc4():
    # Guards the regex/strip logic above against silently matching nothing.
    assert "rc4" in _public_extension_protocols()


def test_stripped_extension_is_not_treated_as_public():
    assert _is_stripped("friTap/protocols/_ext/x.py", ["friTap/protocols/_ext/x.py"])
    assert _is_stripped("friTap/protocols/_ext/x.py", ["friTap/protocols/"])
    assert not _is_stripped("friTap/protocols/_ext/rc4.py", ["friTap/protocols/_ext/x.py"])
