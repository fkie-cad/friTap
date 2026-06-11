"""Regression tests: the pattern loader must accept BOTH pattern schemas.

friTap has two byte-pattern engines, each with its own valid schema (the
codebase calls them Schema A and Schema B — see test_pattern_fallback_gate.py):

* **Schema A** (modern ``PatternStrategy``; the ``--modern`` path) — a flat map
  ``{<library>: {<arch>: {<function>: [pattern_str, ...]}}}``. This is what
  ``friTap/patterns/default_patterns.json`` uses.
* **Schema B** (legacy ``PatternBasedHooking``; the DEFAULT when ``--modern`` is
  off) — an object form under a top-level ``modules`` key:
  ``{"modules": {<module>: {<platform>: {<arch>: {<function>:
  {"primary": "..", "fallback": ".."}}}}}}``. This is what the repo-root
  ``pattern.json`` uses, and what the Cronet/Android hooks consume.

Historically ``PatternLoader.validate`` only understood Schema A and treated a
Schema-B file as invalid; ``PatternLoader.load`` then *fatally dropped* the user
file and forwarded defaults-only, so ``--patterns pattern.json`` was silently
ignored on the default/legacy path. These tests lock in that BOTH schemas
validate and that a Schema-B user file survives ``load()`` intact.
"""

import json
import logging

import pytest

from friTap.patterns.loader import PatternLoader


@pytest.fixture
def logger():
    return logging.getLogger("friTap-test")


@pytest.fixture
def legacy_pattern_file(fritap_root):
    """The shipped repo-root pattern.json — a real Schema-B file."""
    path = fritap_root / "pattern.json"
    if not path.exists():
        pytest.skip("repo-root pattern.json not present")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def modern_pattern_file(fritap_root):
    """The shipped default_patterns.json — a real Schema-A file."""
    path = fritap_root / "friTap" / "patterns" / "default_patterns.json"
    if not path.exists():
        pytest.skip("default_patterns.json not present")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# --- validate() accepts both schemas --------------------------------------

def test_modern_schema_a_validates(modern_pattern_file, logger):
    assert PatternLoader.validate(modern_pattern_file, logger) is True


def test_legacy_schema_b_validates(legacy_pattern_file, logger):
    """The real Schema-B pattern.json must validate (the regression)."""
    assert PatternLoader.validate(legacy_pattern_file, logger) is True


def test_minimal_schema_b_object_form_validates(logger):
    patterns = {
        "modules": {
            "libcronet.so": {
                "android": {
                    "arm64": {
                        "Dump-Keys": {
                            "primary": "FF ?3 02 D1 FD 7B",
                            "fallback": "3F 23 03 D5 FF",
                        }
                    }
                }
            }
        }
    }
    assert PatternLoader.validate(patterns, logger) is True


def test_minimal_schema_a_list_form_validates(logger):
    patterns = {"openssl": {"x64": {"ssl_log_secret": ["55 48 89 E5 48"]}}}
    assert PatternLoader.validate(patterns, logger) is True


# --- Schema-B placeholder tolerance (content is advisory, not fatal) -------

def test_schema_b_empty_and_placeholder_leaves_are_tolerated(logger):
    """Legacy files legitimately ship empty / placeholder entries; validation
    is structural, so these must NOT fail (else the whole file gets dropped)."""
    patterns = {
        "modules": {
            "sshd": {
                "linux": {
                    "x64": {
                        "SSH_Packet_Send": {"primary": "", "fallback": ""},
                        "SSH_Cipher_Init": {"primary": "11 22 33 ..."},
                    }
                }
            }
        }
    }
    assert PatternLoader.validate(patterns, logger) is True


def test_schema_b_string_and_list_leaves_are_accepted(logger):
    patterns = {
        "modules": {
            "libx.so": {
                "android": {
                    "arm64": {
                        "Dump-Keys": "55 48 89 E5",          # bare string leaf
                        "SSL_Read": ["55 48 89", "3F 23 03"],  # list leaf
                    }
                }
            }
        }
    }
    assert PatternLoader.validate(patterns, logger) is True


# --- structural errors are still rejected (both schemas) -------------------

def test_non_dict_is_rejected(logger):
    assert PatternLoader.validate(["not", "a", "dict"], logger) is False


def test_modern_non_list_leaf_is_rejected(logger):
    # Schema A: function leaf must be a list.
    assert PatternLoader.validate({"openssl": {"x64": {"ssl_log_secret": 123}}}, logger) is False


def test_schema_b_scalar_leaf_is_rejected(logger):
    # Schema B: function leaf must be str / list / object — not a bare int.
    patterns = {"modules": {"libx.so": {"android": {"arm64": {"Dump-Keys": 123}}}}}
    assert PatternLoader.validate(patterns, logger) is False


def test_schema_b_non_dict_arch_is_rejected(logger):
    patterns = {"modules": {"libx.so": {"android": {"arm64": "should-be-a-dict"}}}}
    assert PatternLoader.validate(patterns, logger) is False


# --- load() forwards the Schema-B user file intact (the core regression) ---

def test_load_keeps_legacy_modules_subtree(fritap_root, logger):
    pattern_path = fritap_root / "pattern.json"
    if not pattern_path.exists():
        pytest.skip("repo-root pattern.json not present")

    source_modules = json.loads(pattern_path.read_text(encoding="utf-8"))["modules"]
    merged = json.loads(PatternLoader.load(str(pattern_path), logger))

    # The legacy modules subtree must survive intact (not dropped to defaults).
    assert "modules" in merged, "Schema-B user file was dropped by load()"
    assert merged["modules"] == source_modules
    # ...and the modern defaults must still be merged in alongside it.
    assert any(k for k in merged if not k.startswith("_") and k != "modules")
