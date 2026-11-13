"""Regression tests: the pattern loader must accept BOTH pattern schemas.

friTap has two byte-pattern engines, each with its own valid schema (the
codebase calls them Schema A and Schema B — see test_pattern_fallback_gate.py):

* **Schema A** (modern ``PatternStrategy``; the ``--modern`` path) — a nested map
  ``{<library>: {<os>: {<arch>: {<function>: [pattern_str, ...]}}}}`` where the
  ``os`` key is one of android/ios/linux/macos/windows. This is what
  ``friTap/patterns/default_patterns.json`` uses.
* **Schema B** (legacy ``PatternBasedHooking``; the DEFAULT when ``--modern`` is
  off) — an object form under a top-level ``modules`` key:
  ``{"modules": {<module>: {<platform>: {<arch>: {<function>:
  {"primary": "..", "fallback": ".."}}}}}}``. This is what the Cronet/Android
  hooks consume. (The repo-root ``pattern.json`` example is Schema A.)

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
def legacy_pattern_file():
    """A realistic Schema-B file (real libwarp_mobile.so Dump-Keys patterns)."""
    return {
        "modules": {
            "libwarp_mobile.so": {
                "android": {
                    "x64": {
                        "Dump-Keys": {
                            "primary": "55 41 57 41 56 41 55 41 54 53 48 83 EC 48 48 8B 47 68",
                            "fallback": "55 41 57 41 56 41 55 41 54 53 48 83 EC 48",
                        }
                    },
                    "arm64": {
                        "Dump-Keys": {
                            "primary": "3F 23 03 D5 FF 43 02 D1 FD 7B 05 A9 F8 5F 06 A9",
                            "fallback": "3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9",
                        }
                    },
                }
            }
        }
    }


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


def test_minimal_schema_a_os_layer_validates(logger):
    patterns = {"openssl": {"android": {"x64": {"ssl_log_secret": ["55 48 89 E5 48"]}}}}
    assert PatternLoader.validate(patterns, logger) is True


# --- Schema-B placeholder tolerance (content is not fatal) -----------------

def test_schema_b_empty_and_placeholder_leaves_are_tolerated(logger):
    """Legacy files legitimately ship empty / placeholder entries; validation
    is structural, so these must NOT fail (else the whole file gets dropped).
    The non-hex placeholder itself is pruned (see the drop tests below)."""
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
    assert PatternLoader.validate({"openssl": {"android": {"x64": {"ssl_log_secret": 123}}}}, logger) is False


def test_modern_flat_no_os_layer_is_rejected(logger):
    # Breaking change: the modern schema now REQUIRES an OS layer.
    # A flat library -> arch -> function file is rejected.
    assert PatternLoader.validate({"openssl": {"x64": {"ssl_log_secret": ["55 48 89 E5"]}}}, logger) is False


def test_modern_arch_key_at_os_level_is_rejected(logger):
    # An arch name (x64) where an OS key belongs triggers the migration hint and fails.
    assert PatternLoader.validate({"openssl": {"arm64": {"x64": {"ssl_log_secret": ["55 48"]}}}}, logger) is False


def test_modern_non_dict_os_is_rejected(logger):
    # OS-level value must be a dict.
    assert PatternLoader.validate({"openssl": {"android": "should-be-a-dict"}}, logger) is False


def test_schema_b_scalar_leaf_is_rejected(logger):
    # Schema B: function leaf must be str / list / object — not a bare int.
    patterns = {"modules": {"libx.so": {"android": {"arm64": {"Dump-Keys": 123}}}}}
    assert PatternLoader.validate(patterns, logger) is False


def test_schema_b_non_dict_arch_is_rejected(logger):
    patterns = {"modules": {"libx.so": {"android": {"arm64": "should-be-a-dict"}}}}
    assert PatternLoader.validate(patterns, logger) is False


# --- load() forwards the Schema-B user file intact (the core regression) ---

def test_load_keeps_legacy_modules_subtree(tmp_path, legacy_pattern_file, logger):
    pattern_path = tmp_path / "legacy_patterns.json"
    pattern_path.write_text(json.dumps(legacy_pattern_file), encoding="utf-8")

    source_modules = legacy_pattern_file["modules"]
    merged = json.loads(PatternLoader.load(str(pattern_path), logger))

    # The legacy modules subtree must survive intact (not dropped to defaults).
    assert "modules" in merged, "Schema-B user file was dropped by load()"
    assert merged["modules"] == source_modules
    # ...and the modern defaults must still be merged in alongside it.
    assert any(k for k in merged if not k.startswith("_") and k != "modules")


# --- Schema-B invalid hex is warned about and dropped, the rest kept --------

def _legacy(leaves):
    return {"modules": {"libx.so": {"android": {"arm64": leaves}}}}


def _arch(patterns):
    return patterns["modules"]["libx.so"]["android"]["arm64"]


def test_schema_b_invalid_hex_entry_is_dropped_with_warning(caplog, logger):
    patterns = _legacy({
        "Dump-Keys": {"primary": "3F 23 03 D5", "fallback": "11 22 33 ..."},
        "SSL_Read": "AA 55 FF ...",
        "SSL_Write": ["55 48 89", "not hex"],
        "Install-Key-Log-Callback": {"primary": "zz", "fallback": "yy"},
    })
    with caplog.at_level(logging.WARNING, logger=logger.name):
        assert PatternLoader.validate(patterns, logger) is True

    arch = _arch(patterns)
    assert arch["Dump-Keys"] == {"primary": "3F 23 03 D5"}
    assert arch["SSL_Write"] == ["55 48 89"]
    assert "SSL_Read" not in arch
    assert "Install-Key-Log-Callback" not in arch
    warned = caplog.text
    assert "11 22 33 ..." in warned and "not hex" in warned
    assert "SSL_Read" in warned and "Install-Key-Log-Callback" in warned


def test_schema_b_valid_and_empty_entries_are_kept_silently(caplog, logger):
    leaves = {
        "Dump-Keys": {"primary": "3F 23 03 D5", "fallback": ""},
        "SSL_Read": ["55 48 89", "3F ?? 03"],
        "SSL_Write": "",
    }
    patterns = _legacy(json.loads(json.dumps(leaves)))
    with caplog.at_level(logging.WARNING, logger=logger.name):
        assert PatternLoader.validate(patterns, logger) is True
    assert _arch(patterns) == leaves
    assert caplog.text == ""


def test_load_drops_invalid_legacy_hex_but_merges_the_rest(tmp_path, logger):
    path = tmp_path / "user.json"
    path.write_text(json.dumps(_legacy({
        "Dump-Keys": {"primary": "3F 23 03 D5", "fallback": "11 22 ..."},
        "SSL_Read": "bogus",
    })), encoding="utf-8")
    merged = json.loads(PatternLoader.load(str(path), logger))
    assert _arch(merged) == {"Dump-Keys": {"primary": "3F 23 03 D5"}}


# --- the repo-root pattern.json example -------------------------------------

def test_repo_root_pattern_json_is_valid_modern_without_warnings(fritap_root, caplog, logger):
    path = fritap_root / "pattern.json"
    patterns = json.loads(path.read_text(encoding="utf-8"))
    assert "modules" not in patterns, "example should use the modern schema"
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        assert PatternLoader.validate(patterns, logger) is True
        merged = PatternLoader.load(str(path), logger)
    assert merged is not None
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    libs = [k for k in patterns if not k.startswith("_")]
    assert 2 <= len(libs) <= 3


def test_repo_root_pattern_json_entries_come_from_shipped_defaults(fritap_root):
    example = json.loads((fritap_root / "pattern.json").read_text(encoding="utf-8"))
    defaults = json.loads(
        (fritap_root / "friTap" / "patterns" / "default_patterns.json").read_text(encoding="utf-8"))
    for lib, os_map in example.items():
        if lib.startswith("_"):
            continue
        for os_name, arch_map in os_map.items():
            for arch, funcs in arch_map.items():
                for func, pats in funcs.items():
                    assert pats, (lib, os_name, arch, func)
                    assert set(pats) <= set(defaults[lib][os_name][arch][func])
