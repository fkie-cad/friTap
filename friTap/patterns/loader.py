#!/usr/bin/env python3

"""
Pattern loader for friTap.

Handles loading, validating, and merging default and user-supplied
pattern files for the hooking pipeline.
"""

import glob
import json
import logging
import os
import re

# Shared hex-pattern grammar: space-separated 2-char tokens, ``?``/``??`` wildcards
# allowed (used by both the modern list schema and the legacy object schema).
_HEX_PATTERN_RE = re.compile(r'^([0-9A-Fa-f?]{2}\s)*[0-9A-Fa-f?]{2}$')

# Architecture keys recognized at the arch layer of the modern schema. Used to
# detect legacy flat Schema-A files (no OS layer) that put an arch where an OS
# key is now expected.
_KNOWN_ARCH_KEYS = {"x64", "arm64", "arm", "x86", "default"}


class PatternLoader:
    """Loads, validates, and merges pattern data for friTap hooking."""

    @staticmethod
    def load(patterns_path, logger) -> str | None:
        """Load patterns: auto-load defaults, then deep-merge user patterns on top.

        Merge is granular: only the specific library/ABI/function entries
        in the user file override defaults. Everything else stays intact.

        Args:
            patterns_path: Path to user-supplied patterns JSON file (or None).
            logger: A logging.Logger instance.

        Returns:
            JSON string of merged patterns, or None if no patterns available.
        """
        # 1. Auto-load shipped default patterns (always). friTap ships one pattern
        #    file per protocol in this directory (``default_patterns.json`` for TLS,
        #    ``default_mtproto.json`` for MTProto, and so on). Load EVERY
        #    ``default_*.json`` and deep-merge them into one base DB. Per-protocol
        #    files key on disjoint top-level library names (e.g. ``openssl`` vs
        #    ``libtmessages.tmessages.so``), so the merge is collision-free;
        #    ``deep_merge`` still merges any shared subtree granularly.
        patterns_dir = os.path.dirname(os.path.abspath(__file__))
        base_patterns = {}
        # Deterministic order, with ``default_patterns.json`` (the historical TLS
        # base) first so newer per-protocol files layer on top of it.
        default_files = sorted(
            glob.glob(os.path.join(patterns_dir, "default_*.json")),
            key=lambda p: (os.path.basename(p) != "default_patterns.json",
                           os.path.basename(p)),
        )
        for default_pattern_path in default_files:
            try:
                with open(default_pattern_path, "r") as f:
                    file_patterns = json.load(f)
                base_patterns = PatternLoader.deep_merge(base_patterns, file_patterns)
                logger.debug("Loaded default patterns from %s", default_pattern_path)
            except Exception as e:
                logger.warning("Failed to load default patterns from %s: %s",
                               default_pattern_path, e)

        # 2. If user provided --patterns, load and deep-merge
        if patterns_path is not None:
            if not os.path.exists(patterns_path):
                # Historically silent: a typo'd --patterns path just vanished and
                # the run continued on defaults, looking like the file had been
                # honoured. Warn like the invalid-content case below does.
                logger.warning(
                    "User pattern file '%s' does not exist; "
                    "falling back to default patterns only", patterns_path
                )
            else:
                try:
                    with open(patterns_path, "r") as f:
                        user_patterns = json.load(f)
                    if not PatternLoader.validate(user_patterns, logger):
                        logger.warning(
                            "User pattern file '%s' contains invalid patterns; "
                            "falling back to default patterns only", patterns_path
                        )
                    else:
                        base_patterns = PatternLoader.deep_merge(base_patterns, user_patterns)
                        logger.info("Merged user patterns from %s", patterns_path)
                except Exception as e:
                    logger.error("Failed to load user patterns: %s", e)

        if not base_patterns:
            return None
        return json.dumps(base_patterns, ensure_ascii=False)

    @staticmethod
    def validate(patterns: dict, logger=None) -> bool:
        """Validate pattern data against either supported schema.

        friTap has two byte-pattern engines, each with its own valid schema:

        * **Legacy** engine (``PatternBasedHooking``; the default when ``--modern``
          is off) — an object form wrapped in a top-level ``modules`` key::

              {"modules": {<module>: {<platform>: {<arch>: {<function>:
                  {"primary": "..", "fallback": "..", "second_fallback": ".."}}}}}}

          Leaves may also be a bare hex string or a list of hex strings.
        * **Modern** engine (``PatternStrategy``; the ``--modern`` path) — a
          nested map
          ``{<library>: {<os>: {<arch>: {<function>: [pattern_str, ...]}}}}``,
          where ``<os>`` is one of android/ios/linux/macos/windows.

        A file is valid when it matches *either* schema; only files matching
        neither are rejected. (Historically this validator accepted only the
        modern list form and silently dropped legacy ``--patterns`` files.)

        Pattern format (both schemas): hex bytes separated by spaces, ``?``
        wildcards allowed.

        Args:
            patterns: Pattern dictionary to validate.
            logger: Optional logger; falls back to 'friTap' logger if None.

        Returns:
            True if all patterns are valid for the detected schema.
        """
        if logger is None:
            logger = logging.getLogger("friTap")

        if not isinstance(patterns, dict):
            logger.warning("Pattern data must be a dictionary")
            return False

        # The legacy engine wraps everything under a top-level "modules" key;
        # the modern engine does not. Dispatch on that marker.
        if "modules" in patterns:
            return PatternLoader._validate_legacy(patterns["modules"], logger)
        return PatternLoader._validate_modern(patterns, logger)

    @staticmethod
    def _validate_modern(patterns: dict, logger) -> bool:
        """Validate the modern schema: {lib: {os: {arch: {func: [pattern, ...]}}}}."""
        valid = True
        for lib_name, lib_data in patterns.items():
            if lib_name.startswith("_"):
                continue
            if not isinstance(lib_data, dict):
                logger.warning("Pattern library '%s' must be a dictionary", lib_name)
                valid = False
                continue
            for os_name, os_data in lib_data.items():
                if os_name.startswith("_"):
                    continue
                if os_name.lower() in _KNOWN_ARCH_KEYS:
                    logger.warning(
                        "Pattern '%s/%s' looks like the legacy flat Schema A "
                        "(key '%s' is an architecture, not an OS). The modern "
                        "schema now requires an OS layer: library -> os -> arch "
                        "-> function. Use one of: android/ios/linux/macos/windows.",
                        lib_name, os_name, os_name
                    )
                    valid = False
                    continue
                if not isinstance(os_data, dict):
                    logger.warning("Pattern OS '%s/%s' must be a dictionary", lib_name, os_name)
                    valid = False
                    continue
                for arch_name, arch_data in os_data.items():
                    if arch_name.startswith("_"):
                        continue
                    if not isinstance(arch_data, dict):
                        logger.warning(
                            "Pattern arch '%s/%s/%s' must be a dictionary",
                            lib_name, os_name, arch_name
                        )
                        valid = False
                        continue
                    for func_name, pattern_list in arch_data.items():
                        if func_name.startswith("_"):
                            continue
                        if not isinstance(pattern_list, list):
                            logger.warning(
                                "Pattern '%s/%s/%s/%s' must be a list",
                                lib_name, os_name, arch_name, func_name
                            )
                            valid = False
                            continue
                        for i, pat in enumerate(pattern_list):
                            if not isinstance(pat, str) or not _HEX_PATTERN_RE.match(pat):
                                logger.warning(
                                    "Invalid hex pattern at %s/%s/%s/%s[%d]: %r",
                                    lib_name, os_name, arch_name, func_name, i, pat
                                )
                                valid = False
        return valid

    @staticmethod
    def _validate_legacy(modules: dict, logger) -> bool:
        """Validate the legacy object schema under the ``modules`` wrapper:
        {module: {platform: {arch: {function: <leaf>}}}} where <leaf> is a hex
        string, a list of hex strings, or a {primary, fallback, second_fallback}
        object.

        Validation is **structural** (the nesting and leaf *types* must be
        right) — that part is fatal. Hex *content* is not: a malformed hex
        string is logged as a warning and **dropped** from *modules* (in place),
        while the rest of the file is kept. Dropping matters because the agent
        treats any non-empty string as a usable pattern and would otherwise pick
        the broken JSON entry over the library's shipped default pattern. Empty
        strings stay: they are intentional placeholders the agent already skips
        (``isNonEmptyActionPattern``). A function whose every pattern was
        dropped is removed entirely.
        """
        if not isinstance(modules, dict):
            logger.warning("Legacy pattern 'modules' must be a dictionary")
            return False

        valid = True
        for mod_name, mod_data in modules.items():
            if mod_name.startswith("_"):
                continue
            if not isinstance(mod_data, dict):
                logger.warning("Legacy pattern module '%s' must be a dictionary", mod_name)
                valid = False
                continue
            for platform_name, platform_data in mod_data.items():
                if platform_name.startswith("_"):
                    continue
                if not isinstance(platform_data, dict):
                    logger.warning(
                        "Legacy pattern platform '%s/%s' must be a dictionary",
                        mod_name, platform_name
                    )
                    valid = False
                    continue
                for arch_name, arch_data in platform_data.items():
                    if arch_name.startswith("_"):
                        continue
                    label = "%s/%s/%s" % (mod_name, platform_name, arch_name)
                    if not isinstance(arch_data, dict):
                        logger.warning("Legacy pattern arch '%s' must be a dictionary", label)
                        valid = False
                        continue
                    if not PatternLoader._prune_legacy_arch(arch_data, label, logger):
                        valid = False
        return valid

    @staticmethod
    def _prune_legacy_arch(arch_data: dict, label: str, logger) -> bool:
        """Check every function leaf of one legacy arch entry, dropping invalid
        hex in place. Returns False on a structural (leaf type) error."""
        valid = True
        for func_name in list(arch_data):
            if func_name.startswith("_"):
                continue
            func_label = "%s/%s" % (label, func_name)
            leaf = arch_data[func_name]
            if not isinstance(leaf, (str, list, dict)):
                logger.warning(
                    "Legacy pattern '%s' must be a hex string, list, or "
                    "{primary, fallback} object", func_label
                )
                valid = False
            elif PatternLoader._prune_legacy_leaf(leaf, func_label, logger):
                logger.warning("Dropping legacy pattern '%s': no valid hex pattern left",
                               func_label)
                del arch_data[func_name]
        return valid

    @staticmethod
    def _prune_legacy_leaf(leaf, label: str, logger) -> bool:
        """Drop invalid hex from *leaf* in place; True when the whole leaf must go
        (it had invalid hex and nothing valid survived)."""
        if isinstance(leaf, str):
            return PatternLoader._is_invalid_hex(leaf, label, logger)
        if isinstance(leaf, list):
            kept = [pat for i, pat in enumerate(leaf)
                    if not PatternLoader._is_invalid_hex(pat, "%s[%d]" % (label, i), logger)]
            dropped = len(kept) != len(leaf)
            leaf[:] = kept
            return dropped and not kept
        # Object form — any of primary/fallback/second_fallback may be present
        # (mirrors the agent's isNonEmptyActionPattern contract).
        keys = [k for k in ("primary", "fallback", "second_fallback") if k in leaf]
        bad = [k for k in keys
               if PatternLoader._is_invalid_hex(leaf[k], "%s.%s" % (label, k), logger)]
        for key in bad:
            del leaf[key]
        return bool(bad) and len(bad) == len(keys)

    @staticmethod
    def _is_invalid_hex(value, label: str, logger) -> bool:
        """True (and warn) for a non-empty string that is not a hex pattern.
        Empty strings are intentional placeholders and are not invalid."""
        if isinstance(value, str) and value.strip() and not _HEX_PATTERN_RE.match(value):
            logger.warning("Skipping invalid hex in legacy pattern %s: %r", label, value)
            return True
        return False

    @staticmethod
    def deep_merge(base: dict, override: dict) -> dict:
        """Deep merge two dicts. Override values win on conflict.

        Recurses into nested dicts so only leaf values are replaced.

        Args:
            base: Base dictionary.
            override: Override dictionary whose values take precedence.

        Returns:
            Merged dictionary.
        """
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = PatternLoader.deep_merge(result[key], value)
            else:
                result[key] = value
        return result
