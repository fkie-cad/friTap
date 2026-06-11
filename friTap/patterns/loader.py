#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pattern loader for friTap.

Handles loading, validating, and merging default and user-supplied
pattern files for the hooking pipeline.
"""

import json
import os
import re
import logging


# Shared hex-pattern grammar: space-separated 2-char tokens, ``?``/``??`` wildcards
# allowed (used by both the modern list schema and the legacy object schema).
_HEX_PATTERN_RE = re.compile(r'^([0-9A-Fa-f?]{2}\s)*[0-9A-Fa-f?]{2}$')


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
        # 1. Auto-load shipped default patterns (always)
        default_pattern_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "default_patterns.json"
        )
        base_patterns = {}
        if os.path.exists(default_pattern_path):
            try:
                with open(default_pattern_path, "r") as f:
                    base_patterns = json.load(f)
                logger.debug("Loaded default patterns from %s", default_pattern_path)
            except Exception as e:
                logger.warning("Failed to load default patterns: %s", e)

        # 2. If user provided --patterns, load and deep-merge
        if patterns_path is not None and os.path.exists(patterns_path):
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
        * **Modern** engine (``PatternStrategy``; the ``--modern`` path) — a flat
          map ``{<library>: {<arch>: {<function>: [pattern_str, ...]}}}``.

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
        """Validate the modern flat schema: {lib: {arch: {func: [pattern, ...]}}}."""
        valid = True
        for lib_name, lib_data in patterns.items():
            if lib_name.startswith("_"):
                continue
            if not isinstance(lib_data, dict):
                logger.warning("Pattern library '%s' must be a dictionary", lib_name)
                valid = False
                continue
            for arch_name, arch_data in lib_data.items():
                if arch_name.startswith("_"):
                    continue
                if not isinstance(arch_data, dict):
                    logger.warning("Pattern arch '%s/%s' must be a dictionary", lib_name, arch_name)
                    valid = False
                    continue
                for func_name, pattern_list in arch_data.items():
                    if func_name.startswith("_"):
                        continue
                    if not isinstance(pattern_list, list):
                        logger.warning("Pattern '%s/%s/%s' must be a list", lib_name, arch_name, func_name)
                        valid = False
                        continue
                    for i, pat in enumerate(pattern_list):
                        if not isinstance(pat, str) or not _HEX_PATTERN_RE.match(pat):
                            logger.warning(
                                "Invalid hex pattern at %s/%s/%s[%d]: %r",
                                lib_name, arch_name, func_name, i, pat
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
        right) — that part is fatal. Hex *content* is only advisory: the legacy
        engine deliberately tolerates empty / placeholder / not-yet-derived
        entries (``isNonEmptyActionPattern`` skips empties; bad patterns fall
        back to symbol hooking), and shipped pattern files legitimately carry
        placeholders. So a malformed hex string warns at debug level but never
        fails validation — otherwise a perfectly usable legacy file would be
        dropped just because one entry is a placeholder.
        """
        if not isinstance(modules, dict):
            logger.warning("Legacy pattern 'modules' must be a dictionary")
            return False

        valid = True

        def check_hex(label, value):
            # Content-only, advisory. Empty strings are intentional placeholders.
            if isinstance(value, str) and value.strip() and not _HEX_PATTERN_RE.match(value):
                logger.debug("Non-hex legacy pattern at %s: %r", label, value)

        def check_leaf(label, leaf):
            nonlocal valid
            if isinstance(leaf, str):
                check_hex(label, leaf)
            elif isinstance(leaf, list):
                for i, pat in enumerate(leaf):
                    check_hex("%s[%d]" % (label, i), pat)
            elif isinstance(leaf, dict):
                # Object form — any of primary/fallback/second_fallback may be
                # present (mirrors the agent's isNonEmptyActionPattern contract).
                for key in ("primary", "fallback", "second_fallback"):
                    if key in leaf:
                        check_hex("%s.%s" % (label, key), leaf[key])
            else:
                logger.warning(
                    "Legacy pattern '%s' must be a hex string, list, or "
                    "{primary, fallback} object", label
                )
                valid = False

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
                    if not isinstance(arch_data, dict):
                        logger.warning(
                            "Legacy pattern arch '%s/%s/%s' must be a dictionary",
                            mod_name, platform_name, arch_name
                        )
                        valid = False
                        continue
                    for func_name, leaf in arch_data.items():
                        if func_name.startswith("_"):
                            continue
                        check_leaf(
                            "%s/%s/%s/%s" % (mod_name, platform_name, arch_name, func_name),
                            leaf
                        )
        return valid

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
