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
        """Validate pattern data structure and hex format.

        Expected structure: {lib_name: {arch: {function: [pattern_str, ...]}}}
        Pattern format: hex bytes separated by spaces, ? wildcards allowed.

        Args:
            patterns: Pattern dictionary to validate.
            logger: Optional logger; falls back to 'friTap' logger if None.

        Returns:
            True if all patterns are valid.
        """
        if logger is None:
            logger = logging.getLogger("friTap")
        hex_pattern = re.compile(r'^([0-9A-Fa-f?]{2}\s)*[0-9A-Fa-f?]{2}$')
        valid = True

        if not isinstance(patterns, dict):
            logger.warning("Pattern data must be a dictionary")
            return False

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
                        if not isinstance(pat, str) or not hex_pattern.match(pat):
                            logger.warning(
                                "Invalid hex pattern at %s/%s/%s[%d]: %r",
                                lib_name, arch_name, func_name, i, pat
                            )
                            valid = False
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
