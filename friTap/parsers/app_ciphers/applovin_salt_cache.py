"""Persistent cache of recovered AppLovin MAX salts.

The salt is a universal SDK constant (same bytes in every app, Android and
iOS), so recovering it from one bundle is enough: we store
``{protocol_id: salt_hex}`` as JSON in friTap's per-user cache directory and
later analyses -- including iOS captures with no bundle at hand -- reuse it.

Every cached entry is re-verified against the SHA-1 oracle before it is
trusted, and a missing / corrupt file simply reads as empty.

Environment variables:

* ``FRITAP_APPLOVIN_NO_CACHE=1``     -- disable the cache entirely
* ``FRITAP_APPLOVIN_SALT_CACHE=path`` -- use *path* instead of the default file
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Mapping

from friTap.cache_files import (
    CACHE_WRITE_OPTIONS,
    cache_file_lock,
    fritap_cache_dir,
    write_atomic,
)

logger = logging.getLogger("friTap.parsers.app_ciphers.applovin_salt_cache")

ENV_NO_CACHE = "FRITAP_APPLOVIN_NO_CACHE"
ENV_CACHE_PATH = "FRITAP_APPLOVIN_SALT_CACHE"
CACHE_FILE_NAME = "applovin_salts.json"

_FALSE_VALUES = ("", "0", "false", "no", "off")


def _env_value(env: Mapping[str, str], name: str) -> str:
    """*name* from *env*, falling back to the process environment."""
    return (env.get(name) or os.environ.get(name) or "").strip()


def cache_disabled(env: Mapping[str, str] = os.environ) -> bool:
    """True when ``FRITAP_APPLOVIN_NO_CACHE`` is set to a truthy value."""
    return _env_value(env, ENV_NO_CACHE).lower() not in _FALSE_VALUES


def default_cache_path(env: Mapping[str, str] = os.environ) -> str:
    """``FRITAP_APPLOVIN_SALT_CACHE`` or ``<friTap cache dir>/applovin_salts.json``."""
    return _env_value(env, ENV_CACHE_PATH) or os.path.join(fritap_cache_dir(), CACHE_FILE_NAME)


def _salt_matches(protocol_id: str, salt: bytes) -> bool:
    return hashlib.sha1(salt).hexdigest() == protocol_id


class SaltCache:
    """``{protocol_id: salt_hex}`` JSON file; entries are oracle-checked on read."""

    def __init__(self, path: str) -> None:
        self.path = os.fspath(path)

    def load(self) -> dict[str, str]:
        """The raw mapping on disk; ``{}`` when missing, unreadable or corrupt."""
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            logger.debug("Ignoring unreadable AppLovin salt cache %s: %s", self.path, exc)
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k).lower(): v for k, v in data.items() if isinstance(v, str)}

    def get(self, protocol_id: str) -> bytes | None:
        """The cached salt for *protocol_id*, only if it passes the SHA-1 oracle."""
        protocol_id = protocol_id.lower()
        salt_hex = self.load().get(protocol_id)
        if salt_hex is None:
            return None
        try:
            salt = bytes.fromhex(salt_hex)
        except ValueError:
            return None
        if not _salt_matches(protocol_id, salt):
            logger.warning("Ignoring AppLovin salt cache entry that fails the oracle: %s", protocol_id)
            return None
        return salt

    def put(self, protocol_id: str, salt: bytes) -> bool:
        """Store a verified salt (atomic tmp+rename); False when not written."""
        protocol_id = protocol_id.lower()
        if not _salt_matches(protocol_id, salt):
            return False
        try:
            with cache_file_lock(self.path):
                entries = self.load()
                entries[protocol_id] = salt.hex()
                text = json.dumps(entries, indent=2, sort_keys=True) + "\n"
                write_atomic(self.path, text.encode("utf-8"), **CACHE_WRITE_OPTIONS)
        except OSError as exc:
            logger.debug("Could not write AppLovin salt cache %s: %s", self.path, exc)
            return False
        return True


def default_salt_cache(env: Mapping[str, str] = os.environ) -> SaltCache | None:
    """The user's salt cache, or None when disabled via ``FRITAP_APPLOVIN_NO_CACHE``."""
    if cache_disabled(env):
        return None
    return SaltCache(default_cache_path(env))


__all__ = [
    "CACHE_FILE_NAME",
    "ENV_CACHE_PATH",
    "ENV_NO_CACHE",
    "SaltCache",
    "cache_disabled",
    "default_cache_path",
    "default_salt_cache",
]
