"""Key material for the AppLovin MAX ``/1.0/mediate`` cipher.

:class:`AppLovinKeyring` gathers the two secrets the decoder needs — the
per-app 86-char SDK key and the 32-byte SDK salt — from explicit values,
environment variables and app bundles (APK / IPA), and picks the right ones
for a given envelope.

Environment variables (all comma-separated):

* ``FRITAP_APPLOVIN_SDK_KEY`` — SDK keys
* ``FRITAP_APPLOVIN_SALT``    — salts as hex
* ``FRITAP_APPLOVIN_BUNDLE``  — APK / IPA paths to mine for keys and salts
* ``FRITAP_APPLOVIN_NO_CACHE`` / ``FRITAP_APPLOVIN_SALT_CACHE`` — disable or
  relocate the persistent salt cache (see :mod:`.applovin_salt_cache`)

Salt lookup order: explicit / env salts -> persistent cache -> bundle recovery
(a recovered salt is written back to the cache, so recovery is a one-time cost
and later iOS captures benefit from a salt recovered from an APK).

Bundle mining is delegated to :mod:`friTap.parsers.app_ciphers.applovin_keys`,
imported lazily so this module stays importable on its own.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from friTap.parsers.app_ciphers.applovin_mediate import (
    DecryptResult,
    MediateEnvelope,
    decrypt_with_reason,
    protocol_id_for_salt,
    sdk_key_matches_suffix,
)
from friTap.parsers.app_ciphers.applovin_salt_cache import SaltCache, default_salt_cache

logger = logging.getLogger("friTap.parsers.app_ciphers.applovin_keyring")

ENV_SDK_KEY = "FRITAP_APPLOVIN_SDK_KEY"
ENV_SALT = "FRITAP_APPLOVIN_SALT"
ENV_BUNDLE = "FRITAP_APPLOVIN_BUNDLE"

# from_sources() sentinel: "use the user's persistent salt cache".
_USE_DEFAULT_CACHE = object()

REASON_NO_SALT = (
    "no salt matches the envelope's protocol_id (use --applovin-salt/--app-bundle "
    f"with `fritap analyze`, or set {ENV_SALT} / {ENV_BUNDLE})"
)
REASON_NO_SDK_KEY = (
    "no SDK key available (use --applovin-sdk-key/--app-bundle "
    f"with `fritap analyze`, or set {ENV_SDK_KEY} / {ENV_BUNDLE})"
)


def split_csv(value: str | None) -> list[str]:
    """Split a comma-separated value into stripped, non-empty items."""
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def parse_salt_hex(text: str) -> bytes | None:
    """Decode a hex salt, tolerating ``0x`` and whitespace; None when invalid."""
    cleaned = "".join(text.split()).lower().removeprefix("0x")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        logger.warning("Ignoring invalid AppLovin salt hex: %r", text[:80])
        return None


def _unique(items: Iterable) -> list:
    """De-duplicate *items*, keeping first-seen order."""
    return list(dict.fromkeys(items))


def _bundle_sdk_keys(bundle_paths: Iterable[str]) -> list[str]:
    """SDK keys mined from each bundle (best candidates first)."""
    keys: list[str] = []
    for path in bundle_paths:
        try:
            from friTap.parsers.app_ciphers.applovin_keys import find_sdk_key_candidates
            keys += [candidate.key for candidate in find_sdk_key_candidates(path)]
        except Exception as exc:  # noqa: BLE001 - a bad bundle must not abort analysis
            logger.warning("Could not read SDK keys from %s: %s", path, exc)
    return keys


def _bundle_salt(bundle_path: str, protocol_id: str) -> bytes | None:
    """The salt for *protocol_id* recovered from one bundle, or None."""
    try:
        from friTap.parsers.app_ciphers.applovin_keys import recover_salt_from_bundle
        return recover_salt_from_bundle(bundle_path, protocol_id)
    except Exception as exc:  # noqa: BLE001 - a bad bundle must not abort analysis
        logger.warning("Could not recover the AppLovin salt from %s: %s", bundle_path, exc)
        return None


@dataclass
class AppLovinKeyring:
    """SDK keys, salts and bundles available for decrypting mediate envelopes."""

    sdk_keys: list[str] = field(default_factory=list)
    salts: list[bytes] = field(default_factory=list)
    bundle_paths: list[str] = field(default_factory=list)
    salt_cache: SaltCache | None = None
    _salt_cache: dict[str, bytes | None] = field(default_factory=dict, repr=False)

    @classmethod
    def from_sources(
        cls,
        sdk_keys: Iterable[str] = (),
        salts_hex: Iterable[str] = (),
        bundle_paths: Iterable[str] = (),
        env: Mapping[str, str] = os.environ,
        salt_cache: SaltCache | None | object = _USE_DEFAULT_CACHE,
    ) -> "AppLovinKeyring":
        """Merge explicit values with the ``FRITAP_APPLOVIN_*`` environment.

        *salt_cache* defaults to the user's persistent cache (None disables it).
        """
        bundles = _unique([*bundle_paths, *split_csv(env.get(ENV_BUNDLE))])
        keys = [*sdk_keys, *split_csv(env.get(ENV_SDK_KEY)), *_bundle_sdk_keys(bundles)]
        salt_texts = [*salts_hex, *split_csv(env.get(ENV_SALT))]
        salts = [salt for salt in map(parse_salt_hex, salt_texts) if salt]
        return cls(sdk_keys=_unique(k.strip() for k in keys if k.strip()),
                   salts=_unique(salts), bundle_paths=bundles,
                   salt_cache=default_salt_cache(env) if salt_cache is _USE_DEFAULT_CACHE else salt_cache)

    @property
    def is_empty(self) -> bool:
        """True when no key material or bundle was configured at all."""
        return not (self.sdk_keys or self.salts or self.bundle_paths)

    def salt_for(self, protocol_id: str) -> bytes | None:
        """The salt whose SHA-1 is *protocol_id*: known salts, persistent cache, bundles."""
        protocol_id = protocol_id.lower()
        for salt in self.salts:
            if protocol_id_for_salt(salt) == protocol_id:
                return salt
        if protocol_id not in self._salt_cache:
            self._salt_cache[protocol_id] = self._recover_salt(protocol_id)
        return self._salt_cache[protocol_id]

    def _recover_salt(self, protocol_id: str) -> bytes | None:
        """Persistent cache first, then every bundle once; remember a hit."""
        salt = self._cached_salt(protocol_id)
        if salt is None:
            salt = self._bundle_recovered_salt(protocol_id)
            if salt is not None and self.salt_cache is not None:
                self.salt_cache.put(protocol_id, salt)
        if salt is not None:
            self.salts.append(salt)
        return salt

    def _cached_salt(self, protocol_id: str) -> bytes | None:
        return self.salt_cache.get(protocol_id) if self.salt_cache is not None else None

    def _bundle_recovered_salt(self, protocol_id: str) -> bytes | None:
        for path in self.bundle_paths:
            salt = _bundle_salt(path, protocol_id)
            if salt is not None:
                return salt
        return None

    def keys_for(self, envelope: MediateEnvelope) -> list[str]:
        """SDK keys ordered with those matching the envelope's suffix first."""
        return sorted(self.sdk_keys, key=lambda key: not sdk_key_matches_suffix(key, envelope))

    def try_decrypt(self, envelope: MediateEnvelope) -> tuple[DecryptResult | None, str]:
        """Decrypt with the first working key; ``(None, reason)`` otherwise."""
        keys = self.keys_for(envelope)
        if not keys:
            return None, REASON_NO_SDK_KEY
        salt = self.salt_for(envelope.protocol_id)
        if salt is None:
            return None, REASON_NO_SALT
        reason = ""
        for key in keys:
            result, reason = decrypt_with_reason(envelope, key, salt)
            if result is not None:
                return result, ""
        return None, reason


__all__ = [
    "AppLovinKeyring",
    "ENV_BUNDLE",
    "ENV_SALT",
    "ENV_SDK_KEY",
    "REASON_NO_SALT",
    "REASON_NO_SDK_KEY",
    "parse_salt_hex",
    "split_csv",
]
