#!/usr/bin/env python3

"""Pattern loader for friTap's "memory scan for secrets" feature.

This module owns the pattern *database* that drives the memory-scanning agent.
The agent carries no layout knowledge of its own: every offset, stride, byte
pattern and NSS label it uses arrives through its ``configure(profile)`` rpc
call as a single profile object taken from this database. This module therefore
loads the shipped default database, optionally merges a user-supplied database
on top of it, validates a profile *strictly*, and hands back the single profile
dict ready for ``configure()``.

Strictness is the whole point. A typo in a byte pattern, a mislabelled secret
or a struct offset that points at nothing does not raise anything at scan time -
it simply matches nothing or reads the neighbouring heap, which on screen is
indistinguishable from "the target made no TLS connections". Catching those
cross-section mistakes here, before a single byte of memory is scanned, is what
makes retargeting a build fail loudly instead of silently.

The structural validation ported here mirrors the prototype host driver at
``research/memory_scan/bssl_secret_scan.py`` (its ``select_profile`` and its
``_validate_*`` family). The public API is:

    * :class:`MemoryScanPatternError` - the one error type raised on any bad
      database, profile selection or structural reference.
    * :func:`load_database` - load the shipped default and merge a user file.
    * :func:`select_profile` - pick a profile by id, or the first one.
    * :func:`validate_profile` - strict structural validation of one profile.
    * :func:`load_memory_scan_profile` - the convenience one-shot: load, merge,
      validate and select, returning the profile ready for ``configure()``.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Iterator, Optional, Sequence

logger = logging.getLogger("friTap.memory_scanning.loader")

# The shipped default database, located relative to THIS module's directory (as
# friTap/patterns/loader.py locates default_patterns.json) so it is found no
# matter what the current working directory is.
_DEFAULT_DATABASE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "patterns.json",
)

# The database schema version this loader understands. Bumped only when the
# top-level shape changes in a way this code cannot read.
_SUPPORTED_SCHEMA = 1

# --------------------------------------------------------------------------- #
# What the agent dereferences. These lists are the contract between the JSON
# database and agent/scanner.js; a profile missing any of them cannot be scanned
# with. Kept in sync with research/memory_scan/bssl_secret_scan.py.
# --------------------------------------------------------------------------- #

# Top-level profile keys agent/scanner.js dereferences.
_REQUIRED_PROFILE_KEYS = (
    "id", "scan_regions", "constants", "struct_offsets", "tiers",
    "validators", "keylog_labels",
)
# Constants the agent reads directly; their absence breaks a tier outright.
_REQUIRED_CONSTANTS = (
    "ssl_max_md_size", "ssl3_random_size", "valid_hash_lens", "ssl_version_tls12",
)
# Constants the agent never reads but this validator does: they let the
# hand-written offset tables be re-derived and checked (see
# :func:`_validate_derived_offsets`) rather than merely trusted.
_SELF_CHECK_CONSTANTS = ("inplace_vector_stride", "ssl_version_tls13")
_REQUIRED_STRUCTS = ("SSL", "SSL3_STATE", "SSL_HANDSHAKE", "SSL_SESSION")
# Every struct_offsets.SSL_SESSION key the agent dereferences. None is named
# anywhere else in the JSON, so nothing else would notice them missing; checked
# unconditionally as one block that gets retargeted as a unit.
_REQUIRED_SESSION_FIELDS = (
    "ssl_version", "secret", "secret_len", "session_id", "session_id_len",
)

# The two tiers whose JSON sections cross-reference other sections of the file.
_TIER_A = "A_ssl_handshake"
_TIER_B = "B_ssl_method_ptr"

# --------------------------------------------------------------------------- #
# Engine discriminator. Each profile declares which secret-extraction engine it
# targets. The key is absent in the shipped BoringSSL profile, so its absence
# MUST mean "boringssl" for that profile to keep validating unchanged. Only the
# boringssl checks above (structs, session fields, derived offsets) are
# engine-specific; the dispatch in validate_profile() is what keeps them scoped
# to boringssl rather than enforced on every engine.
# --------------------------------------------------------------------------- #
_DEFAULT_ENGINE = "boringssl"
_KNOWN_ENGINES = ("boringssl", "schannel", "rc4", "mtproto")

# --------------------------------------------------------------------------- #
# Applicability metadata (F3). Alongside its engine, each profile declares which
# selected --protocol it belongs to, which platform(s) it applies to, and which
# process the scan must run in. These drive select_profiles(); their absence
# reproduces the shipped BoringSSL profile's behaviour exactly (a TLS, all-
# platform, in-process scan), so a pre-F3 profile keeps resolving unchanged.
# --------------------------------------------------------------------------- #
_DEFAULT_PROTOCOL = "tls"

# Some protocols are umbrellas over a single memory-scan engine: selecting one
# (via --protocol or a bare -ms) should also pick that engine's profile, and
# naming it directly to -ms should target that engine. "telegram" is MTProto +
# E2E and the mtproto engine already scans both cloud and Secret-Chat keys, so
# telegram resolves to the mtproto engine/profile.
_PROTOCOL_ENGINE_ALIASES = {"telegram": "mtproto"}
_DEFAULT_PLATFORMS = ("all",)
_DEFAULT_SCAN_TARGET = "self"
# scan_target names the process the scan runs in: "self" is the injected target
# process (the default, Linux/Android/macOS/iOS and Windows user-space TLS);
# "lsass" is a separate Frida session attached to lsass.exe (Windows Schannel).
_KNOWN_SCAN_TARGETS = ("self", "lsass")
# friTap's canonical platform strings, and the aliases the frida device / host
# report that map onto them (os.query_system_parameters -> os.id, sys.platform).
_KNOWN_OS_NAMES = ("windows", "linux", "android", "macos", "ios")
_OS_ALIASES = {
    "win": "windows",
    "win32": "windows",
    "windows": "windows",
    "linux": "linux",
    "android": "android",
    "darwin": "macos",
    "macos": "macos",
    "mac": "macos",
    "osx": "macos",
    "ios": "ios",
    "iphoneos": "ios",
}
# The minimal shape every profile must have regardless of engine. The per-engine
# validators tighten this; the schannel/rc4 validators are scaffolding today and
# grow their own required-section checks in a later job (F3).
_MINIMAL_PROFILE_KEYS = ("id", "scan_regions")


class MemoryScanPatternError(Exception):
    """A memory-scan pattern database or profile that cannot be trusted.

    Raised on a database that will not load, a profile id that does not exist,
    and - most importantly - any structural reference inside a profile that
    points at nothing (an undeclared label, a struct offset a tier uses but the
    profile never defines, a session/s3 path field, or an offset relation that
    has drifted from the constants it is derived from).
    """


# --------------------------------------------------------------------------- #
# Loading and merging
# --------------------------------------------------------------------------- #

def _load_json(path: str) -> dict[str, Any]:
    """Read one JSON file into a dict, or raise :class:`MemoryScanPatternError`."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise MemoryScanPatternError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise MemoryScanPatternError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise MemoryScanPatternError(f"{path}: expected a top-level JSON object")
    return data


def _profiles_of(database: dict[str, Any], where: str) -> list[dict[str, Any]]:
    """Return the ``profiles`` list of a database, checked to be a list of objects."""
    profiles = database.get("profiles")
    if not isinstance(profiles, list):
        raise MemoryScanPatternError(f"{where}: 'profiles' must be a list")
    for index, profile in enumerate(profiles):
        if not isinstance(profile, dict):
            raise MemoryScanPatternError(f"{where}: profiles[{index}] must be an object")
    return profiles


def _merge_profiles(
    base: list[dict[str, Any]], overrides: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge user profiles into the base list by ``id``.

    A user profile whose id matches a base profile replaces it in place, keeping
    the original ordering; a user profile with a new id is appended. Merging by
    id (rather than deep-merging fields) keeps a profile a single, internally
    consistent unit - a half-overridden profile with one build's offsets and
    another's constants is exactly the silent drift this feature exists to catch.
    """
    merged = list(base)
    index_by_id = {
        profile.get("id"): position
        for position, profile in enumerate(merged)
        if profile.get("id") is not None
    }
    for profile in overrides:
        profile_id = profile.get("id")
        # Only real ids override in place; an id-less profile has no identity to
        # match on, so it is always appended (two of them must not collide on a
        # shared ``None`` key and silently drop one).
        if profile_id is not None and profile_id in index_by_id:
            merged[index_by_id[profile_id]] = profile
            logger.debug("User profile '%s' overrides the shipped profile", profile_id)
        else:
            if profile_id is not None:
                index_by_id[profile_id] = len(merged)
            merged.append(profile)
            logger.debug("User profile '%s' appended to the database", profile_id)
    return merged


def load_database(user_path: Optional[str] = None) -> dict[str, Any]:
    """Load the shipped default database and merge a user database on top.

    The shipped default is always loaded from beside this module. When
    ``user_path`` is given, its ``profiles`` are merged into the database by id:
    a user profile replaces the shipped profile of the same id, otherwise it is
    appended. The user file may add or override profiles; it never removes the
    shipped ones.

    Args:
        user_path: Path to a user-supplied database JSON file, or ``None``.

    Returns:
        The merged database dict (the shipped structure with merged profiles).

    Raises:
        MemoryScanPatternError: if either file is missing, is not valid JSON,
            or does not carry the supported schema.
    """
    database = _load_json(_DEFAULT_DATABASE_PATH)
    if database.get("schema") != _SUPPORTED_SCHEMA:
        raise MemoryScanPatternError(
            f"{_DEFAULT_DATABASE_PATH}: expected \"schema\": {_SUPPORTED_SCHEMA}")
    database["profiles"] = _profiles_of(database, "shipped database")
    logger.debug("Loaded shipped memory-scan database from %s", _DEFAULT_DATABASE_PATH)

    if user_path is None:
        return database

    return _merge_user_db_into(database, user_path)


def select_profile(
    database: dict[str, Any],
    profile_id: Optional[str] = None,
    engine: Optional[str] = None,
) -> dict[str, Any]:
    """Return the profile with ``profile_id``, or the first when it is ``None``.

    Mirrors the prototype's selection: no id means "the first profile in the
    file", the documented default.

    ``engine`` is an optional pre-filter that narrows the candidate profiles to
    those declaring that engine (an absent ``engine`` key counts as boringssl)
    before the id/first selection runs. It defaults to ``None`` - no filtering -
    so every existing caller behaves exactly as before. The full
    protocol/platform/arch resolver is deliberately NOT built here; this is only
    the hook that makes engine selection possible (F3 fills in the resolver).

    Args:
        database: A database dict as returned by :func:`load_database`.
        profile_id: The id to select, or ``None`` for the first profile.
        engine: An engine to filter candidates by, or ``None`` for no filter.

    Returns:
        The selected profile dict.

    Raises:
        MemoryScanPatternError: if the database has no profiles, if no profile
            declares ``engine``, or if no profile matches ``profile_id`` (the
            message lists the known ids).
    """
    profiles = _profiles_of(database, "database")
    if not profiles:
        raise MemoryScanPatternError("database: 'profiles' is empty")
    if engine is not None:
        # Lenient read (not _profile_engine) so filtering never raises on an
        # unrelated profile's bad engine key; that is validate_profile()'s job.
        profiles = [p for p in profiles if p.get("engine", _DEFAULT_ENGINE) == engine]
        if not profiles:
            raise MemoryScanPatternError(
                f"no profile with engine '{engine}' in the database")
    if profile_id is None:
        return profiles[0]
    for profile in profiles:
        if profile.get("id") == profile_id:
            return profile
    known = ", ".join(str(profile.get("id")) for profile in profiles)
    raise MemoryScanPatternError(
        f"no profile with id '{profile_id}'; the database has: {known}")


# --------------------------------------------------------------------------- #
# Strict structural validation
#
# Ported from research/memory_scan/bssl_secret_scan.py's _validate_* family.
# Every check guards against a cross-section reference that would fail silently
# at scan time rather than loudly here.
# --------------------------------------------------------------------------- #

def _require_keys(mapping: Any, keys: Sequence[str], where: str) -> None:
    """Fail with one message listing everything missing under ``where``."""
    if not isinstance(mapping, dict):
        raise MemoryScanPatternError(f"{where}: expected an object")
    missing = [key for key in keys if key not in mapping]
    if missing:
        raise MemoryScanPatternError(
            f"{where}: missing required key(s): {', '.join(missing)}")


def _objects(container: Any, key_path: str) -> list[dict[str, Any]]:
    """A list-of-objects section, checked to actually be one."""
    if not isinstance(container, list):
        raise MemoryScanPatternError(f"{key_path}: expected a list")
    for index, entry in enumerate(container):
        if not isinstance(entry, dict):
            raise MemoryScanPatternError(f"{key_path}[{index}]: expected an object")
    return container


def _tier(profile: dict[str, Any], name: str) -> dict[str, Any]:
    """The named tier, or an empty object when the profile omits it.

    A profile may leave a tier out; what it may not do is define one that refers
    to a label, a struct or an offset that does not exist.
    """
    tier = profile["tiers"].get(name)
    return tier if isinstance(tier, dict) else {}


def _tier_a_slots(profile: dict[str, Any]) -> list[dict[str, Any]]:
    """The SSL_HANDSHAKE secret slots Tier A reads."""
    return _objects(_tier(profile, _TIER_A).get("slots", []), f"tiers.{_TIER_A}.slots")


def _tier_b_s3_secrets(profile: dict[str, Any]) -> list[dict[str, Any]]:
    """The SSL3_STATE traffic secrets Tier B reads, as {field, label} entries."""
    return _objects(
        _tier(profile, _TIER_B).get("s3_secrets", []), f"tiers.{_TIER_B}.s3_secrets")


def _tier_b_session(profile: dict[str, Any]) -> dict[str, Any]:
    """Tier B's TLS 1.2 master-secret section, or {} when it is absent."""
    session = _tier(profile, _TIER_B).get("tls12_session")
    return session if isinstance(session, dict) else {}


def _iter_emitted_labels(profile: dict[str, Any]) -> Iterator[tuple[str, Any]]:
    """Yield (key path, label) for every NSS label some tier can emit."""
    for index, slot in enumerate(_tier_a_slots(profile)):
        if slot.get("label") is not None:
            yield f"tiers.{_TIER_A}.slots[{index}].label", slot["label"]
    for index, secret in enumerate(_tier_b_s3_secrets(profile)):
        yield f"tiers.{_TIER_B}.s3_secrets[{index}].label", secret.get("label")
    session = _tier_b_session(profile)
    if session:
        yield f"tiers.{_TIER_B}.tls12_session.label", session.get("label")


def _validate_label_references(profile: dict[str, Any]) -> None:
    """Every label a tier can emit must be declared in keylog_labels.

    Without this check a mistyped label travels all the way into the keylog
    file, where every consumer ignores the line in silence.
    """
    declared = set(profile["keylog_labels"])
    for key_path, label in _iter_emitted_labels(profile):
        if label not in declared:
            raise MemoryScanPatternError(
                f"{key_path}: '{label}' is not listed in profile.keylog_labels "
                f"({', '.join(sorted(declared))})")


def _validate_s3_secret_fields(profile: dict[str, Any]) -> None:
    """Each Tier B s3_secrets field must name a real SSL3_STATE offset pair.

    The agent reads SSL3_STATE[field] and SSL3_STATE[field + '_len']. A
    misspelled field leaves both undefined, which surfaces at scan time as one
    exception per candidate instead of as a bad profile.
    """
    ssl3_state = profile["struct_offsets"]["SSL3_STATE"]
    for index, secret in enumerate(_tier_b_s3_secrets(profile)):
        field_name = secret.get("field")
        for needed in (field_name, f"{field_name}_len"):
            if needed not in ssl3_state:
                raise MemoryScanPatternError(
                    f"tiers.{_TIER_B}.s3_secrets[{index}].field: '{field_name}' needs "
                    f"struct_offsets.SSL3_STATE.{needed}, which the profile does not define")


def _validate_session_paths(profile: dict[str, Any]) -> None:
    """Each tls12_session path must name a struct the profile describes.

    The agent walks 'from' as a struct name and 'field' as an offset inside it,
    so a path naming either wrongly dereferences an undefined offset rather than
    failing here.
    """
    structs = profile["struct_offsets"]
    session = _tier_b_session(profile)
    if not session:
        return
    base = f"tiers.{_TIER_B}.tls12_session.paths"
    for index, path in enumerate(_objects(session.get("paths", []), base)):
        struct_name, field_name = path.get("from"), path.get("field")
        if struct_name not in structs:
            raise MemoryScanPatternError(
                f"{base}[{index}].from: '{struct_name}' is not a key of "
                f"profile.struct_offsets")
        if field_name not in structs[struct_name]:
            raise MemoryScanPatternError(
                f"{base}[{index}].field: '{field_name}' is not a key of "
                f"profile.struct_offsets.{struct_name}")


def _validate_session_struct_fields(profile: dict[str, Any]) -> None:
    """Every SSL_SESSION offset the agent dereferences must exist and be a number.

    These are named in agent/scanner.js rather than in the profile, so the
    reference checks above cannot reach them. A profile that spells 'secret' as
    'master_key' would otherwise pass startup validation and then throw once per
    candidate for the rest of the run.
    """
    session = profile["struct_offsets"]["SSL_SESSION"]
    _require_keys(session, _REQUIRED_SESSION_FIELDS, "profile.struct_offsets.SSL_SESSION")
    for field_name in _REQUIRED_SESSION_FIELDS:
        offset = session[field_name]
        # bool is a subclass of int, so isinstance() alone would wave a JSON
        # `true` through as offset 1 - a readable address, and therefore silent.
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise MemoryScanPatternError(
                f"profile.struct_offsets.SSL_SESSION.{field_name}: expected an offset "
                f"in bytes, the profile says {offset!r}")


def _require_offset(mapping: dict[str, Any], key: str, expected: int, where: str) -> None:
    """Fail when a hand-written offset disagrees with its derived value."""
    if mapping.get(key) != expected:
        raise MemoryScanPatternError(
            f"{where}.{key}: expected {expected}, the profile says {mapping.get(key)}")


def _validate_derived_offsets(profile: dict[str, Any]) -> None:
    """Re-derive the hand-expanded offset tables from the constants.

    The Tier A slots and the SSL3_STATE '<field>_len' keys are nothing but
    secret_run_base + i * stride and data + capacity. On a build with a
    different SSL_MAX_MD_SIZE every one of them is wrong - and a wrong offset
    does not crash, it reads the neighbouring heap and emits plausible garbage.
    Checking the relation is what makes retargeting fail loudly.
    """
    constants = profile["constants"]
    capacity = constants["ssl_max_md_size"]
    stride = constants["inplace_vector_stride"]
    if stride != capacity + 1:
        raise MemoryScanPatternError(
            f"profile.constants.inplace_vector_stride: an "
            f"InplaceVector<uint8_t, {capacity}> with a one-byte length is "
            f"{capacity + 1} bytes, the profile says {stride}")
    if constants["ssl_version_tls13"] != constants["ssl_version_tls12"] + 1:
        raise MemoryScanPatternError(
            "profile.constants.ssl_version_tls13: TLS 1.2 and 1.3 are 0x0303 and "
            "0x0304, which is what makes the Tier A anchors adjacent little-endian "
            "uint16 pairs")
    slots = _tier_a_slots(profile)
    if slots:
        handshake = profile["struct_offsets"]["SSL_HANDSHAKE"]
        _require_keys(handshake, ("secret_run_base",),
                      "profile.struct_offsets.SSL_HANDSHAKE")
        for index, slot in enumerate(slots):
            where = f"tiers.{_TIER_A}.slots[{index}]"
            _require_offset(slot, "data",
                            handshake["secret_run_base"] + index * stride, where)
            _require_offset(slot, "len", slot["data"] + capacity, where)
    ssl3_state = profile["struct_offsets"]["SSL3_STATE"]
    for secret in _tier_b_s3_secrets(profile):
        field_name = secret["field"]
        _require_offset(ssl3_state, f"{field_name}_len",
                        ssl3_state[field_name] + capacity,
                        "profile.struct_offsets.SSL3_STATE")


def _validate_tier_cross_references(profile: dict[str, Any]) -> None:
    """Check the numbers a tier restates from another section still agree.

    Each of these is written twice in the JSON, once where it is defined and
    once where a tier uses it, and an edit that changes one copy and not the
    other is silent: the scan runs, the patterns match, every candidate fails to
    validate, and the silence report blames the patterns.
    """
    constants = profile["constants"]
    tier_a = _tier(profile, _TIER_A)
    if tier_a:
        anchor = tier_a.get("anchor_offset_in_struct")
        min_version = profile["struct_offsets"]["SSL_HANDSHAKE"].get("min_version")
        if anchor != min_version:
            raise MemoryScanPatternError(
                f"tiers.{_TIER_A}.anchor_offset_in_struct: {anchor} does not equal "
                f"profile.struct_offsets.SSL_HANDSHAKE.min_version ({min_version}). "
                f"The anchor IS the min_version||max_version pair, and the agent "
                f"subtracts this offset from every hit to get the SSL_HANDSHAKE "
                f"base - so a disagreement puts every Tier A base off, which "
                f"validates 0 candidates and reads on screen as a pattern that "
                f"matched nothing")
    session = _tier_b_session(profile)
    if not session:
        return
    where = f"tiers.{_TIER_B}.tls12_session"
    required_version = session.get("require_ssl_version")
    if required_version != constants["ssl_version_tls12"]:
        raise MemoryScanPatternError(
            f"{where}.require_ssl_version: {required_version} does not equal "
            f"profile.constants.ssl_version_tls12 ({constants['ssl_version_tls12']}); "
            f"the TLS 1.2 master-secret path compares SSL_SESSION.ssl_version "
            f"against it, so it would reject every session the profile was written "
            f"to accept")
    required_len = session.get("require_secret_len")
    valid_lens = constants["valid_hash_lens"]
    if required_len not in valid_lens:
        raise MemoryScanPatternError(
            f"{where}.require_secret_len: {required_len} is not one of "
            f"profile.constants.valid_hash_lens "
            f"({', '.join(str(length) for length in valid_lens)}); no secret the "
            f"validators accept can have that length, so the path can only ever "
            f"emit nothing")


def _validate_rescan_every(profile: dict[str, Any]) -> None:
    """Check Tier A's throttle is a scan count the loop can count to.

    The key is optional and its absence means 1 (run the tier every scan), so
    only a value that is actually present is checked. A bool, a zero/negative or
    a non-integer would each silently change how often the tier runs rather than
    fail.
    """
    tier_a = _tier(profile, _TIER_A)
    if "rescan_every" not in tier_a:
        return
    value = tier_a["rescan_every"]
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise MemoryScanPatternError(
            f"tiers.{_TIER_A}.rescan_every: expected an integer scan count >= 1 - "
            f"1 runs the tier on every scan, which is also what leaving the key out "
            f"means - the profile says {value!r}")


def _profile_engine(profile: dict[str, Any]) -> str:
    """Return the profile's engine discriminator, defaulting to boringssl.

    An absent ``engine`` key means ``"boringssl"``, so the shipped profile - and
    any pre-existing user profile written before engines existed - keeps
    validating exactly as before. An ``engine`` that is present but not one this
    loader knows how to validate is a fail-loud error, the same as any other
    unusable profile: better a startup exception than a scan against rules that
    silently do not exist yet.
    """
    engine = profile.get("engine", _DEFAULT_ENGINE)
    if not isinstance(engine, str) or engine not in _KNOWN_ENGINES:
        raise MemoryScanPatternError(
            f"profile.engine: {engine!r} is not one of {', '.join(_KNOWN_ENGINES)}")
    return engine


def _validate_boringssl_profile(profile: dict[str, Any]) -> None:
    """Strict structural validation of a BoringSSL profile.

    This is the original :func:`validate_profile` body, moved verbatim under the
    engine dispatch. The BoringSSL-required structs, session fields and derived
    offsets are enforced here and ONLY here, which is what scopes them to the
    boringssl engine without changing how a boringssl profile is validated.
    """
    _require_keys(profile, _REQUIRED_PROFILE_KEYS, "profile")
    _require_keys(profile["constants"], _REQUIRED_CONSTANTS, "profile.constants")
    _require_keys(profile["constants"], _SELF_CHECK_CONSTANTS, "profile.constants")
    _require_keys(profile["struct_offsets"], _REQUIRED_STRUCTS, "profile.struct_offsets")
    if not isinstance(profile["tiers"], dict) or not profile["tiers"]:
        raise MemoryScanPatternError("profile.tiers: expected a non-empty object")
    if not isinstance(profile["keylog_labels"], list) or not profile["keylog_labels"]:
        raise MemoryScanPatternError("profile.keylog_labels: expected a non-empty list")
    _validate_label_references(profile)
    _validate_s3_secret_fields(profile)
    _validate_session_paths(profile)
    _validate_session_struct_fields(profile)
    _validate_derived_offsets(profile)
    _validate_tier_cross_references(profile)
    _validate_rescan_every(profile)


# --------------------------------------------------------------------------- #
# Schannel (WS4). A schannel profile carries per-arch offset sets under
# ``arch`` — the agent is data-driven, so the host resolves the arch-appropriate
# block (see :func:`resolve_schannel_arch`) into ``profile["resolved"]`` before
# ``configure()``. Validation checks the shape of every arch block so a typo in a
# build-specific offset fails loudly at startup, not as a silent miss in lsass.
# --------------------------------------------------------------------------- #

# Every arch block the agent's tls12_master / session_cache / tls13_secret tiers
# dereference. Numeric offsets are int-checked; the needle candidates are the one
# build-specific value that may legitimately be empty (uncalibrated arch).
_SCHANNEL_TLS12_OFFSETS = ("needle_at", "master_at", "master_len")
_SCHANNEL_SESSION_OFFSETS = (
    "vftable_at", "bddd_ptr_at", "ssl5_ptr_at", "ssl5_needle_at", "master_at",
    "master_len", "bddd_magic_at", "session_id_at", "session_id_maxlen",
)


def _is_int(value: Any) -> bool:
    """A real integer (JSON ``true`` is an int subclass, so exclude it)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _require_int_offsets(mapping: dict[str, Any], keys: Sequence[str], where: str) -> None:
    """Every named key must be present and an integer offset."""
    _require_keys(mapping, keys, where)
    for key in keys:
        if not _is_int(mapping[key]):
            raise MemoryScanPatternError(
                f"{where}.{key}: expected an integer offset, the profile says "
                f"{mapping[key]!r}")


def _validate_schannel_arch_block(block: Any, where: str) -> None:
    """Validate one per-arch offset set (needle + tiers)."""
    if not isinstance(block, dict):
        raise MemoryScanPatternError(f"{where}: expected an object")
    needle = block.get("needle")
    if not isinstance(needle, dict):
        raise MemoryScanPatternError(f"{where}.needle: expected an object")
    if not isinstance(needle.get("module"), str) or not needle["module"]:
        raise MemoryScanPatternError(f"{where}.needle.module: expected a module name")
    candidates = needle.get("candidates", [])
    # An empty candidate list is legal (an uncalibrated arch scans for no needle
    # and no-ops rather than emit garbage); a non-list, or a candidate without a
    # string rva, is a malformed offset set.
    if not isinstance(candidates, list):
        raise MemoryScanPatternError(f"{where}.needle.candidates: expected a list")
    for index, cand in enumerate(candidates):
        if not isinstance(cand, dict) or not isinstance(cand.get("rva"), str):
            raise MemoryScanPatternError(
                f"{where}.needle.candidates[{index}].rva: expected a hex string rva")
    tiers = block.get("tiers")
    if not isinstance(tiers, dict) or not tiers:
        raise MemoryScanPatternError(f"{where}.tiers: expected a non-empty object")
    tls12 = tiers.get("tls12_master")
    if isinstance(tls12, dict):
        _require_int_offsets(tls12, _SCHANNEL_TLS12_OFFSETS, f"{where}.tiers.tls12_master")
    session = tiers.get("session_cache")
    if isinstance(session, dict):
        _require_int_offsets(session, _SCHANNEL_SESSION_OFFSETS,
                             f"{where}.tiers.session_cache")
    tls13 = tiers.get("tls13_secret")
    if isinstance(tls13, dict) and not _is_int(tls13.get("secret_at")):
        raise MemoryScanPatternError(
            f"{where}.tiers.tls13_secret.secret_at: expected an integer offset")


def _validate_schannel_profile(profile: dict[str, Any]) -> None:
    """Strict structural validation of a Schannel profile.

    Enforces the minimal shared shape unconditionally, and — following the
    additive convention the rest of this loader uses — validates the
    schannel-specific ``arch`` offset sets strictly whenever they are PRESENT: a
    profile that carries an ``arch`` block must have every arch describe a needle
    (module + a possibly-empty candidate list of hex rvas) and tier offsets that
    are real integers. A malformed offset set fails here rather than as a silent
    miss in lsass. A skeletal profile that carries no ``arch`` (e.g. a resolver
    test fixture that only exercises engine/protocol/platform selection) is left
    to fail at configure time, exactly as the pre-existing scaffolding did.
    """
    _require_keys(profile, _MINIMAL_PROFILE_KEYS, "schannel profile")
    arch = profile.get("arch")
    if arch is None:
        return
    if not isinstance(arch, dict) or not arch:
        raise MemoryScanPatternError(
            "schannel profile.arch: expected a non-empty object mapping "
            "arch name -> offset set (e.g. {\"arm64\": {...}, \"x64\": {...}})")
    for name, block in arch.items():
        _validate_schannel_arch_block(block, f"schannel profile.arch.{name}")


def select_schannel_offsets(profile: dict[str, Any], arch: Optional[str]) -> dict[str, Any]:
    """Return the arch-appropriate offset set (needle + tiers) from a profile.

    Arch selection is done HERE, in Python, at configure time (not in the agent
    from ``Process.arch``) so the agent stays purely data-driven: it reads
    ``profile["resolved"]`` and never branches on architecture. ``arch`` is the
    frida-reported architecture (``"arm64"``, ``"x64"``, ...). When it names an
    arch the profile describes, that block is returned; when it does not (or is
    ``None``) and the profile describes exactly one arch, that single block is
    returned; otherwise this fails loudly, naming the available arches.
    """
    arch_sets = profile.get("arch")
    if not isinstance(arch_sets, dict) or not arch_sets:
        raise MemoryScanPatternError(
            "schannel profile.arch: no per-arch offset sets to select from")
    if arch and arch in arch_sets:
        return arch_sets[arch]
    if len(arch_sets) == 1:
        return next(iter(arch_sets.values()))
    raise MemoryScanPatternError(
        f"schannel profile.arch: no offset set for arch {arch!r}; the profile "
        f"has: {', '.join(sorted(arch_sets))}")


def resolve_schannel_arch(profile: dict[str, Any], arch: Optional[str]) -> dict[str, Any]:
    """Return a copy of ``profile`` with the arch-resolved offsets under ``resolved``.

    The plugin calls this for every schannel profile before ``configure()`` so
    the agent finds its needle rvas and tier offsets under ``profile["resolved"]``
    without knowing which architecture it is running on. The original profile is
    left untouched (a shallow copy is returned).
    """
    resolved = dict(profile)
    resolved["resolved"] = select_schannel_offsets(profile, arch)
    return resolved


# --------------------------------------------------------------------------- #
# RC4 (WS3). An RC4 profile is fully generic — no build-specific layout — so
# validation checks the tunable parameter shape, the KAT bytes, and that the KAT
# actually holds (RC4(key, plaintext) == ciphertext), so a bad core is caught
# here rather than emitting nothing in the target.
# --------------------------------------------------------------------------- #

_RC4_REQUIRED_PARAMS = (
    "min_key_len", "max_key_len", "trial_prefix", "accept_printable_fraction",
)
_RC4_KAT_FIELDS = ("key", "plaintext", "ciphertext")


def _valid_hex_bytes(value: Any) -> bool:
    """A non-empty, even-length lowercase/uppercase hex string."""
    if not isinstance(value, str) or not value or (len(value) % 2) != 0:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _validate_rc4_profile(profile: dict[str, Any]) -> None:
    """Strict structural validation of an RC4 profile.

    Enforces the minimal shared shape unconditionally, and — following the
    additive convention the rest of this loader uses — validates the RC4
    ``params`` and ``kat`` sections strictly whenever they are PRESENT: the
    tunable parameters must be correctly typed and in bounds, and the KAT bytes
    must be valid hex AND actually hold (RC4(key, plaintext) == ciphertext), so a
    mistyped test vector fails loudly at startup rather than validating the
    agent's core against a false vector. A skeletal profile carrying neither (a
    resolver test fixture) passes here and fails at configure time, exactly as
    the pre-existing scaffolding did.
    """
    _require_keys(profile, _MINIMAL_PROFILE_KEYS, "rc4 profile")

    params = profile.get("params")
    if params is not None:
        _validate_rc4_params(params)
    kat = profile.get("kat")
    if kat is not None:
        _validate_rc4_kat(kat)


def _validate_rc4_params(params: Any) -> None:
    """Validate the RC4 tunable parameter block (present, typed, in bounds)."""
    _require_keys(params, _RC4_REQUIRED_PARAMS, "rc4 profile.params")
    min_len, max_len = params["min_key_len"], params["max_key_len"]
    trial_prefix = params["trial_prefix"]
    frac = params["accept_printable_fraction"]
    if not _is_int(min_len) or min_len < 1 or min_len > 256:
        raise MemoryScanPatternError(
            f"rc4 profile.params.min_key_len: expected an int in 1..256, "
            f"the profile says {min_len!r}")
    if not _is_int(max_len) or max_len < min_len or max_len > 256:
        raise MemoryScanPatternError(
            f"rc4 profile.params.max_key_len: expected an int in "
            f"min_key_len..256, the profile says {max_len!r}")
    if not _is_int(trial_prefix) or trial_prefix < 1:
        raise MemoryScanPatternError(
            f"rc4 profile.params.trial_prefix: expected a positive int, "
            f"the profile says {trial_prefix!r}")
    if not isinstance(frac, (int, float)) or isinstance(frac, bool) \
            or not (0.0 < float(frac) <= 1.0):
        raise MemoryScanPatternError(
            f"rc4 profile.params.accept_printable_fraction: expected a fraction "
            f"in (0, 1], the profile says {frac!r}")
    tokens = params.get("tokens")
    if tokens is not None and not isinstance(tokens, list):
        raise MemoryScanPatternError("rc4 profile.params.tokens: expected a list")
    _validate_rc4_optional_params(params)


# Params the improved scanner reads but that stay OPTIONAL for back-compat: an
# older/skeletal profile that omits them must still validate (their code-fallback
# defaults reproduce the pre-existing behaviour). They are only type-checked when
# PRESENT, following the additive convention the rest of this loader uses.
_RC4_OPTIONAL_HEX_PARAMS = ("ciphertext_sample", "known_plaintext")
_RC4_OPTIONAL_BOOL_PARAMS = (
    "sbox_first", "sbox_exact_validate", "prioritize_anonymous",
    "require_exact_or_accept", "use_cmodule", "grouped_read",
    "needs_mapped_index",
)
_RC4_OPTIONAL_POS_INT_PARAMS = ("cmodule_batch", "read_group_bytes")


def _validate_rc4_optional_params(params: dict[str, Any]) -> None:
    """Type-check the improved scanner's optional params whenever they are present.

    None of these are required (:data:`_RC4_REQUIRED_PARAMS` is unchanged), so a
    profile that omits them is left untouched; a profile that sets one to the
    wrong type fails loudly here rather than being silently misinterpreted by the
    agent. A ``None`` value is always allowed (it means "unset").
    """
    for name in _RC4_OPTIONAL_HEX_PARAMS:
        value = params.get(name)
        if value is not None and not _valid_hex_bytes(value):
            raise MemoryScanPatternError(
                f"rc4 profile.params.{name}: expected a non-empty even-length hex "
                f"string (or null), the profile says {value!r}")
    for name in _RC4_OPTIONAL_BOOL_PARAMS:
        value = params.get(name)
        if value is not None and not isinstance(value, bool):
            raise MemoryScanPatternError(
                f"rc4 profile.params.{name}: expected a bool (or null), "
                f"the profile says {value!r}")
    for name in _RC4_OPTIONAL_POS_INT_PARAMS:
        value = params.get(name)
        if value is not None and (not _is_int(value) or value < 1):
            raise MemoryScanPatternError(
                f"rc4 profile.params.{name}: expected a positive int (or null), "
                f"the profile says {value!r}")


def _validate_rc4_kat(kat: Any) -> None:
    """Validate the RC4 KAT block: hex-valid AND the vector actually holds."""
    _require_keys(kat, _RC4_KAT_FIELDS, "rc4 profile.kat")
    for field in _RC4_KAT_FIELDS:
        if not _valid_hex_bytes(kat[field]):
            raise MemoryScanPatternError(
                f"rc4 profile.kat.{field}: expected a non-empty even-length hex "
                f"string, the profile says {kat[field]!r}")
    # Lazy import so the loader's module load does not pull in the offline RC4
    # subsystem's import side-effects (its __init__ self-registers an offline
    # decryptor) and to keep the loader free of any import cycle.
    from friTap.offline.rc4.crypto import rc4
    got = rc4(bytes.fromhex(kat["key"]), bytes.fromhex(kat["plaintext"]))
    want = bytes.fromhex(kat["ciphertext"])
    if got != want:
        raise MemoryScanPatternError(
            f"rc4 profile.kat: RC4(key, plaintext) = {got.hex()} does not equal "
            f"the profile's ciphertext {want.hex()} — a wrong KAT means the agent "
            f"would validate its core against a false vector")


def _coerce_to_hex(value: str) -> str:
    """Normalise a CLI/config string to the lowercase hex the agent expects.

    A value that is already valid hex is passed through unchanged; anything else
    is treated as plain text and utf-8-encoded to hex. This keeps
    ``--ms-rc4-known-plaintext "GET /"`` and ``--ms-rc4-known-plaintext 474554``
    both usable without the caller having to know which form the agent wants.
    """
    if _valid_hex_bytes(value):
        return value.lower()
    return value.encode("utf-8").hex()


def apply_rc4_param_overrides(
    profile: dict[str, Any],
    *,
    known_plaintext: Optional[str] = None,
    ciphertext_sample: Optional[str] = None,
) -> dict[str, Any]:
    """Merge CLI/config RC4 param overrides into a profile, then re-validate.

    Only non-``None`` overrides are applied, so a call that passes nothing leaves
    the profile untouched (behaviour-preserving default). Each string override is
    normalised to lowercase hex via :func:`_coerce_to_hex` (already-hex is used
    as-is; plain text is utf-8-encoded to hex) so the agent always receives the
    hex form it reads. The merged ``params`` block is re-run through the RC4 param
    validation, so a malformed override still fails loudly here.

    Args:
        profile: The selected RC4 profile dict (mutated in place and returned).
        known_plaintext: An optional known-plaintext oracle (hex or plain text).
        ciphertext_sample: An optional ciphertext sample (hex or plain text).

    Returns:
        The same ``profile`` dict, with any overrides merged into ``params``.
    """
    overrides = {
        "known_plaintext": known_plaintext,
        "ciphertext_sample": ciphertext_sample,
    }
    if all(value is None for value in overrides.values()):
        return profile
    params = profile.setdefault("params", {})
    if not isinstance(params, dict):
        raise MemoryScanPatternError("rc4 profile.params: expected an object")
    for name, value in overrides.items():
        if value is not None:
            params[name] = _coerce_to_hex(value)
    _validate_rc4_params(params)
    return profile


# The engine dispatch table. Adding an engine's real rules later is a change to
# its one validator (registered here) - the dispatch structure itself does not
# move, which is the whole point of scaffolding it now.
def _validate_mtproto_profile(profile: dict[str, Any]) -> None:
    """Strict-where-present structural validation of an MTProto profile.

    Enforces the minimal shared shape unconditionally, then - following the
    additive convention used by the other engine validators - checks the
    sections the agent dereferences whenever they are PRESENT: ``tiers`` must be
    an object, and the two emitting tiers (``B_authkeyid_roundtrip`` for cloud
    auth keys, ``C_art_secretchat_key`` for E2E keys) must carry the fields the
    agent reads to build a keylog line. A skeletal profile (a resolver test
    fixture) passes here and fails later at configure time, exactly as the other
    engines' scaffolding does.
    """
    _require_keys(profile, _MINIMAL_PROFILE_KEYS, "mtproto profile")
    tiers = profile.get("tiers")
    if tiers is not None:
        if not isinstance(tiers, dict):
            raise MemoryScanPatternError("mtproto profile.tiers: expected an object")
        b = tiers.get("B_authkeyid_roundtrip")
        if b is not None:
            _require_keys(
                b, ("label", "slot_roles", "role_keylog_key_type"),
                "mtproto profile.tiers.B_authkeyid_roundtrip")
        c = tiers.get("C_art_secretchat_key")
        if c is not None and "label" not in c:
            raise MemoryScanPatternError(
                "mtproto profile.tiers.C_art_secretchat_key: missing 'label'")
        e = tiers.get("E_connection_ctr_state")
        if e is not None and "label" not in e:
            raise MemoryScanPatternError(
                "mtproto profile.tiers.E_connection_ctr_state: missing 'label'")
    validators = profile.get("validators")
    if validators is not None and not isinstance(validators, dict):
        raise MemoryScanPatternError("mtproto profile.validators: expected an object")


_ENGINE_VALIDATORS = {
    "boringssl": _validate_boringssl_profile,
    "schannel": _validate_schannel_profile,
    "rc4": _validate_rc4_profile,
    "mtproto": _validate_mtproto_profile,
}


def validate_profile(profile: dict[str, Any]) -> None:
    """Validate one profile's structure and cross-section references, strictly.

    Dispatches on the profile's ``engine`` (see :func:`_profile_engine`): a
    boringssl profile (the default when the key is absent) is validated exactly
    as before, by :func:`_validate_boringssl_profile`; schannel and rc4 profiles
    go to their own validators. An unknown engine name is rejected outright.

    For the boringssl engine this checks every section the agent dereferences,
    and that the values a section restates from another section still agree. A
    missing section fails on the first line that touches it; a label or a field
    that merely points at the wrong place fails once per candidate at scan time,
    or never - which is the silent failure this validator exists to prevent.

    Args:
        profile: A single profile dict, e.g. from :func:`select_profile`.

    Raises:
        MemoryScanPatternError: on an unknown engine, or on the first bad or
            missing reference, with a message naming the exact JSON path at
            fault.
    """
    if not isinstance(profile, dict):
        raise MemoryScanPatternError("profile: expected an object")
    engine = _profile_engine(profile)
    _ENGINE_VALIDATORS[engine](profile)


def load_memory_scan_profile(
    user_path: Optional[str],
    profile_id: Optional[str] = None,
    engine: Optional[str] = None,
) -> dict[str, Any]:
    """Load, merge, validate and select one memory-scan profile.

    The one-shot convenience the Frida plugin uses: it returns the single
    profile dict ready to hand straight to the agent's ``configure()`` rpc call.

    Args:
        user_path: Path to a user-supplied database to merge on top of the
            shipped default, or ``None`` to use the shipped default alone.
        profile_id: The profile id to select, or ``None`` for the first profile.
        engine: An engine to pre-filter candidate profiles by, or ``None`` for
            no filter (the default, so existing callers are unaffected). See
            :func:`select_profile`.

    Returns:
        The selected, validated profile dict.

    Raises:
        MemoryScanPatternError: on any load, merge, selection or validation
            failure.
    """
    database = load_database(user_path)
    profile = select_profile(database, profile_id, engine)
    validate_profile(profile)
    logger.info(
        "Selected memory-scan profile '%s' (%d tier(s))",
        profile.get("id"), len(profile.get("tiers", {})))
    # A profile may be calibrated for a specific target-library build (e.g. the
    # mtproto profile for a given libtmessages, where the SHA-1 auth-key
    # round-trip fails safe — recovering nothing rather than garbage — on other
    # builds). That otherwise looks like a silent zero-result run, so surface the
    # calibration whenever the profile records one, for any engine.
    calibrated = profile.get("calibrated_lib_version")
    if calibrated:
        logger.info(
            "Profile '%s' calibrated for %s; recovery may be empty on other "
            "builds.", profile.get("id"), calibrated)
    return profile


# --------------------------------------------------------------------------- #
# Engine/profile resolution (F3)
#
# select_profiles() turns "the user's --protocol set + the target platform + an
# optional -ms override" into the ordered list of profiles to run. It is the
# single place that decides WHICH engines apply; the per-scan_target session
# plumbing in the plugin decides WHERE each resolved profile runs.
# --------------------------------------------------------------------------- #

def _profile_protocol(profile: dict[str, Any]) -> str:
    """The protocol a profile belongs to, defaulting to ``"tls"``."""
    value = profile.get("protocol", _DEFAULT_PROTOCOL)
    return value if isinstance(value, str) else _DEFAULT_PROTOCOL


def _profile_platforms(profile: dict[str, Any]) -> list[str]:
    """The platforms a profile applies to, defaulting to ``["all"]``."""
    value = profile.get("platforms", list(_DEFAULT_PLATFORMS))
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value:
        return [str(item) for item in value]
    return list(_DEFAULT_PLATFORMS)


def _profile_scan_target(profile: dict[str, Any]) -> str:
    """The process a profile's scan runs in ("self" or "lsass"), default "self"."""
    value = profile.get("scan_target", _DEFAULT_SCAN_TARGET)
    return value if isinstance(value, str) else _DEFAULT_SCAN_TARGET


def normalize_os_name(os_name: Optional[str]) -> Optional[str]:
    """Map a device/host OS string onto friTap's canonical platform strings.

    Accepts the values a frida ``query_system_parameters()['os']['id']`` or a
    host ``sys.platform`` reports (``"darwin"`` -> ``"macos"``, ``"win32"`` ->
    ``"windows"``, and so on) and returns one of ``windows | linux | android |
    macos | ios``. An already-canonical name is returned unchanged; an
    unrecognised or ``None`` name returns ``None`` (a profile pinned to a named
    platform then never matches it, while an ``["all"]`` profile still does).
    """
    if not os_name:
        return None
    key = str(os_name).strip().lower()
    if key in _KNOWN_OS_NAMES:
        return key
    return _OS_ALIASES.get(key)


def _platform_matches(profile: dict[str, Any], os_name: Optional[str]) -> bool:
    """True when a profile's ``platforms`` covers ``os_name`` (or is ``["all"]``)."""
    platforms = [p.lower() for p in _profile_platforms(profile)]
    if "all" in platforms:
        return True
    return os_name is not None and os_name in platforms


def _merge_user_db_into(db: dict[str, Any], user_path: str) -> dict[str, Any]:
    """Merge a custom database file's profiles into ``db`` by id, in place.

    Reuses the same merge-by-id semantics as :func:`load_database` so a ``-ms
    <file>`` override behaves identically whether it arrives through the loader
    or through the resolver: a user profile replaces the shipped profile of the
    same id, otherwise it is appended.
    """
    if not os.path.exists(user_path):
        raise MemoryScanPatternError(f"user pattern file '{user_path}' does not exist")
    user_database = _load_json(user_path)
    if "schema" in user_database and user_database.get("schema") != _SUPPORTED_SCHEMA:
        raise MemoryScanPatternError(
            f"{user_path}: expected \"schema\": {_SUPPORTED_SCHEMA}")
    user_profiles = _profiles_of(user_database, user_path)
    db["profiles"] = _merge_profiles(_profiles_of(db, "database"), user_profiles)
    logger.info("Merged %d user profile(s) from %s", len(user_profiles), user_path)
    return db


def _protocol_platform_selection(
    profiles: list[dict[str, Any]],
    selected_protocols: Sequence[str],
    os_name: Optional[str],
) -> list[dict[str, Any]]:
    """Every profile whose protocol is selected and whose platform matches."""
    wanted = set(selected_protocols)
    # An umbrella protocol (e.g. "telegram") also selects the profile of the
    # memory-scan engine it resolves to (e.g. the "mtproto" profile).
    for name in list(wanted):
        alias = _PROTOCOL_ENGINE_ALIASES.get(name)
        if alias:
            wanted.add(alias)
    return [
        profile for profile in profiles
        if _profile_protocol(profile) in wanted and _platform_matches(profile, os_name)
    ]


def select_profiles(
    db: dict[str, Any],
    selected_protocols: Sequence[str],
    os_name: Optional[str],
    ms_arg: Any = None,
) -> list[dict[str, Any]]:
    """Resolve the ordered list of memory-scan profiles to run.

    This is the F3 engine resolver. It maps the user's selected ``--protocol``
    set, the target platform and an optional ``-ms`` override onto the profiles
    in ``db`` (as returned by :func:`load_database`). Resolution order:

    1. ``ms_arg`` is an existing **file path** -> its profiles are merged into
       ``db`` by id (same rule as :func:`load_database`), then the protocol/
       platform selection in step 3 runs over the merged database.
    2. ``ms_arg`` is a known **engine name** (``boringssl | schannel | rc4 |
       mtproto``, plus the ``telegram`` alias for ``mtproto``) or a known profile
       **id** -> *targeted*: only the matching profile(s) are returned, regardless
       of protocol or platform.
    3. ``ms_arg`` is bare (``True`` / ``None`` / empty) -> every profile whose
       ``protocol`` (default ``"tls"``) is in ``selected_protocols`` AND whose
       ``platforms`` (default ``["all"]``) covers ``os_name`` (or is ``["all"]``).

    A string ``ms_arg`` that is neither an existing file, a known engine, nor a
    known profile id is a fail-loud error naming the valid engines. When nothing
    matches, an empty list is returned (the caller logs "no mem-scan engine for
    this protocol/platform" and no-ops). Every returned profile is validated
    through the engine dispatch (:func:`validate_profile`) before it is returned.

    Args:
        db: A database dict from :func:`load_database`.
        selected_protocols: The canonical ``--protocol`` set (e.g. ``["tls"]``).
        os_name: The target OS; normalised via :func:`normalize_os_name`.
        ms_arg: The raw ``-ms`` argument — a file path, an engine/profile name,
            ``True`` (bare ``-ms``), or ``None``.

    Returns:
        The ordered list of profile dicts to run (possibly empty).

    Raises:
        MemoryScanPatternError: on an unknown ``ms_arg`` name, or on any profile
            that fails validation.
    """
    os_name = normalize_os_name(os_name)

    # A real string argument (not the bare ``-ms`` sentinel True) is either a
    # custom database file or a targeted engine/id. File wins over name so a
    # path that happens to collide with an engine name still loads.
    targeted = None
    if isinstance(ms_arg, str) and ms_arg:
        if os.path.exists(ms_arg):
            _merge_user_db_into(db, ms_arg)
        elif ms_arg in _KNOWN_ENGINES:
            targeted = ("engine", ms_arg)
        elif ms_arg in _PROTOCOL_ENGINE_ALIASES:
            targeted = ("engine", _PROTOCOL_ENGINE_ALIASES[ms_arg])
        else:
            profiles = _profiles_of(db, "database")
            if any(p.get("id") == ms_arg for p in profiles):
                targeted = ("id", ms_arg)
            else:
                raise MemoryScanPatternError(
                    f"-ms value '{ms_arg}' is not an existing pattern file, a known "
                    f"engine ({', '.join(_KNOWN_ENGINES)}), or a profile id in the "
                    f"database")

    profiles = _profiles_of(db, "database")

    if targeted is not None:
        kind, value = targeted
        if kind == "engine":
            selected = [p for p in profiles
                        if p.get("engine", _DEFAULT_ENGINE) == value]
        else:
            selected = [p for p in profiles if p.get("id") == value]
    else:
        selected = _protocol_platform_selection(profiles, selected_protocols, os_name)

    for profile in selected:
        validate_profile(profile)
    return selected


def group_profiles_by_scan_target(
    profiles: Sequence[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Split resolved profiles by their ``scan_target``.

    Returns an ordered mapping of ``scan_target`` -> profiles, preserving the
    order profiles appear in ``profiles``. The plugin runs one Frida memscan
    session per key: ``"self"`` profiles load into the injected target process,
    ``"lsass"`` profiles into a separate session attached to lsass.exe.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        grouped.setdefault(_profile_scan_target(profile), []).append(profile)
    return grouped
