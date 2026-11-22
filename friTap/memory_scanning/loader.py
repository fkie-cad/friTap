#!/usr/bin/env python3

"""Pattern loader for friTap's memory-scan feature.

The agent carries no layout knowledge: every offset, stride, byte pattern and
NSS label arrives through ``configure(profile)`` from a profile in the JSON
database. This module loads the shipped database, merges a user database on
top and validates a profile strictly.

Strictness matters: a bad pattern or offset raises nothing at scan time, it
matches nothing or reads neighbouring heap, which looks like "no TLS traffic".
Validation mirrors ``research/memory_scan/bssl_secret_scan.py``.

Entry points: :func:`load_database`, :func:`select_profile`,
:func:`validate_profile`, :func:`load_memory_scan_profile`. Every bad database
or profile raises :class:`MemoryScanPatternError`.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Iterator, Optional, Sequence

logger = logging.getLogger("friTap.memory_scanning.loader")

_DEFAULT_DATABASE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "patterns.json",
)

# Bumped only when the top-level shape changes in a way this code cannot read.
_SUPPORTED_SCHEMA = 1

# What the agent dereferences: the contract between the JSON database and
# agent/scanner.js. Keep in sync with research/memory_scan/bssl_secret_scan.py.
_REQUIRED_PROFILE_KEYS = (
    "id", "scan_regions", "constants", "struct_offsets", "tiers",
    "validators", "keylog_labels",
)
_REQUIRED_CONSTANTS = (
    "ssl_max_md_size", "ssl3_random_size", "valid_hash_lens", "ssl_version_tls12",
)
# Read only by this validator, to re-derive the offset tables
# (see :func:`_validate_derived_offsets`).
_SELF_CHECK_CONSTANTS = ("inplace_vector_stride", "ssl_version_tls13")
_REQUIRED_STRUCTS = ("SSL", "SSL3_STATE", "SSL_HANDSHAKE", "SSL_SESSION")
# Every struct_offsets.SSL_SESSION key the agent dereferences; nothing else in
# the JSON names them, so they are checked unconditionally as one block.
_REQUIRED_SESSION_FIELDS = (
    "ssl_version", "secret", "secret_len", "session_id", "session_id_len",
)

_TIER_A = "A_ssl_handshake"
_TIER_B = "B_ssl_method_ptr"

# A profile without an engine key is "boringssl" (the shipped profile omits it).
# validate_profile() dispatches on engine so the boringssl checks above stay
# scoped to it.
_DEFAULT_ENGINE = "boringssl"
_KNOWN_ENGINES = ("boringssl", "schannel", "rc4", "mtproto")

_DEFAULT_PROTOCOL = "tls"

# Umbrella protocols that resolve to a single engine ("telegram" is MTProto + E2E,
# both scanned by the mtproto engine).
_PROTOCOL_ENGINE_ALIASES = {"telegram": "mtproto"}
_DEFAULT_PLATFORMS = ("all",)
_DEFAULT_SCAN_TARGET = "self"
# "self" is the injected target process; "lsass" is a separate Frida session on
# lsass.exe (Windows Schannel).
_KNOWN_SCAN_TARGETS = ("self", "lsass")
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
_MINIMAL_PROFILE_KEYS = ("id", "scan_regions")


class MemoryScanPatternError(Exception):
    """A pattern database or profile that cannot be trusted (unloadable, unknown id, dangling structural reference)."""


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

    A matching id replaces the base profile in place; a new id is appended. Whole
    profiles are replaced, never deep-merged, so one build's offsets are never
    mixed with another's constants.
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
    """Load the shipped database and merge ``user_path`` (if given) on top by profile id.

    A user file may add or override profiles, never remove shipped ones.
    Raises MemoryScanPatternError on a missing file, bad JSON or unsupported schema.
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

    ``engine`` pre-filters candidates by their engine (absent key = boringssl);
    protocol/platform resolution lives in :func:`select_profiles`.
    Raises MemoryScanPatternError on no profiles, no engine match or unknown id.
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
    """The named tier, or {} when the profile omits it.

    A tier may be absent; it may not reference a label, struct or offset that does not exist.
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
    """Every label a tier can emit must be declared in keylog_labels (a typo would otherwise be ignored silently by every consumer)."""
    declared = set(profile["keylog_labels"])
    for key_path, label in _iter_emitted_labels(profile):
        if label not in declared:
            raise MemoryScanPatternError(
                f"{key_path}: '{label}' is not listed in profile.keylog_labels "
                f"({', '.join(sorted(declared))})")


def _validate_s3_secret_fields(profile: dict[str, Any]) -> None:
    """Each Tier B s3_secrets field must name a real SSL3_STATE offset pair.

    The agent reads SSL3_STATE[field] and [field + '_len']; a misspelling would
    throw once per candidate at scan time.
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
    """Each tls12_session path must name a struct and a field the profile describes."""
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
    """Every SSL_SESSION offset the agent dereferences must exist and be an int.

    These are named in agent/scanner.js, not in the profile, so the other
    reference checks cannot reach them.
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

    Tier A slots and SSL3_STATE '<field>_len' keys are secret_run_base + i * stride
    and data + capacity. A wrong offset does not crash, it emits plausible garbage,
    so retargeting must fail loudly here.
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
    """Check numbers a tier restates from another section still agree.

    An edit to one copy only is silent: every candidate fails to validate and the
    silence report blames the patterns.
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
    """Check Tier A's optional ``rescan_every`` is a positive int (absent means 1).

    A bool, zero, negative or non-int would silently change how often the tier runs.
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
    """Return the profile's engine, defaulting to boringssl.

    An unknown engine raises: a startup error beats scanning against rules that do not exist.
    """
    engine = profile.get("engine", _DEFAULT_ENGINE)
    if not isinstance(engine, str) or engine not in _KNOWN_ENGINES:
        raise MemoryScanPatternError(
            f"profile.engine: {engine!r} is not one of {', '.join(_KNOWN_ENGINES)}")
    return engine


def _validate_boringssl_profile(profile: dict[str, Any]) -> None:
    """Strict validation of a BoringSSL profile; its structs, session fields and derived offsets are enforced only here."""
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
    """Validate a Schannel profile: minimal shape always, ``arch`` offset sets strictly when present.

    A skeletal profile without ``arch`` is left to fail at configure time.
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
    """Return the offset set (needle + tiers) for ``arch`` from a profile.

    Selected in Python so the agent only reads ``profile["resolved"]``. ``arch`` is
    frida's name ("arm64", "x64"). An unknown or None arch falls back to the single
    described arch; otherwise raises, naming the available arches.
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
    """Return a shallow copy of ``profile`` with the arch-resolved offsets under ``resolved``."""
    resolved = dict(profile)
    resolved["resolved"] = select_schannel_offsets(profile, arch)
    return resolved



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
    """Validate an RC4 profile: minimal shape always, ``params`` and ``kat`` strictly when present.

    The KAT must hold (RC4(key, plaintext) == ciphertext) so a mistyped vector fails at startup.
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


_RC4_OPTIONAL_HEX_PARAMS = ("ciphertext_sample", "known_plaintext")
_RC4_OPTIONAL_BOOL_PARAMS = (
    "sbox_first", "sbox_exact_validate", "prioritize_anonymous",
    "require_exact_or_accept", "use_cmodule", "grouped_read",
    "needs_mapped_index",
)
_RC4_OPTIONAL_POS_INT_PARAMS = ("cmodule_batch", "read_group_bytes")


def _validate_rc4_optional_params(params: dict[str, Any]) -> None:
    """Type-check the optional scanner params when present (None means unset); the required set is unchanged."""
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
    # Lazy: importing the offline RC4 package self-registers a decryptor and risks a cycle.
    from friTap.offline.rc4.crypto import rc4
    got = rc4(bytes.fromhex(kat["key"]), bytes.fromhex(kat["plaintext"]))
    want = bytes.fromhex(kat["ciphertext"])
    if got != want:
        raise MemoryScanPatternError(
            f"rc4 profile.kat: RC4(key, plaintext) = {got.hex()} does not equal "
            f"the profile's ciphertext {want.hex()} — a wrong KAT means the agent "
            f"would validate its core against a false vector")


def _coerce_to_hex(value: str) -> str:
    """Return a CLI/config string as lowercase hex: valid hex passes through, anything else is utf-8 encoded."""
    if _valid_hex_bytes(value):
        return value.lower()
    return value.encode("utf-8").hex()


def apply_rc4_param_overrides(
    profile: dict[str, Any],
    *,
    known_plaintext: Optional[str] = None,
    ciphertext_sample: Optional[str] = None,
) -> dict[str, Any]:
    """Merge non-None CLI/config RC4 overrides into ``profile["params"]`` (in place), re-validate and return it.

    String overrides are normalised to hex via :func:`_coerce_to_hex`.
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


def _validate_mtproto_profile(profile: dict[str, Any]) -> None:
    """Validate an MTProto profile: minimal shape always, ``tiers`` strictly when present.

    The emitting tiers (B_authkeyid_roundtrip, C_art_secretchat_key) must carry the
    fields the agent reads to build a keylog line.
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

    Dispatches on ``engine`` (see :func:`_profile_engine`); an unknown engine is
    rejected. Raises MemoryScanPatternError naming the JSON path at fault.
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
    """Load, merge, validate and select one profile, ready for the agent's ``configure()``.

    ``engine`` pre-filters as in :func:`select_profile`. Raises MemoryScanPatternError on any failure.
    """
    database = load_database(user_path)
    profile = select_profile(database, profile_id, engine)
    validate_profile(profile)
    logger.info(
        "Selected memory-scan profile '%s' (%d tier(s))",
        profile.get("id"), len(profile.get("tiers", {})))
    # A profile calibrated for one library build recovers nothing on others,
    # which looks like a silent zero-result run, so surface the calibration.
    calibrated = profile.get("calibrated_lib_version")
    if calibrated:
        logger.info(
            "Profile '%s' calibrated for %s; recovery may be empty on other "
            "builds.", profile.get("id"), calibrated)
    return profile



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
    """Map a frida/``sys.platform`` OS string onto windows | linux | android | macos | ios.

    Unrecognised or None returns None (an ``["all"]`` profile still matches).
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
    """Merge a custom database file into ``db`` by id, in place (same semantics as :func:`load_database`)."""
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

    Maps the user's selected ``--protocol``
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
