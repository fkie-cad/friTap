"""
Capture protocol catalog: what ``start_capture`` can hook, and how options map to CLI flags.

The capture protocol enum is derived from the protocol registry at call time
(never hard-coded): a filtered build advertises only what it ships. Omitting
``protocols`` means ``--protocol auto`` (every protocol, no prompt).

Capture options are a FLAT ``{name: value}`` dict shared by all selected
protocols (``patterns`` is the same ``--patterns`` flag for TLS and SSH)::

    validate_protocol_options(["tls"], {"pairip_safe": True, "force_scan": ["libfoo.so"]})
    options_to_cli_flags({"pairip_safe": True, "force_scan": ["libfoo.so"]})
    # -> ["--force-scan", "libfoo.so", "--pairip-safe"]

File options follow the CLI loaders: ``offsets`` is a file path or inline
JSON (``--offsets`` tries the file, then parses the text as JSON), ``patterns``
is a file path only (``PatternLoader`` never parses inline JSON, so inline
JSON is rejected here). The caller must sandbox file paths before building the
argv (:class:`~friTap.agent_api.capture.manager.SessionManager` does, see
:func:`path_option_names` / :func:`is_inline_value`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Sequence

from friTap.agent_api.errors import ToolError
from friTap.agent_api.json_input import load_json
from friTap.agent_api.schema import check_value
from friTap.suggest import did_you_mean

CAPTURE_MODES = ("keys", "plaintext", "full")
ALL_PLATFORMS = ("android", "ios", "linux", "macos", "windows")
UNKNOWN_PLATFORM = "unknown"
CUSTOM_GROUP = "custom"

# Best-effort platform support per protocol (handlers expose no platform list).
_PLATFORMS: dict[str, tuple[str, ...]] = {
    "tls": ALL_PLATFORMS,
    "ssh": ("linux", "android", "macos"),
    "ipsec": ("linux",),
    "telegram": ("android",),
    "mtproto": ("android",),
    "signal": ("android",),
    "rc4": ALL_PLATFORMS,
}


@dataclass(frozen=True)
class OptionSpec:
    """One capture option and the friTap CLI flag it becomes.

    Attributes:
        name: Option key in the ``options`` dict.
        flag: CLI flag (verified against ``friTap/friTap.py`` argparse).
        type: JSON type: ``boolean`` (flag only when true), ``string``
            (flag + value) or ``array`` of strings (flag repeated per item).
        description: One line for agents.
        protocols: Protocols the option applies to.
        value_kind: ``path`` (a file path) or ``path_or_json`` (a file path or
            inline JSON), mirroring how the CLI loads the flag's value.
    """

    name: str
    flag: str
    type: str
    description: str
    protocols: tuple[str, ...]
    value_kind: str = ""

    def json_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {"type": self.type, "description": self.description}
        if self.type == "array":
            schema["items"] = {"type": "string", "minLength": 1}
        elif self.type == "string":
            schema["minLength"] = 1
        return schema


VALUE_KIND_PATH = "path"
VALUE_KIND_PATH_OR_JSON = "path_or_json"
_PATH_KINDS = (VALUE_KIND_PATH, VALUE_KIND_PATH_OR_JSON)

_TLS = ("tls",)
OPTIONS: tuple[OptionSpec, ...] = (
    OptionSpec("offsets", "--offsets", "string",
               "Hook offsets JSON file or inline JSON string.", _TLS,
               VALUE_KIND_PATH_OR_JSON),
    OptionSpec("patterns", "--patterns", "string",
               "Byte-pattern JSON file (path inside the sandbox root; no inline JSON).",
               ("tls", "ssh"), VALUE_KIND_PATH),
    OptionSpec("force_scan", "--force-scan", "array",
               "Modules to force the BoringSSL pattern scan on (regex with 're:').", _TLS),
    OptionSpec("library_scan", "--library-scan", "boolean",
               "Pre-scan for renamed/statically linked TLS libraries.", _TLS),
    OptionSpec("pairip_safe", "--pairip-safe", "boolean",
               "Android: minimal scan-free hooks for PairIP-protected apps.", _TLS),
    OptionSpec("no_loader_hook", "--no-loader-hook", "boolean",
               "Android: skip the android_dlopen_ext loader hook.", _TLS),
    OptionSpec("quic_only", "--quic-only", "boolean",
               "Install only QUIC hooks (Android/Linux).", _TLS),
)
_OPTIONS_BY_NAME: dict[str, OptionSpec] = {spec.name: spec for spec in OPTIONS}

# Options agents ask for that have no CLI equivalent -> hint.
_UNSUPPORTED_OPTIONS: dict[str, str] = {
    "libraries": "no CLI equivalent; use force_scan or offsets",
}


@dataclass(frozen=True)
class ProtocolInfo:
    """Agent-facing description of one capture protocol."""

    name: str
    display_name: str
    description: str
    category: str
    platforms: tuple[str, ...]
    options: tuple[dict, ...]
    capture_modes: tuple[str, ...]
    implies: tuple[str, ...]
    backends: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        doc = asdict(self)
        return {key: list(value) if isinstance(value, tuple) else value
                for key, value in doc.items()}


# ---------------------------------------------------------------------------
# Enum
# ---------------------------------------------------------------------------

def capture_protocol_names() -> list[str]:
    """Valid ``start_capture`` protocol names, sorted (plus ``custom`` if any cipher ships).

    ``auto``/``all`` are not included: omit ``protocols`` for auto.
    """
    from friTap.protocols.registry import available_protocol_names, custom_cipher_names

    names = list(available_protocol_names())
    if custom_cipher_names():
        names.append(CUSTOM_GROUP)
    return sorted(names)


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

def _handler(name: str):
    from friTap.protocols.registry import _all_handler_factories

    factory = _all_handler_factories().get(name)
    return factory() if factory is not None else None


def _option_rows(name: str) -> tuple[dict, ...]:
    """Options usable with *name*, including those of its implied protocols."""
    selected = _expand([name])
    return tuple(
        {"name": spec.name, "flag": spec.flag, "type": spec.type,
         "description": spec.description, **({"value_kind": spec.value_kind} if spec.value_kind else {})}
        for spec in OPTIONS if selected & set(spec.protocols)
    )


def _backends(handler: Any) -> tuple[str, ...]:
    support = getattr(handler, "supported_backends", {}) or {}
    return tuple(sorted(str(getattr(b, "value", b)) for b, level in support.items()
                        if str(getattr(level, "value", level)) == "full"))


def _custom_group_info() -> ProtocolInfo:
    from friTap.protocols.registry import custom_cipher_names

    members = ", ".join(custom_cipher_names())
    return ProtocolInfo(CUSTOM_GROUP, "Custom ciphers", f"All custom ciphers ({members}).",
                        "group", ALL_PLATFORMS, (), CAPTURE_MODES, (), ("frida",))


def describe(name: str) -> ProtocolInfo:
    """Catalog entry for capture protocol *name* (``unknown_protocol`` if absent)."""
    if name == CUSTOM_GROUP and CUSTOM_GROUP in capture_protocol_names():
        return _custom_group_info()
    handler = _handler(name)
    if handler is None:
        raise _unknown_protocol(name)
    from friTap.protocols.registry import implied_protocols

    return ProtocolInfo(
        name=name,
        display_name=getattr(handler, "display_name", name) or name,
        description=getattr(handler, "description", "") or "",
        category=getattr(handler, "category", "protocol"),
        platforms=tuple(getattr(handler, "platforms", None) or _PLATFORMS.get(name, (UNKNOWN_PLATFORM,))),
        options=_option_rows(name),
        capture_modes=CAPTURE_MODES,
        implies=tuple(implied_protocols(name)),
        backends=_backends(handler),
    )


def catalog() -> list[dict[str, Any]]:
    """Every capture protocol as a JSON-ready dict, sorted by name."""
    return [describe(name).to_dict() for name in capture_protocol_names()]


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

def options_schema() -> dict[str, Any]:
    """JSON-Schema object of every capture option (for a ``start_capture`` param)."""
    return {
        "type": "object",
        "properties": {spec.name: spec.json_schema() for spec in OPTIONS},
        "additionalProperties": False,
        "description": "Protocol capture options; see list_supported_protocols.",
    }


def _unknown_protocol(name: str) -> ToolError:
    return ToolError(f"unknown capture protocol {name!r}", "unknown_protocol",
                     hint=did_you_mean(str(name), capture_protocol_names(), show_all=True))


def _check_protocols(protocols: Iterable[str]) -> None:
    valid = set(capture_protocol_names())
    for name in protocols:
        if name not in valid:
            raise _unknown_protocol(name)


def _expand(protocols: Sequence[str]) -> set[str]:
    from friTap.protocols.registry import custom_cipher_names, expand_protocols

    names = set(protocols)
    if CUSTOM_GROUP in names:
        names = (names - {CUSTOM_GROUP}) | set(custom_cipher_names())
    return set(expand_protocols(names))


def _option_spec(name: str) -> OptionSpec:
    spec = _OPTIONS_BY_NAME.get(name)
    if spec is not None:
        return spec
    hint = _UNSUPPORTED_OPTIONS.get(name) or did_you_mean(name, list(_OPTIONS_BY_NAME), show_all=True)
    raise ToolError(f"unsupported capture option {name!r}", "unsupported_option",
                    hint=hint, option=name)


def _check_applies(spec: OptionSpec, selected: set[str] | None) -> None:
    if selected is None or selected & set(spec.protocols):
        return
    raise ToolError(
        f"option {spec.name!r} does not apply to protocols {sorted(selected)}",
        "unsupported_option", hint=f"{spec.name} applies to: {', '.join(spec.protocols)}",
        option=spec.name,
    )


def validate_protocol_options(
    protocols: Sequence[str] | None, options: Mapping[str, Any] | None
) -> None:
    """Validate a capture request's protocol list and flat ``options`` dict.

    Args:
        protocols: Capture protocol names (see :func:`capture_protocol_names`);
            ``None``/empty means auto, which accepts every option.
        options: ``{option_name: value}``; ``None`` values count as absent.

    Raises:
        ToolError: ``unknown_protocol`` (hint: valid names),
            ``unsupported_option`` (unknown option, no CLI equivalent, or not
            applicable to any selected protocol; ``extra["option"]`` names it)
            or ``bad_param`` (wrong value type, ``extra["param"]`` = ``options.<name>``).
    """
    _check_protocols(protocols or ())
    selected = _expand(protocols) if protocols else None
    for name, value in (options or {}).items():
        if value is None:
            continue
        spec = _option_spec(name)
        _check_applies(spec, selected)
        check_value(f"options.{name}", value, spec.json_schema())
        _check_path_only(spec, value)


def _check_path_only(spec: OptionSpec, value: Any) -> None:
    """Reject inline JSON for a path-only option (the CLI would treat it as a missing file)."""
    if spec.value_kind == VALUE_KIND_PATH and is_inline_json(value):
        raise ToolError(
            f"options.{spec.name} must be a file path; {spec.flag} does not accept inline JSON",
            "bad_param", hint="write the JSON to a file inside the sandbox root and pass its path",
            option=spec.name, param=f"options.{spec.name}")


def path_option_names() -> tuple[str, ...]:
    """Options whose value may be a file path (``value_kind`` ``path``/``path_or_json``)."""
    return tuple(spec.name for spec in OPTIONS if spec.value_kind in _PATH_KINDS)


def is_inline_json(value: Any) -> bool:
    """True when ``value`` is an inline JSON object/array (parsed as untrusted input)."""
    if not isinstance(value, str) or not value.strip().startswith(("{", "[")):
        return False
    try:
        load_json(value, "value")
    except ToolError:
        return False
    return True


def is_inline_value(name: str, value: Any) -> bool:
    """True when option ``name`` accepts inline JSON and ``value`` is inline JSON (not a path)."""
    spec = _OPTIONS_BY_NAME.get(name)
    return spec is not None and spec.value_kind == VALUE_KIND_PATH_OR_JSON and is_inline_json(value)


def options_to_cli_flags(options: Mapping[str, Any] | None) -> list[str]:
    """Map a validated ``options`` dict to friTap CLI argv tokens (catalog order).

    ``boolean`` -> ``[flag]`` when true (nothing when false); ``string`` ->
    ``[flag, value]``; ``array`` -> ``[flag, item]`` per item. ``None`` values
    are skipped. Call :func:`validate_protocol_options` first; an unknown name
    raises ``unsupported_option`` here too.
    """
    given = {name: value for name, value in (options or {}).items() if value is not None}
    for name in given:
        _option_spec(name)
    argv: list[str] = []
    for spec in OPTIONS:
        if spec.name in given:
            argv.extend(_flag_tokens(spec, given[spec.name]))
    return argv


def _flag_tokens(spec: OptionSpec, value: Any) -> list[str]:
    if spec.type == "boolean":
        return [spec.flag] if value else []
    if spec.type == "array":
        return [token for item in value for token in (spec.flag, str(item))]
    return [spec.flag, str(value)]


__all__ = [
    "CAPTURE_MODES",
    "OPTIONS",
    "OptionSpec",
    "ProtocolInfo",
    "capture_protocol_names",
    "catalog",
    "describe",
    "options_schema",
    "options_to_cli_flags",
    "path_option_names",
    "is_inline_json",
    "is_inline_value",
    "VALUE_KIND_PATH",
    "VALUE_KIND_PATH_OR_JSON",
    "validate_protocol_options",
]
