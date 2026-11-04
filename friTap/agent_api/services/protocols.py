"""
Protocol services: protocols seen in a capture and validation of slice parameters.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from friTap.agent_api.errors import ToolError
from friTap.filter.protocols import known_protocol_names
from friTap.suggest import did_you_mean

_MAX_LABEL_CHARS = 48
# Digest groups that are not filter protocol names (see digest.flow_group).
_DIGEST_ONLY_GROUPS = ("grpc",)


def known_app_protocols() -> list[str]:
    """Valid ``app_protocol`` values: protocol names plus digest-only groups (``grpc``)."""
    return sorted(set(known_protocol_names()) | set(_DIGEST_ONLY_GROUPS))


def _unknown(param: str, value: str, valid: list[str]) -> ToolError:
    return ToolError(f"{param}: unknown protocol {value!r}", "unknown_protocol",
                     hint=did_you_mean(value, valid) or "call list_protocols for valid names",
                     param=param)


def check_protocol_name(param: str, value: str | None) -> None:
    """Raise ``unknown_protocol`` (with a did-you-mean hint) for an unknown ``protocol``."""
    from friTap.filter.protocols import protocol_members

    if value and protocol_members(value) is None:
        raise _unknown(param, value, known_protocol_names())


def check_app_protocol_name(param: str, value: str | None) -> None:
    """Raise ``unknown_protocol`` for an ``app_protocol`` no digest group can match."""
    if not value or value.strip().lower() in _DIGEST_ONLY_GROUPS:
        return
    from friTap.filter.protocols import protocol_members

    if protocol_members(value) is None:
        raise _unknown(param, value, known_app_protocols())


def check_slice(params: dict[str, Any]) -> None:
    """Validate the ``protocol`` / ``app_protocol`` slice parameters."""
    check_protocol_name("protocol", params.get("protocol"))
    check_app_protocol_name("app_protocol", params.get("app_protocol"))


def _sorted_counts(counter: Counter) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def protocols_in_tap(tap: Path) -> dict[str, Any]:
    """Flows per canonical protocol and per app group (memoized per capture file).

    Needs the full flows: a ``.tap`` flow summary carries no layer names, so
    layer protocols (websocket, telegram_e2e, ...) and the grpc group would be
    missed when counting from summaries.
    """
    from friTap.agent_api.services.reading import scan_cache

    return scan_cache.get_or_compute(tap, ("protocols",), lambda: _count_protocols(tap))


def _count_protocols(tap: Path) -> dict[str, Any]:
    from friTap.analysis._digest_shapes import safe_untrusted
    from friTap.analysis.digest import flow_group
    from friTap.filter.protocols import canonical_protocols
    from friTap.flow.tap_reader import TapReader

    protocols: Counter = Counter()
    groups: Counter = Counter()
    with TapReader(str(tap)) as reader:
        total = reader.flow_count
        for _ordinal, _summary, flow in reader.iter_flows():
            groups[safe_untrusted(flow_group(flow), _MAX_LABEL_CHARS)] += 1
            for name in canonical_protocols(flow):
                protocols[safe_untrusted(name, _MAX_LABEL_CHARS)] += 1
    return {"flows_total": total, "protocols": _sorted_counts(protocols),
            "app_protocols": _sorted_counts(groups)}


__all__ = ["known_app_protocols", "check_protocol_name",
           "check_app_protocol_name", "check_slice", "protocols_in_tap"]
