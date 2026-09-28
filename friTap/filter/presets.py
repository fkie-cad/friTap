"""Display-filter presets: the single source of truth for the quick toggles.

Consumed by the filter modal (toggle buttons), the filter bar (active-toggle
summary) and the filter help screen. Active presets are ANDed together and
with the text filter.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FilterPreset:
    """One quick-toggle preset.

    Attributes:
        toggle_id: Widget id of the toggle button (stable, persisted in state).
        label: Button / summary label.
        expression: Display-filter expression the toggle applies.
        description: One-line text for the filter help screen.
    """

    toggle_id: str
    label: str
    expression: str
    description: str


FILTER_PRESETS: tuple[FilterPreset, ...] = (
    FilterPreset("toggle-http", "HTTP", "http", "HTTP traffic (any version)"),
    FilterPreset("toggle-errors", "Errors", "http.response.code >= 400",
                 "HTTP error responses (4xx/5xx)"),
    FilterPreset("toggle-ohttp", "OHTTP", "ohttp.present", "Flows with OHTTP encapsulation"),
    FilterPreset("toggle-ipsec", "IPSec", "ipsec", "IPSec flows"),
    FilterPreset("toggle-ssh", "SSH", "ssh", "SSH flows"),
    FilterPreset("toggle-telegram", "Telegram", "telegram",
                 "Telegram flows (MTProto cloud + Secret Chats)"),
    FilterPreset("toggle-signal", "Signal", "signal", "Signal flows"),
)

_PRESETS_BY_ID: dict[str, FilterPreset] = {p.toggle_id: p for p in FILTER_PRESETS}


def preset_label(toggle_id: str) -> str:
    """Return the label for *toggle_id*, or the id itself if unknown."""
    preset = _PRESETS_BY_ID.get(toggle_id)
    return preset.label if preset else toggle_id


def combined_preset_expression(active_ids: set[str]) -> str:
    """AND the expressions of the active presets, in preset order.

    Returns ``""`` when no known preset is active.
    """
    return " and ".join(
        f"({p.expression})" for p in FILTER_PRESETS if p.toggle_id in active_ids
    )


__all__ = [
    "FILTER_PRESETS",
    "FilterPreset",
    "combined_preset_expression",
    "preset_label",
]
