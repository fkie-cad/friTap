#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
friTap TUI theme definitions.

Provides dark and light themes using Textual's Theme API, plus a
``c()`` color accessor for inline Rich markup that adapts to the
current theme at runtime.
"""

from __future__ import annotations

try:
    from textual.theme import Theme
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

# ── Semantic color variables ─────────────────────────────────────

_DARK_VARIABLES = {
    "fritap-info": "#7dd3fc",
    "fritap-error-strong": "#ef4444",
    "fritap-accent-data": "#c4b5fd",
    "fritap-accent-library": "#67e8f9",
    "fritap-text-dim": "#8f9bb3",
    "fritap-text-muted": "#64748b",
    "fritap-text-disabled": "#6b7280",
    "fritap-text-secondary": "#94a3b8",
    "fritap-target": "#d4945a",
    "fritap-warning-amber": "#f59e0b",
    "fritap-brand-fri": "#e8756e",
    "fritap-brand-tap": "#6b8db5",
    "fritap-bg-header": "#0b1628",
    "fritap-bg-modal": "#0d1117",
    "fritap-bg-selected": "#2563eb",
    "fritap-bg-capture": "#1a3a1a",
    "fritap-modal-overlay": "rgba(5,8,17,0.85)",
    "fritap-border-default": "#1e3a5f",
    "fritap-border-panel": "#111827",
    "fritap-button-hover": "#3b82f6",
    "fritap-hex-offset": "#94a3b8",
    "fritap-hex-data": "#60a5fa",
    "fritap-hex-ascii": "#fca5a5",
    "fritap-hex-sel-offset": "#1e2a3a",
    "fritap-hex-sel-data": "#1e3a5f",
    "fritap-hex-sel-ascii": "#3b1c2e",
}

_LIGHT_VARIABLES = {
    "fritap-info": "#0369a1",
    "fritap-error-strong": "#b91c1c",
    "fritap-accent-data": "#7c3aed",
    "fritap-accent-library": "#0891b2",
    "fritap-text-dim": "#475569",
    "fritap-text-muted": "#64748b",
    "fritap-text-disabled": "#94a3b8",
    "fritap-text-secondary": "#334155",
    "fritap-target": "#b45309",
    "fritap-warning-amber": "#d97706",
    "fritap-brand-fri": "#dc2626",
    "fritap-brand-tap": "#1d4ed8",
    "fritap-bg-header": "#cbd5e1",
    "fritap-bg-modal": "#ffffff",
    "fritap-bg-selected": "#3b82f6",
    "fritap-bg-capture": "#dcfce7",
    "fritap-modal-overlay": "rgba(0,0,0,0.3)",
    "fritap-border-default": "#cbd5e1",
    "fritap-border-panel": "#e2e8f0",
    "fritap-button-hover": "#1d4ed8",
    "fritap-hex-offset": "#64748b",
    "fritap-hex-data": "#2563eb",
    "fritap-hex-ascii": "#be123c",
    "fritap-hex-sel-offset": "#cbd5e1",
    "fritap-hex-sel-data": "#bfdbfe",
    "fritap-hex-sel-ascii": "#fecdd3",
}

# ── Theme objects ────────────────────────────────────────────────

if TEXTUAL_AVAILABLE:
    FRITAP_DARK = Theme(
        name="fritap-dark",
        primary="#38bdf8",
        secondary="#818cf8",
        warning="#fbbf24",
        error="#fb7185",
        success="#4ade80",
        accent="#22d3ee",
        foreground="#e2e8f0",
        background="#050811",
        surface="#080c18",
        panel="#0a0f1e",
        dark=True,
        variables=_DARK_VARIABLES,
    )

    FRITAP_LIGHT = Theme(
        name="fritap-light",
        primary="#0369a1",
        secondary="#6366f1",
        warning="#b45309",
        error="#dc2626",
        success="#15803d",
        accent="#0c6478",
        foreground="#1e293b",
        background="#f8fafc",
        surface="#f1f5f9",
        panel="#e2e8f0",
        dark=False,
        variables=_LIGHT_VARIABLES,
    )
else:
    FRITAP_DARK = None  # type: ignore[assignment]
    FRITAP_LIGHT = None  # type: ignore[assignment]

# ── Runtime color accessor for Rich markup ───────────────────────

_current: dict[str, str] = {}


def c(role: str) -> str:
    """Return the current theme color for *role*.

    Usage in f-strings::

        f"[bold {c('primary')}]hello[/]"
    """
    return _current.get(role, "#ffffff")


def set_theme(theme: "Theme") -> None:
    """Populate the ``c()`` lookup from *theme*.

    Called once at startup and on every theme toggle.
    Builds a new dict and swaps atomically to avoid races with
    background threads calling ``c()`` during the update.
    """
    global _current

    new: dict[str, str] = {
        "primary": theme.primary,
        "secondary": theme.secondary,
        "warning": theme.warning,
        "error": theme.error,
        "success": theme.success,
        "accent": theme.accent,
        "foreground": theme.foreground,
        "background": theme.background,
        "surface": theme.surface,
        "panel": theme.panel,
    }

    # Custom fritap variables  (strip the "fritap-" prefix for convenience)
    for key, value in (theme.variables or {}).items():
        new[key] = value
        if key.startswith("fritap-"):
            new[key[7:]] = value

    _current = new
