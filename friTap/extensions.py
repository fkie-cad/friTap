"""Core viewer-extension registry (detail tabs, columns, body decoders, filter fields).

Lives in core, not ``friTap.ui``, so ``friTap.filter`` can read registered
filter fields without importing any UI package (layering rule R14).
``friTap.ui`` re-exports these names. No textual / frida / capture imports.

Nothing is discovered at import time: call :func:`load_extensions` before
reading a ``.tap`` (filter fields only reach flows extracted afterwards). It
also discovers external offline decryptors (switch
``FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY``; viewer screens skip it and
discover on decrypt). ``FRITAP_DISABLE_UI_EXTENSIONS`` disables UI discovery.
Failures show in :func:`extension_load_errors`.

Entry-point group :data:`UI_EXTENSION_ENTRY_POINT_GROUP` (``fritap.ui_extensions``);
each target is a zero-argument callable that calls the ``register_*`` functions::

    [fritap.ui_extensions]
    my-ext = my_pkg.fritap_ext:register

A later registration with the same key replaces the earlier one (never raises);
getters return specs in first-registration order. :func:`register_filter_field`
also registers the spec with the display-filter layer fields;
:func:`reset_extensions` removes it again.
"""

from __future__ import annotations

import logging
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional

from friTap import discovery_base
from friTap.filter.layer_fields import (
    LayerFieldSpec,
    clear_registered_layer_fields,
    register_layer_field,
)

logger = logging.getLogger("friTap.extensions")

UI_EXTENSION_ENTRY_POINT_GROUP = "fritap.ui_extensions"
DISABLE_ENV_VAR = "FRITAP_DISABLE_UI_EXTENSIONS"
_OFFLINE_DISCOVERY_MODULE = "friTap.offline.discovery"


@dataclass(frozen=True)
class DetailTabSpec:
    """A detail tab; ``render(flow)`` returns a renderable or ``None`` (hide tab)."""
    id: str
    label: str
    render: Callable[[Any], Any]


@dataclass(frozen=True)
class FlowColumnSpec:
    """A flow-list column; ``value(summary_row)`` returns the cell text."""
    key: str
    label: str
    width: int
    value: Callable[[Any], str]


@dataclass(frozen=True)
class BodyDecoderSpec:
    """A body decoder; ``decode(body, headers)`` returns display lines."""
    name: str
    label: str
    decode: Callable[[bytes, Any], "list[str]"]


@dataclass(frozen=True)
class ExtensionLoadError:
    """One recorded :func:`load_extensions` failure (for hosts that mute logs)."""
    source: str
    error: str


_LOCK = threading.RLock()
# UI-step failures only; offline per-source failures are read live from the discovery module.
_LOAD_ERRORS: list[ExtensionLoadError] = []
# The offline discovery step as a whole failed (e.g. its import).
_OFFLINE_STEP_ERROR: Optional[ExtensionLoadError] = None


class _Registry:
    """Specs keyed by one attribute; a re-registration replaces in place."""

    def __init__(self, key_attr: str) -> None:
        self._key_attr = key_attr
        self._specs: dict[Any, Any] = {}

    def register(self, spec: Any) -> None:
        with _LOCK:
            self._specs[getattr(spec, self._key_attr)] = spec

    def all(self) -> list:
        with _LOCK:
            return list(self._specs.values())

    def clear(self) -> None:
        with _LOCK:
            self._specs.clear()


_DETAIL_TABS = _Registry("id")
_FLOW_COLUMNS = _Registry("key")
_BODY_DECODERS = _Registry("name")
_FILTER_FIELDS = _Registry("field")
_REGISTRIES = (_DETAIL_TABS, _FLOW_COLUMNS, _BODY_DECODERS, _FILTER_FIELDS)
_LOADED = False


def _require_spec_type(spec: Any, spec_type: type) -> None:
    if not isinstance(spec, spec_type):
        raise TypeError(
            f"expected a {spec_type.__name__}, got {type(spec).__name__}")


def _require_str(spec: Any, field: str, *, nonblank: bool) -> None:
    value = getattr(spec, field)
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a str, got {type(value).__name__}")
    if nonblank and not value.strip():
        raise ValueError(f"{field} must not be empty or blank")


def _require_callable(spec: Any, field: str) -> None:
    if not callable(getattr(spec, field)):
        raise TypeError(f"{field} must be callable")


def _require_width(width: Any) -> None:
    if isinstance(width, bool) or not isinstance(width, int):
        raise TypeError(f"width must be an int, got {type(width).__name__}")
    if width < 0:
        raise ValueError(f"width must be non-negative, got {width}")


def register_detail_tab(spec: DetailTabSpec) -> None:
    """Register (or replace, by ``spec.id``) a detail tab.

    Raises ``TypeError`` / ``ValueError`` for an invalid spec (registry unchanged).
    """
    _require_spec_type(spec, DetailTabSpec)
    _require_str(spec, "id", nonblank=True)
    _require_str(spec, "label", nonblank=False)
    _require_callable(spec, "render")
    _DETAIL_TABS.register(spec)


def register_flow_column(spec: FlowColumnSpec) -> None:
    """Register (or replace, by ``spec.key``) a flow-list column.

    Raises ``TypeError`` / ``ValueError`` for an invalid spec (registry unchanged).
    """
    _require_spec_type(spec, FlowColumnSpec)
    _require_str(spec, "key", nonblank=True)
    _require_str(spec, "label", nonblank=False)
    _require_width(spec.width)
    _require_callable(spec, "value")
    _FLOW_COLUMNS.register(spec)


def register_body_decoder(spec: BodyDecoderSpec) -> None:
    """Register (or replace, by ``spec.name``) a body decoder.

    Raises ``TypeError`` / ``ValueError`` for an invalid spec (registry unchanged).
    """
    _require_spec_type(spec, BodyDecoderSpec)
    _require_str(spec, "name", nonblank=True)
    _require_str(spec, "label", nonblank=False)
    _require_callable(spec, "decode")
    _BODY_DECODERS.register(spec)


def register_filter_field(spec: LayerFieldSpec) -> None:
    """Register (or replace, by ``spec.field``) a display-filter layer field.

    The field becomes usable in the display filter immediately (the filter
    indexes are rebuilt); its name and layer names are lowercased.
    """
    with _LOCK:
        _FILTER_FIELDS.register(register_layer_field(spec))


def get_detail_tabs() -> list[DetailTabSpec]:
    """Return registered detail tabs in first-registration order."""
    return _DETAIL_TABS.all()


def get_flow_columns() -> list[FlowColumnSpec]:
    """Return registered flow-list columns in first-registration order."""
    return _FLOW_COLUMNS.all()


def get_body_decoders() -> list[BodyDecoderSpec]:
    """Return registered body decoders in first-registration order."""
    return _BODY_DECODERS.all()


def get_filter_fields() -> list[LayerFieldSpec]:
    """Return registered display-filter layer fields in first-registration order."""
    return _FILTER_FIELDS.all()


def _format_error(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"


def _offline_source_errors() -> list[ExtensionLoadError]:
    """Per-source failures of the last offline scan; empty unless the discovery module is already loaded (importing it pulls in the offline stack)."""
    discovery = sys.modules.get(_OFFLINE_DISCOVERY_MODULE)
    if discovery is None:
        return []
    return [ExtensionLoadError(f"offline-decryptor:{source}", error)
            for source, error in discovery.offline_discovery_errors()]


def extension_load_errors() -> list[ExtensionLoadError]:
    """The current extension load failures (a new list), in this order.

    Failing ``fritap.ui_extensions`` entry points of the last UI step (source =
    entry-point name, or ``"entry-points"``); the offline step as a whole
    (``"offline-decryptors"``); each failing source of the last offline scan
    (``"offline-decryptor:dir:<file>"``, ``":entrypoint:<name>"``, ``":entrypoints"``),
    whether it ran from :func:`load_extensions` or the viewer's first decrypt.
    """
    with _LOCK:
        errors = list(_LOAD_ERRORS)
        if _OFFLINE_STEP_ERROR is not None:
            errors.append(_OFFLINE_STEP_ERROR)
    return errors + _offline_source_errors()


def _run_ui_entry_points() -> None:
    """Run every ``fritap.ui_extensions`` entry point (skipped under :data:`DISABLE_ENV_VAR`)."""
    if discovery_base.discovery_disabled(DISABLE_ENV_VAR):
        return
    try:
        entry_points = discovery_base.get_entry_points(
            UI_EXTENSION_ENTRY_POINT_GROUP)
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to enumerate UI extension entry points: %s", e)
        _LOAD_ERRORS.append(ExtensionLoadError("entry-points", _format_error(e)))
        return
    for ep in entry_points:
        try:
            ep.load()()
        except (Exception, SystemExit) as e:  # noqa: BLE001 — one bad extension must not break the rest
            logger.error("Failed to load UI extension entry point %s: %s",
                         getattr(ep, "name", ep), e)
            _LOAD_ERRORS.append(ExtensionLoadError(
                str(getattr(ep, "name", ep)), _format_error(e)))


def _discover_offline_decryptors(force: bool) -> None:
    """Register third-party offline decryptors (never raises).

    The discovery module caches its scan (no-op until *force*). A failure of the
    step is the single ``"offline-decryptors"`` error. Governed by
    ``FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY``, independent of :data:`DISABLE_ENV_VAR`.
    The import is lazy to keep this module cheap and textual/frida-free.
    """
    global _OFFLINE_STEP_ERROR
    _OFFLINE_STEP_ERROR = None
    try:
        from friTap.offline.discovery import discover_external_offline_decryptors
        discover_external_offline_decryptors(force=force)
    except Exception as e:  # noqa: BLE001 — third-party code must not break the host
        logger.error("Failed to discover offline decryptors: %s", e)
        _OFFLINE_STEP_ERROR = ExtensionLoadError("offline-decryptors", _format_error(e))


def load_extensions(force: bool = False, *, offline_decryptors: bool = True) -> None:
    """Load every third-party extension once (idempotent).

    Two independent steps, each with an opt-out switch:

    * run every ``fritap.ui_extensions`` entry point (detail tabs, columns, body
      decoders, filter fields); ``FRITAP_DISABLE_UI_EXTENSIONS`` disables it;
    * discover external offline decryptors (drop-in directory and
      ``fritap.offline_decryptors`` entry points);
      ``FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY`` disables it. Skipped with
      ``offline_decryptors=False`` (viewer screens, so ``fritap -r`` has no
      discovery side effects); a later default call still runs it.

    The UI step runs once (until *force*); the offline step uses the discovery
    module's cache. A failing entry point (even ``SystemExit``) is logged, skipped
    and reported by :func:`extension_load_errors`. *force* re-runs the steps
    (registration is replace-by-id).
    """
    global _LOADED
    with _LOCK:
        if force or not _LOADED:
            _LOADED = True
            _LOAD_ERRORS.clear()
            _run_ui_entry_points()
        if offline_decryptors:
            _discover_offline_decryptors(force)


def reset_extensions() -> None:
    """Clear all registrations and the loaded flag (for tests / reload)."""
    global _LOADED, _OFFLINE_STEP_ERROR
    with _LOCK:
        for registry in _REGISTRIES:
            registry.clear()
        clear_registered_layer_fields()
        _LOAD_ERRORS.clear()
        _LOADED = False
        _OFFLINE_STEP_ERROR = None


__all__ = [
    "UI_EXTENSION_ENTRY_POINT_GROUP", "DetailTabSpec", "FlowColumnSpec",
    "BodyDecoderSpec", "LayerFieldSpec", "register_detail_tab",
    "register_flow_column", "register_body_decoder", "register_filter_field",
    "get_detail_tabs", "get_flow_columns", "get_body_decoders",
    "get_filter_fields", "load_extensions", "reset_extensions",
    "DISABLE_ENV_VAR", "ExtensionLoadError", "extension_load_errors",
]
