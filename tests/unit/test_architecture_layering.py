"""Architecture layering guard for the friTap package.

Encodes the TARGET layering (generic code must not depend on
protocol-specific packages) as AST-checked import rules. Current
violations are listed explicitly in ``KNOWN_VIOLATIONS``; each entry is
removed by a refactoring step. The tests fail when:

* a NEW violation appears (not in the allowlist), or
* an allowlisted violation no longer exists (stale entry -> shrink the list).

Both module-level and function-level (lazy) imports are collected.
Relative imports are resolved to absolute module names. ``from pkg import
name`` counts as importing ``pkg`` and, if ``pkg/name`` is a module or
package on disk, ``pkg.name`` as well.

Rules (importer prefix -> forbidden imported prefixes):

R1 friTap.parsers.*        -/-> offline protocol pkgs, friTap.flow.display, friTap.tui
R2 GENERIC_CORE_MODULES (offline.net/tls/pipeline_api/registry/tls_spans/tshark/
   result_schema/keylog_paths, connection_index, filter, flow.collector/models/
   layer_pipeline, message_router, events)
                           -/-> offline protocol pkgs, friTap.offline.pcap_to_tap, friTap.tui
R3 offline rc4/tls_midstream/signal/schannel -/-> friTap.offline.mtproto
   offline tls_midstream/schannel            -/-> friTap.offline.rc4
R4 friTap.protocols.*      -/-> friTap.offline (any level, incl. lazy)
R5 nobody but pcap_to_tap may import a private name from friTap.offline.pcap_to_tap
R6 offline signal/rc4/schannel/tls_midstream must not import private names
   from one another (recorded as "module:_name")
R7 leaf modules: friTap.offline.result_schema imports nothing at all;
   friTap.parsers.http2_constants imports nothing from friTap
R8 per-module allowlists of friTap-internal imports (ALLOWED_INTERNAL_IMPORTS);
   R8c: an allowed import cycle edge may only be a function-level (lazy) import
R9 friTap.tui.* must not import private names from friTap.parsers /
   friTap.offline / friTap.flow (recorded as "module:_name")
R10 friTap.parsers.* -/-> rich, textual
R11 R1/R2 modules must not name an offline protocol package in a string
   literal (importlib-style string imports; recorded as "string:<literal>")
R12 no module outside an offline protocol package may import a private name
   from inside that package (recorded as "module:_name"; superset of R6)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterator, NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_DIR = REPO_ROOT / "friTap"

OFFLINE = "friTap.offline"
PCAP_TO_TAP = f"{OFFLINE}.pcap_to_tap"
PROTOCOL_PACKAGES = tuple(
    f"{OFFLINE}.{name}" for name in ("mtproto", "signal", "rc4", "schannel", "tls_midstream")
)
PRIVATE_SHARING_PACKAGES = tuple(
    f"{OFFLINE}.{name}" for name in ("signal", "rc4", "schannel", "tls_midstream")
)

PARSERS = ("friTap.parsers",)
# Protocol-neutral core: must not reach into protocol packages, the
# pcap_to_tap orchestrator, or the TUI (R2, R11).
GENERIC_CORE_MODULES = (
    f"{OFFLINE}.net",
    f"{OFFLINE}.tls",
    f"{OFFLINE}.pipeline_api",
    f"{OFFLINE}.registry",
    f"{OFFLINE}.tls_spans",
    f"{OFFLINE}.tshark",
    f"{OFFLINE}.result_schema",
    f"{OFFLINE}.keylog_paths",
    "friTap.connection_index",
    "friTap.filter",
    "friTap.flow.collector",
    "friTap.flow.models",
    "friTap.flow.layer_pipeline",
    "friTap.message_router",
    "friTap.events",
)

# (importer prefixes, forbidden imported prefixes) per module-dependency rule.
MODULE_RULES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "R1": (PARSERS, PROTOCOL_PACKAGES + ("friTap.flow.display", "friTap.tui")),
    "R2": (GENERIC_CORE_MODULES, PROTOCOL_PACKAGES + (PCAP_TO_TAP, "friTap.tui")),
    "R3a": (PRIVATE_SHARING_PACKAGES, (f"{OFFLINE}.mtproto",)),
    "R3b": ((f"{OFFLINE}.tls_midstream", f"{OFFLINE}.schannel"), (f"{OFFLINE}.rc4",)),
    "R4": (("friTap.protocols",), (OFFLINE,)),
    "R10": (PARSERS, ("rich", "textual")),
}

# R7: modules that must import nothing at all / nothing from friTap.
IMPORT_FREE_MODULES = (f"{OFFLINE}.result_schema",)
FRITAP_FREE_MODULES = ("friTap.parsers.http2_constants",)

# R8: module -> the only friTap prefixes it may import (exact module match).
ALLOWED_INTERNAL_IMPORTS: dict[str, tuple[str, ...]] = {
    f"{OFFLINE}.net.capture_cache": (f"{OFFLINE}.net.tcp_reassembly",),
    # The fast pcap parser is a leaf: stdlib + scapy only, fallback passed in.
    f"{OFFLINE}.net.pcap_fast": (),
    # TLS record-layer leaves: stdlib + cryptography only.
    f"{OFFLINE}.tls.records": (),
    # tls12 reuses the tls13 AEAD helpers and the records constants.
    f"{OFFLINE}.tls.tls12": (f"{OFFLINE}.tls.tls13", f"{OFFLINE}.tls.records"),
    f"{OFFLINE}.tls.tls13": (),
    f"{OFFLINE}.tls.keylog": (),
    f"{OFFLINE}.tls.stream": (f"{OFFLINE}.tls.tls13", f"{OFFLINE}.tls.records"),
    # The tshark driver and the decryptor registry are protocol-neutral leaves.
    f"{OFFLINE}.tshark": (),
    f"{OFFLINE}.registry": (),
    # Schannel: the sidecar reader is a leaf; the Python record oracle only
    # needs the generic TLS record layer and TCP reassembly.
    f"{OFFLINE}.schannel.unpaired": (),
    f"{OFFLINE}.schannel.oracle": (f"{OFFLINE}.tls", f"{OFFLINE}.net.tcp_reassembly"),
    f"{OFFLINE}.mtproto.state": (f"{OFFLINE}.pipeline_api",),
    f"{OFFLINE}.rc4.state": (f"{OFFLINE}.pipeline_api",),
    "friTap.parsers.protobuf.view": ("friTap.parsers.protobuf", "friTap.parsers.decompress"),
    "friTap.tui.widgets.protobuf_render": ("friTap.parsers.protobuf.view", "friTap.tui.themes"),
}
# R8c: (importer, imported) cycle edges that are tolerated only as lazy,
# function-level imports (capture_cache imports tcp_reassembly at module level).
# friTap.filter's package __init__ imports the evaluator, which imports
# flow.models, so flow -> filter edges must stay lazy as well.
FUNCTION_LEVEL_ONLY_IMPORTS: frozenset[tuple[str, str]] = frozenset({
    (f"{OFFLINE}.net.tcp_reassembly", f"{OFFLINE}.net.capture_cache"),
    ("friTap.flow.models", "friTap.filter.protocols"),
    ("friTap.flow.models", "friTap.filter.layer_fields"),
    ("friTap.flow.tap_format", "friTap.filter.protocols"),
    ("friTap.flow.tap_format", "friTap.filter.layer_fields"),
})

# R9: TUI must not reach into private names of these layers.
TUI = ("friTap.tui",)
TUI_PRIVATE_FORBIDDEN = ("friTap.parsers", OFFLINE, "friTap.flow")

# R11: an importlib-style string naming an offline protocol module
# ("pkg.mod" or "pkg.mod:attr"); prose mentioning one does not match.
PROTOCOL_STRING_IMPORT = re.compile(
    r"(?:%s)(?:\.\w+)*(?::\w+(?:\.\w+)*)?" % "|".join(re.escape(p) for p in PROTOCOL_PACKAGES)
)


# --------------------------------------------------------------------------
# Allowlist of current violations. Every entry names the plan step that
# removes it. Keep sorted within each group.
# --------------------------------------------------------------------------
KNOWN_VIOLATIONS: frozenset[tuple[str, str]] = frozenset({
    # --- R1: parsers -> protocol/display/tui ---------------------------------
    # back-compat shim: the TL parsers now live in friTap.offline.mtproto.tl_parser;
    # the old path lazily re-exports them.
    ("friTap.parsers.telegram_tl", "friTap.offline.mtproto.tl_parser"),

    # --- R2: offline.net / offline.tls / pipeline_api -------------------------
    # (packages do not exist yet -- no entries)

    # --- R3a: rc4 / tls_midstream / signal / schannel -> mtproto ---------------
    # (none left -- generic TCP reassembly now lives in friTap.offline.net)

    # --- R3b: tls_midstream / schannel -> rc4 ---------------------------------
    # (none left -- the TLS 1.3 record layer now lives in friTap.offline.tls)

    # --- R4: protocols -> offline ---------------------------------------------
    # (none left -- handlers use the side-effect-free protocols.*_backend leaves)

    # --- R5: private names from offline.pcap_to_tap ---------------------------
    # (none left -- plugins import the public friTap.offline.pipeline_api)

    # --- R6: cross-protocol private names -------------------------------------
    # (none today)

    # --- R7: leaf modules -----------------------------------------------------
    # (none today)

    # --- R8 / R8c: per-module internal-import allowlists ----------------------
    # (none today)

    # --- R9: TUI -> private names of parsers / offline / flow -----------------
    # Pre-existing reach-ins; remove once flow exposes public names for them.
    ("friTap.tui.replay_controller", "friTap.flow.replay:_LRUCache"),
    ("friTap.tui.widgets.flow_detail", "friTap.flow.display:_layer_display_name"),

    # --- R10: parsers -> rich / textual ---------------------------------------
    # (none today)

    # --- R12: private names from inside a protocol package ----------------------
    # (none today)

    # --- R11: protocol packages named in string literals ----------------------
    # parsers/registry.py _BUILTIN_LAZY_PINS: deliberate lazy transport pins to
    # the TL parsers, resolved on first lookup (see the R1 shim above).
    ("friTap.parsers.registry", "string:friTap.offline.mtproto.tl_parser:MtprotoParser"),
    ("friTap.parsers.registry", "string:friTap.offline.mtproto.tl_parser:TelegramE2EParser"),
})


class ImportRecord(NamedTuple):
    module: str  # absolute imported module name
    name: str | None  # name imported via ``from module import name``
    lazy: bool = False  # inside a function body (not run at module import)


# ----------------------------- collection --------------------------------

def module_name_for(path: Path) -> str:
    parts = list(path.relative_to(REPO_ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def is_module_on_disk(module: str) -> bool:
    base = REPO_ROOT.joinpath(*module.split("."))
    return base.with_suffix(".py").is_file() or (base / "__init__.py").is_file()


def resolve_relative(importer: str, is_package: bool, level: int, module: str | None) -> str:
    """Resolve ``from <level dots><module> import ...`` inside ``importer``."""
    if level == 0:
        return module or ""
    package_parts = importer.split(".") if is_package else importer.split(".")[:-1]
    base_parts = package_parts[: len(package_parts) - (level - 1)]
    return ".".join(base_parts + ([module] if module else []))


FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def parse_module(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def iter_nodes_with_laziness(tree: ast.AST, lazy: bool = False) -> Iterator[tuple[ast.AST, bool]]:
    """Every node below ``tree`` with whether it sits inside a function body."""
    for child in ast.iter_child_nodes(tree):
        yield child, lazy
        yield from iter_nodes_with_laziness(child, lazy or isinstance(child, FUNCTION_NODES))


def collect_imports(path: Path) -> list[ImportRecord]:
    """All imports in ``path`` (module-level and lazy), absolutely resolved."""
    importer = module_name_for(path)
    is_package = path.name == "__init__.py"
    records: list[ImportRecord] = []
    for node, lazy in iter_nodes_with_laziness(parse_module(path)):
        if isinstance(node, ast.Import):
            records.extend(ImportRecord(alias.name, None, lazy) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            source = resolve_relative(importer, is_package, node.level, node.module)
            records.extend(_records_for_from_import(source, node.names, lazy))
    return records


def _records_for_from_import(
    source: str, aliases: list[ast.alias], lazy: bool
) -> Iterator[ImportRecord]:
    for alias in aliases:
        yield ImportRecord(source, alias.name, lazy)
        submodule = f"{source}.{alias.name}"
        if alias.name != "*" and is_module_on_disk(submodule):
            yield ImportRecord(submodule, None, lazy)


def collect_string_literals(path: Path) -> Iterator[str]:
    for node in ast.walk(parse_module(path)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value


def iter_package_modules() -> Iterator[tuple[str, Path]]:
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        if "__pycache__" not in path.parts:
            yield module_name_for(path), path


# ------------------------------- rules -----------------------------------

def under(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(module == p or module.startswith(p + ".") for p in prefixes)


def is_private(name: str | None) -> bool:
    return bool(name) and name.startswith("_") and not name.startswith("__")


def owning_package(module: str, packages: tuple[str, ...]) -> str | None:
    return next((p for p in packages if under(module, (p,))), None)


def module_rule_violations(importer: str, record: ImportRecord) -> Iterator[tuple[str, str]]:
    for importer_prefixes, forbidden in MODULE_RULES.values():
        if under(importer, importer_prefixes) and under(record.module, forbidden):
            yield importer, record.module


def private_name_violations(importer: str, record: ImportRecord) -> Iterator[tuple[str, str]]:
    if not is_private(record.name):
        return
    target = f"{record.module}:{record.name}"
    if record.module == PCAP_TO_TAP and importer != PCAP_TO_TAP:  # R5
        yield importer, target
    importer_pkg = owning_package(importer, PRIVATE_SHARING_PACKAGES)
    imported_pkg = owning_package(record.module, PRIVATE_SHARING_PACKAGES)
    if importer_pkg and imported_pkg and importer_pkg != imported_pkg:  # R6
        yield importer, target
    protocol_pkg = owning_package(record.module, PROTOCOL_PACKAGES)
    if protocol_pkg and not under(importer, (protocol_pkg,)):  # R12
        yield importer, target


def tui_private_name_violations(importer: str, record: ImportRecord) -> Iterator[tuple[str, str]]:
    """R9: the TUI uses only public names of parsers / offline / flow."""
    if under(importer, TUI) and is_private(record.name) and under(record.module, TUI_PRIVATE_FORBIDDEN):
        yield importer, f"{record.module}:{record.name}"


def leaf_module_violations(importer: str, record: ImportRecord) -> Iterator[tuple[str, str]]:
    """R7: import-free and friTap-free leaf modules."""
    if importer in IMPORT_FREE_MODULES:
        yield importer, record.module
    elif importer in FRITAP_FREE_MODULES and under(record.module, ("friTap",)):
        yield importer, record.module


def is_covered_by_submodule_record(record: ImportRecord) -> bool:
    """``from pkg import mod`` is judged by its ``pkg.mod`` companion record."""
    return record.name not in (None, "*") and is_module_on_disk(f"{record.module}.{record.name}")


def internal_allowlist_violations(importer: str, record: ImportRecord) -> Iterator[tuple[str, str]]:
    """R8: modules with an explicit allowlist of friTap-internal imports."""
    allowed = ALLOWED_INTERNAL_IMPORTS.get(importer)
    if allowed is None or not under(record.module, ("friTap",)):
        return
    if not under(record.module, allowed) and not is_covered_by_submodule_record(record):
        yield importer, record.module


def eager_cycle_edge_violations(importer: str, record: ImportRecord) -> Iterator[tuple[str, str]]:
    """R8c: tolerated cycle edges must stay function-level (lazy) imports."""
    if not record.lazy and (importer, record.module) in FUNCTION_LEVEL_ONLY_IMPORTS:
        yield importer, record.module


def string_import_violations(importer: str, path: Path) -> Iterator[tuple[str, str]]:
    """R11: generic modules must not string-import an offline protocol package."""
    if not under(importer, PARSERS + GENERIC_CORE_MODULES):
        return
    for literal in collect_string_literals(path):
        if PROTOCOL_STRING_IMPORT.fullmatch(literal.strip()):
            yield importer, f"string:{literal.strip()}"


RECORD_RULES = (
    module_rule_violations,
    private_name_violations,
    tui_private_name_violations,
    leaf_module_violations,
    internal_allowlist_violations,
    eager_cycle_edge_violations,
)


def violations() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for importer, path in iter_package_modules():
        for record in collect_imports(path):
            for rule in RECORD_RULES:
                found.update(rule(importer, record))
        found.update(string_import_violations(importer, path))
    return found


# ------------------------------- tests -----------------------------------

def _format(entries: set[tuple[str, str]]) -> str:
    return "\n".join(f"  ({a!r}, {b!r})" for a, b in sorted(entries))


def test_no_new_layering_violations():
    new = violations() - KNOWN_VIOLATIONS
    assert not new, (
        "New architecture-layering violations (fix the import, do not just "
        "allowlist it; rules R1-R12 are listed in this module's docstring; "
        "'module:_name' = private-name import, 'string:...' = importlib string):"
        f"\n{_format(new)}"
    )


def test_no_stale_allowlist_entries():
    stale = KNOWN_VIOLATIONS - violations()
    assert not stale, (
        "These KNOWN_VIOLATIONS no longer occur -- remove them from the "
        f"allowlist:\n{_format(stale)}"
    )


def test_resolve_relative_handles_package_and_module_importers():
    assert resolve_relative("friTap.offline.rc4.flow", False, 2, "mtproto.reassembly") == (
        "friTap.offline.mtproto.reassembly"
    )
    assert resolve_relative("friTap.offline.rc4", True, 1, "flow") == "friTap.offline.rc4.flow"
    assert resolve_relative("friTap.offline.rc4.flow", False, 1, None) == "friTap.offline.rc4"
    assert resolve_relative("x.y", False, 0, "a.b") == "a.b"


def test_rule_targets_exist_on_disk():
    """A renamed module must not silently drop out of a rule."""
    named = (
        GENERIC_CORE_MODULES
        + IMPORT_FREE_MODULES
        + FRITAP_FREE_MODULES
        + tuple(ALLOWED_INTERNAL_IMPORTS)
        + tuple(p for allowed in ALLOWED_INTERNAL_IMPORTS.values() for p in allowed)
        + tuple(m for edge in FUNCTION_LEVEL_ONLY_IMPORTS for m in edge)
    )
    missing = [m for m in named if not is_module_on_disk(m)]
    assert not missing, f"Layering rules name modules that do not exist: {missing}"


def test_cycle_edge_is_present_and_lazy():
    """R8c is only meaningful while each listed lazy cycle edge exists."""
    for importer, imported in FUNCTION_LEVEL_ONLY_IMPORTS:
        path = REPO_ROOT.joinpath(*importer.split(".")).with_suffix(".py")
        edges = [r for r in collect_imports(path) if r.module == imported]
        assert edges and all(r.lazy for r in edges), (
            f"{importer} -> {imported} must exist only as a function-level import; "
            f"drop it from FUNCTION_LEVEL_ONLY_IMPORTS if the edge was removed"
        )


def test_laziness_tracking_distinguishes_function_and_module_level():
    tree = ast.parse("import a\nclass C:\n    import b\ndef f():\n    import c\n")
    lazy_by_module = {
        alias.name: lazy
        for node, lazy in iter_nodes_with_laziness(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert lazy_by_module == {"a": False, "b": False, "c": True}


def test_protocol_string_import_pattern_ignores_prose():
    assert PROTOCOL_STRING_IMPORT.fullmatch("friTap.offline.mtproto.tl_parser:MtprotoParser")
    assert PROTOCOL_STRING_IMPORT.fullmatch("friTap.offline.signal")
    assert not PROTOCOL_STRING_IMPORT.fullmatch("see friTap.offline.signal for details")
    assert not PROTOCOL_STRING_IMPORT.fullmatch("friTap.offline.signals")
