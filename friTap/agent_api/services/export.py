"""
Export service: write a capture as HAR, Markdown or an NSS keylog file.

The content never travels back to the caller; the result is
``{path, bytes, sha256, format}``. Output paths resolve inside the sandbox
root, an existing file is replaced only with ``overwrite``, files are written
atomically with mode 0600, and the keylog (key material) needs both the
call's ``confirm_secrets`` and the server's ``ctx.allow_secrets``.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable

from friTap.agent_api.context import ToolContext
from friTap.agent_api.errors import ToolError
from friTap.agent_api.paths import resolve_under_root
from friTap.agent_api.services.reading import selector_for

EXPORT_FORMATS = ("har", "markdown", "keylog")
MARKDOWN_DIGEST_BUDGET = 8000
MARKDOWN_MAX_FLOWS = 200
MARKDOWN_FLOW_BYTES = 2048
_SLICE_KEYS = ("protocol", "app_protocol", "filter")


# ---------------------------------------------------------------------------
# Content builders (tap, params) -> text
# ---------------------------------------------------------------------------

def har_text(tap: Path, params: dict[str, Any]) -> str:
    """HAR 1.2 JSON of the sliced capture."""
    from friTap.analysis.export_har import tap_to_har

    keep = selector_for(params).matches
    har = tap_to_har(str(tap), include_bodies=params.get("include_bodies", False), keep=keep)
    return json.dumps(har, indent=2, ensure_ascii=False, default=str) + "\n"


def _flow_markdown(tap: Path, refs: list[str], show_values: bool) -> list[str]:
    """Render every ref from ONE open reader (the capture is opened and indexed once)."""
    from friTap.analysis.digest import ordered_flow_ids
    from friTap.analysis.digest_flow import flow_detail_from
    from friTap.analysis.digest_render import render_flow_markdown
    from friTap.flow.tap_reader import TapReader

    with TapReader(str(tap)) as reader:
        ids = ordered_flow_ids(reader)
        details = [flow_detail_from(reader, ids, ref, source_file=tap.name,
                                    max_bytes=MARKDOWN_FLOW_BYTES, show_values=show_values)
                   for ref in refs]
    return [render_flow_markdown(detail) for detail in details]


def _selected_refs(scan) -> list[str]:
    """Refs of the first ``MARKDOWN_MAX_FLOWS`` flows *scan* selected, in capture order."""
    from friTap.analysis.digest import flow_ref

    ordinals = sorted(scan.ordinals.values())
    return [flow_ref(ordinal) for ordinal in ordinals[:MARKDOWN_MAX_FLOWS]]


def markdown_text(tap: Path, params: dict[str, Any]) -> str:
    """Digest Markdown followed by per-flow detail (first ``MARKDOWN_MAX_FLOWS`` flows).

    The digest and the flow selection share one cached scan of the capture.
    """
    from friTap.agent_api.services import reading

    show_values = params.get("show_values", False)
    digest_params = {**params, "budget": MARKDOWN_DIGEST_BUDGET}
    doc = reading.digest(tap, digest_params)
    parts = [reading.digest_markdown(doc), "\n# Flows\n"]
    parts += _flow_markdown(tap, _selected_refs(reading.digest_scan(tap, digest_params)), show_values)
    return "\n".join(parts)


def keylog_text(tap: Path, params: dict[str, Any]) -> str:
    """Keylog lines of the capture, in file order.

    The REC_KEYLOG records stored in the tap; for a live capture session (whose
    tap carries no key records) the session's keylog files written with
    ``capture: "keys"``/``"full"`` instead.
    """
    del params
    from friTap.flow.tap_reader import TapReader
    from friTap.output.keylog_format import filter_safe_keylog_lines

    with TapReader(str(tap)) as reader:
        lines = [line for key_data, _ts in reader.iter_keylogs() if key_data
                 for line in key_data.splitlines() if line.strip()]
    if not lines:
        lines = _session_keylog_lines(tap)
    return "".join(f"{line}\n" for line in filter_safe_keylog_lines(lines))


def _session_keylog_lines(tap: Path) -> list[str]:
    """Non-empty lines of the keylog files next to a capture session's tap.

    Read line by line with the offline keylog reader (over-long lines skipped),
    never the whole file at once.
    """
    from friTap.agent_api.capture.manager import SESSIONS_DIRNAME
    from friTap.agent_api.capture.runner import TAP_NAME, session_keylog_files
    from friTap.offline.keylog_io import load_keylog_lines

    if tap.name != TAP_NAME or tap.parent.parent.name != SESSIONS_DIRNAME:
        return []
    lines: list[str] = []
    for path in session_keylog_files(tap.parent):
        lines += load_keylog_lines(str(path), _non_empty_line)
    return lines


def _non_empty_line(line: str) -> str | None:
    text = line.rstrip("\r\n")
    return text if text.strip() else None


_BUILDERS: dict[str, Callable[[Path, dict[str, Any]], str]] = {
    "har": har_text,
    "markdown": markdown_text,
    "keylog": keylog_text,
}


# ---------------------------------------------------------------------------
# Policy checks
# ---------------------------------------------------------------------------

def _check_secrets(params: dict[str, Any], ctx: ToolContext) -> None:
    if params.get("format") != "keylog":
        return
    if not params.get("confirm_secrets"):
        raise ToolError("keylog export writes TLS key material", "forbidden",
                        hint="pass confirm_secrets=true to confirm")
    if not ctx.allow_secrets:
        raise ToolError("keylog export is disabled on this server", "forbidden",
                        hint="restart the server with --allow-secrets")
    sliced = [key for key in _SLICE_KEYS if params.get(key)]
    if sliced:
        raise ToolError(f"{sliced[0]} does not apply to keylog export", "bad_param",
                        hint="keylog exports every key; drop protocol/app_protocol/filter",
                        param=sliced[0])


def resolve_output(params: dict[str, Any], ctx: ToolContext, tap: Path) -> Path:
    """Sandboxed output path; refuses the source capture and (without overwrite) existing files."""
    out = resolve_under_root(params["out"], ctx.root, must_exist=False)
    if out == tap.resolve():
        raise ToolError("out must not be the source capture", "bad_param",
                        hint="choose a new file name", param="out")
    if out.is_dir():
        raise ToolError(f"out is a directory: {params['out']}", "bad_param",
                        hint="pass a file path", param="out")
    if out.exists() and not params.get("overwrite"):
        raise ToolError(f"file exists: {params['out']}", "already_exists",
                        hint="pass overwrite=true or choose another path", param="out")
    return out


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def write_atomic(out: Path, data: bytes) -> None:
    """Write *data* to *out* via a 0600 temp file in the same directory + rename."""
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{out.name}.", dir=out.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, out)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def export(tap: Path, params: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """Write the capture in ``params["format"]`` to ``params["out"]``.

    Returns:
        ``{"path", "bytes", "sha256", "format"}`` (never the content).
    """
    _check_secrets(params, ctx)
    out = resolve_output(params, ctx, tap)
    data = _BUILDERS[params["format"]](tap, params).encode("utf-8")
    write_atomic(out, data)
    return {"path": str(out), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "format": params["format"]}


__all__ = ["EXPORT_FORMATS", "export", "har_text", "keylog_text", "markdown_text",
           "resolve_output", "write_atomic"]
