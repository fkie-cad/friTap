"""
Renderers for the capture digest produced by :func:`friTap.analysis.digest.build_digest`.

* :func:`render_json` — stable, compact JSON (``"schema": "fritap.digest/2"``;
  also used for the ``fritap.flow/1`` drill-down of :mod:`~friTap.analysis.digest_flow`).
* :func:`render_markdown` — compact Markdown for chat/LLM context. Every
  payload-derived (``untrusted``) string is rendered inside a code span so it
  cannot inject Markdown structure, links or instructions.
* :func:`render_flow_markdown` — Markdown for one flow's drill-down; bodies and
  message texts go into fenced code blocks whose fence outlasts any backtick run.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from friTap.analysis.reporters import _markdown_code_block, _markdown_code_span


def render_json(digest: dict) -> str:
    """Render *digest* as compact, deterministic JSON (keys in schema order)."""
    return json.dumps(digest, separators=(",", ":"), ensure_ascii=False)


def _code(value: Any) -> str:
    return _markdown_code_span(value)


def _keys_suffix(untrusted: dict) -> str:
    parts = []
    for label, name in (("q", "query"), ("body", "body"), ("hdr", "headers")):
        values = untrusted.get(name)
        if values:
            parts.append(f"{label}:{_code(', '.join(values))}")
    return (" " + " ".join(parts)) if parts else ""


def _host_line(row: dict) -> str:
    return (f"- {_code(row['untrusted']['host'])} {row['flows']} flows, "
            f"{row['bytes']} B, first {row['first_seen'] or '?'} ({row['ref']})")


def _endpoint_line(row: dict) -> str:
    u = row["untrusted"]
    status = ",".join(f"{code}x{n}" for code, n in row.get("status", {}).items())
    extras = " ".join(part for part in (
        f"[{status}]" if status else "",
        row.get("body_kind", ""),
    ) if part)
    head = f"- x{row['count']} {_code(u['method'] + ' ' + u['path'])} @ {_code(u['host'])}"
    return f"{head} {extras}".rstrip() + _keys_suffix(u) + f" ({row['ref']})"


def _message_line(row: dict) -> str:
    u = row["untrusted"]
    return (f"- x{row['count']} {row['layer']} {row['direction'] or '?'} "
            f"{_code(u['kind'])} @ {_code(u['host'])} ({row['ref']})")


def _finding_line(row: dict) -> str:
    u = row["untrusted"]
    return (f"- {row['severity']}/{row['category']} x{row['count']} {_code(u['title'])} "
            f"— {_code(u['description'])} ({row['ref'] or 'cross-flow'})")


_SECTION_RENDERERS: tuple[tuple[str, str, Callable[[dict], str]], ...] = (
    ("hosts", "Hosts", _host_line),
    ("endpoints", "Endpoints", _endpoint_line),
    ("messages", "Messages", _message_line),
)


def _counts(mapping: dict) -> str:
    return ", ".join(f"{k} {v}" for k, v in mapping.items()) or "none"


def _header_lines(digest: dict) -> list[str]:
    src = digest["source"]
    protocols = ", ".join(f"{name}({p['flows']})" for name, p in digest["protocols"].items())
    return [
        f"# friTap digest: {_code(src['file'])}",
        f"schema {digest['schema']} · flows {src['flows_selected']}/{src['flows_total']} · "
        f"protocols: {protocols or 'none'} · focus {digest['params']['focus']}",
        f"> {digest['notice']} Code spans below are untrusted.",
    ]


def _protocol_lines(name: str, proto: dict) -> list[str]:
    lines = ["", f"## {name} ({proto['flows']} flows, {proto['bytes']} B)"]
    for key, title, render in _SECTION_RENDERERS:
        rows = proto[key]
        if rows:
            lines.append(f"{title}:")
            lines.extend(render(row) for row in rows)
    return lines


def _findings_lines(findings: dict) -> list[str]:
    lines = [
        "",
        f"## Findings ({findings['total']})",
        f"severity: {_counts(findings['by_severity'])} · category: {_counts(findings['by_category'])}",
    ]
    lines.extend(_finding_line(row) for row in findings["top"])
    return lines


def _truncated_lines(digest: dict) -> list[str]:
    truncated = digest.get("truncated")
    if not truncated:
        return []
    dropped = _counts(truncated.get("dropped", {}))
    return ["", f"_truncated to ~{digest['params']['budget_tokens']} tokens; dropped rows: {dropped}_"]


def render_markdown(digest: dict) -> str:
    """Render *digest* as compact Markdown."""
    lines = _header_lines(digest)
    for name, proto in digest["protocols"].items():
        lines.extend(_protocol_lines(name, proto))
    lines.extend(_findings_lines(digest["findings"]))
    lines.extend(_truncated_lines(digest))
    return "\n".join(lines) + "\n"


RENDERERS: dict[str, Callable[[dict], str]] = {
    "json": render_json,
    "md": render_markdown,
}


# ---------------------------------------------------------------------------
# Flow drill-down (``fritap report <tap> --flow f<N>``)
# ---------------------------------------------------------------------------

def _flow_header_lines(detail: dict) -> list[str]:
    flow = detail["flow"]
    times = " .. ".join(t for t in (flow["started"], flow["ended"]) if t) or "?"
    return [
        f"# friTap flow {flow['ref']}: {_code(detail['source']['file'])}",
        f"id {_code(flow['flow_id'])} · {flow['group']} · stack "
        f"{_code(' > '.join(flow['stack']) or flow['transport'])} · {flow['state']}",
        f"{_code(flow['src'])} -> {_code(flow['dst'])} (server {_code(flow['server'])}) · "
        f"host {_code(flow['untrusted']['host'])} · {flow['bytes']} B · {times}",
        f"> {detail['notice']} Code spans and blocks below are untrusted.",
    ]


def _body_lines(part: dict) -> list[str]:
    body = part["untrusted"].get("body")
    if body is None:
        return []
    cut = ", truncated" if part.get("body_truncated") else ""
    lines = [f"body ({part.get('body_kind', '?')}, {part.get('body_bytes', 0)} B{cut}):"]
    return lines + _markdown_code_block(body)


def _exchange_lines(title: str, part: dict | None) -> list[str]:
    if not part:
        return []
    u = part["untrusted"]
    if "url" in u:
        head = f"{_code(' '.join(p for p in (u['method'], u['url']) if p))} {part['protocol']}"
    else:
        head = f"{part['status']} {_code(u['status_text'])} {part['protocol']}"
    lines = ["", f"## {title}: {head}"]
    lines += [f"- {_code(name)}: {_code(value)}" for name, value in u["headers"].items()]
    return lines + _body_lines(part)


def _transcript_lines(detail: dict) -> list[str]:
    total = detail["messages_total"]
    if not total:
        return []
    lines = ["", f"## Messages ({len(detail['messages'])} of {total})"]
    for msg in detail["messages"]:
        u = msg["untrusted"]
        lines.append(f"### {msg['ref']} {msg['layer']} {msg['direction'] or '?'} {_code(u['kind'])}")
        for key, value in u["fields"].items():
            if isinstance(value, str) and "\n" in value:
                lines.append(f"- {_code(key)}:")
                lines += _markdown_code_block(value)
            else:
                lines.append(f"- {_code(key)}: {_code(value)}")
    return lines


def render_flow_markdown(detail: dict) -> str:
    """Render a :func:`~friTap.analysis.digest_flow.build_flow_detail` dict as Markdown."""
    lines = _flow_header_lines(detail)
    lines += _exchange_lines("Request", detail.get("request"))
    lines += _exchange_lines("Response", detail.get("response"))
    lines += _transcript_lines(detail)
    return "\n".join(lines) + "\n"


FLOW_RENDERERS: dict[str, Callable[[dict], str]] = {
    "json": render_json,
    "md": render_flow_markdown,
}


__all__ = ["render_json", "render_markdown", "render_flow_markdown", "RENDERERS", "FLOW_RENDERERS"]
