"""Rendering of the agent's DetachReport (the ``gracefulDetach`` RPC result).

The agent returns, from ``rpc.exports.gracefulDetach()``, a small JSON object
describing its own teardown (contract version 1)::

    {version: 1, repeat: bool, total_ms: number,
     steps: [{name, ok, ms, summary?: {k: v}, error?: str}],
     logs: [{level: "info"|"debug"|"warn"|"error", msg}], dropped_logs: number}

Older bundles return nothing (``None``). Everything here is a pure function of
the report so the wording is unit-testable; :func:`log_detach_report` is the
only function that touches a logger.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

NO_REPORT_MESSAGE = "Agent detach: agent returned no detach report"
REPEAT_MESSAGE = "Agent detach: already ran (repeat call, no new report)"

# Teardown step whose summary gets its own phrase in the INFO line.
NSS_CALLBACKS_STEP = "teardown:nss-key-callbacks"


def _steps(report: dict) -> List[dict]:
    steps = report.get("steps")
    if not isinstance(steps, list):
        return []
    return [step for step in steps if isinstance(step, dict)]


def _format_ms(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:g} ms"
    return "? ms"


def _format_summary(summary: Any) -> str:
    if not isinstance(summary, dict) or not summary:
        return ""
    return " ".join(f"{key}={value}" for key, value in summary.items())


def nss_callbacks_phrase(report: dict) -> Optional[str]:
    """``NSS callbacks restored app=… null=… stale=… failed=…[ echDual=…]`` or ``None``."""
    for step in _steps(report):
        if step.get("name") != NSS_CALLBACKS_STEP:
            continue
        summary = step.get("summary")
        if not isinstance(summary, dict):
            return None
        phrase = ("NSS callbacks restored "
                  f"app={summary.get('toApp', '?')} null={summary.get('toNull', '?')} "
                  f"stale={summary.get('stale', '?')} failed={summary.get('failed', '?')}")
        if "echDual" in summary:
            phrase += f" echDual={summary['echDual']}"
        return phrase
    return None


def summary_line(report: Optional[dict]) -> str:
    """The one INFO line summarising the agent's teardown."""
    if not isinstance(report, dict):
        return NO_REPORT_MESSAGE
    if report.get("repeat"):
        return REPEAT_MESSAGE
    steps = _steps(report)
    failed = sum(1 for step in steps if not step.get("ok"))
    line = (f"Agent detach: {len(steps) - failed}/{len(steps)} steps ok, "
            f"{failed} failed, total {_format_ms(report.get('total_ms'))}")
    nss = nss_callbacks_phrase(report)
    return f"{line}; {nss}" if nss else line


def step_lines(report: Optional[dict]) -> List[str]:
    """One DEBUG line per step: ``name ok|FAILED ms summary|error``."""
    if not isinstance(report, dict):
        return []
    lines = []
    for step in _steps(report):
        status = "ok" if step.get("ok") else "FAILED"
        detail = step.get("error") if not step.get("ok") else _format_summary(step.get("summary"))
        line = f"Agent detach step {step.get('name', '?')}: {status} {_format_ms(step.get('ms'))}"
        lines.append(f"{line} {detail}" if detail else line)
    return lines


def failed_step_lines(report: Optional[dict]) -> List[str]:
    """One WARNING line per failed step."""
    if not isinstance(report, dict):
        return []
    return [f"Agent detach step {step.get('name', '?')} failed: "
            f"{step.get('error') or 'no error message'}"
            for step in _steps(report) if not step.get("ok")]


#: Captured agent log levels rendered at WARNING; everything else stays at DEBUG.
WARNING_AGENT_LEVELS = ("warn", "error")


def _agent_log_records(report: Optional[dict]) -> List[tuple]:
    """``(agent level, rendered line)`` per captured agent log entry."""
    if not isinstance(report, dict):
        return []
    logs = report.get("logs")
    records = []
    for entry in logs if isinstance(logs, list) else []:
        if isinstance(entry, dict):
            level = entry.get("level", "info")
            records.append((level, f"[agent:{level}] {entry.get('msg', '')}"))
        else:
            records.append(("info", f"[agent] {entry}"))
    dropped = report.get("dropped_logs")
    if isinstance(dropped, int) and dropped > 0:
        records.append(("debug", f"[agent] {dropped} further teardown log line(s) dropped"))
    return records


def agent_log_lines(report: Optional[dict]) -> List[str]:
    """The agent log lines captured during its teardown."""
    return [line for _level, line in _agent_log_records(report)]


def log_detach_report(logger: logging.Logger, report: Optional[dict]) -> None:
    """Log *report*: INFO summary, DEBUG steps/logs, WARNING per failed step.

    Captured agent lines of level warn/error are logged at WARNING.
    """
    logger.info(summary_line(report))
    for line in step_lines(report):
        logger.debug(line)
    for level, line in _agent_log_records(report):
        if level in WARNING_AGENT_LEVELS:
            logger.warning(line)
        else:
            logger.debug(line)
    for line in failed_step_lines(report):
        logger.warning(line)
