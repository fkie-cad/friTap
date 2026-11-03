"""Neutralise terminal control characters in untrusted text.

Text reported by the Frida agent (console lines, log messages, script error
descriptions and stacks) originates inside a possibly hostile target process.
Written raw to the analyst's terminal or log file, ``ESC [ ... m`` (ANSI/CSI)
and ``ESC ] ... BEL`` (OSC) sequences can recolour or clear the screen, forge
log lines, set the window title or plant clickable hyperlinks.

This is the core (TUI-independent) twin of
``friTap.tui.widgets.wire_text.visible_controls``: every C0/C1 control, the
Unicode line/paragraph separators and the bidi override/isolate controls are
rendered as visible ``\\xNN`` / ``\\uNNNN`` escapes, so they cannot act on a
terminal.
"""

from __future__ import annotations

import re

# C0 controls except TAB and LF, DEL, C1 controls, Unicode line/paragraph
# separators and the bidi embedding/override/isolate controls.
_TERMINAL_UNSAFE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f  ‪-‮⁦-⁩]"
)

# Same set, but LF is escaped too (single-line contexts / wire_text parity).
_TERMINAL_UNSAFE_SINGLE_LINE = re.compile(
    "[\x00-\x08\x0a-\x1f\x7f-\x9f  ‪-‮⁦-⁩]"
)

_NAMED_ESCAPES = {
    "\r": "\\r",
    "\n": "\\n",
    "\x1b": "\\x1b",
    "\x00": "\\x00",
}


def _escape_control(match: re.Match) -> str:
    char = match.group(0)
    named = _NAMED_ESCAPES.get(char)
    if named:
        return named
    code = ord(char)
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def safe_terminal_text(value) -> str:
    """Return *value* as text that is safe to log or print to a terminal.

    ``\\n`` and ``\\t`` are kept (multi-line agent messages and stack traces
    stay readable); every other control character becomes a visible escape.
    ``None`` becomes the empty string.
    """
    if value is None:
        return ""
    return _TERMINAL_UNSAFE.sub(_escape_control, str(value))


def visible_controls(value) -> str:
    """Return *value* with every control character -- including ``\\n`` -- escaped.

    TAB is kept. Behaviour matches the TUI's ``wire_text.visible_controls``.
    """
    return _TERMINAL_UNSAFE_SINGLE_LINE.sub(_escape_control, str(value))
