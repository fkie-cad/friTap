"""
Shared user-facing hints for MTProto-transport captures (mtproto + telegram).

MTProto's obfuscated transport normally needs each connection captured from
byte 0, so attach mode misses already-open connections — unless memory
scanning (-ms) recovers their live keys (Tier E). The same wording is emitted
by the mtproto/telegram CLI handlers and the TUI, so it lives here once.
Callers add their own tag/capitalisation and choose their own severity.
"""

from __future__ import annotations

ATTACH_MEMORY_SCAN_RECOVERY = (
    "keys for already-open connections are recovered from live memory "
    "(Tier E). Keep the app in the foreground and exchange a few messages "
    "so the connection stays alive and recent traffic is captured; spawning "
    "is only needed to catch connections that close before the scan."
)

ATTACH_WITHOUT_MEMORY_SCAN = (
    "connections opened before capture can't be decrypted "
    "(obfuscated-transport init bytes are missed). Use -s (spawn) so every "
    "connection is captured from the start, or force-stop + relaunch the app "
    "before attaching. Or enable memory scanning (-ms) to recover keys for "
    "already-open connections."
)


def attach_mode_hint(memory_scan: bool) -> str:
    """The CLI attach-mode hint, tailored to whether memory scanning is on."""
    if memory_scan:
        return f"attach mode + memory scan: {ATTACH_MEMORY_SCAN_RECOVERY}"
    return f"attach mode: {ATTACH_WITHOUT_MEMORY_SCAN}"
