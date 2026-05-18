#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Output file-naming helpers for per-protocol keylog splits."""

from __future__ import annotations

import os


def split_keylog_path(base_path: str, protocol: str) -> str:
    """Insert ``.<protocol>`` before the final extension of *base_path*.

    Used by the output factory when more than one protocol is active in
    a single ``friTap`` run, so each protocol's Wireshark-loadable
    keylog format lands in its own file:

    >>> split_keylog_path("mykeys.log", "ssh")
    'mykeys.ssh.log'
    >>> split_keylog_path("mykeys", "ssh")
    'mykeys.ssh'
    >>> split_keylog_path("/p/keys.log", "ssh")
    '/p/keys.ssh.log'
    >>> split_keylog_path("keys.tar.gz", "ssh")  # splits on LAST '.'
    'keys.tar.ssh.gz'
    >>> split_keylog_path(".keylog", "ssh")  # dotfile, no extension
    '.keylog.ssh'
    >>> split_keylog_path("", "ssh")
    '.ssh'

    The directory component is preserved untouched; only the basename
    is rewritten.
    """
    if not base_path:
        return f".{protocol}"
    head, tail = os.path.split(base_path)
    root, ext = os.path.splitext(tail)
    if not root:
        # Dotfile (``splitext('.keylog')`` returns ``('', '.keylog')``):
        # treat the entire basename as the stem.
        new_tail = f"{tail}.{protocol}"
    elif not ext:
        new_tail = f"{root}.{protocol}"
    else:
        new_tail = f"{root}.{protocol}{ext}"
    return os.path.join(head, new_tail) if head else new_tail
