#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared test helper: a fake RichLog that captures VISIBLE rendered text.

The Message tab now writes Rich renderables (the ``Table``/``Panel`` chat
bubbles) in addition to markup strings. ``str()`` of a renderable is an object
repr (``'<rich.table.Table object …>'``) — useless for the substring assertions
the Message-tab tests rely on. :class:`RenderingFakeLog` renders each written
item (markup string *or* renderable) through a real :class:`rich.console.Console`
at a fixed width and stores the exported plain text, so tests assert on the text
a user would actually see.

It also exposes ``content_size.width`` so the widget's bubble width-probe
(``_bubble_width_ok``) sees a real width: wide (default) → bubbles render; narrow
→ the single-column fallback is exercised.
"""

from __future__ import annotations

import io
from collections import namedtuple

from rich.console import Console

_Size = namedtuple("_Size", "width")


class RenderingFakeLog:
    def __init__(self, width: int = 120) -> None:
        self.lines: list[str] = []
        self.width = width

    @property
    def content_size(self) -> _Size:
        return _Size(self.width)

    def write(self, item) -> None:
        console = Console(width=self.width, file=io.StringIO(),
                          force_terminal=False, color_system=None,
                          highlight=False, markup=True, emoji=True)
        console.print(item)
        self.lines.append(console.file.getvalue().rstrip("\n"))

    def clear(self) -> None:
        self.lines = []

    def scroll_home(self, *a, **k) -> None:
        pass
