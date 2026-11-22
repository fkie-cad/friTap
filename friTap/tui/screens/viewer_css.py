"""Scoped CSS for the embeddable tap viewer.

``VIEWER_CSS`` is meant to be the ``DEFAULT_CSS`` of :class:`ViewerBody`.
Textual scopes a widget's DEFAULT_CSS (``SCOPED_CSS = True``) by prefixing each
selector with the widget's type name, so every rule below only matches inside
a ``ViewerBody`` subtree and cannot restyle the host app.

The rules are verbatim copies of the viewer-layout blocks of
``friTap/tui/css/fritap.tcss`` (lines 69-91 and 155-275); no rule there
targets ``Screen`` or another global selector, so no translation was needed.
``tests/unit/test_viewer_css_drift.py`` keeps the copy in sync.
``$fritap-*`` variables are resolved by the theme installed by the host.
"""

from textual.containers import Vertical

VIEWER_CSS = """
#activity-title-row {
    height: 3;
    background: $surface;
}

#capture-indicator {
    width: 30;
    padding: 1 1 0 1;          /* matches filter-bar horizontal pad so left edge aligns with `/:` */
    text-align: left;
    text-style: bold;
}

#activity-title {
    width: 1fr;
    text-align: center;
    text-style: bold;
    color: $success;
    padding: 1 0;
}

#title-spacer {
    width: 30;                 /* mirror of #capture-indicator to keep #activity-title centered */
}

#filter-bar {
    height: 1;
    background: $surface;
    padding: 0 1;
    display: none;
}

#filter-summary {
    width: 1fr;
}

#filter-status {
    width: auto;
    min-width: 16;
    content-align: right middle;
}

/* Analyzer panel (docked between the filter bar and the flow list).
   Kept compact so it never crowds the flow list — the analyzer list scrolls
   internally rather than the panel growing tall. */
#analyzer-panel {
    height: auto;
    max-height: 12;
    background: $surface;
    border: round $fritap-border-default;
    padding: 0 1;
    display: none;
}

#analyzer-panel:focus-within {
    border: round $primary;
}

#analyzer-panel #analyzer-select {
    height: auto;
    max-height: 5;
    background: $surface;
}

#analyzer-panel #analyzer-progress {
    color: $fritap-text-muted;
}

#analyzer-panel .analyzer-chip {
    background: $fritap-border-default;
}

#analyzer-panel .analyzer-chip:hover {
    background: $fritap-bg-selected;
}

/* Analyzer finding-detail view (opened with Enter on a finding) */
#finding-detail {
    height: 1fr;
    display: none;
    background: $surface;
}

#finding-detail-header {
    height: auto;
    padding: 0 1;
    background: $fritap-bg-header;
    color: $text;
}

#finding-detail-body {
    height: auto;
    padding: 0 1;
    background: $surface;
}

/* Flow list */
#flow-list {
    height: 1fr;
    scrollbar-size: 1 1;
    background: $surface;
}

#flow-list > .datatable--header {
    background: $fritap-bg-header;
    color: $primary;
    text-style: bold;
}

#flow-list > .datatable--cursor {
    background: $fritap-bg-selected;
    color: $text;
}

#flow-list > .datatable--even-row {
    background: $surface;
}

#flow-list > .datatable--odd-row {
    background: $panel;
}

/* Flow detail */
#flow-detail {
    height: 1fr;
    background: $surface;
}

#flow-detail-header {
    height: auto;
    max-height: 3;
    padding: 0 1;
    background: $fritap-bg-header;
    color: $foreground;
}

#flow-tabs {
    height: 1fr;
}

#request-log, #response-log, #detail-log {
    height: 1fr;
    scrollbar-size: 1 1;
    background: $surface;
}

"""


class ViewerBody(Vertical):
    """Container whose DEFAULT_CSS confines the viewer styling to its subtree."""

    DEFAULT_CSS = VIEWER_CSS
