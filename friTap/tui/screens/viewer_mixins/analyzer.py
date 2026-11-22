#!/usr/bin/env python3

"""Analyzer panel: run analyzers interactively over the loaded flows.

A plain mixin (no BINDINGS/CSS/compose); the host screen supplies ``query_one``,
``run_worker``, ``workers``, ``app``, ``_analyzer_run_id``, ``_findings_cache``,
the findings-view helpers and the ``_divert_analyzer_key`` /
``_analyzer_flow_ids_and_getter`` hooks. No capture/wizard code.

Runs use worker group ``"analyzer"`` and the stale-run token ``_analyzer_run_id``;
a Clear and a source swap (``_forget_analyzer_results``) both invalidate an in-flight run.
"""

from __future__ import annotations

from friTap.analysis.filtering import summarize
from friTap.analysis.registry import available_analyzers, resolve_analyzers

from ...widgets.analyzer_panel import AnalyzerPanel
from ...widgets.findings_list import FindingsListWidget


class AnalyzerMixin:
    """Analyzer panel toggle, run worker and dashboard (host: a Textual ``Screen``)."""

    def _analyzer_panel(self) -> "AnalyzerPanel":
        return self.query_one("#analyzer-panel", AnalyzerPanel)

    def action_analyzer_panel(self) -> None:
        """Toggle the analyzer panel ('a'); only when flows are loaded, else 'a' keeps its capture meaning (attach)."""
        if self._divert_analyzer_key():
            return

        panel = self._analyzer_panel()
        if panel.display:
            panel.display = False
            try:
                self.query_one("#flow-list").focus()
            except Exception:
                pass
            return

        # The panel docks above the flow list; leave the findings view first so it is not stacked on it.
        if self._findings_list_displayed():
            self._activate_flow_view()

        panel.set_available(available_analyzers())
        panel.reset()
        panel.display = True
        panel.focus()

    def on_analyzer_panel_run_requested(
        self, event: "AnalyzerPanel.RunRequested"
    ) -> None:
        """Run the selected analyzers over the loaded flows in a worker."""
        if not event.analyzer_names:
            self._analyzer_panel().set_progress(0, 0, label="select at least one analyzer")
            return
        names = list(event.analyzer_names)
        path = event.analyzer_path
        # A late completion of an in-flight worker is then recognised as stale.
        self._analyzer_run_id += 1
        run_id = self._analyzer_run_id
        # Own group so exclusive=True cancels only a prior analyzer run, not the capture session or server workers.
        self.run_worker(
            lambda: self._run_analyzers_worker(names, path, run_id),
            thread=True,
            exclusive=True,
            group="analyzer",
        )

    def _run_analyzers_worker(self, names: list, analyzer_path, run_id: int) -> None:
        """Worker body (thread): resolve analyzers, run them, collect findings.

        Polls the cancellation flag (thread workers cannot be killed) and tags the
        result with *run_id* so a superseded run never overwrites a newer one.
        """
        from textual.worker import get_current_worker

        worker = get_current_worker()
        panel = self._analyzer_panel()
        try:
            analyzers = resolve_analyzers(",".join(names), analyzer_path=analyzer_path)
        except Exception as e:  # bad spec / unloadable plugin path
            if not worker.is_cancelled:
                self.app.call_from_thread(panel.set_progress, 0, 0, f"error: {e}")
            return

        flow_ids, get_flow = self._analyzer_flow_ids_and_getter()

        total = len(flow_ids)
        findings: list = []
        for i, fid in enumerate(flow_ids, 1):
            if worker.is_cancelled:
                return  # superseded by a newer run — drop this work
            try:
                flow = get_flow(fid)
            except Exception:
                flow = None
            if flow is not None:
                for analyzer in analyzers:
                    try:
                        findings.extend(analyzer.analyze_flow(flow))
                    except Exception:
                        continue
            if i % 5 == 0 or i == total:
                self.app.call_from_thread(panel.set_progress, i, total)

        if worker.is_cancelled:
            return
        self.app.call_from_thread(self._on_analyzers_complete, findings, run_id)

    def _on_analyzers_complete(self, findings: list, run_id: int) -> None:
        """Replace the session findings with this run's results and show counts; stale runs are ignored."""
        if run_id != self._analyzer_run_id:
            return
        try:
            findings_list = self.query_one("#findings-list", FindingsListWidget)
            findings_list.clear_findings()
            findings_list.add_findings(findings)
        except Exception:
            pass
        # The cache mirrors exactly this run so shift+f and the dashboard counts agree.
        self._findings_cache = list(findings)
        try:
            self._analyzer_panel().show_dashboard(summarize(findings))
        except Exception:
            pass

    def on_analyzer_panel_chip_selected(
        self, event: "AnalyzerPanel.ChipSelected"
    ) -> None:
        """A dashboard chip drops into the findings view, pre-filtered."""
        self._analyzer_panel().display = False
        self._activate_findings_view()
        self._apply_findings_filter(event.flt, event.label)

    def on_analyzer_panel_clear_requested(
        self, event: "AnalyzerPanel.ClearRequested"
    ) -> None:
        """Clear analyzer results for this session."""
        # A late completion must not resurrect cleared results.
        self._invalidate_analyzer_run()
        try:
            self.query_one("#findings-list", FindingsListWidget).clear_findings()
        except Exception:
            pass
        self._findings_cache = []
        self._analyzer_panel().reset()

    def _invalidate_analyzer_run(self) -> None:
        """Drop any in-flight analyzer run: bump the run id, cancel its worker."""
        self._analyzer_run_id += 1
        try:
            self.workers.cancel_group(self, "analyzer")
        except Exception:
            pass

    def _forget_analyzer_results(self) -> None:
        """Drop the analyzer state of a source being replaced (reload).

        Like a Clear, but the findings cache returns to ``None`` so the findings view
        reads the NEW source's findings. Only the "analyzer" group is cancelled (the
        reload is triggered by the "decrypt" worker). ``_swap_in_source`` also empties the rows.
        """
        # A late completion of a run on the old source compares run ids and is dropped.
        self._invalidate_analyzer_run()
        self._findings_cache = None
        try:
            self._analyzer_panel().reset()  # drops the old run's dashboard
        except Exception:
            pass

    def on_analyzer_panel_close_requested(
        self, event: "AnalyzerPanel.CloseRequested"
    ) -> None:
        """Close the analyzer panel and return focus to the flow list."""
        self._analyzer_panel().display = False
        try:
            self.query_one("#flow-list").focus()
        except Exception:
            pass
