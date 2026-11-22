"""Output handling for :class:`SSL_Logger`: handler setup and close, keylog
accessors, sidecars, live FIFO and live scan, JSON finalize and the SChannel relabel.

The host class owns the state. Names tests patch on ``ssl_logger_core`` are read
through ``_core()`` at call time so the patches take effect.
"""

import json
import os
import queue
import threading
import time
from datetime import datetime, timezone

from ..events import SessionEvent
from ..pcap import PCAP
from .ssl_logger_state import core_module as _core


def _schannel_keylog_candidates(config, protocol_registry):
    """Return the TLS keylog files an SChannel relabel pass should repair.

    The LSASS worker (``hook_lsass``) uses the default single ``tls`` protocol,
    so it writes SChannel secrets to the base ``-k`` path, never to a split
    file. ``pcap_obj.keylog_path`` is unusable here: under ``--protocol tls,rc4``
    it holds whichever split handler was set up last.

    This session's own TLS split file is repaired too; non-TLS splits never are.
    """
    base_keylog = config.output.keylog
    if not base_keylog:
        return []
    candidates = [base_keylog]
    try:
        from ..output.factory import active_keylog_paths
        protocols = list(getattr(config, "protocols", None) or ["tls"])
        tls_keylog = active_keylog_paths(
            base_keylog, protocols, protocol_registry).get("tls")
    except Exception:  # noqa: BLE001 - best-effort discovery
        tls_keylog = None
    if tls_keylog and tls_keylog != base_keylog:
        candidates.append(tls_keylog)
    return candidates


def _drop_still_open_keylogs(logger, pcap_name, keylog_paths):
    """Return the *keylog_paths* no writer in this process still holds open.

    The ``-k`` file is refcounted across the main and LSASS keylog handlers. A
    path still open would be renamed under a live writer (later keys land in the
    ``.raw`` backup; Windows refuses the rename), so it is skipped with a warning.
    """
    from ..output.shared_keylog_writer import is_keylog_path_open
    closed = []
    for path in keylog_paths:
        if is_keylog_path_open(path):
            logger.warning(
                "SChannel keylog auto-relabel skipped for %s: the keylog is still "
                "open by another friTap session. The keylog was kept unchanged; "
                "to fix it manually, run: fritap --from-pcap %s --keylog %s "
                "--repair-keylog", path, pcap_name, path)
        else:
            closed.append(path)
    return closed


def _warn_relabel_not_applied(logger, pcap_name, keylog_path, relabeled_path, error):
    """Tell the user the relabel could not be written and how to apply it by hand."""
    logger.warning(
        "SChannel keylog auto-relabel could not replace %s (%s); the original keylog "
        "was kept unchanged. The relabeled copy is at %s. To redo the fix manually, "
        "run: fritap --from-pcap %s --keylog %s --repair-keylog",
        keylog_path, error, relabeled_path, pcap_name, keylog_path)


def _swap_in_relabeled_keylog(logger, pcap_name, keylog_path, relabeled_path, raw_backup):
    """Move *keylog_path* to *raw_backup* and *relabeled_path* into its place.

    Returns ``True`` on success. On ``OSError`` (e.g. Windows PermissionError for
    a file still held open) the original is kept or restored, a warning with the
    manual command is logged, and ``False`` is returned.
    """
    try:
        os.replace(keylog_path, raw_backup)
    except OSError as e:
        _warn_relabel_not_applied(logger, pcap_name, keylog_path, relabeled_path, e)
        return False
    try:
        os.replace(relabeled_path, keylog_path)
    except OSError as e:
        try:
            os.replace(raw_backup, keylog_path)
        except OSError:
            logger.warning("Could not restore %s; the original keylog is at %s",
                           keylog_path, raw_backup)
        _warn_relabel_not_applied(logger, pcap_name, keylog_path, relabeled_path, e)
        return False
    return True


def _relabel_one_schannel_keylog(logger, tshark_bin, pcap_name, keylog_path):
    """Trial-decrypt-relabel one keylog in place, keeping ``<stem>.raw<ext>``."""
    from ..offline.keylog_coverage import relabel_keylog
    result = relabel_keylog(
        tshark_bin, pcap_name, keylog_path,
        progress=lambda m: logger.debug("relabel: %s", m))
    if not result.repaired_path:
        logger.debug("SChannel keylog auto-relabel (%s): %s", keylog_path, result.message)
        return
    stem, ext = os.path.splitext(keylog_path)
    raw_backup = f"{stem}.raw{ext or '.keylog'}"
    if not _swap_in_relabeled_keylog(logger, pcap_name, keylog_path,
                                     result.repaired_path, raw_backup):
        return
    logger.info(
        "SChannel keylog relabeled by trial decryption (%s); raw agent output saved "
        "to %s. Load %s directly in Wireshark.",
        result.message, os.path.basename(raw_backup), os.path.basename(keylog_path))


class _PluginSessionShim:
    """Session-like object giving plugins the on_load/on_unload API, backed by the EventBus."""

    def __init__(self, event_bus, pipeline=None, connection_index=None):
        self.lifecycle_bus = event_bus
        self.pipeline = pipeline
        self.connection_index = connection_index

    def register_sink(self, sink):
        """Register a sink (no-op in legacy mode unless pipeline is set)."""
        if self.pipeline is not None:
            self.pipeline.add_sink(sink)

    def push_message(self, payload, data=None):
        """Not supported in the legacy shim."""
        raise NotImplementedError(
            "push_message() is not supported on the legacy SSL_Logger shim. "
            "Use CoreController + Session for pipeline-based message routing."
        )

    def astart(self):
        """Not available in legacy mode."""
        raise NotImplementedError(
            "astart() is not available in legacy mode. "
            "Use CoreController + Session for async API."
        )

    def astop(self):
        """Not available in legacy mode."""
        raise NotImplementedError(
            "astop() is not available in legacy mode. "
            "Use CoreController + Session for async API."
        )

    def await_done(self):
        """Not available in legacy mode."""
        raise NotImplementedError(
            "await_done() is not available in legacy mode. "
            "Use CoreController + Session for async API."
        )


class OutputsMixin:
    """Output handlers from setup to close, plus the finalizers that run on them."""

    def _remember_tls_keylog_handler(self, handler) -> None:
        """Keep the hooked-key keylog handler; a ``tls`` one beats other splits.

        The memory-scan handler is never kept (it is not the ``-k`` keylog).
        """
        if self._is_memory_scan_handler(handler):
            return
        current = getattr(self, "_tls_keylog_handler", None)
        if current is None or not self._is_tls_keylog_handler(current):
            self._tls_keylog_handler = handler

    @staticmethod
    def _is_tls_keylog_handler(handler) -> bool:
        formatter = getattr(handler, "_formatter", None)
        return getattr(formatter, "protocol", None) == "tls"

    def _live_keylog_file(self):
        """The keylog handle as it is NOW (handler-owned when handlers are active)."""
        handler = getattr(self, "_tls_keylog_handler", None)
        if handler is not None:
            return handler._file
        return getattr(self, "keylog_file", None)

    def _live_keylog_path(self):
        """The hooked-key keylog path (handler path, else the ``-k`` option)."""
        handler = getattr(self, "_tls_keylog_handler", None)
        if handler is not None:
            return handler._path
        return getattr(self, "keylog", None)

    @staticmethod
    def _is_memory_scan_handler(handler) -> bool:
        """Whether *handler* is the heap scanner's (``-ms``) keylog writer."""
        formatter = getattr(handler, "_formatter", None)
        return getattr(formatter, "protocol", None) == "memscan"

    def _record_memory_scan_keylogs(self):
        """Hand the memory-scan keylog paths to the PCAP object for the manifest."""
        if self.pcap_obj is None or not hasattr(self.pcap_obj, "set_memory_scan_keylogs"):
            return
        from ..memory_scanning import memory_scan_protocol_keylogs
        mapping = memory_scan_protocol_keylogs(self._config)
        if mapping:
            self.pcap_obj.capture_protocol = self.protocol
            self.pcap_obj.set_memory_scan_keylogs(mapping)
        # Advertise the writer's real mid-stream secret-bundle path (incl. the
        # CWD-literal fallback) so the manifest reader need not recompute it.
        engine = getattr(self, "_memory_scan_engine", None)
        if engine is not None and hasattr(self.pcap_obj, "set_tls_midstream_secrets_path"):
            try:
                self.pcap_obj.set_tls_midstream_secrets_path(
                    engine.intended_tls_secret_bundle_path())
            except Exception as e:
                self.logger.debug(
                    f"mid-stream secrets path advertisement skipped: {e}")

    def _full_capture_hooks_enabled(self) -> bool:
        """-f with plaintext hooks not disabled; the agent's ``full_capture`` switch."""
        output = self._config.output
        return bool(output.full_capture) and not output.plaintext_hooks_disabled

    def _request_context_sidecar_wanted(self) -> bool:
        """-f with --attribute-sdk: the offline .tap build needs request contexts beside the pcap.

        Keys are required too, mirroring the agent gate (``full_capture &&
        keylog_enabled``), so a run without request-context hooks gets no empty sidecar.
        """
        from ..output.key_material import json_key_material_enabled
        return (self.pcap_obj is not None and self._full_capture_hooks_enabled()
                and json_key_material_enabled(self._config.output)
                and bool(getattr(self._config.hooking, 'attribute_sdk', False)))

    def _attach_request_context_sidecar(self):
        self._request_context_sidecar = None
        if not self._request_context_sidecar_wanted():
            return
        from ..output.request_context_sidecar import (
            RequestContextSidecar,
            request_contexts_sidecar_path,
        )
        sidecar = RequestContextSidecar(
            request_contexts_sidecar_path(self.pcap_obj.pcap_file_name), self.logger)
        sidecar.attach(self._event_bus)
        self._request_context_sidecar = sidecar

    def _close_request_context_sidecar(self):
        """Close the sidecar and hand a written one to the manifest. Never raises."""
        # getattr: teardown also runs on __new__-built loggers (tests, early failures).
        sidecar = getattr(self, "_request_context_sidecar", None)
        if sidecar is None:
            return
        try:
            sidecar.close()
            if sidecar.rows_written:
                self.pcap_obj.set_request_contexts_path(sidecar.path)
        except Exception:  # noqa: BLE001 - never break teardown
            self.logger.debug("request-context sidecar close failed", exc_info=True)

    def _hand_endpoint_pinner_to_pcap(self):
        """Give the PCAP object the router's option-5 pinner for the -p rewrite at stop."""
        router = getattr(self, "_message_router", None)
        pinner = getattr(router, "endpoint_pinner", None)
        if self.pcap_obj is None or pinner is None \
                or not hasattr(self.pcap_obj, "set_endpoint_pinner"):
            return
        self.pcap_obj.set_endpoint_pinner(pinner)

    def _finalize_plaintext_pcap(self, full_capture):
        """Rewrite the closed -p pcap's safe synthetic streams.

        Runs only after the output handlers closed the file; never for -f (a
        different file and finalize path) or the LSASS helper session.
        """
        output = getattr(getattr(self, "_config", None), "output", None)
        if (self.pcap_obj is None or full_capture or not self._handlers_active
                or getattr(output, "auxiliary_session", False)):
            return
        finalize = getattr(self.pcap_obj, "finalize_plaintext_capture", None)
        if callable(finalize):
            finalize()

    def _seed_known_server_ports(self):
        """Seed explicit ``--tls-port``/``--quic-port`` values into the manifest.

        Needed for a pure ``--full_capture`` that never observes a non-standard or
        loopback server (e.g. 127.0.0.1:8443). No-op when the ports are unset.
        """
        if self.pcap_obj is None or not hasattr(self.pcap_obj, "set_known_tls_ports"):
            return
        output_cfg = getattr(self._config, "output", None)
        tls_ports = getattr(output_cfg, "tls_ports", None)
        quic_ports = getattr(output_cfg, "quic_ports", None)
        if tls_ports:
            self.pcap_obj.set_known_tls_ports(tls_ports)
        if quic_ports:
            self.pcap_obj.set_known_quic_ports(quic_ports)

    def _setup_output_handlers(self):
        """Create and register output handlers based on config."""
        from ..output.factory import OutputHandlerFactory
        self._output_handlers, live_info = OutputHandlerFactory.create_handlers(
            self._config, self.pcap_obj, self._protocol_handler,
            self.session_data, self.logger,
            protocol_registry=self._protocol_registry,
        )
        if live_info:
            self.tmpdir = live_info.get('tmpdir')
            self.filename = live_info.get('filename')

        from ..output import KeylogOutputHandler
        from ..output.live_autodecrypt_handler import LiveAutoDecryptHandler
        from ..output.live_pcapng_handler import LivePcapngHandler
        from ..output.live_wireshark_handler import LiveWiresharkHandler
        for handler in self._output_handlers:
            handler.setup(self._event_bus)
            if isinstance(handler, KeylogOutputHandler):
                # The handler opens its file lazily on the first key, so this snapshot
                # is normally None; use _live_keylog_file() / _live_keylog_path().
                self.keylog_file = handler._file
                self._remember_tls_keylog_handler(handler)
                # The manifest's 'keylog' branch (PCAP._write_capture_manifest) reads
                # PCAP.keylog_path, and capture_protocol selects the protocol-specific
                # field (e.g. "mtproto_keylog") so offline decryption routes correctly.
                # The memory-scan handler is recorded separately below so each protocol
                # points at the scanner's real file, not the TLS-only memscan keylog.
                if self.pcap_obj is not None:
                    if not self._is_memory_scan_handler(handler):
                        self.pcap_obj.keylog_path = handler._path
                    self.pcap_obj.capture_protocol = self.protocol
            if isinstance(handler, (LivePcapngHandler, LiveAutoDecryptHandler, LiveWiresharkHandler)):
                self._live_handler = handler
        self._record_memory_scan_keylogs()
        self._hand_endpoint_pinner_to_pcap()
        self._attach_request_context_sidecar()

        from ..plugins.loader import PluginLoader
        self._plugin_loader = PluginLoader()
        self._plugin_shim = _PluginSessionShim(self._event_bus)
        self._plugin_loader.load_all(self._plugin_shim)

        # Legacy --custom_script runs as a ScriptPlugin.
        if self.custom_hook_script is not None:
            from ..plugins.legacy_custom_script import LegacyCustomScriptPlugin
            legacy_plugin = LegacyCustomScriptPlugin(self.custom_hook_script)
            self._plugin_loader.register_builtin(legacy_plugin, self._plugin_shim)

        # Memory scanning (-ms) is not a plugin: the core drives the engine directly
        # from instrument()/detach/cleanup. It injects a separate heap-scanner agent
        # (fritap_memscan.js) with its own poll loop and, on Windows, its own lsass
        # session. Alone, instrument() skips the main TLS agent; with -k/-p/-c it
        # runs alongside them.
        if getattr(self._config.hooking, "memory_scan", False):
            from ..memory_scanning import build_memory_scan_engine
            self._memory_scan_engine = build_memory_scan_engine(self._config)
            # If the scan agent dies on its own (target killed / ANR'd) the poll loop
            # calls back; a memory-scan-only run is then over, so end it rather than
            # leave the session stuck in "capturing".
            self._memory_scan_engine.set_scan_ended_callback(
                self._on_memory_scan_ended)
        else:
            self._memory_scan_engine = None

    def connect_live(self) -> bool:
        """Connect the live Wireshark FIFO handler.

        Emits LiveReadyEvent (so the TUI can launch Wireshark), then blocks until
        Wireshark connects to the FIFO or times out. Call it after wiring event
        subscribers so they see the event. Idempotent.

        Returns True if connected (or not in live mode), False on timeout.
        """
        if self._live_handler is None:
            return True

        live_handler = self._live_handler
        self._live_handler = None  # consumed: makes repeat calls no-ops

        from ..events import LiveReadyEvent
        self._event_bus.emit(LiveReadyEvent(fifo_path=self.filename))

        time.sleep(1.0)  # Give event loop time to process Wireshark launch

        connected = live_handler.connect(timeout=30)
        if connected:
            from ..events import WiresharkConnectedEvent
            self._event_bus.emit(WiresharkConnectedEvent(fifo_path=self.filename))
            return True

        from ..events import LiveConnectionFailedEvent
        self._event_bus.emit(LiveConnectionFailedEvent(
            fifo_path=self.filename,
            reason="Wireshark did not connect within 30 seconds",
        ))
        self._output_handlers.remove(live_handler)
        live_handler.close()
        return False

    # Bounds the scan queue so a slow analyzer cannot grow memory; when full,
    # completed flows are dropped (and counted) instead of blocking Frida's callback.
    _SCAN_QUEUE_MAXSIZE = 2048

    def _signal_live_selected(self) -> bool:
        """True when 'signal' is a configured capture protocol (live decode without --scan)."""
        if getattr(self._config, "protocol", None) == "signal":
            return True
        protocols = getattr(self._config, "protocols", None) or []
        return "signal" in protocols

    def apply_resolved_process_name(self, name: str) -> None:
        """Push the process name resolved after a numeric-PID attach to every flow collector.

        Reaches this logger's own collector and any output handler's (``--tap``);
        flows already stamped with the PID-only name are re-classified.
        """
        self.resolved_process_name = name
        if self._flow_collector is not None:
            self._flow_collector.set_capture_target(self._config.target, process_name=name)
        for handler in getattr(self, "_output_handlers", []):
            set_process_name = getattr(handler, "set_process_name", None)
            if callable(set_process_name):
                set_process_name(name)

    def _setup_live_scan(self):
        """Wire up live passive analysis of observed traffic, if requested.

        Call before instrumentation starts so no completed flows are missed.
        Completed flows go onto a bounded queue that a daemon worker drains, so
        analyzers never run on the Frida callback thread. No-op without --scan or
        live Signal decoding.
        """
        scan_spec = getattr(self._config.output, "scan", None)
        signal_live = self._signal_live_selected()
        if not scan_spec and not signal_live:
            return

        try:
            from ..analysis import AnalyzerPlugin
            from ..analysis.registry import resolve_analyzers
            from ..events import FlowEvent
            from ..flow.collector import FlowCollector
            from ..flow.models import FlowEventType

            if scan_spec:
                # reveal_pii keeps raw values in the privacy analyzer; redaction is
                # still enforced by the reporter in _finalize_live_scan.
                reveal_pii = getattr(self._config.output, "scan_show_pii", False)
                analyzer_path = getattr(self._config.output, "scan_analyzer_path", None)
                self._scan_plugins = [
                    AnalyzerPlugin(a)
                    for a in resolve_analyzers(
                        scan_spec, analyzer_path=analyzer_path, reveal_pii=reveal_pii
                    )
                ]

            if not self._scan_plugins and not signal_live:
                return

            # Mirrors the TUI wiring (capture_controller.py). Live Signal decoding
            # only sees keys arriving before/at the DATA; late keys are recovered by
            # the session-end offline reprocess (_maybe_reprocess_signal).
            if self._flow_collector is None:
                self._flow_collector = FlowCollector(
                    event_bus=self._event_bus, signal_messages=signal_live
                )
            self._flow_collector.set_event_bus(self._event_bus)
            self._flow_collector.subscribe_to(self._event_bus)
            self._flow_collector.set_capture_target(self._config.target)

            # A signal-only collector needs no queue or worker.
            if self._scan_plugins:
                self._scan_queue = queue.Queue(maxsize=self._SCAN_QUEUE_MAXSIZE)
                self._scan_stop.clear()

                def _enqueue_completed_flow(event):
                    if event.flow_event_type != FlowEventType.COMPLETED or event.flow is None:
                        return
                    try:
                        self._scan_queue.put_nowait(event.flow)
                    except queue.Full:
                        self._scan_drop_count += 1

                self._event_bus.subscribe(FlowEvent, _enqueue_completed_flow)

                self._scan_thread = threading.Thread(
                    target=self._scan_worker, name="fritap-scan", daemon=True,
                )
                self._scan_thread.start()
                self.logger.info(
                    "Passive analysis enabled (%s) — analyzing observed traffic",
                    ", ".join(p.name for p in self._scan_plugins),
                )
        except Exception as e:
            # A scan setup failure must never break normal capture.
            self.logger.warning("Could not enable passive analysis: %s", e)
            self._scan_plugins = []
            self._scan_queue = None
            self._scan_thread = None

    def _scan_worker(self):
        """Daemon worker: drain completed flows and run them through analyzers."""
        while not (self._scan_stop.is_set() and self._scan_queue.empty()):
            try:
                flow = self._scan_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            for plugin in self._scan_plugins:
                try:
                    plugin.analyze(flow)
                except Exception:
                    self.logger.debug("Analyzer raised on flow", exc_info=True)
            self._scan_queue.task_done()

    def _finalize_live_scan(self):
        """Flush, drain, and render passive-analysis findings. Never raises."""
        if not self._scan_plugins:
            return
        try:
            from ..analysis.filtering import FindingFilter, apply, split_csv
            from ..commands.analyze import _REPORTER_REGISTRY

            if self._flow_collector is not None:
                try:
                    self._flow_collector.flush()
                except Exception:
                    self.logger.debug("FlowCollector flush failed", exc_info=True)

            # Drain the worker first: it extends plugin.findings from its own thread.
            self._scan_stop.set()
            if self._scan_thread is not None:
                self._scan_thread.join(timeout=10)
                if self._scan_thread.is_alive():
                    self.logger.warning(
                        "Passive-analysis worker did not finish draining within "
                        "10s; reported findings may be incomplete",
                    )

            # list() is a GIL-atomic copy, so a still-alive worker cannot make us
            # iterate a list mid-extend; worst case a few findings are omitted,
            # which the warning above flags.
            findings = []
            for plugin in self._scan_plugins:
                findings.extend(list(plugin.findings))

            min_sev = getattr(self._config.output, "scan_min_severity", "info")
            min_conf = getattr(self._config.output, "scan_min_confidence", 0.0)
            sources = split_csv(getattr(self._config.output, "scan_source", None))
            categories = split_csv(getattr(self._config.output, "scan_category", None))
            flt = FindingFilter(
                min_severity=min_sev,
                sources=sources,
                categories=categories,
                min_confidence=min_conf or None,
            )
            findings = apply(findings, flt)

            show_pii = getattr(self._config.output, "scan_show_pii", False)
            report_fmt = getattr(self._config.output, "scan_report", "table")
            reporter = _REPORTER_REGISTRY.get(report_fmt, _REPORTER_REGISTRY["table"])(
                redact_pii=not show_pii
            )
            meta = {"analyzers": [p.name for p in self._scan_plugins]}
            rendered = reporter.report(findings, meta)

            report_out = getattr(self._config.output, "scan_report_out", None)
            if report_out:
                with open(report_out, "w", encoding="utf-8") as fh:
                    fh.write(rendered)
                self.logger.info("Passive-analysis report written to %s", report_out)
            else:
                self.special_logger.info("\n%s", rendered)

            if self._scan_drop_count:
                self.logger.warning(
                    "Passive analysis dropped %d completed flows (queue full)",
                    self._scan_drop_count,
                )
        except Exception as e:
            self.logger.warning("Passive-analysis finalization failed: %s", e)

    def set_keylog_file(self, keylog_name):
        self.keylog_file = open(keylog_name, "w")

    def _plaintext_hooks_needed(self) -> bool:
        """Whether the agent installs plaintext read/write hooks.

        Defers to OutputHandlerFactory.plaintext_hooks_needed unless the output opts
        out (the LSASS helper of a -f run, see friTap._build_lsass_config).
        """
        from ..output.factory import OutputHandlerFactory
        output = self._config.output
        if output.plaintext_hooks_disabled:
            return False
        return OutputHandlerFactory.plaintext_hooks_needed(output)

    def _close_output_handlers_safely(self):
        """close_output_handlers() for the exit path: idempotent, never raises."""
        try:
            self.close_output_handlers()
        except Exception as exc:  # noqa: BLE001 - must not block the exit
            self.logger.error(f"Error closing output handlers: {exc}")
        self._finish_json_stream()

    def _finish_json_stream(self):
        """'-j -' safety net: complete the stream envelope if the JSONL handler never closed it.

        Covers runs that failed before handlers were set up. Never raises; a no-op
        without '-j -', after a normal close, and for the LSASS helper (which shares
        but does not own the stream).
        """
        output = getattr(getattr(self, "_config", None), "output", None)
        if getattr(output, "auxiliary_session", False):
            return
        try:
            from ..output.stdout_stream import finish_unclosed_stream
            finish_unclosed_stream(self._exit_status)
        except Exception:  # noqa: BLE001 - must not block the exit
            pass

    def close_output_handlers(self):
        """Close every output handler (keylog, json, live, ...) exactly once.

        Idempotent, so both normal teardown and ``LsassHookManager.stop_lsass_hook``
        (which must release the LSASS keylog handle before the SChannel relabel
        renames the file) can call it.
        """
        if not self._handlers_active or getattr(self, "_output_handlers_closed", False):
            return
        self._output_handlers_closed = True
        self._emit_detach_report()
        for handler in self._output_handlers:
            try:
                handler.close()
            except Exception as e:
                self.logger.error(f"Error closing handler: {e}")

    def _auto_relabel_schannel_keylog(self, pcap_name):
        """Fix a Windows SChannel/lsass keylog in place by trial decryption.

        The ncrypt hooks correlate a TLS 1.3 secret's client_random and phase per
        thread, but lsass runs one handshake's hooks across a thread pool, so the raw
        keylog has swapped labels and ``???`` client_randoms. Once the full capture is
        written, every secret is trial-decrypted against it
        (:func:`~friTap.offline.keylog_coverage.relabel_keylog`) and the keylog is
        replaced by the corrected one; the raw output is kept as ``<stem>.raw.keylog``.

        Best-effort: any problem leaves the original intact. Windows full captures
        only; ``--no-auto-relabel`` opts out. Without tshark a hint to run
        ``--repair-keylog`` is logged and nothing changes.
        """
        try:
            if not getattr(self._config.output, "auto_relabel", True):
                return
            from ..fritap_utility import are_we_running_on_windows
            if not are_we_running_on_windows():
                return
            if not pcap_name or not os.path.isfile(pcap_name):
                return
            keylog_paths = [
                path for path in _schannel_keylog_candidates(
                    self._config, getattr(self, "_protocol_registry", None))
                if os.path.isfile(path) and os.path.getsize(path) > 0
            ]
            if not keylog_paths:
                return
            # The separate lsass SSL_Logger shares this keylog path. Tear it down
            # first so its handle is flushed and closed: Windows refuses to rename an
            # open file, and later lsass writes would land in the .raw backup.
            _core()._release_lsass_keylog_writer(self.logger)
            try:
                live_keylog_file = self._live_keylog_file()
                if live_keylog_file is not None and not live_keylog_file.closed:
                    live_keylog_file.flush()
            except Exception:  # noqa: BLE001
                pass
            # Confirm the shared writer really dropped to zero references.
            keylog_paths = _drop_still_open_keylogs(self.logger, pcap_name, keylog_paths)
            if not keylog_paths:
                return
            from ..offline.tshark import find_tshark
            try:
                tshark_bin = find_tshark(getattr(self._config.output, "tshark_path", None))
            except RuntimeError:  # TsharkNotFoundError subclasses RuntimeError
                self.logger.info(
                    "SChannel keylog may have swapped TLS 1.3 labels / '???' client_randoms, "
                    "but tshark was not found to auto-fix it. Install tshark, or run: "
                    "fritap --from-pcap %s --keylog %s --repair-keylog",
                    pcap_name, keylog_paths[0])
                return
            for keylog_path in keylog_paths:
                _relabel_one_schannel_keylog(self.logger, tshark_bin, pcap_name, keylog_path)
        except Exception:  # noqa: BLE001 - never break teardown
            self.logger.debug("SChannel keylog auto-relabel failed", exc_info=True)

    def _full_capture_keylog_path(self):
        """The keylog this full capture really wrote, else ``None`` (never raises)."""
        try:
            written = getattr(self.pcap_obj, "written_keylog_path", None)
            if callable(written):
                return written()
        except Exception:  # noqa: BLE001
            pass
        return None

    def _auto_build_tap_from_full_capture(self, pcap_name):
        """With ``-f --tap X.tap``, convert the finished full capture into X.tap.

        Uses the in-process offline pipeline (:func:`friTap.offline.auto_tap.auto_build_tap`).
        No-op without --tap, for the LSASS helper, or when no pcap was written. Never raises.
        """
        try:
            from ..offline.auto_tap import auto_build_tap, should_auto_build_tap
            output = self._config.output
            tap_path = getattr(output, "tap_output", None)
            if not should_auto_build_tap(
                    full_capture=True, tap_path=tap_path, pcap_path=pcap_name,
                    auxiliary_session=getattr(output, "auxiliary_session", False)):
                return
            auto_build_tap(pcap_name, tap_path,
                           keylog_path=self._full_capture_keylog_path(),
                           capture_target=str(getattr(self._config, "target", "") or ""),
                           logger=self.logger)
        except Exception:  # noqa: BLE001 - never break teardown
            self.logger.debug("auto .tap build from full capture failed", exc_info=True)

    def _log_session_end(self, reason):
        """Emit the session-ended event and record end time and reason in the JSON data."""
        self._event_bus.emit(SessionEvent(
            event_type="ended",
            session_id=str(id(self.process)) if self.process else "",
        ))
        if self.json_output:
            with self._session_data_lock:
                self.session_data["session_info"]["end_time"] = datetime.now(timezone.utc).isoformat()
                self.session_data["session_info"]["end_reason"] = reason
                self.session_data["statistics"]["total_sessions"] = len(self.session_data["ssl_sessions"])

    def _finalize_json_output(self):
        """Write final JSON output to file. Idempotent.

        When the legacy path streamed its document (``finalize_legacy_json``), the
        ``json_file`` handle from init_compat for the same path is only closed, so it
        cannot overwrite the streamed document.
        """
        from .message_handler import finalize_legacy_json
        if getattr(self, "_legacy_json_stream", None) is not None:
            finalize_legacy_json(self)
            self._close_legacy_json_file()
            self.logger.info(f"JSON output saved to {self.json_output}")
            return
        if self.json_file and not self.json_file.closed:
            try:
                with self._session_data_lock:
                    self.session_data["session_info"]["end_time"] = datetime.now(timezone.utc).isoformat()
                    json.dump(self.session_data, self.json_file, indent=2, ensure_ascii=False)
                self.json_file.close()
                self.logger.info(f"JSON output saved to {self.json_output}")
            except Exception as e:
                self.logger.error(f"Error writing JSON output: {e}")

    def _close_legacy_json_file(self):
        json_file = getattr(self, "json_file", None)
        if json_file is not None and not json_file.closed:
            try:
                json_file.close()
            except Exception:  # noqa: BLE001 - never break teardown
                pass

    def add_ssl_session(self, session_info):
        """Append one SSL session entry to the JSON output."""
        if self.json_output:
            session_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": session_info.get("session_id"),
                "cipher_suite": session_info.get("cipher_suite"),
                "protocol_version": session_info.get("protocol_version"),
                "server_name": session_info.get("server_name"),
                "certificate_info": session_info.get("certificate_info")
            }
            with self._session_data_lock:
                self.session_data["ssl_sessions"].append(session_entry)

    def write_socket_trace(self, socket_trace_name):
        with open(socket_trace_name, 'a') as trace_file:
            trace_file.write(PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display") + '\n')
