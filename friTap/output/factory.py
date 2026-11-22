#!/usr/bin/env python3

"""Builds the output handlers selected by a FriTapConfig (decoupled from SSL_Logger)."""



def _active_keylog_formatters(protocol, protocol_registry):
    """The :class:`KeylogFormatter` instances to wire for the active-protocol selection.

    *protocol* is a name or a list/set of names. The result is the union over the
    selection (each protocol plus the companions it implies), de-duplicated by
    protocol, order-preserving. ``all``/``auto`` selects every registered handler's
    formatter in registration order; unknown names yield none.
    """
    if protocol_registry is None:
        return []
    if isinstance(protocol, (list, tuple, set)):
        selected = list(protocol)
    else:
        selected = [protocol]
    if any(p in ("all", "auto") for p in selected):
        handlers = protocol_registry.get_all()
    else:
        # A TLS-wrapped protocol implies TLS, so its keylog splits into
        # <stem>.<proto><ext> + <stem>.tls<ext>. Registry-driven: new protocols need no edit.
        from ..protocols.registry import implied_protocols
        names = []
        for p in selected:
            for n in [p] + implied_protocols(p):
                if n not in names:
                    names.append(n)
        handlers = [protocol_registry.get(n) for n in names]
        handlers = [h for h in handlers if h is not None]
    formatters = []
    seen = set()
    for h in handlers:
        fmt = h.keylog_formatter()
        if fmt is None:
            continue
        # Two selections implying "tls" must not wire its formatter (and split file) twice.
        key = getattr(fmt, "protocol", None)
        key = key if key is not None else id(fmt)
        if key in seen:
            continue
        seen.add(key)
        formatters.append(fmt)
    return formatters


def memory_scan_keylog_path(config):
    """Where memory-scan (``-ms``) findings are written; ``None`` when scanning is off.

    The scanner gets its own file: two truncating handlers on one path would
    corrupt each other. With ``-k`` it is ``<stem>.memscan<ext>``; alone it is
    ``<sanitized-target>_memscan.keylog`` in the cwd. In memory-scan-only mode
    (:func:`friTap.config.memory_scan_only`) no hook handler writes ``-k``, so
    the scanner owns the ``-k`` path.
    """
    import os
    import re

    from ..config import memory_scan_only

    if not getattr(config.hooking, "memory_scan", False):
        return None
    keylog = config.output.keylog
    if keylog and memory_scan_only(config):
        return keylog
    if keylog:
        from .keylog_paths import split_keylog_path
        return split_keylog_path(keylog, "memscan")
    target = config.target
    if isinstance(target, (list, tuple)):
        target = "_".join(str(t) for t in target)
    stem = os.path.basename(str(target or "target").strip()) or "target"
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("_") or "target"
    return f"{stem}_memscan.keylog"


def active_keylog_paths(base_keylog, protocol, protocol_registry, protocol_handler=None):
    """``{protocol_name: keylog_path}`` for every keylog file :meth:`OutputHandlerFactory.create_handlers` writes.

    One active formatter writes the base path; several split it into
    ``<stem>.<proto><ext>``. Empty when no protocol emits keys. Shares
    ``_active_keylog_formatters`` and ``split_keylog_path`` with ``create_handlers``
    so naming and the active set cannot drift.
    """
    from .keylog_paths import split_keylog_path
    if not base_keylog:
        return {}
    active = _active_keylog_formatters(protocol, protocol_registry)
    if not active and protocol_handler is not None \
            and hasattr(protocol_handler, "keylog_formatter"):
        fmt = protocol_handler.keylog_formatter()
        if fmt is not None:
            active = [fmt]
    # UAT (IPsec) formatters write fixed-name files in the keylog directory, so no split path exists.
    active = [f for f in active if not getattr(f, "writes_decryption_tables", False)]
    if not active:
        return {}
    if len(active) == 1:
        return {active[0].protocol: base_keylog}
    return {f.protocol: split_keylog_path(base_keylog, f.protocol) for f in active}


def _pcap_handler_class(output_config):
    """The -p handler class (PCAPNG or PCAP), None without -p; uses the resolved ``pcap_container`` like the PCAP object and finalizer."""
    from ..pcap_utility import PCAP_FORMAT_PCAPNG
    from .pcap_handler import PcapOutputHandler
    from .pcapng_handler import PcapngOutputHandler
    pcap_name = output_config.pcap
    if not pcap_name:
        return None
    if output_config.pcap_container == PCAP_FORMAT_PCAPNG:
        return PcapngOutputHandler
    return PcapOutputHandler


def _json_handler_class(output_config):
    """The -j handler class: stdout JSONL stream, *.jsonl file or JSON document."""
    if output_config.json_stream:
        from .jsonl_stdout_handler import JsonlStdoutHandler
        return JsonlStdoutHandler
    if not output_config.json_output:
        return None
    if output_config.json_output.endswith(".jsonl"):
        from .jsonl_handler import JsonlOutputHandler
        return JsonlOutputHandler
    from .json_handler import JsonOutputHandler
    return JsonOutputHandler


def _tap_handler_class(output_config):
    """The --tap handler class, or None without --tap."""
    if not output_config.tap_output:
        return None
    from .tap_handler import TapOutputHandler
    return TapOutputHandler


def _live_view_supported() -> bool:
    """The -l named pipe needs mkfifo, so there is no live view on Windows."""
    from ..fritap_utility import are_we_running_on_windows
    return not are_we_running_on_windows()


def _live_handler_class(output_config):
    """The -l handler class for the configured live mode, or None when no live handler is created."""
    if not output_config.live or not _live_view_supported():
        return None
    if output_config.live_mode == "live_pcapng":
        from .live_autodecrypt_handler import LiveAutoDecryptHandler
        return LiveAutoDecryptHandler
    if output_config.live_mode == "wireshark":
        from .live_wireshark_handler import LiveWiresharkHandler
        return LiveWiresharkHandler
    from .live_pcapng_handler import LivePcapngHandler
    return LivePcapngHandler


def _log_tap_deferred_to_full_capture(tap_path, logger):
    """Log that -f --tap builds the .tap after the capture ends."""
    logger.info("Full capture (-f): %s will be built from the full-capture pcap "
                "and keylog when the capture ends.", tap_path)



def _add_pcap_handlers(config, pcap_obj, protocol_handler, handlers):
    """Append the -p handler (non-live, non-full-capture) and the full-capture key collector."""
    from . import PcapngOutputHandler, PcapOutputHandler
    # One pcapng decision shared by the -p handler and the full-capture DSB injection.
    wants_pcapng = _pcap_handler_class(config.output) is PcapngOutputHandler
    pcap_name = config.output.pcap
    if pcap_name and not config.output.live and not config.output.full_capture:
        if wants_pcapng:
            handlers.append(PcapngOutputHandler(pcap_name, protocol_handler=protocol_handler))
        else:
            handlers.append(PcapOutputHandler(pcap_obj))

    # Key collector enables DSB injection at finalization for full-capture pcapng.
    if config.output.full_capture and wants_pcapng:
        from .key_collector_handler import KeyCollectorHandler
        handlers.append(KeyCollectorHandler(protocol_handler=protocol_handler))


def _resolve_keylog_formatters(config, protocol_handler, protocol_registry):
    """Return (line_formatters, uat_formatters) for the -k keylog."""
    active = _active_keylog_formatters(config.protocols, protocol_registry)
    if not active and protocol_handler is not None \
            and hasattr(protocol_handler, "keylog_formatter"):
        # Fallback for callers without a registry.
        fmt = protocol_handler.keylog_formatter()
        if fmt is not None:
            active = [fmt]
    # IPsec (and any future table-based protocol) writes Wireshark UAT
    # decryption-table files into the keylog's directory rather than NSS keylog
    # lines, so it is kept OUT of the line-based keylog split.
    uat_formatters = [f for f in active
                      if getattr(f, "writes_decryption_tables", False)]
    active = [f for f in active
              if not getattr(f, "writes_decryption_tables", False)]
    # The generic memory-scan engine (--scan-keys-region) emits candidates under
    # the protocol-agnostic "scan_candidate" classifier regardless of --protocol,
    # so wire its formatter whenever a scan region is configured.
    if getattr(config.hooking, "scan_keys_region", None):
        from .scan_candidate_formatter import ScanCandidateKeylogFormatter
        if not any(getattr(f, "protocol", None) == "scan_candidate" for f in active):
            active = list(active) + [ScanCandidateKeylogFormatter()]
    return active, uat_formatters


def _add_keylog_handlers(config, protocol_handler, protocol_registry, logger,
                         handlers, live_info):
    """Wire the -k keylog writers; returns the per-protocol split paths or None."""
    from . import KeylogOutputHandler
    from ..config import memory_scan_only
    from .keylog_paths import split_keylog_path

    keylog = config.output.keylog
    # Memory-scan-only: the scanner writes -k itself; a second truncating handler would clobber it.
    if not keylog or memory_scan_only(config):
        return None

    active, uat_formatters = _resolve_keylog_formatters(
        config, protocol_handler, protocol_registry)
    split_paths = None
    if not active and not uat_formatters:
        logger.warning(
            "--keylog set but no active protocol emits key material; "
            "-k has no effect with --protocol %s", config.protocol,
        )
    elif len(active) == 1 and not uat_formatters:
        handlers.append(KeylogOutputHandler(keylog, formatter=active[0]))
    elif active:
        split_paths = {f.protocol: split_keylog_path(keylog, f.protocol)
                       for f in active}
        logger.info(
            "keylog split: %s",
            ", ".join(f"{p} → {path}" for p, path in split_paths.items()),
        )
        # The capture manifest records every protocol's keylog.
        live_info["keylogs"] = split_paths
        for fmt in active:
            handlers.append(KeylogOutputHandler(
                split_paths[fmt.protocol], formatter=fmt,
            ))
    # The Wireshark UAT files live in the -k keylog's directory.
    for fmt in uat_formatters:
        from .ipsec_decryption_tables import IPsecDecryptionTableHandler
        handler = IPsecDecryptionTableHandler(keylog, formatter=fmt)
        handlers.append(handler)
        logger.info(
            "ipsec decryption tables → %s/{ikev2_decryption_table,esp_sa}",
            handler._dir,
        )
    return split_paths


def _record_split_keylogs(config, pcap_obj, split_paths):
    """Hand the split keylog paths to the PCAP object for its capture manifest."""
    if split_paths and pcap_obj is not None \
            and hasattr(pcap_obj, "set_active_keylogs"):
        pcap_obj.set_active_keylogs(split_paths)
        # Fallback when a split is never written (Windows TLS secrets land in the base keylog);
        # config.output.keylog, not the memory-scan-only nulled value.
        if hasattr(pcap_obj, "set_base_keylog"):
            pcap_obj.set_base_keylog(config.output.keylog)


def _add_memory_scan_handler(config, logger, handlers, live_info):
    """Wire the -ms keylog: its own file, independent of -k."""
    from . import KeylogOutputHandler
    ms_path = memory_scan_keylog_path(config)
    if ms_path:
        from ..memory_scanning.formatter import MemoryScanKeylogFormatter
        handlers.append(KeylogOutputHandler(ms_path, formatter=MemoryScanKeylogFormatter()))
        live_info["memory_scan_keylog"] = ms_path
        logger.info("memory-scan keylog → %s", ms_path)


def _add_json_handler(config, session_data, handlers):
    """Wire the -j handler (JSON document, JSONL file or stdout stream)."""
    from . import JsonlOutputHandler, JsonOutputHandler
    json_cls = _json_handler_class(config.output)
    if json_cls is None:
        return
    from .key_material import json_key_material_enabled
    # Raw key material only when explicitly requested (-k or --json-keys), else redacted.
    include_keys = json_key_material_enabled(config.output)
    # Agent dev diagnostics reach the JSONL outputs only with -d / -do.
    include_dev_logs = bool(getattr(config, "debug_output", False))
    if json_cls is JsonOutputHandler:
        handlers.append(JsonOutputHandler(
            config.output.json_output,
            session_info=session_data.get("session_info", {}),
            auxiliary=getattr(config.output, "auxiliary_session", False),
            include_key_material=include_keys,
        ))
    elif json_cls is JsonlOutputHandler:
        handlers.append(JsonlOutputHandler(
            config.output.json_output, include_key_material=include_keys,
            include_agent_dev_logs=include_dev_logs))
    else:
        handlers.append(json_cls(include_key_material=include_keys,
                                 include_agent_dev_logs=include_dev_logs))


def _add_tap_handler(config, logger, handlers):
    """Wire --tap; under -f the .tap is built after the capture (offline/auto_tap.py) instead."""
    tap_cls = _tap_handler_class(config.output)
    if tap_cls is not None and config.output.full_capture:
        _log_tap_deferred_to_full_capture(config.output.tap_output, logger)
    elif tap_cls is not None:
        handlers.append(tap_cls(config.output.tap_output, target=config.target or ""))


def _build_live_handler(config):
    """``(live_handler, description)`` for the configured live mode."""
    from . import LivePcapngHandler
    live_mode = config.output.live_mode
    if live_mode == "live_pcapng":
        from .live_autodecrypt_handler import LiveAutoDecryptHandler
        is_mobile = bool(config.device.mobile)
        device_id = (
            config.device.mobile
            if isinstance(config.device.mobile, str)
            else None
        )
        live_handler = LiveAutoDecryptHandler(
            is_mobile=is_mobile, device_id=device_id,
            include_loopback=getattr(config.output, "include_loopback", False),
            filter_infrastructure=getattr(config.output, "filter_infrastructure", True),
        )
        return live_handler, 'friTap live auto-decrypt (raw capture + TLS keys)'
    if live_mode == "wireshark":
        from .live_wireshark_handler import LiveWiresharkHandler
        # PCAP is created lazily in connect() to avoid a FIFO deadlock.
        return LiveWiresharkHandler(), 'friTap live view on Wireshark (plaintext stream)'
    return LivePcapngHandler(), 'friTap live view on Wireshark (PCAPNG with auto-decrypt)'


def _add_live_handler(config, logger, handlers, live_info):
    """Wire the live Wireshark modes (named pipe); not supported on Windows."""
    if not config.output.live:
        return
    from ..fritap_utility import WINDOWS_LIVE_UNSUPPORTED
    if not _live_view_supported():
        logger.error(WINDOWS_LIVE_UNSUPPORTED)
        return
    if config.output.pcap:
        logger.warning(
            "YOU ARE TRYING TO WRITE A PCAP AND HAVING A LIVE VIEW\n"
            "THIS IS NOT SUPPORTED!\n"
            "WHEN YOU DO A LIVE VIEW YOU CAN SAVE YOUR CAPTURE WITH WIRESHARK."
        )
    live_handler, description = _build_live_handler(config)

    fifo_file = live_handler.create_fifo()
    live_info['tmpdir'] = live_handler.tmpdir
    live_info['filename'] = live_handler.fifo_path

    logger.info(description)
    logger.info('Created named pipe: %s', fifo_file)
    logger.info('Open with: wireshark -k -i %s', fifo_file)
    handlers.append(live_handler)


class OutputHandlerFactory:
    """Factory that creates output handler instances based on configuration."""

    @staticmethod
    def plaintext_hooks_needed(output_config) -> bool:
        """Whether any selected output (-p, -j, --tap, -l) consumes decrypted data events.

        Gates the agent's plaintext hooks; never in full-capture (-f) mode (tcpdump records raw packets).
        """
        if output_config.full_capture:
            return False
        selected = (_pcap_handler_class(output_config),
                    _json_handler_class(output_config),
                    _tap_handler_class(output_config),
                    _live_handler_class(output_config))
        return any(cls is not None and cls.consumes_plaintext for cls in selected)

    @staticmethod
    def create_handlers(config, pcap_obj, protocol_handler, session_data, logger,
                        protocol_registry=None) -> tuple:
        """Create output handlers for *config*.

        *protocol_registry* is needed for keylog wiring under ``--protocol all|auto``;
        ``None`` falls back to a single-protocol formatter.
        Returns ``(handlers, live_info)``; ``live_info`` has 'tmpdir' and 'filename' in live mode.
        """
        from . import ConsoleOutputHandler

        live_info = {}
        handlers = [ConsoleOutputHandler(verbose=config.output.verbose)]

        _add_pcap_handlers(config, pcap_obj, protocol_handler, handlers)
        split_paths = _add_keylog_handlers(
            config, protocol_handler, protocol_registry, logger, handlers, live_info)
        _record_split_keylogs(config, pcap_obj, split_paths)
        _add_memory_scan_handler(config, logger, handlers, live_info)
        _add_json_handler(config, session_data, handlers)
        _add_tap_handler(config, logger, handlers)
        _add_live_handler(config, logger, handlers, live_info)

        return handlers, live_info
