#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Output handler factory for friTap.

Creates and configures output handlers based on a FriTapConfig,
decoupling handler instantiation from SSL_Logger.
"""



def _active_keylog_formatters(protocol: str, protocol_registry):
    """Return the list of :class:`KeylogFormatter` instances that should be wired
    up for the current run, based on the active-protocol set.

    - ``tls`` / ``ssh`` / ``ipsec``: that single protocol, if its handler exposes
      a formatter.
    - ``all`` / ``auto``: every registered handler's formatter (preserves
      registration order, which is the deterministic insertion order of
      :class:`ProtocolRegistry`).
    - Anything else (defensive): empty list.
    """
    if protocol_registry is None:
        return []
    if protocol in ("all", "auto"):
        handlers = protocol_registry.get_all()
    else:
        # Any single named protocol: use its handler's formatter if registered,
        # plus any companion protocols it implies (a TLS-wrapped protocol also
        # emits TLS keys, so its keylog is split into <stem>.<proto><ext> +
        # <stem>.tls<ext>). Registry-driven (not a hardcoded tuple) so new
        # protocols need no edit here; an unknown name resolves to no formatter.
        from ..protocols.registry import implied_protocols
        names = [protocol] + implied_protocols(protocol)
        handlers = [protocol_registry.get(n) for n in names]
        handlers = [h for h in handlers if h is not None]
    formatters = []
    for h in handlers:
        fmt = h.keylog_formatter()
        if fmt is not None:
            formatters.append(fmt)
    return formatters


def active_keylog_paths(base_keylog, protocol, protocol_registry, protocol_handler=None):
    """Return ``{protocol_name: keylog_path}`` for every keylog file that
    :meth:`OutputHandlerFactory.create_handlers` writes for this run.

    Mirrors that method's keylog branch: a single active formatter writes the
    base path directly; multiple active formatters (e.g. ``--protocol signal``,
    which also emits TLS keys) split it into ``<stem>.<proto><ext>`` per
    protocol (``keys.log`` -> ``keys.tls.log`` + ``keys.signal.log``). Empty when
    no active protocol emits key material.

    Lets post-capture callers (the results modal, the decrypt-to-flow offer)
    locate the real keylog files instead of the possibly-never-written base path.
    Shares ``_active_keylog_formatters`` + ``split_keylog_path`` with
    ``create_handlers`` so the two cannot drift on naming or the active-set rule.
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
    if not active:
        return {}
    if len(active) == 1:
        return {active[0].protocol: base_keylog}
    return {f.protocol: split_keylog_path(base_keylog, f.protocol) for f in active}


class OutputHandlerFactory:
    """Factory that creates output handler instances based on configuration."""

    @staticmethod
    def create_handlers(config, pcap_obj, protocol_handler, session_data, logger,
                        protocol_registry=None) -> tuple:
        """Create output handlers based on config.

        Args:
            config: A FriTapConfig instance.
            pcap_obj: An existing PCAP object (or None).
            protocol_handler: The active protocol handler (used by PCAP/full-capture).
            session_data: Session data dict (used by JSON handler).
            logger: A logging.Logger instance.
            protocol_registry: The :class:`ProtocolRegistry` for this run.
                Required to wire keylog handlers correctly under ``--protocol
                all|auto``; falls back to a single-protocol formatter when
                ``None`` so callers without a registry still work.

        Returns:
            (handlers_list, live_info_dict) where live_info_dict has keys
            'tmpdir' and 'filename' if live mode is active, else empty dict.
        """
        from . import (
            PcapOutputHandler, KeylogOutputHandler, JsonOutputHandler,
            JsonlOutputHandler, ConsoleOutputHandler, PcapngOutputHandler, LivePcapngHandler,
        )
        from .keylog_paths import split_keylog_path
        from ..pcap_utility import is_pcapng_filename

        handlers = []
        live_info = {}
        # Per-protocol split keylog paths, populated below when multiple
        # protocol formatters are active. Used to record all split keylogs in
        # the capture manifest while preserving the single "keylog" field.
        split_paths = None

        # Console always active
        handlers.append(ConsoleOutputHandler(verbose=config.output.verbose))

        # Filename extension wins over output_format; the latter only acts
        # as a fallback for unrecognised extensions.
        pcap_name = config.output.pcap
        wants_pcapng = bool(pcap_name) and (
            is_pcapng_filename(pcap_name) or config.output.output_format == "pcapng"
        )

        # PCAP/PCAPNG (non-live, non-full-capture only)
        if pcap_name and not config.output.live and not config.output.full_capture:
            if pcap_name.lower().endswith(".pcap"):
                handlers.append(PcapOutputHandler(pcap_obj))
            elif wants_pcapng:
                handlers.append(PcapngOutputHandler(pcap_name, protocol_handler=protocol_handler))
            else:
                handlers.append(PcapOutputHandler(pcap_obj))

        # Key collector enables DSB injection at finalization for full-capture pcapng.
        if config.output.full_capture and wants_pcapng:
            from .key_collector_handler import KeyCollectorHandler
            handlers.append(KeyCollectorHandler(protocol_handler=protocol_handler))

        # Keylog — unified across protocols. The user provides one ``-k`` path;
        # if a single protocol is active that file is written directly, if
        # multiple protocols emit keys (``--protocol all|auto``) the path is
        # split per protocol so each Wireshark-loadable format gets its own
        # file (``mykeys.log`` → ``mykeys.tls.log`` + ``mykeys.ssh.log``).
        keylog = config.output.keylog
        if keylog:
            active = _active_keylog_formatters(config.protocol, protocol_registry)
            if not active and protocol_handler is not None \
                    and hasattr(protocol_handler, "keylog_formatter"):
                # Fallback for callers without a registry: use the active
                # protocol_handler's formatter if it has one.
                fmt = protocol_handler.keylog_formatter()
                if fmt is not None:
                    active = [fmt]
            # The generic memory-scan engine (--scan-keys-region) emits candidates
            # under the protocol-agnostic "scan_candidate" classifier regardless of
            # the selected --protocol, so wire its formatter whenever a scan region
            # is configured. It gets its own split keylog file when other protocols
            # are also active; on its own it writes straight to the -k path.
            if getattr(config.hooking, "scan_keys_region", None):
                from .scan_candidate_formatter import ScanCandidateKeylogFormatter
                if not any(getattr(f, "protocol", None) == "scan_candidate" for f in active):
                    active = list(active) + [ScanCandidateKeylogFormatter()]
            if not active:
                logger.warning(
                    "--keylog set but no active protocol emits key material; "
                    "-k has no effect with --protocol %s", config.protocol,
                )
            elif len(active) == 1:
                handlers.append(KeylogOutputHandler(keylog, formatter=active[0]))
            else:
                split_paths = {f.protocol: split_keylog_path(keylog, f.protocol)
                               for f in active}
                logger.info(
                    "keylog split: %s",
                    ", ".join(f"{p} → {path}" for p, path in split_paths.items()),
                )
                # Surface all split keylogs so callers (and the capture manifest)
                # can record every protocol's keylog, not just the single -k path.
                live_info["keylogs"] = split_paths
                for fmt in active:
                    handlers.append(KeylogOutputHandler(
                        split_paths[fmt.protocol], formatter=fmt,
                    ))

        # In the multi-format case, hand the split keylog paths to the PCAP
        # object so its capture manifest records every protocol's keylog under
        # "keylogs" (the single "keylog" field is set elsewhere and preserved).
        if split_paths and pcap_obj is not None \
                and hasattr(pcap_obj, "set_active_keylogs"):
            pcap_obj.set_active_keylogs(split_paths)

        # JSON / JSONL
        json_output = config.output.json_output
        if json_output:
            if json_output.endswith(".jsonl"):
                handlers.append(JsonlOutputHandler(json_output))
            else:
                handlers.append(JsonOutputHandler(
                    json_output, session_info=session_data.get("session_info", {})
                ))

        # Live Wireshark modes
        if config.output.live:
            from ..fritap_utility import are_we_running_on_windows, WINDOWS_LIVE_UNSUPPORTED
            if are_we_running_on_windows():
                logger.error(WINDOWS_LIVE_UNSUPPORTED)
            else:
                if pcap_name:
                    logger.warning(
                        "YOU ARE TRYING TO WRITE A PCAP AND HAVING A LIVE VIEW\n"
                        "THIS IS NOT SUPPORTED!\n"
                        "WHEN YOU DO A LIVE VIEW YOU CAN SAVE YOUR CAPTURE WITH WIRESHARK."
                    )
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
                        is_mobile=is_mobile, device_id=device_id
                    )
                    description = 'friTap live auto-decrypt (raw capture + TLS keys)'
                elif live_mode == "wireshark":
                    from .live_wireshark_handler import LiveWiresharkHandler
                    # PCAP created lazily in connect() to avoid FIFO deadlock
                    live_handler = LiveWiresharkHandler()
                    description = 'friTap live view on Wireshark (plaintext stream)'
                else:
                    live_handler = LivePcapngHandler()
                    description = 'friTap live view on Wireshark (PCAPNG with auto-decrypt)'

                fifo_file = live_handler.create_fifo()
                live_info['tmpdir'] = live_handler.tmpdir
                live_info['filename'] = live_handler.fifo_path

                logger.info(description)
                logger.info('Created named pipe: %s', fifo_file)
                logger.info('Open with: wireshark -k -i %s', fifo_file)
                handlers.append(live_handler)

        return handlers, live_info
