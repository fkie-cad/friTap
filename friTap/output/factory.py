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
    elif protocol in ("tls", "ssh", "ipsec"):
        h = protocol_registry.get(protocol)
        handlers = [h] if h is not None else []
    else:
        handlers = []
    formatters = []
    for h in handlers:
        fmt = h.keylog_formatter()
        if fmt is not None:
            formatters.append(fmt)
    return formatters


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
                for fmt in active:
                    handlers.append(KeylogOutputHandler(
                        split_paths[fmt.protocol], formatter=fmt,
                    ))

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
