#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Output handler factory for friTap.

Creates and configures output handlers based on a FriTapConfig,
decoupling handler instantiation from SSL_Logger.
"""



class OutputHandlerFactory:
    """Factory that creates output handler instances based on configuration."""

    @staticmethod
    def create_handlers(config, pcap_obj, protocol_handler, session_data, logger) -> tuple:
        """Create output handlers based on config.

        Args:
            config: A FriTapConfig instance.
            pcap_obj: An existing PCAP object (or None).
            protocol_handler: The active protocol handler for key formatting.
            session_data: Session data dict (used by JSON handler).
            logger: A logging.Logger instance.

        Returns:
            (handlers_list, live_info_dict) where live_info_dict has keys
            'tmpdir' and 'filename' if live mode is active, else empty dict.
        """
        from . import (
            PcapOutputHandler, KeylogOutputHandler, JsonOutputHandler,
            JsonlOutputHandler, ConsoleOutputHandler, PcapngOutputHandler, LivePcapngHandler,
        )

        handlers = []
        live_info = {}

        # Console always active
        handlers.append(ConsoleOutputHandler(verbose=config.output.verbose))

        # PCAP/PCAPNG (non-live, non-full-capture only)
        pcap_name = config.output.pcap
        if pcap_name and not config.output.live and not config.output.full_capture:
            if pcap_name.endswith(".pcapng") or config.output.output_format == "pcapng":
                handlers.append(PcapngOutputHandler(pcap_name, protocol_handler=protocol_handler))
            else:
                handlers.append(PcapOutputHandler(pcap_obj))

        # Keylog
        keylog = config.output.keylog
        if keylog:
            handlers.append(KeylogOutputHandler(keylog, protocol_handler=protocol_handler))

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
