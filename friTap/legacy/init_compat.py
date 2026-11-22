#!/usr/bin/env python3

"""Output-file setup for the non-handler path (``_handlers_active`` is False)."""

def init_output_files_legacy(logger_instance):
    """Open the keylog/JSON files and, for ``--live``, the Wireshark named pipe."""
    from ..pcap import PCAP
    from ..ssl_logger import SSL_READ, SSL_WRITE

    if logger_instance.keylog:
        logger_instance.keylog_file = open(logger_instance.keylog, "w")

    if logger_instance.json_output:
        logger_instance.json_file = open(logger_instance.json_output, "w")
        logger_instance.logger.info(f"JSON output will be saved to {logger_instance.json_output}")

    if logger_instance.live:
        if logger_instance.pcap_name:
            logger_instance.logger.warning("YOU ARE TRYING TO WRITE A PCAP AND HAVING A LIVE VIEW\nTHIS IS NOT SUPPORTED!\nWHEN YOU DO A LIVE VIEW YOU CAN SAVE YOUR CAPTURE WITH WIRESHARK.")
        fifo_file = logger_instance.temp_fifo()
        logger_instance.logger.info('friTap live view on Wireshark')
        logger_instance.logger.info(f'Created named pipe for Wireshark live view to {fifo_file}')
        logger_instance.logger.info(f'Now open this named pipe with Wireshark in another terminal: sudo wireshark -k -i {fifo_file}')
        logger_instance.logger.info('friTap will continue after the named pipe is ready....')
        logger_instance.pcap_obj = PCAP(fifo_file, SSL_READ, SSL_WRITE, logger_instance.full_capture, logger_instance.mobile, logger_instance.debug_output)
