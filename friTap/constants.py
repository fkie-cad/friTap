#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared constants used by both legacy and modern paths."""

SSL_READ = frozenset({
    "SSL_read", "wolfSSL_read", "readApplicationData", "NSS_read", "Full_read",
    "gnutls_record_recv", "PR_Read", "mbedtls_ssl_read", "s2n_recv",
})

SSL_WRITE = frozenset({
    "SSL_write", "wolfSSL_write", "writeApplicationData", "NSS_write", "Full_write",
    "gnutls_record_send", "PR_Write", "mbedtls_ssl_write", "s2n_send",
})


class ContentType:
    """String constants for agent message contentType field."""
    KEYLOG = "keylog"
    DATALOG = "datalog"
    CONSOLE = "console"
    CONSOLE_DEV = "console_dev"
    CONSOLE_DEBUG = "console_debug"
    CONSOLE_INFO = "console_info"
    CONSOLE_WARN = "console_warn"
    CONSOLE_ERROR = "console_error"
    LIBRARY_DETECTED = "library_detected"
    SOCKET_TRACE = "socket_trace"
    SSH_KEY = "ssh_key"
    IPSEC_CHILD_SA = "ipsec_child_sa_keys"
    NETLOG = "netlog"
    ERROR = "error"
