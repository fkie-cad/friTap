"""
Network exposure policy shared by the MCP (HTTP) and REST servers.

Servers bind to loopback by default. Binding anywhere else exposes capture
and read tools to the network, so a bearer token is then mandatory.
"""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import os

DEFAULT_HOST = "127.0.0.1"
TOKEN_ENV_VAR = "FRITAP_API_TOKEN"
_LOOPBACK_NAMES = frozenset({"localhost", "ip6-localhost"})


def is_loopback(host: str) -> bool:
    """True if ``host`` is a loopback name or address (``0.0.0.0`` is not)."""
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def bind_error(host: str, token: str | None) -> str | None:
    """Return a usage error message if binding ``host`` without ``token`` is unsafe."""
    if token or is_loopback(host):
        return None
    return f"refusing to bind non-loopback host {host!r} without --token"


def bearer_matches(header_value: str | None, token: str) -> bool:
    """Constant-time check of an ``Authorization: Bearer <token>`` header."""
    prefix = "Bearer "
    if not header_value or not header_value.startswith(prefix):
        return False
    return hmac.compare_digest(header_value[len(prefix):].encode(), token.encode())


def add_network_options(parser: argparse.ArgumentParser, *, default_port: int) -> None:
    """Add ``--host``, ``--port`` and ``--token`` (token falls back to $FRITAP_API_TOKEN)."""
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"Bind address (default {DEFAULT_HOST}; non-loopback requires --token).")
    parser.add_argument("--port", type=int, default=default_port,
                        help=f"TCP port (default {default_port}).")
    parser.add_argument("--token", default=os.environ.get(TOKEN_ENV_VAR) or None,
                        help=f"Require 'Authorization: Bearer TOKEN' (default: ${TOKEN_ENV_VAR}).")


def enforce_bind_policy(parser: argparse.ArgumentParser, ns: argparse.Namespace) -> None:
    """Exit with a usage error (code 2) when ``ns.host`` needs a token but has none."""
    message = bind_error(ns.host, ns.token)
    if message:
        parser.error(message)


__all__ = [
    "DEFAULT_HOST", "TOKEN_ENV_VAR", "is_loopback", "bind_error", "bearer_matches",
    "add_network_options", "enforce_bind_policy",
]
