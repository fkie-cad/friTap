"""Register the RC4 protocol handler into the public registry.

Discovered by the generic extension scan
(:func:`friTap.protocols.registry._discover_protocol_extensions`). Unlike the
Signal extension, RC4 is PUBLIC (NOT listed in ``private.txt``), so it ships in
every build. The registration passes NO ``implies=``: RC4 is an INDEPENDENT
protocol that neither implies nor is implied by TLS. ``--protocol tls,rc4``
activates both only because both were explicitly selected.
"""

from ..registry import register_protocol_handler
from ..rc4_handler import RC4Handler

register_protocol_handler("rc4", RC4Handler)
