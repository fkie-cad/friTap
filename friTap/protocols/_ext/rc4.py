"""Register the RC4 protocol handler into the public registry.

RC4 is public (not in ``private.txt``). It passes no ``implies=``: it is
independent of TLS; ``--protocol tls,rc4`` activates both only when both are selected.
"""

from ..rc4_handler import RC4Handler
from ..registry import register_protocol_handler

register_protocol_handler("rc4", RC4Handler)
