"""Protocol-neutral TLS 1.3 record layer shared by the offline decryptors.

AEAD peeling from a raw traffic secret: RFC 8446 key schedule and record
protection (:mod:`.tls13`), record splitting and hello field extraction
(:mod:`.records`), and stream decryption, handshake-anchored and mid-stream
(:mod:`.stream`). The optional ``cryptography`` backend is imported lazily;
:func:`.backend.backend_available` probes for it.

Nothing here knows the protocol riding on TLS (RC4, Signal, Schannel): protocol
packages import from this package, never the reverse.
"""
