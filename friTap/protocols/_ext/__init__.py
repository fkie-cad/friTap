"""Self-registering protocol-handler extensions.

Modules here register a protocol via
:func:`friTap.protocols.registry.register_protocol_handler` and are imported by
:func:`friTap.protocols.registry._discover_protocol_extensions`. The core never
names them, so a filtered build can omit one cleanly.

A new PUBLIC extension must also be added to the protocol allowlist in
``scripts/check_public_denylist.sh``; otherwise the publish leak guard treats it
as a private protocol and refuses to publish.
"""
