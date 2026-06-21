"""Self-registering protocol-handler extensions.

Modules in this package register an optional (or private) protocol with the
public registry via
:func:`friTap.protocols.registry.register_protocol_handler`, and are imported by
:func:`friTap.protocols.registry._discover_protocol_extensions` through a
directory scan. The public core therefore never imports or names them, so a
filtered build that omits an extension module drops that protocol cleanly while
the core stays protocol-agnostic.
"""
