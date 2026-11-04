"""
Adapters that expose the agent tool registry: CLI (``fritap q``), MCP and REST.

Each adapter is generated from :meth:`friTap.agent_api.registry.Registry.specs`
and runs tools through :meth:`Registry.call`; nothing here is imported eagerly.
"""
