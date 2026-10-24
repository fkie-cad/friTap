"""Standalone GDB-backend key-extraction scripts shipped with friTap.

Each subpackage drives ``gdb`` (via ``gdb -x <script>``) to extract key material
for a given target class. ``agent_gdb.wine`` is wired into friTap's runtime for
Wine targets on Linux; the others are run manually.
"""
