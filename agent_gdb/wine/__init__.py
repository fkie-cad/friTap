"""GDB-based TLS key extraction for Windows programs running under Wine.

The importable entry point is :func:`agent_gdb.wine.wine_key_extract.run_wine_key_extraction`.
The actual in-gdb logic lives in ``gdb_script/gdb_wine_extract.py``, which is
package *data* (it subclasses ``gdb.Breakpoint`` at import time and is only ever
loaded inside gdb), located at runtime via :func:`~agent_gdb.wine.wine_key_extract.resolve_gdb_script_path`.
"""
