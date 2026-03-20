#!/usr/bin/env python3
"""
Standalone GDB script for IPSec key extraction from strongSwan charon.

Usage:
    gdb -x ipsec_key_extract.py -p <charon_pid>
    gdb -batch -x ipsec_key_extract.py -p <charon_pid>

Sets breakpoints on ikev2_derive_child_sa_keys() and derive_ike_keys()
to extract ESP and IKE SA key material.

Based on keys-in-flux research:
https://github.com/fkie-cad/keys-in-flux-paper-material
"""

import sys
import os

try:
    import gdb  # noqa: F401
except ImportError:
    print("ERROR: This script must be run inside GDB.")
    print("Usage: gdb -x ipsec_key_extract.py -p <charon_pid>")
    sys.exit(1)

# Add project root to path for agent_debugger imports
_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(_script_dir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from agent_debugger.definitions.ipsec_strongswan import IPSEC_STRONGSWAN
from agent_debugger.runner import run_gdb_main

run_gdb_main(IPSEC_STRONGSWAN)
