#!/usr/bin/env python3
"""
LLDB script for IPSec key extraction from strongSwan charon.

Usage:
    lldb -p <charon_pid> -o "command script import ipsec_key_extract.py"

Sets breakpoints on ikev2_derive_child_sa_keys() and derive_ike_keys()
to extract ESP and IKE SA key material.

Based on keys-in-flux research:
https://github.com/fkie-cad/keys-in-flux-paper-material
"""

import sys
import os

try:
    import lldb  # noqa: F401
except ImportError:
    print("ERROR: This script must be run inside LLDB.")
    print("Usage: lldb -p <charon_pid> -o 'command script import ipsec_key_extract.py'")
    raise

# Add project root to path for agent_debugger imports
_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(_script_dir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from agent_debugger.definitions.ipsec_strongswan import IPSEC_STRONGSWAN
from agent_debugger.runner import run_lldb_main


def __lldb_init_module(debugger, internal_dict):
    """Entry point when imported via LLDB command script import."""
    run_lldb_main(IPSEC_STRONGSWAN, debugger)
