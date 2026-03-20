#!/usr/bin/env python3
"""
LLDB script for SSH key extraction from OpenSSH.

Usage:
    lldb -p <sshd_pid> -o "command script import ssh_key_extract.py"

Sets breakpoints on kex_derive_keys() and ssh_set_newkeys(),
then reads the sshenc struct to extract cipher keys and IVs.

Based on keys-in-flux research:
https://github.com/fkie-cad/keys-in-flux-paper-material
"""

import sys
import os

try:
    import lldb  # noqa: F401
except ImportError:
    print("ERROR: This script must be run inside LLDB.")
    print("Usage: lldb -p <sshd_pid> -o 'command script import ssh_key_extract.py'")
    raise

# Add project root to path for agent_debugger imports
_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(_script_dir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from agent_debugger.definitions.ssh_openssh import SSH_OPENSSH  # noqa: E402
from agent_debugger.runner import run_lldb_main  # noqa: E402


def __lldb_init_module(debugger, internal_dict):
    """Entry point when imported via LLDB command script import."""
    run_lldb_main(SSH_OPENSSH, debugger)
