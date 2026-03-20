#!/usr/bin/env python3
"""
Standalone GDB script for SSH key extraction from OpenSSH.

Usage:
    gdb -x ssh_key_extract.py -p <sshd_pid>
    gdb -batch -x ssh_key_extract.py -p <sshd_pid>

Sets breakpoints on kex_derive_keys() and ssh_set_newkeys(),
then reads the sshenc struct to extract cipher keys and IVs.

Based on keys-in-flux research:
https://github.com/fkie-cad/keys-in-flux-paper-material
"""

import sys
import os

try:
    import gdb  # noqa: F401
except ImportError:
    print("ERROR: This script must be run inside GDB.")
    print("Usage: gdb -x ssh_key_extract.py -p <sshd_pid>")
    sys.exit(1)

# Add project root to path for agent_debugger imports
_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(_script_dir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from agent_debugger.definitions.ssh_openssh import SSH_OPENSSH
from agent_debugger.runner import run_gdb_main

run_gdb_main(SSH_OPENSSH)
