# LLDB Backend Agent Scripts

Hook scripts for the LLDB instrumentation backend.

Each protocol has its own subdirectory containing LLDB Python scripts
for breakpoint-based key extraction.

## Structure

- `ssh/ssh_key_extract.py` — SSH key extraction from OpenSSH via LLDB
- `ipsec/ipsec_key_extract.py` — IPSec key extraction from strongSwan via LLDB
- `tls/tls_key_extract.py` — TLS key extraction (planned)
