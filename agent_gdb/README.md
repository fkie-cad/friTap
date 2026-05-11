# GDB Backend Agent Scripts

Hook scripts for the GDB instrumentation backend.

Each protocol has its own subdirectory containing standalone GDB Python scripts
that can be sourced via `gdb -x <script>.py -p <pid>`.

## Structure

- `ssh/ssh_key_extract.py` — SSH key extraction from OpenSSH
- `ipsec/ipsec_key_extract.py` — IPSec key extraction from strongSwan
- `tls/tls_key_extract.py` — TLS key extraction (planned)
