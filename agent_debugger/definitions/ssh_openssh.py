"""SSH key extraction definition for OpenSSH.

Encodes the extraction logic from the GDB script (agent_gdb/ssh/ssh_key_extract.py)
as pure data. The GDB script does:

1. Breaks on kex_derive_keys(), runs to return
2. Reads arg0 (struct ssh*), dereferences to state_ptr, then iterates
   mode 0 (client) and mode 1 (server)
3. Each newkeys_ptr points to a sshenc struct with:
   - offset 0:  cipher_name (pointer to string)
   - offset 20: key_len (uint32)
   - offset 24: iv_len (uint32)
   - offset 32: key_ptr (pointer to bytes, length from key_len)
   - offset 32+ptr_size: iv_ptr (pointer to bytes, length from iv_len)
4. Breaks on ssh_set_newkeys() just for logging (arg1 = mode)
5. Output format: SSH_ENC_KEY_CLIENT {hex}, SSH_IV_CLIENT {hex}, etc.

Struct layout reference (OpenSSH 9.x / 10.x):

    struct sshenc {
        char    *name;          // offset 0
        // padding to align ...
        u_int    key_len;       // offset 20
        u_int    iv_len;        // offset 24
        // padding ...
        u_char  *key;           // offset 32
        u_char  *iv;            // offset 32 + ptr_size
    };
"""
from .base import (
    StructField,
    StructExtraction,
    BreakpointSpec,
    ExtractionDefinition,
)

# --- sshenc struct fields (OpenSSH 9.x / 10.x) ---

_SSHENC_FIELDS = [
    StructField(
        name="cipher_name",
        offset=0,
        read_type="deref_string",
    ),
    StructField(
        name="key_len",
        offset=20,
        read_type="uint32",
    ),
    StructField(
        name="iv_len",
        offset=24,
        read_type="uint32",
    ),
    StructField(
        name="key",
        offset=32,
        read_type="deref_bytes",
        size_from_field="key_len",
    ),
    StructField(
        name="iv",
        offset="32+ptr_size",
        read_type="deref_bytes",
        size_from_field="iv_len",
    ),
]


# --- kex_derive_keys breakpoint ---
#
# arg0 = struct ssh*
# Dereference chain: ssh->state (offset 0) gives the session_state pointer.
# From session_state, newkeys[0] and newkeys[1] are consecutive pointers,
# so we iterate ["client", "server"] advancing by ptr_size each time.
# Each newkeys pointer leads to a sshenc struct.

_KEX_DERIVE_KEYS = BreakpointSpec(
    function_name="kex_derive_keys",
    timing="on_return",
    struct_extractions=[
        StructExtraction(
            base_arg="arg0",
            dereference_chain=[0],  # ssh -> state (first field)
            fields=_SSHENC_FIELDS,
            iterate=["client", "server"],  # newkeys[0], newkeys[1]
        ),
    ],
    output_labels={
        "key": "SSH_ENC_KEY_{direction} {hex}",
        "iv": "SSH_IV_{direction} {hex}",
    },
)


# --- ssh_set_newkeys breakpoint ---
#
# arg1 = mode (0=client, 1=server)
# This breakpoint is used only for logging key activation; no struct
# extraction is needed.

_SSH_SET_NEWKEYS = BreakpointSpec(
    function_name="ssh_set_newkeys",
    timing="on_entry",
    struct_extractions=[],
    output_labels={},
)


# --- Top-level definition ---

SSH_OPENSSH = ExtractionDefinition(
    protocol="ssh",
    library="openssh",
    breakpoints=[_KEX_DERIVE_KEYS, _SSH_SET_NEWKEYS],
    keylog_env_var="SSH_KEYLOG_FILE",
    default_keylog_file="ssh_keys.log",
)
