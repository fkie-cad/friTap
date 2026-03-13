"""IPSec key extraction definition for strongSwan charon.

Encodes the extraction logic from the GDB script
(agent_gdb/ipsec/ipsec_key_extract.py) as pure data.

The GDB script does:

1. Breaks on ikev2_derive_child_sa_keys(), captures args in registers
   (rdi, rsi, rdx, rcx, r8, r9) on entry, runs to return, then reads
   args 4-7 as output pointers to key_material_t structs.
2. Breaks on derive_ike_keys(), captures args 0-5 on entry, runs to
   return, then reads each as a key_material_t pointer.

key_material_t layout (strongSwan):

    struct key_material_t {
        void   *ptr;    // offset 0
        size_t  len;    // offset ptr_size
    };

Each key is from a SEPARATE register argument (not iterating over a single
struct). The BreakpointSpec uses capture_args_on_entry=True so that register
values are saved before the function clobbers them, and each StructExtraction
has its own base_arg and label.

Output format: IPSEC_ENCR_I {hex}, IPSEC_SK_AI {hex}, etc.
"""
from .base import (
    StructField,
    StructExtraction,
    BreakpointSpec,
    ExtractionDefinition,
)

# --- key_material_t struct fields ---
#
# This is a two-field struct: a pointer to the data and a size_t length.
# The actual key bytes are read by dereferencing the pointer and reading
# `len` bytes. We model this as three logical fields:
#   1. "ptr"  - the raw pointer value (offset 0)
#   2. "len"  - the size_t length (offset ptr_size)
#   3. "key_data" - the dereferenced bytes (uses ptr_field="ptr",
#                   size_from_field="len")

_KEY_MATERIAL_FIELDS = [
    StructField(
        name="ptr",
        offset=0,
        read_type="pointer",
    ),
    StructField(
        name="len",
        offset="ptr_size",
        read_type="pointer",  # size_t is pointer-width
    ),
    StructField(
        name="key_data",
        offset=0,
        read_type="deref_bytes",
        size_from_field="len",
        ptr_field="ptr",
    ),
]


# --- Child SA key labels and their argument indices ---
#
# ikev2_derive_child_sa_keys() passes output key_material_t pointers in
# args 4-7 (r8, r9, and two stack args on x86-64).

CHILD_KEY_LABELS = ["encr_i", "encr_r", "integ_i", "integ_r"]

_CHILD_SA_EXTRACTIONS = [
    StructExtraction(
        base_arg=f"arg{i + 4}",
        dereference_chain=[],
        fields=_KEY_MATERIAL_FIELDS,
        label=label,
    )
    for i, label in enumerate(CHILD_KEY_LABELS)
]

_DERIVE_CHILD_SA_KEYS = BreakpointSpec(
    function_name="ikev2_derive_child_sa_keys",
    timing="on_return",
    capture_args_on_entry=True,
    struct_extractions=_CHILD_SA_EXTRACTIONS,
    output_labels={
        "key_data": "IPSEC_{label} {hex}",
    },
)


# --- IKE SA key labels and their argument indices ---
#
# derive_ike_keys() passes six key_material_t pointers in args 0-5
# (rdi, rsi, rdx, rcx, r8, r9 on x86-64).

IKE_KEY_LABELS = ["SK_ai", "SK_ar", "SK_ei", "SK_er", "SK_pi", "SK_pr"]

_IKE_EXTRACTIONS = [
    StructExtraction(
        base_arg=f"arg{i}",
        dereference_chain=[],
        fields=_KEY_MATERIAL_FIELDS,
        label=label,
    )
    for i, label in enumerate(IKE_KEY_LABELS)
]

_DERIVE_IKE_KEYS = BreakpointSpec(
    function_name="derive_ike_keys",
    timing="on_return",
    capture_args_on_entry=True,
    struct_extractions=_IKE_EXTRACTIONS,
    output_labels={
        "key_data": "IPSEC_{label} {hex}",
    },
)


# --- Top-level definition ---

IPSEC_STRONGSWAN = ExtractionDefinition(
    protocol="ipsec",
    library="strongswan",
    breakpoints=[_DERIVE_CHILD_SA_KEYS, _DERIVE_IKE_KEYS],
    keylog_env_var="IPSEC_KEYLOG_FILE",
    default_keylog_file="ipsec_keys.log",
)
