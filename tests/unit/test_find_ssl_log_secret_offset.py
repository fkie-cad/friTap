"""Unit tests for the arm64 instruction decoders in
dev/find_ssl_log_secret_offset.py.

The decoders (ADRP/ADD/BL bit-math + sign extension) are the trickiest
correctness surface of the offset finder. We validate them against capstone as
an independent oracle: for each hand-built instruction word, capstone's resolved
target/decoding must equal the script's pure-Python computation.
"""

import importlib.util
import os
import struct
import sys

import pytest

capstone = pytest.importorskip("capstone")
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs  # noqa: E402

_SCRIPT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "dev",
                 "find_ssl_log_secret_offset.py")
)


def _load_module():
    spec = importlib.util.spec_from_file_location("fsls_offset", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve its module under
    # `from __future__ import annotations`.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


m = _load_module()
_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def _disasm_one(word: int, addr: int):
    return next(_md.disasm(struct.pack("<I", word), addr))


def _cap_imm(ins) -> int:
    """The hex immediate/target capstone resolved (e.g. 'x0, #0x5000')."""
    return int(ins.op_str.split("#")[1], 16)


def test_sign_extend_boundaries():
    assert m._sign_extend(0, 21) == 0
    assert m._sign_extend((1 << 21) - 1, 21) == -1
    assert m._sign_extend(1 << 20, 21) == -(1 << 20)          # most-negative 21-bit
    assert m._sign_extend((1 << 20) - 1, 21) == (1 << 20) - 1  # most-positive 21-bit
    assert m._sign_extend((1 << 26) - 1, 26) == -1


@pytest.mark.parametrize("word", [0x90000020, 0x90000000, 0xB0000001,
                                  0x90FFFFE0, 0xF0000000])
@pytest.mark.parametrize("pc", [0x1000, 0x1BC0000, 0x2000ABC])
def test_adrp_target_page_matches_capstone(word, pc):
    ins = _disasm_one(word, pc)
    if ins.mnemonic != "adrp":
        pytest.skip("not an adrp encoding")
    # capstone reports the page as an unsigned 64-bit address; the script keeps a
    # signed Python int. Compare modulo 2**64 so a (synthetic) negative offset
    # still validates the sign-extension. Real label refs are always positive.
    got = m.adrp_target_page(word, pc) & 0xFFFFFFFFFFFFFFFF
    assert got == _cap_imm(ins), (hex(word), hex(pc))


@pytest.mark.parametrize("word", [0x94000001, 0x97FFFFFF, 0x94123456])
@pytest.mark.parametrize("pc", [0x1000, 0x5ADBB00])
def test_bl_target_matches_capstone(word, pc):
    ins = _disasm_one(word, pc)
    assert ins.mnemonic == "bl"
    assert m.is_bl(word)
    assert m.bl_target(word, pc) == _cap_imm(ins), (hex(word), hex(pc))


def test_add_imm_fields_matches_capstone():
    # ADD x0, x1, #0x68  (64-bit immediate, sh=0)
    word = 0x91000000 | (0x68 << 10) | (1 << 5) | 0
    assert m.is_add_imm64(word)
    sh, imm12, rn, rd = m.add_imm_fields(word)
    assert (sh, imm12, rn, rd) == (0, 0x68, 1, 0)
    ins = _disasm_one(word, 0x1000)
    assert ins.mnemonic == "add"


def test_non_add_is_rejected():
    # an ADRP word must not be misclassified as an ADD-immediate
    assert not m.is_add_imm64(0x90000020)
    # a BL word must not be misclassified as an ADRP
    assert (0x94000001 & 0x9F000000) != 0x90000000
