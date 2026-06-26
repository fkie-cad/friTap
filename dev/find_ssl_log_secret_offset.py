#!/usr/bin/env python3
"""
find_ssl_log_secret_offset.py — locate bssl::ssl_log_secret in a stripped
BoringSSL/Chromium shared object, for friTap's --pairip-safe offset hook.

WHY THIS EXISTS
---------------
Statically-linked, fully-stripped BoringSSL hosts (Android System WebView's
libwebviewchromium.so, Cronet forks, …) expose no SSL_* symbols in .dynsym or
.symtab, and PairIP-protected apps forbid friTap's byte-pattern (Memory.scan)
tier. The one scan-free hook point is bssl::ssl_log_secret(ssl, label, secret),
which BoringSSL calls on EVERY handshake — friTap reads its args in onEnter, so
it captures keys even when the embedder never installs a keylog callback.

HOW IT FINDS THE FUNCTION (no symbols needed)
---------------------------------------------
Every call site passes a TLS keylog LABEL string literal ("CLIENT_RANDOM",
"CLIENT_HANDSHAKE_TRAFFIC_SECRET", …) as arg1. On arm64 the label address is
materialised with an ADRP+ADD pair, then a BL into ssl_log_secret. So:

  1. find each label string's virtual address (lief),
  2. scan .text for ADRP+ADD pairs that compute a label address (fast bit-math),
  3. record the BL target that follows each materialisation,
  4. the target shared by the MOST distinct labels is ssl_log_secret (voting),
  5. validate it is a real function entry (capstone prologue check).

The emitted offset is RUNTIME-RELATIVE (label/.text vaddr minus the ELF load
bias), i.e. exactly what `module.base.add(offset)` needs and what friTap's
--offsets expects.

USAGE
-----
  python3 find_ssl_log_secret_offset.py <libwebviewchromium.so>
  python3 find_ssl_log_secret_offset.py --apk webview.apk         # auto-extract
  python3 find_ssl_log_secret_offset.py <so> --module-name libwebviewchromium.so

Dependencies: lief, capstone, numpy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field

import lief
import numpy as np
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

# BoringSSL keylog labels (NSS SSLKEYLOGFILE format). Stable across versions;
# each is passed as arg1 to ssl_log_secret at its call site. The trailing NUL
# disambiguates substrings (CLIENT_TRAFFIC_SECRET_0 vs ..._SECRET).
DEFAULT_LABELS = [
    "CLIENT_RANDOM",                    # TLS 1.2
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",  # TLS 1.3
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
    "EARLY_EXPORTER_SECRET",
]

# How far past an ADRP+ADD label materialisation we look for the BL that calls
# ssl_log_secret (intervening movs / arg setup).
BL_SEARCH_WINDOW = 32


@dataclass
class TextSection:
    vaddr: int
    words: np.ndarray  # uint32 view of the section's instruction stream


@dataclass
class Result:
    func_vaddr: int
    load_bias: int
    votes: int
    voting_labels: list[str] = field(default_factory=list)
    ranked: list[tuple[int, int]] = field(default_factory=list)  # (vaddr, votes)

    @property
    def offset(self) -> int:
        """Runtime-relative offset: module.base.add(offset) == function."""
        return self.func_vaddr - self.load_bias


# --------------------------------------------------------------------------- #
#  ELF helpers
# --------------------------------------------------------------------------- #
def load_bias_of(binary: lief.ELF.Binary) -> int:
    """Lowest PT_LOAD virtual address — subtract to get base-relative offsets."""
    loads = [s.virtual_address for s in binary.segments
             if str(s.type).endswith("LOAD")]
    return min(loads) if loads else 0


def exec_sections(binary: lief.ELF.Binary) -> list[TextSection]:
    """Executable sections as uint32 instruction arrays."""
    out: list[TextSection] = []
    for s in binary.sections:
        flags = int(s.flags)
        is_exec = bool(flags & 0x4)  # SHF_EXECINSTR
        if not is_exec or s.size < 4:
            continue
        raw = bytes(s.content)
        n = (len(raw) // 4) * 4
        out.append(TextSection(s.virtual_address,
                               np.frombuffer(raw[:n], dtype="<u4")))
    return out


def find_label_vaddrs(data: bytes, binary: lief.ELF.Binary,
                      labels: list[str]) -> dict[str, list[int]]:
    """Map each label to every virtual address it appears at (NUL-terminated)."""
    # file-offset -> vaddr via section ranges (offset>0, allocated content)
    ranges = [(s.offset, s.offset + s.size, s.virtual_address)
              for s in binary.sections if s.size > 0 and s.offset > 0]

    def off_to_va(off: int):
        for a, b, va in ranges:
            if a <= off < b:
                return va + (off - a)
        return None

    found: dict[str, list[int]] = {}
    for label in labels:
        needle = label.encode() + b"\x00"
        vas: list[int] = []
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            va = off_to_va(i)
            if va is not None:
                vas.append(va)
            start = i + 1
        if vas:
            found[label] = vas
    return found


# --------------------------------------------------------------------------- #
#  arm64 instruction decode (vectorised where it matters)
# --------------------------------------------------------------------------- #
def _sign_extend(value: int, bits: int) -> int:
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def adrp_target_page(word: int, pc: int) -> int:
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = _sign_extend((immhi << 2) | immlo, 21)
    return (pc & ~0xFFF) + (imm << 12)


def is_add_imm64(word: int) -> bool:
    return (word & 0xFF800000) == 0x91000000


def add_imm_fields(word: int) -> tuple[int, int, int, int]:
    sh = (word >> 22) & 1
    imm12 = (word >> 10) & 0xFFF
    rn = (word >> 5) & 0x1F
    rd = word & 0x1F
    return sh, imm12, rn, rd


def is_bl(word: int) -> bool:
    return (word & 0xFC000000) == 0x94000000


def bl_target(word: int, pc: int) -> int:
    return pc + _sign_extend(word & 0x03FFFFFF, 26) * 4


# --------------------------------------------------------------------------- #
#  Core: vote for ssl_log_secret across label call sites
# --------------------------------------------------------------------------- #
def collect_bl_targets(text: TextSection,
                       label_vaddrs: dict[str, list[int]]
                       ) -> dict[str, set[int]]:
    """For each label, the set of BL targets reached right after the label's
    address is materialised (ADRP+ADD) in this text section."""
    words = text.words
    base = text.vaddr
    n = words.size

    # Vectorised ADRP candidate filter.
    is_adrp = (words & 0x9F000000) == 0x90000000
    adrp_idx = np.nonzero(is_adrp)[0]

    # Precompute each ADRP's target page (vectorised).
    w_adrp = words[adrp_idx].astype(np.int64)
    immlo = (w_adrp >> 29) & 0x3
    immhi = (w_adrp >> 5) & 0x7FFFF
    imm21 = (immhi << 2) | immlo
    imm21 = np.where(imm21 >= (1 << 20), imm21 - (1 << 21), imm21)
    adrp_pc = base + adrp_idx * 4
    adrp_page = (adrp_pc & ~0xFFF) + (imm21 << 12)
    adrp_rd = (w_adrp & 0x1F).astype(np.int64)

    # page -> list of (instr_index, adrp_rd) for quick lookup per label page
    page_to_sites: dict[int, list[tuple[int, int]]] = {}
    for k in range(adrp_idx.size):
        page_to_sites.setdefault(int(adrp_page[k]), []).append(
            (int(adrp_idx[k]), int(adrp_rd[k])))

    out: dict[str, set[int]] = {}
    for label, vaddrs in label_vaddrs.items():
        targets: set[int] = set()
        for labva in vaddrs:
            page = labva & ~0xFFF
            low = labva & 0xFFF
            for i, rd in page_to_sites.get(page, ()):
                # find an ADD that adds `low` to the ADRP register, shortly after
                for j in range(i + 1, min(i + 6, n)):
                    wj = int(words[j])
                    if is_add_imm64(wj):
                        sh, imm12, rn, _ = add_imm_fields(wj)
                        if rn == rd and sh == 0 and imm12 == low:
                            # scan forward for the call into ssl_log_secret
                            for k in range(j + 1, min(j + BL_SEARCH_WINDOW, n)):
                                if is_bl(int(words[k])):
                                    targets.add(bl_target(int(words[k]),
                                                          base + k * 4))
                                    break
                            break
                    if is_bl(wj):
                        break  # call before materialisation completes — give up
        if targets:
            out[label] = targets
    return out


def vote(per_label_targets: dict[str, set[int]]
         ) -> list[tuple[int, int, list[str]]]:
    """Rank candidate BL targets by how many distinct labels reach them."""
    tally: dict[int, list[str]] = {}
    for label, targets in per_label_targets.items():
        for t in targets:
            tally.setdefault(t, []).append(label)
    ranked = sorted(((t, len(labels), sorted(labels))
                     for t, labels in tally.items()),
                    key=lambda r: r[1], reverse=True)
    return ranked


# --------------------------------------------------------------------------- #
#  Validation
# --------------------------------------------------------------------------- #
def looks_like_function_entry(binary: lief.ELF.Binary, data: bytes,
                              vaddr: int) -> tuple[bool, list[str]]:
    """Disassemble the prologue; confirm it starts a function."""
    ranges = [(s.virtual_address, s.virtual_address + s.size, s.offset)
              for s in binary.sections if s.size > 0 and s.offset > 0]
    foff = None
    for a, b, off in ranges:
        if a <= vaddr < b:
            foff = off + (vaddr - a)
            break
    if foff is None:
        return False, ["address not in any section"]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    lines, ok = [], False
    for ins in md.disasm(data[foff:foff + 8 * 4], vaddr):
        lines.append(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}".strip())
        m = ins.mnemonic
        if m in ("paciasp", "stp", "sub") and len(lines) <= 3:
            ok = True
    return ok, lines


# --------------------------------------------------------------------------- #
#  APK extraction (optional convenience)
# --------------------------------------------------------------------------- #
def extract_so_from_apk(apk_path: str, prefer: str) -> str:
    with zipfile.ZipFile(apk_path) as z:
        sos = [n for n in z.namelist()
               if n.startswith("lib/arm64-v8a/") and n.endswith(".so")]
        if not sos:
            sys.exit("no arm64 .so in APK")
        chosen = next((n for n in sos if prefer in n), None)
        if chosen is None:
            chosen = max(sos, key=lambda n: z.getinfo(n).file_size)
        out = os.path.join(tempfile.mkdtemp(prefix="ssllog_"),
                           os.path.basename(chosen))
        with z.open(chosen) as src, open(out, "wb") as dst:
            dst.write(src.read())
        print(f"[*] extracted {chosen} -> {out}")
        return out


# --------------------------------------------------------------------------- #
def analyse(binary: lief.ELF.Binary, data: bytes, labels: list[str]) -> Result:
    bias = load_bias_of(binary)
    label_vaddrs = find_label_vaddrs(data, binary, labels)
    if not label_vaddrs:
        sys.exit("none of the TLS keylog label strings were found — is this a "
                 "BoringSSL host?")
    print(f"[*] load bias: 0x{bias:x}")
    print(f"[*] labels found: "
          + ", ".join(f"{k}@0x{v[0]:x}" for k, v in label_vaddrs.items()))

    merged: dict[str, set[int]] = {}
    for text in exec_sections(binary):
        for label, targets in collect_bl_targets(text, label_vaddrs).items():
            merged.setdefault(label, set()).update(targets)

    ranked = vote(merged)
    if not ranked:
        sys.exit("no ADRP+ADD->BL call sites found for any label")

    print("\n[*] candidate BL targets (votes = distinct labels calling it):")
    for vaddr, votes, labs in ranked[:6]:
        print(f"      0x{vaddr:x}  votes={votes}  ({', '.join(labs)})")

    best_vaddr, best_votes, best_labs = ranked[0]
    return Result(func_vaddr=best_vaddr, load_bias=bias, votes=best_votes,
                  voting_labels=best_labs,
                  ranked=[(v, c) for v, c, _ in ranked])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("so", nargs="?", help="path to the (stripped) .so")
    ap.add_argument("--apk", help="extract the BoringSSL .so from this APK")
    ap.add_argument("--prefer", default="libwebviewchromium",
                    help="substring to prefer when picking a .so from --apk")
    ap.add_argument("--module-name", default=None,
                    help="module name for the emitted --offsets JSON "
                         "(default: basename of the .so)")
    ap.add_argument("--labels", nargs="*", default=DEFAULT_LABELS,
                    help="override the TLS keylog label set")
    args = ap.parse_args()

    so_path = args.so
    if args.apk:
        so_path = extract_so_from_apk(args.apk, args.prefer)
    if not so_path:
        ap.error("provide a .so path or --apk")

    # Parse + read the .so ONCE; reuse for analysis and prologue validation.
    binary = lief.parse(so_path)
    if binary is None:
        sys.exit(f"could not parse ELF: {so_path}")
    data = open(so_path, "rb").read()

    res = analyse(binary, data, args.labels)
    ok, prologue = looks_like_function_entry(binary, data, res.func_vaddr)

    mod = args.module_name or os.path.basename(so_path)
    print("\n" + "=" * 64)
    print(f"  ssl_log_secret @ vaddr 0x{res.func_vaddr:x}  "
          f"(votes={res.votes}: {', '.join(res.voting_labels)})")
    print(f"  runtime-relative offset: 0x{res.offset:x}  (load bias 0x{res.load_bias:x})")
    print(f"  prologue valid: {'YES' if ok else 'NO (review below)'}")
    for line in prologue:
        print(f"      {line}")
    print("=" * 64)
    offsets = {mod: {"ssl_log_secret": {"address": f"0x{res.offset:x}",
                                        "absolute": False}}}
    print("\n--offsets argument:")
    print("  " + json.dumps(offsets))
    if not ok:
        sys.exit(2)


if __name__ == "__main__":
    main()
