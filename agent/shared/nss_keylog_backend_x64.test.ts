// Unit tests for the NSS keylog-writer locator's x86-64 backend and its
// instruction decoder, on real Fenix 160.0.1 x86_64 libnss3.so bytes
// (static validation only; no x86_64 device run).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { decodeX64KeylogWriter, x64DirectCallTargets, x64FirstCallAfterSite } from "./nss_keylog_backend_x64.js";
import { NSS_HEX_TABLE } from "./nss_layout_constants.js";
import type { ModuleByteReader } from "./module_mapping.js";
import { decodeX64Insn, sweepX64, x64RegsWritten, RIP, X64 } from "./x64_insn.js";
import {
    CLIENT_RANDOM_FN, CLIENT_RANDOM_LEA, CLIENT_RANDOM_OFF, CLIENT_RANDOM_SITE, CLIENT_RANDOM_SITE_VADDR,
    ECH_CONFIG_LEA, ECH_FN, ECH_FN_END, ECH_FN_VADDR, ECH_SECRET_LEA, HEX_TABLE_OFFSETS, TLS13_WRAP,
    TLS13_WRAP_VADDR, WRITER, WRITER_END, WRITER_INSN_STARTS, WRITER_VADDR,
} from "./__fixtures__/nss_fenix160_x64.js";
import {
    LINUX_CLIENT_RANDOM_FN, LINUX_CLIENT_RANDOM_LEA, LINUX_CLIENT_RANDOM_OFF, LINUX_CLIENT_RANDOM_SITE, LINUX_HEX_TABLE_OFFSETS,
    LINUX_RECORD_KEYLOG, LINUX_RECORD_KEYLOG_VADDR, LINUX_WRITER, LINUX_WRITER_END, LINUX_WRITER_VADDR,
} from "./__fixtures__/nss_linux_ff160_x64_libssl3.js";

/** Test readers written as text: each returned string becomes its byte codes. */
type TextReader = (addr: number, length: number) => string | null;
const textReader = (read: TextReader): ModuleByteReader => (addr, length) => {
    const text = read(addr, length);
    return text === null ? null : Uint8Array.from(text, (c) => c.charCodeAt(0));
};

const WRITER_HEX_TABLE = 0x39f70;

/** The real module's hex-table copies; every other address reads as non-matching text. */
const fenixLiterals = textReader((addr, length) =>
    HEX_TABLE_OFFSETS.includes(addr) ? NSS_HEX_TABLE.slice(0, length) : "x".repeat(length));

const hex = (h: string) => new Uint8Array(h.replace(/\s+/g, "").match(/../g)!.map((b) => parseInt(b, 16)));

/** WRITER with `replacement` written over the bytes at `vaddr`. */
function patchedWriter(vaddr: number, replacement: string): Uint8Array {
    const bytes = new Uint8Array(WRITER);
    bytes.set(hex(replacement), vaddr - WRITER_VADDR);
    return bytes;
}

const NOP7 = "0f1f8000000000";

// ---- x64_insn: the length decoder -------------------------------------------------

test("the sweep walks exactly capstone's instruction starts over the real writer", () => {
    const sweep = sweepX64(WRITER, WRITER_VADDR);
    assert.ok(sweep.complete);
    assert.deepEqual(sweep.insns.map((i) => i.addr), WRITER_INSN_STARTS);
    assert.equal(WRITER_VADDR + WRITER.length, WRITER_END);
});

test("decoder: SIB disp32 memory operand of `movzx edi, byte [r12+rsi+0x650]`", () => {
    const i = decodeX64Insn(hex("410fb6bc3450060000"), 0, 0x2925aa)!;
    assert.equal(i.length, 9);
    assert.deepEqual(i.mem, { base: X64.r12, index: X64.rsi, scale: 1, disp: 0x650 });
    assert.deepEqual(x64RegsWritten(i), [X64.rdi]);
});

test("decoder: RIP-relative lea, rel32 call/jmp targets", () => {
    const lea = decodeX64Insn(hex("488d0dc679daff"), 0, 0x2925a3)!;
    assert.equal(lea.mem!.base, RIP);
    assert.equal(lea.addr + lea.length + lea.mem!.disp, WRITER_HEX_TABLE);
    assert.equal(decodeX64Insn(hex("e8468bffff"), 0, 0x2999d5)!.target, WRITER_VADDR);
    assert.equal(decodeX64Insn(hex("e9f34afdff"), 0, 0x2bda28)!.target, WRITER_VADDR);
});

test("decoder: immediate sizes follow prefixes (66, REX.W, moffs, VEX)", () => {
    const len = (h: string) => decodeX64Insn(hex(h), 0, 0)?.length ?? null;
    assert.equal(len("66c7004100"), 5);              // mov word [rax], 0x41 (imm16)
    assert.equal(len("48b80123456789abcdef"), 10);   // movabs rax, imm64
    assert.equal(len("b801000000"), 5);              // mov eax, imm32
    assert.equal(len("48a10000000000000000"), 10);   // mov rax, moffs64
    assert.equal(len("c5f9efc0"), 4);                // vpxor xmm0, xmm0, xmm0
    assert.equal(len("c4e3790fc108"), 6);            // vpalignr (map 0F3A, imm8)
    assert.equal(len("f30f1efa"), 4);                // endbr64
    assert.equal(len("06"), null);                   // push es: invalid in 64-bit mode
    assert.equal(len("410fb6bc34500600"), null);     // truncated
});

test("register writes: a call clobbers rdi but not r12; op-encoded regs honour REX.B", () => {
    const writes = (h: string) => x64RegsWritten(decodeX64Insn(hex(h), 0, 0)!);
    assert.ok(writes("e800000000").includes(X64.rdi));
    assert.ok(!writes("e800000000").includes(X64.r12));
    assert.deepEqual(writes("b801000000"), [X64.rax]);          // mov eax, 1
    assert.deepEqual(writes("41b801000000"), [X64.r8]);         // mov r8d, 1
    assert.deepEqual(writes("415c"), [X64.r12]);                // pop r12
    assert.deepEqual(writes("f30f1efa"), []);                   // endbr64
    assert.deepEqual(writes("4883fe20"), []);                   // cmp rsi, 0x20
});

// ---- decodeX64KeylogWriter on the real writer ----------------------------------------

test("real 3.132 x86_64 writer decodes client_random +0x650", () => {
    assert.deepEqual(decodeX64KeylogWriter(WRITER, WRITER_VADDR, fenixLiterals), { clientRandomOff: CLIENT_RANDOM_OFF });
});

test("writer without a hex-table reference does not decode", () => {
    assert.equal(decodeX64KeylogWriter(WRITER, WRITER_VADDR, textReader((_a, n) => "x".repeat(n))), null);
    const otherCopies = textReader((a, n) =>
        a !== WRITER_HEX_TABLE && HEX_TABLE_OFFSETS.includes(a) ? NSS_HEX_TABLE.slice(0, n) : "x".repeat(n));
    assert.equal(decodeX64KeylogWriter(WRITER, WRITER_VADDR, otherCopies), null); // content changed
    assert.equal(decodeX64KeylogWriter(patchedWriter(0x2925a3, NOP7), WRITER_VADDR, fenixLiterals), null); // lea removed
});

test("a second distinct ss+disp makes the writer ambiguous", () => {
    // second movzx @0x2925be: [r12+rsi+0x650] -> [r12+rsi+0x700]
    const bytes = patchedWriter(0x2925be, "410fb6bc3400070000");
    assert.equal(decodeX64KeylogWriter(bytes, WRITER_VADDR, fenixLiterals), null);
});

test("a use of r12 after it is overwritten does not count", () => {
    // @0x292659 `mov dword [r15+0x98], 1` -> `mov dword [r12+0x700], 1` (same length),
    // after `lea r12, [rip+...]` @0x29263a: r12 is no longer ss.
    const bytes = patchedWriter(0x292659, "41c7842400070000" + "010000");
    assert.deepEqual(decodeX64KeylogWriter(bytes, WRITER_VADDR, fenixLiterals), { clientRandomOff: CLIENT_RANDOM_OFF });
    // Control: without the overwrite r12 is still ss there, and the 0x700 use is counted.
    const stillCopy = new Uint8Array(bytes);
    stillCopy.set(hex(NOP7), 0x29263a - WRITER_VADDR);
    assert.equal(decodeX64KeylogWriter(stillCopy, WRITER_VADDR, fenixLiterals), null);
});

test("tls13_DeriveSecretWrap does not decode (TLS 1.3 votes can never win)", () => {
    assert.equal(decodeX64KeylogWriter(TLS13_WRAP, TLS13_WRAP_VADDR, fenixLiterals), null);
});

// ---- decodeX64KeylogWriter on synthetic shapes ---------------------------------------

/** `lea rcx, [rip+disp]` at `at` pointing to 0x2000, and a reader with the hex table there. */
const leaHexTableAt = (at: number) => {
    const disp = 0x2000 - (at + 7);
    return "488d0d" + [0, 8, 16, 24].map((s) => ((disp >>> s) & 0xff).toString(16).padStart(2, "0")).join("");
};
const synthLiterals = textReader((a, n) => (a === 0x2000 ? NSS_HEX_TABLE.slice(0, n) : null));

test("an error block laid out before `mov rbx, rdi` that clobbers rdi is rolled back", () => {
    // 0x1000 test rsi,rsi ; jne +6 ; mov edi,0x13 ; ret ; mov rbx,rdi ; movzx eax,byte [rbx+0x650] ; lea rcx,[rip..] ; ret
    const head = "4885f6" + "7506" + "bf13000000" + "c3" + "4889fb" + "0fb68350060000";
    const code = hex(head + leaHexTableAt(0x1000 + head.length / 2) + "c3");
    assert.deepEqual(decodeX64KeylogWriter(code, 0x1000, synthLiterals), { clientRandomOff: 0x650 });
});

test("chained copies and `add <copy>, imm32` count; a copy of rdi taken after a call does not", () => {
    // mov rbx,rdi ; mov r13,rbx ; add r13,0x650 ; lea rcx,[rip..] ; ret
    const head = "4889fb" + "4989dd" + "4981c550060000";
    const ok = hex(head + leaHexTableAt(0x1000 + head.length / 2) + "c3");
    assert.deepEqual(decodeX64KeylogWriter(ok, 0x1000, synthLiterals), { clientRandomOff: 0x650 });
    // call ; mov rbx,rdi ; movzx eax,byte [rbx+0x650] ; lea ; ret
    const afterCall = "e800000000" + "4889fb" + "0fb68350060000";
    const bad = hex(afterCall + leaHexTableAt(0x1000 + afterCall.length / 2) + "c3");
    assert.equal(decodeX64KeylogWriter(bad, 0x1000, synthLiterals), null);
});

test("byte-scan pseudo-decodes inside an instruction do not produce matches", () => {
    // mov r12,rdi ; movabs rax, <bytes of `lea r8,[r12+0x700]`> ; movzx eax,byte [r12+0x650] ; lea ; ret
    const phantom = "4d8d842400070000";
    const head = "4989fc" + "48b8" + phantom + "410fb684245006" + "0000";
    const code = hex(head + leaHexTableAt(0x1000 + head.length / 2) + "c3");
    // Decoding from inside the movabs (a byte scan) would see ss+0x700 ...
    const pseudo = decodeX64Insn(code, 5, 0x1000)!;
    assert.deepEqual(pseudo.mem, { base: X64.r12, index: null, scale: 1, disp: 0x700 });
    // ... the instruction-start walk does not.
    assert.deepEqual(decodeX64KeylogWriter(code, 0x1000, synthLiterals), { clientRandomOff: 0x650 });
});

test("undecodable bytes in the body fail closed", () => {
    const head = "4989fc" + "06" + "410fb684245006" + "0000";
    const code = hex(head + leaHexTableAt(0x1000 + head.length / 2) + "c3" + "cc".repeat(16));
    assert.equal(decodeX64KeylogWriter(code, 0x1000, synthLiterals), null);
});

// ---- label-site resolution and direct callees ------------------------------------------

test("CLIENT_RANDOM label site: the first call after the site is the writer", () => {
    const site = CLIENT_RANDOM_SITE.subarray(CLIENT_RANDOM_LEA - CLIENT_RANDOM_SITE_VADDR);
    assert.equal(x64FirstCallAfterSite(site, CLIENT_RANDOM_LEA, CLIENT_RANDOM_FN.start, CLIENT_RANDOM_FN.end), WRITER_VADDR);
});

test("ECH_SECRET site calls the writer; ECH_CONFIG site reaches it by tail jmp", () => {
    const from = (lea: number) => ECH_FN.subarray(lea - ECH_FN_VADDR);
    assert.equal(x64FirstCallAfterSite(from(ECH_SECRET_LEA), ECH_SECRET_LEA, ECH_FN_VADDR, ECH_FN_END), WRITER_VADDR);
    assert.equal(x64FirstCallAfterSite(from(ECH_CONFIG_LEA), ECH_CONFIG_LEA, ECH_FN_VADDR, ECH_FN_END), WRITER_VADDR);
    // A jmp whose target lies inside the function is an intra-function jump, not a tail call.
    assert.equal(x64FirstCallAfterSite(from(ECH_CONFIG_LEA), ECH_CONFIG_LEA, WRITER_VADDR, ECH_FN_END), null);
});

test("label-site walk stops at the function end", () => {
    const site = CLIENT_RANDOM_SITE.subarray(CLIENT_RANDOM_LEA - CLIENT_RANDOM_SITE_VADDR);
    assert.equal(x64FirstCallAfterSite(site, CLIENT_RANDOM_LEA, CLIENT_RANDOM_FN.start, 0x2999d5), null);
});

test("writer direct callees: calls plus the tail jmp, not the intra-function jmp", () => {
    const targets = x64DirectCallTargets(WRITER, WRITER_VADDR);
    assert.ok(targets.includes(0x2c41c0));      // first PLT call, listed once
    assert.ok(targets.includes(0x2c4230));      // tail jmp @0x2926a1
    assert.ok(!targets.includes(0x292634));     // jmp @0x2926a8 stays inside
    assert.equal(new Set(targets).size, targets.length);
});

test("the TLS 1.3 wrap calls the writer directly (diagnostic)", () => {
    assert.ok(x64DirectCallTargets(TLS13_WRAP, TLS13_WRAP_VADDR).includes(WRITER_VADDR));
    assert.ok(x64DirectCallTargets(ECH_FN, ECH_FN_VADDR).includes(WRITER_VADDR));
});

// ---- desktop Firefox 160.0.1 Linux x86_64 libssl3.so (NSS not folded) ----------------

const linuxLiterals = textReader((addr, length) =>
    LINUX_HEX_TABLE_OFFSETS.includes(addr) ? NSS_HEX_TABLE.slice(0, length) : "x".repeat(length));

test("linux libssl3: the unrolled writer decodes +0x650 (the odd +0x651 is not a plausible offset)", () => {
    assert.ok(sweepX64(LINUX_WRITER, LINUX_WRITER_VADDR).complete);
    assert.equal(LINUX_WRITER_VADDR + LINUX_WRITER.length, LINUX_WRITER_END);
    assert.deepEqual(decodeX64KeylogWriter(LINUX_WRITER, LINUX_WRITER_VADDR, linuxLiterals),
        { clientRandomOff: LINUX_CLIENT_RANDOM_OFF });
});

test("linux libssl3: CLIENT_RANDOM reaches out-of-line ssl3_RecordKeyLog, which tail-jumps to the writer", () => {
    const fn = LINUX_CLIENT_RANDOM_FN;
    assert.equal(x64FirstCallAfterSite(LINUX_CLIENT_RANDOM_SITE, LINUX_CLIENT_RANDOM_LEA, fn.start, fn.end),
        LINUX_RECORD_KEYLOG_VADDR);
    assert.equal(decodeX64KeylogWriter(LINUX_RECORD_KEYLOG, LINUX_RECORD_KEYLOG_VADDR, linuxLiterals), null);
    assert.ok(x64DirectCallTargets(LINUX_RECORD_KEYLOG, LINUX_RECORD_KEYLOG_VADDR).includes(LINUX_WRITER_VADDR));
});

test("decodeWriter: a function near its readable range end (inside the module) is a definite miss, not unreadable", async () => {
    const { withFakeCodeModule } = await import("./frida-test-stubs.js");
    const { resetReadableCache } = await import("../util/safe_memory.js");
    const { DECODE_UNREADABLE } = await import("./keylog_guards.js");
    const { x64NssLocatorBackend } = await import("./nss_keylog_backend_x64.js");
    resetReadableCache();
    // Module image 0x4000 bytes, only the first 0x200 readable: 0x100 bytes from fn to the range end.
    withFakeCodeModule(0x42000000n, new Uint8Array(0x4000), (mod) => {
        const verdict = x64NssLocatorBackend.decodeWriter(mod.base.add(0x100), mod);
        assert.notEqual(verdict, DECODE_UNREADABLE);
        assert.equal(verdict, null);
    }, 0x200);
    resetReadableCache();
});
