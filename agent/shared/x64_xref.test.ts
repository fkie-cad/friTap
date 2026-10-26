// Unit tests for the pure x86-64 helpers behind the BoringSSL tier-4 anchor
// locator on Windows / Wine PE modules (x64_xref.ts) and the Win64 Span-by-
// reference decision (call_abi.ts).
//
// Run: npm run test:agent
//
// The byte fixtures are real clang-cl output from CEF's libcef.dll:
//   CEF 120.2.7 (Chromium 120.0.6099.234)  ssl_log_secret @ rva 0x1a23fb0
//   CEF 156.0.14 (Chromium 156.0.8078.48)  ssl_log_secret @ rva 0x1ee6970
// (both confirmed against the release PDB symbol
// ?ssl_log_secret@bssl@@YA_NPEBVSSLImpl@1@PEBDV?$Span@$$CBE$0?0@1@@Z).

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    decodeX64CtxKeylogOffsets, findRipLeaRefs, firstCallAfter, X64_REG,
} from "./x64_xref.js";
import { win64SpanIsByReference } from "./call_abi.js";

// ssl_log_secret prologue, CEF 120: push/sub/stack-cookie, then
//   mov rax,[rcx+0x68] ; mov bl,1 ; cmp qword [rax+0x1f0],0 ; jne
const CEF120_PROLOGUE = Uint8Array.from([
    0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x81, 0xec, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x05, 0x75,
    0x70, 0xaa, 0x0a, 0x48, 0x31, 0xe0, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8b,
    0x41, 0x68, 0xb3, 0x01, 0x48, 0x83, 0xb8, 0xf0, 0x01, 0x00, 0x00, 0x00, 0x75, 0x1f, 0x48, 0x8b,
]);

// CEF 156: same shape plus a movaps xmm6 spill; keylog_callback moved to 0x238.
const CEF156_PROLOGUE = Uint8Array.from([
    0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x81, 0xec, 0x88, 0x00, 0x00, 0x00, 0x0f, 0x29, 0x74, 0x24,
    0x70, 0x48, 0x8b, 0x05, 0xb8, 0xe6, 0xf6, 0x0e, 0x48, 0x31, 0xe0, 0x48, 0x89, 0x44, 0x24, 0x68,
    0x48, 0x8b, 0x41, 0x68, 0xb3, 0x01, 0x48, 0x83, 0xb8, 0x38, 0x02, 0x00, 0x00, 0x00, 0x75, 0x35,
]);

// CEF 156 call site @ 0x182ca9f59:
//   lea rdx,[rip+0xd9c0b40]  ; "CLIENT_HANDSHAKE_TRAFFIC_SECRET" @ 0x19066aaa0
//   mov rcx,rsi
//   call 0x181ee6970         ; ssl_log_secret
//   ...
//   lea rax,[rip+0xd9c0b46]  ; an unrelated rodata reference
const CEF156_SITE_VA = 0x182ca9f59;
const CEF156_SITE = Uint8Array.from([
    0x48, 0x8d, 0x15, 0x40, 0x0b, 0x9c, 0x0d, 0x48, 0x89, 0xf1, 0xe8, 0x08, 0xca, 0x23, 0xff, 0x84,
    0xc0, 0x74, 0x7d, 0x4c, 0x8d, 0xb7, 0xb3, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x05, 0x46, 0x0b, 0x9c,
    0x0d, 0x4c, 0x8d, 0x4c, 0x24, 0x40, 0x49, 0x89,
]);
const LABEL_VA = 0x19066aaa0;
const SSL_LOG_SECRET_VA = 0x181ee6970;
const IMAGE_LO = 0x180000000;
const IMAGE_HI = 0x180000000 + 0x11b00000;

test("decodeX64CtxKeylogOffsets: CEF 120 (cmp [rax+0x1f0],0 form, ssl in rcx)", () => {
    assert.deepEqual(decodeX64CtxKeylogOffsets(CEF120_PROLOGUE, X64_REG.rcx), { ctxOff: 0x68, cbOff: 0x1f0 });
});

test("decodeX64CtxKeylogOffsets: CEF 156 (keylog_callback moved to 0x238)", () => {
    assert.deepEqual(decodeX64CtxKeylogOffsets(CEF156_PROLOGUE, X64_REG.rcx), { ctxOff: 0x68, cbOff: 0x238 });
});

test("decodeX64CtxKeylogOffsets: wrong ssl register (SysV rdi) fails closed", () => {
    assert.equal(decodeX64CtxKeylogOffsets(CEF120_PROLOGUE, X64_REG.rdi), null);
});

test("decodeX64CtxKeylogOffsets: SysV load-then-test form", () => {
    // mov rax,[rdi+0x68] ; mov rax,[rax+0x250] ; test rax,rax ; je
    const code = Uint8Array.from([
        0x55, 0x48, 0x89, 0xe5,
        0x48, 0x8b, 0x47, 0x68,
        0x48, 0x8b, 0x80, 0x50, 0x02, 0x00, 0x00,
        0x48, 0x85, 0xc0,
        0x74, 0x10,
    ]);
    assert.deepEqual(decodeX64CtxKeylogOffsets(code, X64_REG.rdi), { ctxOff: 0x68, cbOff: 0x250 });
});

test("decodeX64CtxKeylogOffsets: follows a mov copy of the ssl register", () => {
    // mov rsi,rcx ; mov rax,[rsi+0x68] ; cmp qword [rax+0x1f0],0
    const code = Uint8Array.from([
        0x48, 0x89, 0xce,
        0x48, 0x8b, 0x46, 0x68,
        0x48, 0x83, 0xb8, 0xf0, 0x01, 0x00, 0x00, 0x00,
    ]);
    assert.deepEqual(decodeX64CtxKeylogOffsets(code, X64_REG.rcx), { ctxOff: 0x68, cbOff: 0x1f0 });
});

test("decodeX64CtxKeylogOffsets: cmp against a non-zero immediate is rejected", () => {
    const code = Uint8Array.from([
        0x48, 0x8b, 0x41, 0x68,
        0x48, 0x83, 0xb8, 0xf0, 0x01, 0x00, 0x00, 0x05,
    ]);
    assert.equal(decodeX64CtxKeylogOffsets(code, X64_REG.rcx), null);
});

test("decodeX64CtxKeylogOffsets: implausible ctx offset is rejected", () => {
    // mov rax,[rcx+0x4000] (beyond the ctx-offset bound)
    const code = Uint8Array.from([
        0x48, 0x8b, 0x81, 0x00, 0x40, 0x00, 0x00,
        0x48, 0x83, 0xb8, 0xf0, 0x01, 0x00, 0x00, 0x00,
    ]);
    assert.equal(decodeX64CtxKeylogOffsets(code, X64_REG.rcx), null);
});

test("findRipLeaRefs: finds the real CEF 156 label LEA and its register (rdx)", () => {
    const refs = findRipLeaRefs(CEF156_SITE, CEF156_SITE_VA, new Set([LABEL_VA]));
    assert.deepEqual(refs, [{ site: CEF156_SITE_VA, target: LABEL_VA, reg: X64_REG.rdx }]);
});

test("findRipLeaRefs: ignores LEAs to other targets", () => {
    assert.deepEqual(findRipLeaRefs(CEF156_SITE, CEF156_SITE_VA, new Set([0x1234])), []);
});

test("findRipLeaRefs: scanEnd excludes LEAs starting in the overlap tail", () => {
    assert.deepEqual(findRipLeaRefs(CEF156_SITE, CEF156_SITE_VA, new Set([LABEL_VA]), 0), []);
});

test("findRipLeaRefs: negative displacement", () => {
    // lea rdx,[rip-0x10] at va 0x1000 -> target 0x1000 + 7 - 0x10 = 0xff7
    const code = Uint8Array.from([0x48, 0x8d, 0x15, 0xf0, 0xff, 0xff, 0xff]);
    assert.deepEqual(findRipLeaRefs(code, 0x1000, new Set([0xff7])), [{ site: 0x1000, target: 0xff7, reg: X64_REG.rdx }]);
});

test("findRipLeaRefs: REX.R LEA (lea r8, ...) reports reg 8", () => {
    const code = Uint8Array.from([0x4c, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00]);
    assert.deepEqual(findRipLeaRefs(code, 0x2000, new Set([0x2007])), [{ site: 0x2000, target: 0x2007, reg: 8 }]);
});

test("firstCallAfter: resolves the real CEF 156 call to ssl_log_secret", () => {
    assert.equal(firstCallAfter(CEF156_SITE, CEF156_SITE_VA, 0, IMAGE_LO, IMAGE_HI), SSL_LOG_SECRET_VA);
});

test("firstCallAfter: callee outside the module is skipped", () => {
    assert.equal(firstCallAfter(CEF156_SITE, CEF156_SITE_VA, 0, IMAGE_LO, SSL_LOG_SECRET_VA), null);
});

test("firstCallAfter: no call within the window", () => {
    const code = new Uint8Array(80); // all zeros: no E8
    code.set([0x48, 0x8d, 0x15, 0, 0, 0, 0], 0);
    assert.equal(firstCallAfter(code, 0x1000, 0, 0, 0x100000), null);
});

test("win64SpanIsByReference: real secret sizes are by reference", () => {
    assert.equal(win64SpanIsByReference(32), true);
    assert.equal(win64SpanIsByReference(48), true);
});

test("win64SpanIsByReference: secret bytes / unreadable / zero fall back to scalar", () => {
    assert.equal(win64SpanIsByReference(0x9a3c55e1d00f7a21), false);
    assert.equal(win64SpanIsByReference(null), false);
    assert.equal(win64SpanIsByReference(0), false);
    assert.equal(win64SpanIsByReference(65), false);
});

test("findRipLeaRefs: several LEAs in one buffer, only target hits reported", () => {
    const code = Uint8Array.from([
        0x90, 0x8d, // stray 0x8d without REX at offset 1
        0x48, 0x8d, 0x15, 0x10, 0x00, 0x00, 0x00, // lea rdx,[rip+0x10] @ +2 -> +0x19
        0x48, 0x8d, 0x0d, 0x20, 0x00, 0x00, 0x00, // lea rcx,[rip+0x20] @ +9 -> +0x30
        0x4c, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00, // lea r8,[rip+0x100] @ +16 (not a target)
    ]);
    const va = 0x5000;
    assert.deepEqual(findRipLeaRefs(code, va, new Set([va + 0x19, va + 0x30])), [
        { site: va + 2, target: va + 0x19, reg: X64_REG.rdx },
        { site: va + 9, target: va + 0x30, reg: X64_REG.rcx },
    ]);
});
