// Unit tests for the Win64 -> System V thunk encoder (win64_thunk.ts).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import { win64ToSysvThunkBytes } from "./win64_thunk.js";

const hex = (b: number[]) => b.map((x) => x.toString(16).padStart(2, "0")).join(" ");

test("win64ToSysvThunkBytes: two-arg thunk layout", () => {
    const b = win64ToSysvThunkBytes("0x7f0011223344", 2);
    const h = hex(b);
    assert.ok(h.startsWith("57 56 48 81 ec a8 00 00 00"), "push rdi; push rsi; sub rsp,0xa8");
    // xmm6 stored at [rsp+0], xmm15 at [rsp+0x90] (REX.R form).
    assert.ok(h.includes("f3 0f 7f b4 24 00 00 00 00"), "movdqu [rsp], xmm6");
    assert.ok(h.includes("f3 44 0f 7f bc 24 90 00 00 00"), "movdqu [rsp+0x90], xmm15");
    assert.ok(h.includes("48 89 cf 48 89 d6 48 b8 44 33 22 11 00 7f 00 00 ff d0"),
        "mov rdi,rcx; mov rsi,rdx; mov rax,target; call rax");
    assert.ok(!h.includes("4c 89 c2"), "no third-argument move");
    assert.ok(h.includes("f3 0f 6f b4 24 00 00 00 00"), "movdqu xmm6, [rsp]");
    assert.ok(h.endsWith("48 81 c4 a8 00 00 00 5e 5f c3"), "add rsp,0xa8; pop rsi; pop rdi; ret");
});

test("win64ToSysvThunkBytes: four-arg moves keep sources intact", () => {
    const h = hex(win64ToSysvThunkBytes("0x1000", 4));
    // rdi<-rcx and rsi<-rdx BEFORE rdx<-r8 and rcx<-r9.
    assert.ok(h.includes("48 89 cf 48 89 d6 4c 89 c2 4c 89 c9 48 b8"));
});

test("win64ToSysvThunkBytes: stack stays 16-byte aligned at the inner call", () => {
    // entry rsp = 8 (mod 16); two pushes (16) + frame must be = 8 (mod 16).
    const b = win64ToSysvThunkBytes("0x1000", 2);
    const frame = b[5] | (b[6] << 8) | (b[7] << 16) | (b[8] << 24);
    assert.equal((8 + 16 + frame) % 16, 0);
});

test("win64ToSysvThunkBytes: rejects more than four args", () => {
    assert.throws(() => win64ToSysvThunkBytes("0x1000", 5));
});
