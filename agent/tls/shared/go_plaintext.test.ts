// Unit tests for the onEnter-only Go crypto/tls plaintext hooks (agent/tls/shared/go_plaintext.ts)
// and their wiring in the modern Go definition (agent/tls/definitions/gotls.ts).
//
// Run: npm run test:agent
//
// WHY: the modern definition attached the generic SSL_read/SSL_write executors to
// (*Conn).Read/(*Conn).Write: onLeave on a Go function (a goroutine blocked in the socket
// call can resume on another OS thread -> Frida invocation-stack mismatch; the swapped return
// address breaks Go's unwinder) and Frida's C args[] (rdi/rsi/rdx on x64), which are not Go's
// parameters. Writes now hook writeRecordLocked at entry; reads probe the runtime.memmove call
// inside (*Conn).Read — whose registers hold exactly the plaintext Read returns.
// Layouts were checked against a Go 1.21 darwin/arm64 build (objdump + live Frida probe).

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { installFakes, call, take, takeMessages, addr, mem, int } from "../../shared/write_hook_fakes.js";

import { findGoCallSite, goDefaultFdMessageBuilder, installGoConnReadHook, installGoPlaintextHooks, installGoWriteRecordHook } from "./go_plaintext.js";
import { createGoTlsDefinition } from "../definitions/gotls.js";

installFakes();
const G = globalThis as any;

/** A numeric fake NativePointer (enough surface for the call-site scan). */
function P(n: number): any {
    return {
        value: n, isNull: () => n === 0, toString: () => `0x${n.toString(16)}`,
        add: (k: any) => P(n + Number(k)), sub: (o: any) => P(n - (typeof o === "number" ? o : o.value)),
        compare: (o: any) => (n < o.value ? -1 : n > o.value ? 1 : 0), equals: (o: any) => o?.value === n,
    };
}

/** Fake disassembly: address -> [size, mnemonic, opStr]. */
function program(insns: Array<[number, number, string, string]>): void {
    const byAddress = new Map(insns.map(([at, size, mnemonic, opStr]) => [at, { size, mnemonic, opStr }]));
    G.Instruction = {
        parse: (p: any) => {
            const i = byAddress.get(p.value);
            if (!i) throw new Error(`invalid instruction at ${p}`);
            return { mnemonic: i.mnemonic, opStr: i.opStr, next: P(p.value + i.size) };
        },
    };
}
G.ptr = (s: string) => P(parseInt(s, 16));

const READ_FN = 0x1000, MEMMOVE = 0x9000;

test("findGoCallSite: arm64 (*Conn).Read — the one bl runtime.memmove, scan ends at the morestack trailer", () => {
    program([
        [0x1000, 4, "ldr", "x16, [x28, #0x10]"],
        [0x1004, 4, "bl", "#0x5000"],           // readRecordOrCCS
        [0x1008, 4, "b.eq", "#0x1010"],
        [0x100c, 4, "bl", "#0x9000"],           // the inlined bytes.Reader.Read copy
        [0x1010, 4, "ret", ""],
        [0x1014, 4, "bl", "#0x7000"],           // morestack_noctxt
        [0x1018, 4, "b", "#0x1000"],            // trailer: back to the entry
        [0x101c, 4, "bl", "#0x9000"],           // the NEXT function: must not count
    ]);
    assert.equal(findGoCallSite(P(READ_FN), P(MEMMOVE))?.value, 0x100c);
});

test("findGoCallSite: x64 call rel32; ambiguous (two copies) or absent -> null", () => {
    program([
        [0x1000, 5, "call", "0x9000"],
        [0x1005, 5, "call", "0x9000"],
        [0x100a, 5, "jmp", "0x1000"],
    ]);
    assert.equal(findGoCallSite(P(READ_FN), P(MEMMOVE)), null, "two memmove calls: ambiguous");
    program([[0x1000, 5, "call", "0x8000"], [0x1005, 5, "jmp", "0x1000"]]);
    assert.equal(findGoCallSite(P(READ_FN), P(MEMMOVE)), null);
    program([[0x1000, 5, "call", "0x9000"]]); // undecodable after: stop, keep what was seen
    assert.equal(findGoCallSite(P(READ_FN), P(MEMMOVE))?.value, 0x1000);
});

/** writeRecordLocked(c, typ, data.ptr, data.len, data.cap) / memmove(to, from, n) registers. */
const REGS: { [arch: string]: string[] } = { x64: ["rax", "rbx", "rcx", "rdi", "rsi"], arm64: ["x0", "x1", "x2", "x3", "x4"] };
function goContext(arch: string, values: any[]): any {
    const ctx: any = {};
    REGS[arch].forEach((r, i) => { ctx[r] = values[i]; });
    return ctx;
}
const builder = (isRead: boolean) => ({ function: isRead ? "Go_Conn_Read" : "Go_Conn_Write" });

test("write/read probes emit exactly the Go-register plaintext, from onEnter only", () => {
    installGoWriteRecordHook(addr("go_wrl"), builder);
    program([[0x2000, 4, "bl", "#0x9000"], [0x2004, 4, "b", "#0x2000"]]);
    assert.ok(installGoConnReadHook(P(0x2000), P(MEMMOVE), builder));
    for (const arch of ["x64", "arm64"]) {
        G.Process.arch = arch;
        call("go_wrl", [int(0), int(0), int(0)], 0, goContext(arch, [addr("conn"), int(0x1700 | 23), mem("GET / HTTP/1.1\r\n\r\n"), int(18), int(32)]));
        call("go_wrl", [], 0, goContext(arch, [addr("conn"), int(22), mem("hs"), int(2), int(2)])); // handshake: skipped
        // memmove(to=b, from=decrypted record + i, n): `from` holds the plaintext, `to` is not written yet.
        call("2000", [], 0, goContext(arch, [mem("\0\0\0\0\0"), mem("HTTP/1.1 200 OK...rest"), int(15)]));
        call("2000", [], 0, goContext(arch, [mem("x"), mem("x"), int(0)])); // empty copy
        const messages = takeMessages();
        assert.deepEqual(messages.map((m) => m.function), ["Go_Conn_Write", "Go_Conn_Read"]);
    }
    for (const arch of ["x64", "arm64"]) {
        G.Process.arch = arch;
        call("2000", [], 0, goContext(arch, [mem("....."), mem("HTTP/1.1 200 OK...rest"), int(15)]));
    }
    assert.deepEqual(take(), ["HTTP/1.1 200 OK", "HTTP/1.1 200 OK"]);
    G.Process.arch = "x64";
});

test("the modern Go definition uses no generic (onLeave, C-args) read/write executors", () => {
    const def = createGoTlsDefinition();
    assert.equal(def.readHook, undefined);
    assert.equal(def.writeHook, undefined);
    assert.equal(def.extraHooks?.length, 1);
});

test("definition plaintext hooks: onEnter-only, unattributable without --enable_default_fd", () => {
    const def = createGoTlsDefinition();
    const attached: any[] = [];
    const realAttach = G.Interceptor.attach;
    G.Interceptor.attach = (target: any, callbacks: any) => { attached.push(callbacks); return realAttach(target, callbacks); };
    program([[0x3000, 4, "bl", "#0x9000"], [0x3004, 4, "b", "#0x3000"]]);
    const addresses = { "app.go1.22": {
        "crypto/tls.(*Conn).writeRecordLocked": addr("def_wrl"),
        "crypto/tls.(*Conn).Read": P(0x3000),
        "runtime.memmove": P(MEMMOVE),
    } };
    def.extraHooks![0].install(addresses, "app.go1.22", {}, false);
    G.Interceptor.attach = realAttach;
    assert.equal(attached.length, 2);
    assert.ok(attached.every((c) => c.onEnter && !c.onLeave), "no onLeave on Go code");
    call("def_wrl", [], 0, goContext("x64", [addr("conn"), int(23), mem("hello"), int(5), int(5)]));
    assert.deepEqual(take(), [], "no fd and no --enable_default_fd: not attributable");

    // --enable_default_fd: the synthesized 5-tuple (a *tls.Conn exposes no fd).
    def.extraHooks![0].install(addresses, "app.go1.22", {}, true);
    call("def_wrl", [], 0, goContext("x64", [addr("conn"), int(23), mem("hello"), int(5), int(5)]));
    call("3000", [], 0, goContext("x64", [mem("....."), mem("world"), int(5)]));
    const messages = takeMessages();
    assert.deepEqual(messages.map((m) => [m.function, m.dst_port]), [["Go_Conn_Write", 2345], ["Go_Conn_Read", 2345]]);
});

test("shared installer (legacy + modern): stripped module without Go symbols installs nothing, never throws", () => {
    const attached: any[] = [];
    const realAttach = G.Interceptor.attach;
    G.Interceptor.attach = (target: any, callbacks: any) => { attached.push(callbacks); return realAttach(target, callbacks); };
    try {
        installGoPlaintextHooks("stripped.exe", {}, true);
        installGoPlaintextHooks("partial.exe", { "crypto/tls.(*Conn).Read": P(0x3000) }, true); // no memmove
    } finally {
        G.Interceptor.attach = realAttach;
    }
    assert.equal(attached.length, 0);
});

test("goDefaultFdMessageBuilder: null without -ed; with -ed the synthesized tuple and Go labels", () => {
    assert.equal(goDefaultFdMessageBuilder(false)(true), null);
    const build = goDefaultFdMessageBuilder(true);
    assert.equal(build(true)?.function, "Go_Conn_Read");
    assert.equal(build(false)?.function, "Go_Conn_Write");
    assert.equal(build(false)?.ssl_session_id, "");
});

test("386/arm (stack ABI): the Go plaintext probes are not installed (keys only)", () => {
    for (const arch of ["ia32", "arm"]) {
        G.Process.arch = arch;
        installGoWriteRecordHook(addr(`go_wrl_${arch}`), builder);
        assert.throws(() => call(`go_wrl_${arch}`, [], 0, {}), /no listener attached/);
        assert.equal(installGoConnReadHook(P(0x7000), P(MEMMOVE), builder), false);
    }
    G.Process.arch = "x64";
});

// alt 19: 32-bit Go captures were silently keys-only (only a devlog said why), which reads
// like a hooking failure. The definition now warns the user once per module.
test("definition on 386/arm: no plaintext probes and one user-visible warning per module", () => {
    const def = createGoTlsDefinition();
    const consoleLines: string[] = [];
    const realSend = G.send;
    const realAttach = G.Interceptor.attach;
    let attached = 0;
    G.send = (message: any, data?: any) => {
        if (message?.contentType === "console") consoleLines.push(message.console);
        return realSend(message, data);
    };
    G.Interceptor.attach = (t: any, c: any) => { attached++; return realAttach(t, c); };
    const addresses = { "app32.go": { "crypto/tls.(*Conn).writeRecordLocked": addr("wrl32") } };
    try {
        G.Process.arch = "arm";
        def.extraHooks![0].install(addresses, "app32.go", {}, true);
        def.extraHooks![0].install(addresses, "app32.go", {}, true);
        G.Process.arch = "ia32";
        def.extraHooks![0].install({ "other32.go": {} }, "other32.go", {}, true);
    } finally {
        G.Process.arch = "x64";
        G.send = realSend;
        G.Interceptor.attach = realAttach;
    }
    assert.equal(attached, 0);
    assert.deepEqual(consoleLines, [
        "[!] app32.go: Go TLS plaintext is not captured on 32-bit Go (arm); keys only",
        "[!] other32.go: Go TLS plaintext is not captured on 32-bit Go (ia32); keys only",
    ]);
});

// Moved from the removed GoTLS.install_plaintext_write_hook tests (legacy gotls_write.test.ts):
// the shared write probe replaced that never-installed method.
test("writeRecordLocked: handshake/CCS/alert records and empty writes are skipped; C args[] are ignored", () => {
    installGoWriteRecordHook(addr("go_wrl_skip"), builder);
    for (const arch of ["x64", "arm64"]) {
        G.Process.arch = arch;
        for (const typ of [20, 21, 22]) call("go_wrl_skip", [], 0, goContext(arch, [addr("conn"), int(typ), mem("hs"), int(2), int(2)]));
        call("go_wrl_skip", [], 0, goContext(arch, [addr("conn"), int(23), mem(""), int(0), int(0)]));
        assert.deepEqual(take(), []);
        // Frida's C args[] hold garbage: only the Go registers are read.
        call("go_wrl_skip", [int(22), int(0), int(0)], 0, goContext(arch, [addr("conn"), int(23), mem("GET /healthz"), int(12), int(16)]));
        assert.deepEqual(take(), ["GET /healthz"]);
    }
    G.Process.arch = "x64";
});
