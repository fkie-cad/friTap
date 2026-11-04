// Unit tests for the shared Go writeKeyLog hook (agent/tls/shared/go_keylog_hook.ts) on its
// pattern-based path: stripped Go binaries, where writeKeyLog is located by byte pattern by
// either PatternBasedHooking copy (tls/shared: Linux, legacy/tls/shared: Android).
//
// Run: npm run test:agent
//
// WHY: the legacy Linux/Android pattern callbacks decoded writeKeyLog from Frida's C
// args[2..8] (label=args[2]/[3], clientRandom=args[4]/[5], secret=args[7]/[8]). Go's
// ABIInternal passes c=X0/RAX, label=X1/X2 (RBX/RCX), clientRandom=X3/X4 (RDI/RSI),
// secret=X6/X7 (R9/R10), so on arm64 args[2] was the label LENGTH used as a pointer and
// on x64 args[2] is RDX (not a Go argument register at all): no correct key was ever logged
// from a stripped Go binary. The pattern path now installs the same register-based hook as
// the symbol path, attached via attachGoFunctionEntry (arm64: after the stack check).

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { installFakes, listener, addr } from "../../shared/write_hook_fakes.js";
import { setKeylogEnabled } from "../../shared/shared_structures.js";

import { installGoKeylogByPattern } from "./go_keylog_hook.js";
import { PatternBasedHooking } from "./pattern_based_hooking.js";
import { PatternBasedHooking as LegacyPatternBasedHooking } from "../../legacy/tls/shared/pattern_based_hooking.js";
import { isGoArm64StackGuardLoad } from "../../shared/go_attach.js";
import { GoTLS_Linux } from "../../legacy/tls/platforms/linux/gotls_linux.js";
import { GoTLS_Android } from "../../legacy/tls/platforms/android/gotls_android.js";
import { GoTLS as LegacyGoTLS } from "../../legacy/tls/libs/gotls.js";
import { GoTLS as ModernGoTLS, gotls_execute_class_based } from "../libs/gotls.js";
import { BORINGSSL_SSL_LOG_SECRET_MANGLED } from "../../shared/boringssl_symbol_hook.js";
import { createGoTlsDefinition } from "../definitions/gotls.js";

installFakes();
setKeylogEnabled(true);
const G = globalThis as any;
const keylogs: string[] = [];
const fakeSend = G.send;
G.send = (message: any, data?: any) => {
    if (message?.contentType === "keylog") keylogs.push(message.keylog);
    return fakeSend(message, data);
};

/** A register value usable both as a length and as a pointer to `bytes`. */
function reg(n: number, bytes?: Buffer): any {
    return {
        value: n, isNull: () => n === 0, toInt32: () => n | 0, toUInt32: () => n >>> 0,
        readUtf8String: (len: number) => { if (!bytes) throw new Error(`access violation at 0x${n.toString(16)}`); return bytes.subarray(0, len).toString(); },
        readCString: () => { if (!bytes) throw new Error(`access violation at 0x${n.toString(16)}`); return bytes.toString(); },
        readByteArray: (len: number) => { if (!bytes) throw new Error(`access violation at 0x${n.toString(16)}`); return new Uint8Array(bytes.subarray(0, len)).buffer; },
    };
}
const LABEL = Buffer.from("SERVER_HANDSHAKE_TRAFFIC_SECRET");
const CR = Buffer.alloc(32, 0xc1);
const SECRET = Buffer.alloc(48, 0x3f);
const EXPECTED = `SERVER_HANDSHAKE_TRAFFIC_SECRET ${"c1".repeat(32)} ${"3f".repeat(48)}`;

/** writeKeyLog's Go argument registers at entry; C-ABI-only registers hold garbage. */
function writeKeyLogContext(arch: string): any {
    const names = arch === "x64"
        ? ["rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11"]
        : ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8"];
    const values = [reg(0xc000), reg(0x1000, LABEL), reg(LABEL.length), reg(0x2000, CR), reg(32), reg(32),
                    reg(0x3000, SECRET), reg(48), reg(64)];
    const ctx: any = arch === "x64" ? { rdx: reg(0xdead) } : {};
    names.forEach((n, i) => { ctx[n] = values[i]; });
    return ctx;
}

/**
 * The same call on a stack-ABI arch (386/arm) at entry: sp+0 is the return address / saved-LR
 * slot, the 9 argument words follow at sp+4, sp+8, ... The argument registers hold garbage.
 */
function stackWriteKeyLogContext(): any {
    const words = [reg(0x8badf00d), reg(0xc000), reg(0x1000, LABEL), reg(LABEL.length), reg(0x2000, CR), reg(32), reg(32),
                   reg(0x3000, SECRET), reg(48), reg(64)];
    const sp = { add: (offset: number) => ({ readPointer: () => words[offset / 4] }) };
    return { sp, eax: reg(0xdead), r0: reg(0xdead), r1: reg(0xdead) };
}

/** Frida's C args[] for the same call: what the old callbacks read (args[2..8]). */
function cArgs(ctx: any, arch: string): any[] {
    const order = arch === "x64" ? ["rdi", "rsi", "rdx", "rcx", "r8", "r9"] : ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8"];
    return order.map((r) => ctx[r] ?? reg(0));
}

function fakeModule(name: string): any {
    return { name, base: addr(`${name}_base`), size: 0x1000, enumerateRanges: () => [] };
}

/** Memory.scan reports one match per scan at `matchName`, then completes. */
function scanMatches(matchName: string): string[] {
    const scanned: string[] = [];
    G.Memory.scan = (_base: any, _size: number, pattern: string, callbacks: any) => {
        scanned.push(pattern);
        callbacks.onMatch(addr(matchName), 4);
        callbacks.onComplete();
    };
    return scanned;
}

function replay(matchName: string, arch: string): void {
    G.Process.arch = arch;
    const ctx = writeKeyLogContext(arch);
    listener(matchName).onEnter.call({ context: ctx }, cArgs(ctx, arch));
    G.Process.arch = "x64";
}

/** The shared pattern path on a fake module, scanning with `Hooker` and the x64 `primary`. */
function installByPattern(Hooker: any, primary: string): any {
    return installGoKeylogByPattern("app.go1.24", { x64: { primary, fallback: "" } },
        { module: fakeModule("app.go1.24"), newHooker: (m) => new Hooker(m) });
}

for (const [label, Hooker] of [["tls/shared", PatternBasedHooking], ["legacy/tls/shared", LegacyPatternBasedHooking]] as const) {
    test(`${label}: a pattern-located writeKeyLog logs the key from the Go registers (arm64 + x64)`, () => {
        const match = `wkl_pattern_${label}`;
        const scanned = scanMatches(match);
        const hooker = installByPattern(Hooker, "90 0B 40 F9");
        assert.ok(hooker instanceof Hooker, "scanned by the requested PatternBasedHooking copy");
        assert.deepEqual(scanned, ["90 0B 40 F9"]);
        replay(match, "arm64");
        replay(match, "x64");
        assert.deepEqual(keylogs.splice(0), [EXPECTED, EXPECTED]);
    });

    test(`${label}: arm32/ia32 (stack ABI) decode writeKeyLog from the stack words at sp+4`, () => {
        const match = `wkl_pattern_stack_${label}`;
        scanMatches(match);
        installByPattern(Hooker, "AA");
        for (const arch of ["arm", "ia32"]) {
            G.Process.arch = arch;
            listener(match).onEnter.call({ context: stackWriteKeyLogContext() }, []);
        }
        G.Process.arch = "x64";
        assert.deepEqual(keylogs.splice(0), [EXPECTED, EXPECTED]);
    });

    test(`${label}: implausible arguments (registers or stack) emit nothing`, () => {
        const match = `wkl_pattern_none_${label}`;
        scanMatches(match);
        installByPattern(Hooker, "AA");
        G.Process.arch = "arm";
        listener(match).onEnter.call({ context: { r0: reg(1), r1: reg(0x1000, LABEL), r2: reg(5) } }, []); // no sp
        const ctx = stackWriteKeyLogContext();
        const sp = ctx.sp;
        ctx.sp = { add: (offset: number) => (offset === 4 * 8 ? { readPointer: () => reg(0x7fffffff) } : sp.add(offset)) };
        listener(match).onEnter.call({ context: ctx }, []); // implausible secret length on the stack
        G.Process.arch = "arm64";
        listener(match).onEnter.call({ context: { ...writeKeyLogContext("arm64"), x7: reg(0x7fffffff) } }, []);
        G.Process.arch = "x64";
        assert.deepEqual(keylogs.splice(0), []);
    });
}

// The --experimental gate for Go pattern hooking on Android lives in installGoKeylogByPattern
// now (shared by the modern definition and both legacy classes).
test("installGoKeylogByPattern: Android without --experimental scans nothing; elsewhere it scans", () => {
    const scanned = scanMatches("wkl_gate");
    const java = G.Java;
    const saved = { available: java.available, androidVersion: java.androidVersion };
    try {
        java.available = true;
        java.androidVersion = "14";
        assert.equal(installByPattern(PatternBasedHooking, "AA"), null);
        assert.deepEqual(scanned, []);
    } finally {
        Object.assign(java, saved);
    }
    assert.notEqual(installByPattern(PatternBasedHooking, "AA"), null);
    assert.deepEqual(scanned, ["AA"]);
    assert.equal(installGoKeylogByPattern("app_not_loaded", { x64: { primary: "AA", fallback: "" } }, { module: null }), null,
        "module not loaded");
});

// simp 5: the Go stack-check placement is not a per-instance override any more — every
// onEnter pattern hook goes through go_attach, which only moves Go arm64 entries.
test("pattern hooks on arm64: a Go entry is hooked after its stack check, a C match at the match", () => {
    const words: Record<number, number> = { 0x1000: 0xf9400b90, 0x2000: 0xa9bf7bfd };
    const P = (n: number): any => ({
        value: n, isNull: () => false, toString: () => `0x${n.toString(16)}`, add: (k: number) => P(n + k),
        readU32: () => words[n],
    });
    const insns: Record<number, [string, string]> = { 0x1004: ["sub", "x17, sp, #0x30"], 0x1008: ["cmp", "x17, x16"], 0x100c: ["b.ls", "#0x1208"] };
    const parse = G.Instruction?.parse;
    const realAttach = G.Interceptor.attach;
    const attachedAt: number[] = [];
    G.Instruction = { ...(G.Instruction ?? {}), parse: (p: any) => {
        const i = insns[p.value];
        if (!i) throw new Error("invalid instruction");
        return { mnemonic: i[0], opStr: i[1], next: P(p.value + 4) };
    } };
    G.Interceptor.attach = (t: any, _c: any) => { attachedAt.push(t.value); return { detach: () => { } }; };
    for (const match of [0x1000, 0x2000]) {
        G.Memory.scan = (_b: any, _s: number, _p: string, cb: any) => { cb.onMatch(P(match), 4); cb.onComplete(); };
        for (const Hooker of [PatternBasedHooking, LegacyPatternBasedHooking]) {
            G.Process.arch = "arm64";
            try {
                new (Hooker as any)(fakeModule("app_arm64")).hookModuleByPattern({ primary: "AA", fallback: "" }, () => { });
            } finally {
                G.Process.arch = "x64";
            }
        }
    }
    G.Interceptor.attach = realAttach;
    if (parse) G.Instruction.parse = parse;
    assert.deepEqual(attachedAt, [0x1010, 0x1010, 0x2000, 0x2000]);
});

for (const [label, Hooker] of [["legacy Linux", GoTLS_Linux], ["modern (tls/libs)", ModernGoTLS]] as const)
test(`${label} GoTLS: stripped binary (no writeKeyLog symbol) hooks the pattern match with the Go register decoder`, () => {
    const moduleName = `app_stripped_${label}.go1.24`;
    const module = fakeModule(moduleName);
    const findModule = G.Process.findModuleByName;
    G.Process.findModuleByName = (name: string) => (name === moduleName ? module : null);
    const match = `wkl_stripped_${label}`;
    const scanned = scanMatches(match);
    try {
        const gotls: any = new (Hooker as any)(moduleName, "libc", false);
        delete gotls.addresses[moduleName]["crypto/tls.(*Config).writeKeyLog"];
        gotls.install_key_extraction_hook();
        assert.equal(scanned.length, 1, "scanned with the shipped x64 default pattern");
        replay(match, "arm64");
        replay(match, "x64");
        assert.deepEqual(keylogs.splice(0), [EXPECTED, EXPECTED]);
    } finally {
        G.Process.findModuleByName = findModule;
    }
});

test("modern Go definition: unresolved writeKeyLog (stripped) scans the Go patterns and hooks the match", () => {
    const moduleName = "app_cgo_stripped.go1.24";
    const findModule = G.Process.findModuleByName;
    G.Process.findModuleByName = (name: string) => (name === moduleName ? fakeModule(moduleName) : null);
    const scanned = scanMatches("wkl_modern_stripped");
    try {
        const def = createGoTlsDefinition();
        const installed = (def.keylog as any).install({ [moduleName]: {} }, moduleName, {}, false);
        assert.equal(installed, true);
        assert.equal(scanned.length, 1, "scanned with GO_WRITE_KEYLOG_PATTERNS (x64)");
        replay("wkl_modern_stripped", "arm64");
        replay("wkl_modern_stripped", "x64");
        assert.deepEqual(keylogs.splice(0), [EXPECTED, EXPECTED]);
    } finally {
        G.Process.findModuleByName = findModule;
    }
});

test("isGoArm64StackGuardLoad: accepts exactly ldr x16, [x28, #0x10] (the pattern gate lets Go entries through)", () => {
    assert.equal(isGoArm64StackGuardLoad(0xf9400b90), true);
    assert.equal(isGoArm64StackGuardLoad(0xf9400b91), false, "ldr x17");
    assert.equal(isGoArm64StackGuardLoad(0xa9bf7bfd), false, "stp x29, x30 (C prologue)");
});

// WHY: the legacy Linux GoTLS class extended the tls/libs GoTLS copy, which (unlike the legacy
// copy Android uses) never checks keylog_enabled — and both platform classes override
// install_key_extraction_hook, so the stripped (pattern) path ignored -k on both platforms.
test("legacy Linux GoTLS extends the legacy hooker (the keylog_enabled-aware copy), like Android", () => {
    assert.equal(Object.getPrototypeOf(GoTLS_Linux.prototype), LegacyGoTLS.prototype);
    assert.equal(Object.getPrototypeOf(GoTLS_Android.prototype), LegacyGoTLS.prototype);
});

for (const [label, Platform] of [["legacy Linux", GoTLS_Linux], ["legacy Android", GoTLS_Android], ["modern (tls/libs)", ModernGoTLS]] as const) {
    test(`${label} GoTLS: no key hooks without -k (stripped pattern path and symbol path)`, () => {
        const moduleName = `app_nokeys_${label.replace(/\W/g, "_")}`;
        const findModule = G.Process.findModuleByName;
        G.Process.findModuleByName = (name: string) => (name === moduleName ? fakeModule(moduleName) : null);
        const scanned = scanMatches(`wkl_nokeys_${label}`);
        const realAttach = G.Interceptor.attach;
        let attached = 0;
        G.Interceptor.attach = (t: any, c: any) => { attached++; return realAttach(t, c); };
        setKeylogEnabled(false);
        try {
            const gotls: any = new (Platform as any)(moduleName, "libc", false);
            delete gotls.addresses[moduleName]["crypto/tls.(*Config).writeKeyLog"];
            assert.equal(gotls.install_key_extraction_hook(), undefined, "stripped: no pattern hooker");
            gotls.addresses[moduleName]["crypto/tls.(*Config).writeKeyLog"] = addr(`wkl_sym_${label}`);
            gotls.install_key_extraction_hook();
            assert.deepEqual(scanned, []);
            assert.equal(attached, 0);
        } finally {
            setKeylogEnabled(true);
            G.Interceptor.attach = realAttach;
            G.Process.findModuleByName = findModule;
        }
    });

    // WHY: the fallback hooked the FIRST symbol containing "ssl_log" and read Go-style
    // args[2..8] (label/clientRandom/secret ptr+len pairs) from it. No Go function is named
    // ssl_log*: the symbols are C BoringSSL's (bssl::ssl_log_secret(ssl, label, secret, len),
    // and e.g. ssl_log_rsa_client_key_exchange) — so a C function was decoded with Go indices.
    test(`${label} GoTLS: the ssl_log fallback hooks C bssl::ssl_log_secret with the C ABI`, () => {
        const moduleName = `app_cgo_boringssl_${label.replace(/\W/g, "_")}`;
        const module = {
            ...fakeModule(moduleName),
            enumerateSymbols: () => [
                { name: "ssl_log_rsa_client_key_exchange", type: "function", address: addr(`rsa_${label}`) },
                { name: BORINGSSL_SSL_LOG_SECRET_MANGLED[0], type: "function", address: addr(`sls_${label}`) },
            ],
            enumerateExports: () => [],
        };
        const getModule = G.Process.getModuleByName;
        G.Process.getModuleByName = (name: string) => { if (name !== moduleName) throw new Error("not loaded"); return module; };
        try {
            const gotls: any = new (Platform as any)(moduleName, "libc", false);
            gotls.execute_symbol_based_hooking({ no_hooking_success: false });
            assert.throws(() => listener(`sls_${label}`), /no listener/, "writeKeyLog pattern hooked: no fallback");
            gotls.execute_symbol_based_hooking({ no_hooking_success: true });
            assert.throws(() => listener(`rsa_${label}`), /no listener/, "not the first ssl_log* symbol");
            // x64 SysV: ssl_log_secret(ssl=rdi, label=rsi, secret=rdx, len=rcx)
            const ssl = { isNull: () => false, toString: () => "0x5510", add: () => { throw new Error("unmapped"); } };
            const ctx = { rdi: ssl, rsi: reg(0x1000, Buffer.from("CLIENT_TRAFFIC_SECRET_0")), rdx: reg(0x3000, SECRET), rcx: reg(48) };
            G.Process.arch = "x64";
            listener(`sls_${label}`).onEnter.call({ context: ctx }, [ctx.rdi, ctx.rsi, ctx.rdx, ctx.rcx]);
            const [line] = keylogs.splice(0);
            assert.match(line, new RegExp(`^CLIENT_TRAFFIC_SECRET_0 .* ${"3f".repeat(48)}$`, "i"));
        } finally {
            G.Process.getModuleByName = getModule;
        }
    });
}

// The modern class-based executor (the fallback of gotls_execute_modern) is keys-only and -k gated.
test("modern gotls_execute_class_based: no hooks without -k; with -k a stripped module is pattern-scanned", () => {
    const moduleName = "app_class_based.go1.24";
    const findModule = G.Process.findModuleByName;
    G.Process.findModuleByName = (name: string) => (name === moduleName ? fakeModule(moduleName) : null);
    const scanned = scanMatches("wkl_class_based");
    const realSetTimeout = G.setTimeout;
    G.setTimeout = () => 0; // the cgo BoringSSL last resort is covered above
    try {
        setKeylogEnabled(false);
        gotls_execute_class_based(moduleName, "libc", false);
        assert.deepEqual(scanned, []);
        setKeylogEnabled(true);
        gotls_execute_class_based(moduleName, "libc", false, { x64: { primary: "AB CD", fallback: "" } });
        assert.deepEqual(scanned, ["AB CD"]);
        replay("wkl_class_based", "x64");
        assert.deepEqual(keylogs.splice(0), [EXPECTED]);
    } finally {
        setKeylogEnabled(true);
        G.setTimeout = realSetTimeout;
        G.Process.findModuleByName = findModule;
    }
});
