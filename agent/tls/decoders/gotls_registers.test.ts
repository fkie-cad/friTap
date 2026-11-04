// Unit tests for the Go writeKeyLog register decoding (shared/go_abi.ts goKeyLogArgs,
// tls/decoders/gotls_registers.ts) and the symbol-based keylog hook of both GoTLS hooker
// copies (agent/legacy/tls/libs/gotls.ts, agent/tls/libs/gotls.ts).
//
// Run: npm run test:agent
//
// WHY: crypto/tls.(*Config).writeKeyLog(label string, clientRandom, secret []byte) puts
// c=X0, label=X1/X2, clientRandom=X3/X4/X5(cap), secret=X6/X7/X8(cap) on arm64. The arm64
// decoder read the secret from X5/X6 — clientRandom's cap (0x20) as a pointer — so no Go
// key was ever logged on arm64 (confirmed live: Go 1.21 darwin/arm64, X5 == 0x20 on every
// call). x64 (RBX/RCX, RDI/RSI, R9/R10) was already right; both now share goKeyLogArgs.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { installFakes, listener, addr } from "../../shared/write_hook_fakes.js";
import { setKeylogEnabled } from "../../shared/shared_structures.js";

import { goKeyLogArgs, goMemmoveArgs } from "../../shared/go_abi.js";
import { extractKeylogFromRegisters } from "./gotls_registers.js";
import { GoTLS as LegacyGoTLS } from "../../legacy/tls/libs/gotls.js";
import { GoTLS } from "../libs/gotls.js";

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
        readByteArray: (len: number) => { if (!bytes) throw new Error(`access violation at 0x${n.toString(16)}`); return new Uint8Array(bytes.subarray(0, len)).buffer; },
    };
}
const LABEL = Buffer.from("CLIENT_TRAFFIC_SECRET_0");
const CR = Buffer.alloc(32, 0xaa);
const SECRET = Buffer.alloc(32, 0x5e);
const EXPECTED = `CLIENT_TRAFFIC_SECRET_0 ${"aa".repeat(32)} ${"5e".repeat(32)}`;

/** writeKeyLog's 9 Go argument slots: c, label(ptr,len), cr(ptr,len,cap), secret(ptr,len,cap). */
function writeKeyLogContext(arch: string): any {
    const names = arch === "x64"
        ? ["rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11"]
        : ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8"];
    const values = [reg(0xc000), reg(0x1000, LABEL), reg(LABEL.length), reg(0x2000, CR), reg(32), reg(32),
                    reg(0x3000, SECRET), reg(32), reg(48)];
    const ctx: any = {};
    names.forEach((n, i) => { ctx[n] = values[i]; });
    return ctx;
}

test("goKeyLogArgs: the secret is argument 6/7 (arm64 X6/X7, x64 R9/R10) — X5 is clientRandom's cap", () => {
    for (const arch of ["x64", "arm64"]) {
        const args = goKeyLogArgs(writeKeyLogContext(arch), arch)!;
        assert.equal((args.secret as any).value, 0x3000, arch);
        assert.equal(args.secretLength, 32);
        assert.equal((args.clientRandom as any).value, 0x2000);
        assert.equal(args.labelLength, LABEL.length);
    }
    assert.equal(goKeyLogArgs({ r0: reg(1) } as any, "arm"), null, "no register ABI");
});

test("extractKeylogFromRegisters decodes an NSS keylog line on both arches", () => {
    assert.equal(extractKeylogFromRegisters(writeKeyLogContext("arm64"), "arm64"), EXPECTED);
    assert.equal(extractKeylogFromRegisters(writeKeyLogContext("x64"), "x64"), EXPECTED);
    assert.equal(extractKeylogFromRegisters(writeKeyLogContext("x64"), "ia32"), null);
});

test("goMemmoveArgs: to/from/n are arguments 0..2", () => {
    const copy = goMemmoveArgs({ x0: reg(1), x1: reg(2), x2: reg(3) } as any, "arm64")!;
    assert.deepEqual([(copy.to as any).value, (copy.from as any).value, copy.length], [1, 2, 3]);
});

for (const [label, Hooker] of [["legacy (Android)", LegacyGoTLS], ["tls/libs", GoTLS]] as const) {
    test(`${label}: the symbol-based writeKeyLog hook logs the key on arm64 and x64`, () => {
        const hooker: any = Object.create(Hooker.prototype);
        hooker.module_name = "libgojni.so";
        hooker.addresses = { "libgojni.so": { "crypto/tls.(*Config).writeKeyLog": addr(`wkl_${label}`) } };
        hooker.install_tls_keys_callback_hook();
        for (const arch of ["arm64", "x64"]) {
            G.Process.arch = arch;
            listener(`wkl_${label}`).onEnter.call({ context: writeKeyLogContext(arch) }, []);
        }
        G.Process.arch = "x64";
        assert.deepEqual(keylogs.splice(0), [EXPECTED, EXPECTED]);
    });
}

for (const [label, Hooker] of [["legacy (Android)", LegacyGoTLS], ["tls/libs", GoTLS]] as const) {
    test(`${label}: the symbol-based writeKeyLog hook is not installed without -k`, () => {
        const hooker: any = Object.create(Hooker.prototype);
        hooker.module_name = "libgojni.so";
        hooker.addresses = { "libgojni.so": { "crypto/tls.(*Config).writeKeyLog": addr(`wkl_nokeys_${label}`) } };
        setKeylogEnabled(false);
        try {
            hooker.install_tls_keys_callback_hook();
        } finally {
            setKeylogEnabled(true);
        }
        assert.throws(() => listener(`wkl_nokeys_${label}`), /no listener/);
    });
}
