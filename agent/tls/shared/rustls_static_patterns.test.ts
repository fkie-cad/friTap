// Unit tests for the shared static-rustls pattern hooks (agent/tls/shared/rustls_static_patterns.ts),
// used by the legacy and the modern Linux rustls hookers for plain Rust binaries.
//  - the table: one TLS 1.3 + one TLS 1.2 pattern for arm64 and x64, well-formed tokens;
//  - TLS 1.3: the secret is OkmBlock.buf[..used] at the OUT pointer (args[0]), the label comes
//    from the SecretKind byte (args[3]), the client random from args[9];
//  - TLS 1.2: Ok(ConnectionSecrets) at the indirect-result pointer (arm64 x8, x64 args[0]):
//    client_random at +8, master_secret at +72, a NULL suite (+0) is the Err niche;
//  - an ambiguous pattern (more than one match) is never hooked.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { setKeylogEnabled } from "../../shared/shared_structures.js";
import {
    RUSTLS_STATIC_PATTERNS, TLS13_SECRET_LABELS, installRustlsStaticPatternHooks, tls13KeylogLine,
    tls12KeylogLineAt, RustlsStaticPattern, isArm64SubSpImmediate, arm64EntryBefore,
} from "./rustls_static_patterns.js";
import { Rustls_Linux_Modern } from "../platforms/linux/rustls_linux.js";
import { Rustls_Linux } from "../../legacy/tls/platforms/linux/rustls_linux.js";

const G = globalThis as any;
setKeylogEnabled(true);

const keylogs: string[] = [];
G.send = (message: any) => {
    if (message?.contentType === "keylog") keylogs.push(message.keylog);
};

/** Fake memory over `bytes` (little-endian), with the NativePointer surface the hooks use. */
function mem(bytes: Buffer, off = 0): any {
    return {
        isNull: () => false,
        add: (n: number) => mem(bytes, off + Number(n)),
        readU64: () => ({ toNumber: () => Number(bytes.readBigUInt64LE(off)) }),
        readPointer: () => {
            const v = bytes.readBigUInt64LE(off);
            return { isNull: () => v === 0n };
        },
        readByteArray: (n: number) => new Uint8Array(bytes.subarray(off, off + n)).buffer,
    };
}
const NULL_PTR: any = { isNull: () => true };

/** A code pointer at instruction `index` of `words` (readU32 / sub like a NativePointer). */
function codeAt(words: number[], index: number, name = `code+${index}`): any {
    return {
        index, name, toString: () => name,
        readU32: () => words[index] ?? 0,
        sub: (n: number) => codeAt(words, index - Number(n) / 4),
    };
}
const int = (n: number): any => ({ toUInt32: () => n >>> 0, isNull: () => n === 0 });
const fill = (len: number, byte: number) => Buffer.alloc(len, byte);
const hex = (b: Buffer) => b.toString("hex");

/** Run one attached hook: onEnter(args) then onLeave on one invocation context. */
function invoke(listener: any, args: any[], context: any = {}): void {
    const self: any = { context };
    listener.onEnter.call(self, args);
    listener.onLeave.call(self, int(0));
}

/** Fake module + scanSync: `hitsByPattern` gives each pattern's match addresses. */
function withFakeScan(arch: string, hitsByPattern: Map<string, string[]>, fn: (attached: Map<string, any>) => void): void {
    const attached = new Map<string, any>();
    const saved = { arch: G.Process.arch, scanSync: G.Memory.scanSync, attach: G.Interceptor.attach };
    G.Process.arch = arch;
    // A match is preceded by `sub sp, sp, #0x130` two instructions back (for entryBacktrack).
    const preceded = (a: string): any => ({
        toString: () => a, name: a,
        sub: (n: number) => ({ toString: () => (n === 8 ? `${a}-entry` : `${a}-${n}`), readU32: () => (n === 8 ? 0xd104c3ff : 0) }),
    });
    G.Memory.scanSync = (_b: any, _s: any, pattern: string) =>
        (hitsByPattern.get(pattern) ?? []).map((a) => ({ address: preceded(a) }));
    G.Interceptor.attach = (target: any, callbacks: any) => { attached.set(String(target), callbacks); return { detach: () => { } }; };
    try {
        fn(attached);
    } finally {
        G.Process.arch = saved.arch;
        G.Memory.scanSync = saved.scanSync;
        G.Interceptor.attach = saved.attach;
    }
}
const fakeModule: any = { name: "rustls_client", enumerateRanges: () => [{ base: 0x1000, size: 0x1000 }] };
const entry = (arch: string, hook: string): RustlsStaticPattern =>
    RUSTLS_STATIC_PATTERNS.find((p) => p.arch === arch && p.layout.hook === hook)!;

test("table: TLS 1.3 and TLS 1.2 patterns for arm64 and x64, well-formed tokens, unique ids", () => {
    for (const arch of ["arm64", "x64"]) {
        const hooks = new Set(RUSTLS_STATIC_PATTERNS.filter((p) => p.arch === arch).map((p) => p.layout.hook));
        assert.deepEqual([...hooks].sort(), ["tls12_from_key_exchange", "tls13_derive_logged_secret"]);
    }
    for (const p of RUSTLS_STATIC_PATTERNS) {
        for (const tok of p.pattern.split(" ")) assert.match(tok, /^[0-9A-F?]{2}$/, `${p.id}: token ${tok}`);
        const fixed = p.pattern.split(" ").filter((t) => t !== "??").length;
        assert.ok(fixed >= (p.entryBacktrack ? 14 : 24), `${p.id}: enough fixed bytes (${fixed})`);
        if (p.entryBacktrack) assert.equal(p.arch, "arm64", `${p.id}: entry backtrack is arm64-only`);
    }
    assert.equal(new Set(RUSTLS_STATIC_PATTERNS.map((p) => p.id)).size, RUSTLS_STATIC_PATTERNS.length);
});

test("arm64 entry backtrack: nearest `sub sp, sp, #imm` before the body match, else null", () => {
    assert.equal(isArm64SubSpImmediate(0xd107c3ff), true);  // sub sp, sp, #0x1f0
    assert.equal(isArm64SubSpImmediate(0xd10483ff), true);  // sub sp, sp, #0x120
    assert.equal(isArm64SubSpImmediate(0xd10343b6), false); // sub x22, x29, #0xd0
    assert.equal(isArm64SubSpImmediate(0xa91b7bfd), false); // stp x29, x30, [sp, #432]
    // sub sp; str x29; stp x30,x23; stp x22,x21; stp x20,x19; <body>
    const words = [0xd107c3ff, 0xf900dbfd, 0xa91c5ffe, 0xa91d57f6, 0xa91e4ff4];
    const body = codeAt(words, words.length);
    assert.equal(arm64EntryBefore(body, 8)?.index, 0);
    assert.equal(arm64EntryBefore(body, 3), null, "entry further back than allowed");
});

test("tls13KeylogLine: SecretKind declaration order → NSS labels; non-loggable kinds → null", () => {
    const cr = fill(32, 0xaa).buffer.slice(0, 32) as ArrayBuffer;
    const secret = new Uint8Array([1, 2, 3]).buffer;
    assert.equal(tls13KeylogLine(2, cr, secret), `CLIENT_HANDSHAKE_TRAFFIC_SECRET ${"aa".repeat(32)} 010203`);
    assert.equal(TLS13_SECRET_LABELS[5], "SERVER_TRAFFIC_SECRET_0");
    assert.equal(TLS13_SECRET_LABELS[6], "EXPORTER_SECRET");
    for (const kind of [0, 7, 8, 9]) assert.equal(tls13KeylogLine(kind, cr, secret), null);
});

for (const arch of ["arm64", "x64"]) {
    test(`${arch} TLS 1.3: derive_logged_secret → OkmBlock at args[0], kind args[3], client random args[9]`, () => {
        const p = entry(arch, "tls13_derive_logged_secret");
        withFakeScan(arch, new Map([[p.pattern, ["0xd1s"]]]), (attached) => {
            const result = installRustlsStaticPatternHooks(fakeModule, [p]);
            assert.deepEqual(result, { tls13: true, tls12: false });
            const okm = Buffer.alloc(72);
            fill(48, 0x5c).copy(okm, 0);
            okm.writeBigUInt64LE(48n, 64); // used = 48 (SHA-384 suite)
            const clientRandom = fill(32, 0x11);
            const args = [mem(okm), int(0), int(0), int(4), int(0), int(0), int(0), int(0), int(0), mem(clientRandom)];
            keylogs.length = 0;
            invoke(attached.get("0xd1s"), args);
            assert.deepEqual(keylogs, [`CLIENT_TRAFFIC_SECRET_0 ${hex(clientRandom)} ${hex(fill(48, 0x5c))}`]);
        });
    });
}

test("arm64 TLS 1.2: from_key_exchange result via x8; Ok → CLIENT_RANDOM line, Err (NULL suite) → nothing", () => {
    const p = entry("arm64", "tls12_from_key_exchange");
    withFakeScan("arm64", new Map([[p.pattern, ["0xfke"]]]), (attached) => {
        assert.deepEqual(installRustlsStaticPatternHooks(fakeModule, [p]), { tls13: false, tls12: true });
        const secrets = Buffer.alloc(120);
        secrets.writeBigUInt64LE(0x1234n, 0);   // suite (non-NULL: Ok)
        fill(32, 0x22).copy(secrets, 8);         // client_random
        fill(32, 0x33).copy(secrets, 40);        // server_random
        fill(48, 0x44).copy(secrets, 72);        // master_secret
        keylogs.length = 0;
        assert.deepEqual([...attached.keys()], ["0xfke-entry"], "hooked at the entry, not the body match");
        invoke(attached.get("0xfke-entry"), [NULL_PTR], { x8: mem(secrets) });
        assert.deepEqual(keylogs, [`CLIENT_RANDOM ${hex(fill(32, 0x22))} ${hex(fill(48, 0x44))}`]);

        keylogs.length = 0;
        invoke(attached.get("0xfke-entry"), [NULL_PTR], { x8: mem(Buffer.alloc(120)) });
        assert.deepEqual(keylogs, [], "Err result: nothing logged");
    });
});

test("x64 TLS 1.2: from_key_exchange result via args[0] (rdi)", () => {
    const secrets = Buffer.alloc(120);
    secrets.writeBigUInt64LE(1n, 0);
    fill(32, 0x01).copy(secrets, 8);
    fill(48, 0x02).copy(secrets, 72);
    assert.equal(tls12KeylogLineAt(mem(secrets)), `CLIENT_RANDOM ${hex(fill(32, 0x01))} ${hex(fill(48, 0x02))}`);
    const p = entry("x64", "tls12_from_key_exchange");
    assert.deepEqual(p.layout, { hook: "tls12_from_key_exchange", out: { arg: 0 } });
});

test("an ambiguous pattern (two matches) is not hooked; the other arch's patterns are not scanned", () => {
    const p13 = entry("arm64", "tls13_derive_logged_secret");
    const x64 = entry("x64", "tls13_derive_logged_secret");
    const scanned: string[] = [];
    withFakeScan("arm64", new Map([[p13.pattern, ["0xa", "0xb"]]]), (attached) => {
        const realScan = G.Memory.scanSync;
        G.Memory.scanSync = (b: any, s: any, pattern: string) => { scanned.push(pattern); return realScan(b, s, pattern); };
        assert.deepEqual(installRustlsStaticPatternHooks(fakeModule, [p13, x64]), { tls13: false, tls12: false });
        assert.equal(attached.size, 0);
        assert.deepEqual(scanned, [p13.pattern]);
    });
});

test("both Linux rustls hookers (legacy + modern) use the shared table before their old x64 patterns", () => {
    for (const Hooker of [Rustls_Linux, Rustls_Linux_Modern]) {
        const findModule = G.Process.findModuleByName;
        G.Process.findModuleByName = () => fakeModule;
        const p13 = entry("arm64", "tls13_derive_logged_secret");
        const p12 = entry("arm64", "tls12_from_key_exchange");
        let oldScans = 0;
        const realScan = G.Memory.scan;
        G.Memory.scan = () => { oldScans++; };
        try {
            withFakeScan("arm64", new Map([[p13.pattern, ["0x13"]], [p12.pattern, ["0x12"]]]), (attached) => {
                const hooker = new (Hooker as any)("rustls_client", "libc", false);
                hooker.install_key_extraction_hook();
                assert.deepEqual([...attached.keys()].sort(), ["0x12-entry", "0x13"], Hooker.name);
                assert.equal(oldScans, 0, `${Hooker.name}: no fallback scan when the table hooked both`);
            });
        } finally {
            G.Process.findModuleByName = findModule;
            G.Memory.scan = realScan;
        }
    }
});
