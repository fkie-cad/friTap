// Unit tests for the arm64 generic BoringSSL ssl_log_secret `fallback` pattern
// (agent/shared/bundled_cronet_patterns.ts and every copy of it).
//
// Run: npm run test:agent
//
// The pattern matcher itself is Frida's native Memory.scan, which Node cannot
// run. `fridaPatternMatches` below re-implements its documented pattern
// grammar (space-separated bytes, `?` masks ONE nibble, `??` a whole byte) so
// the shipped strings can be checked against verified binary prologues.
//
// Why this exists: the last byte of the prologue is the early-return branch
// on `ctx->keylog_callback`. Chrome 153's libchrome.so compiles it as cbz (B4),
// the tethering-APEX libhttpengine.so as cbnz (B5). The pattern used to end in
// a literal `B4`, so libhttpengine.so got 0 pattern hits and no keys. It now
// ends in `B?`. Both verified on-device (Pixel 7): exactly one hit each,
// libchrome.so @ 0x4bcdd60 and libhttpengine.so @ 0x67032c.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { getBundledPatterns, BUNDLED_OPENSSL_SSL_LOG_SECRET, GENERIC_BORINGSSL_ARM64_FALLBACK } from "./bundled_cronet_patterns.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// Verified ssl_log_secret prologues (in-memory reads of the device binaries).
const CHROME_153_LIBCHROME =
    "3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 29 41 F9 C8 05 00 B4";
const LIBHTTPENGINE =
    "3f 23 03 d5 ff 03 02 d1 fd 7b 04 a9 f7 2b 00 f9 f6 57 06 a9 f4 4f 07 a9 fd 03 01 91 08 34 40 f9 08 29 41 f9 48 01 00 b5";

// Common, unique prefix of the generic arm64 fallback pattern, used to find
// every hardcoded copy of it in the source tree.
const FALLBACK_PREFIX = "3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 ";

/** Frida Memory.scan semantics for a pattern anchored at the start of `hex`. */
function fridaPatternMatches(pattern: string, hex: string): boolean {
    const pat = pattern.trim().split(/\s+/);
    const bytes = hex.trim().split(/\s+/);
    if (bytes.length < pat.length) return false;
    return pat.every((token, i) => {
        const b = bytes[i].toUpperCase();
        return [0, 1].every((n) => token[n] === "?" || token[n].toUpperCase() === b[n]);
    });
}

function withLastByte(hex: string, last: string): string {
    return hex.trim().split(/\s+/).slice(0, -1).concat(last).join(" ");
}

const genericFallback = getBundledPatterns("generic_boringssl", "arm64")!.fallback;

test("reference matcher honours nibble and byte wildcards", () => {
    assert.ok(fridaPatternMatches("B? ?? 0?", "B5 12 07"));
    assert.ok(!fridaPatternMatches("B?", "A4"));
    assert.ok(!fridaPatternMatches("?4", "B5"));
    assert.ok(!fridaPatternMatches("B4 00", "B4"));
});

test("generic arm64 fallback matches the Chrome 153 libchrome.so prologue (cbz)", () => {
    assert.ok(fridaPatternMatches(genericFallback, CHROME_153_LIBCHROME));
});

test("generic arm64 fallback matches the libhttpengine.so prologue (cbnz)", () => {
    assert.ok(fridaPatternMatches(genericFallback, LIBHTTPENGINE));
});

test("the widening is limited to the cbz/cbnz nibble", () => {
    // `B?` accepts any byte with high nibble B (cbz=B4, cbnz=B5, and also
    // tbz/tbnz=B6/B7); the ~40 fixed prologue bytes before it keep the pattern
    // unique (one hit per library on-device). Bytes outside that nibble miss.
    assert.ok(!fridaPatternMatches(genericFallback, withLastByte(LIBHTTPENGINE, "A5")));
    assert.ok(!fridaPatternMatches(genericFallback, withLastByte(LIBHTTPENGINE, "34")));
});

test("the 3d floor carries the same widened pattern", () => {
    assert.ok(BUNDLED_OPENSSL_SSL_LOG_SECRET.arm64!.some((p) => fridaPatternMatches(p, LIBHTTPENGINE)));
});

// LEGACY-SYNC parity: the TypeScript tree references the single exported
// GENERIC_BORINGSSL_ARM64_FALLBACK constant; only the Python-shipped default
// patterns (JSON) still carry their own hardcoded copy.
const FALLBACK_LITERAL = /"(3F 23 03 D5 FF \?3 02 D1[0-9A-F? ]*)"/g;

function inlineFallbackCopies(src: string): string[] {
    return [...src.matchAll(FALLBACK_LITERAL)].map((m) => m[1]).filter((p) => p.startsWith(FALLBACK_PREFIX));
}

test("the exported constant is the bundled generic arm64 fallback", () => {
    assert.equal(genericFallback, GENERIC_BORINGSSL_ARM64_FALLBACK);
    assert.ok(BUNDLED_OPENSSL_SSL_LOG_SECRET.arm64!.includes(GENERIC_BORINGSSL_ARM64_FALLBACK));
});

const REFERENCING_MODULES = [
    "agent/legacy/tls/platforms/android/cronet_android.ts",
    "agent/legacy/tls/platforms/android/gotls_android.ts",
    "agent/legacy/tls/platforms/linux/cronet_linux.ts",
    "agent/legacy/tls/platforms/linux/gotls_linux.ts",
    "agent/legacy/tls/platforms/linux/openssl_boringssl_linux.ts",
];

for (const rel of REFERENCING_MODULES) {
    test(`${rel} uses the shared generic arm64 fallback constant`, () => {
        const src = readFileSync(join(REPO_ROOT, rel), "utf8");
        assert.match(src, /\bGENERIC_BORINGSSL_ARM64_FALLBACK\b/, `${rel} no longer references the constant`);
    });
}

test("no TypeScript module hardcodes its own copy of the fallback pattern", () => {
    const agentDir = join(REPO_ROOT, "agent");
    const definingModule = join("shared", "bundled_cronet_patterns.ts");
    for (const rel of readdirSync(agentDir, { recursive: true }) as string[]) {
        if (!rel.endsWith(".ts") || rel.endsWith(".test.ts")) continue;
        const copies = inlineFallbackCopies(readFileSync(join(agentDir, rel), "utf8"));
        const allowed = rel === definingModule ? 1 : 0;
        assert.equal(copies.length, allowed, `agent/${rel}: inline fallback copy; use GENERIC_BORINGSSL_ARM64_FALLBACK`);
    }
});

test("every generic arm64 fallback copy in friTap/patterns/default_patterns.json matches both prologues", () => {
    const rel = "friTap/patterns/default_patterns.json";
    const copies = inlineFallbackCopies(readFileSync(join(REPO_ROOT, rel), "utf8"));
    assert.ok(copies.length > 0, `no copy of the fallback pattern found in ${rel}`);
    for (const p of copies) {
        assert.ok(fridaPatternMatches(p, CHROME_153_LIBCHROME), `${rel}: ${p} misses libchrome.so`);
        assert.ok(fridaPatternMatches(p, LIBHTTPENGINE), `${rel}: ${p} misses libhttpengine.so`);
    }
});
