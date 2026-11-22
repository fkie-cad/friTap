// Unit tests for the NSS HPKE (OHTTP) hook definition in agent/ohttp/definitions/nss_hpke.ts:
// one definition for every platform. PK11_HPKE_Seal / PK11_HPKE_Open resolve in the hooked
// nss3 module itself (libnss3.so / libnss3.dylib / (lib)nss3.dll), which is exactly what each
// platform row matches. Also covers the guarded SECItem reader the hooks use.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { stubRanges } from "../../shared/frida-test-stubs.js";
import "../../shared/write_hook_fakes.js";   // loads the agent graph from its entry (fritap_agent.js)
import { createNssHpkeDefinition } from "./nss_hpke.js";
import { readSecItemView } from "../../shared/sec_item.js";
import { resetReadableCache } from "../../util/safe_memory.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HPKE = ["PK11_HPKE_Seal", "PK11_HPKE_Open"];
const here = dirname(fileURLToPath(import.meta.url));

test("HPKE symbols are resolved in the hooked module itself, with no auxiliary glob", () => {
    const def = createNssHpkeDefinition();
    assert.deepEqual(def.functions.librarySymbols, HPKE);
    assert.equal(def.functions.auxiliaryLibraries, undefined);
    assert.deepEqual(def.functions.socketSymbols, []);
});

test("definition identity and OHTTP extra hook", () => {
    const def = createNssHpkeDefinition();
    assert.equal(def.libraryId, "nss_hpke");
    assert.equal(def.offsetKey, "nss_hpke");
    assert.deepEqual(def.keylog, { kind: "none" });
    assert.equal(def.extraHooks?.length, 1);
});

test("every platform executor uses the one shared definition", () => {
    for (const p of ["android", "linux", "macos", "windows"]) {
        const src = readFileSync(join(here, `../platforms/${p}/nss_hpke_${p}.ts`), "utf8");
        assert.match(src, /executeFromDefinition\(createNssHpkeDefinition\(\), moduleName,/, p);
    }
});

test("every Unix platform row matches only the nss3 module that exports PK11_HPKE_*", () => {
    // Rows live in agent/platforms/{linux,android,macos}.ts, which Node cannot import: read the
    // pattern literal of the one row labelled "NSS HPKE (OHTTP)".
    for (const [file, nss3] of [["linux.ts", "libnss3.so"], ["android.ts", "libnss3.so"], ["macos.ts", "libnss3.dylib"]]) {
        const rows = readFileSync(join(here, "../../platforms", file), "utf8").split("\n")
            .filter((l) => l.includes('library: "NSS HPKE (OHTTP)"'));
        assert.equal(rows.length, 1, file);
        const literal = /pattern: \/(.+?)\/,/.exec(rows[0]);
        assert.ok(literal, file);
        const pattern = new RegExp(literal[1]);
        assert.ok(pattern.test(nss3), `${file} matches ${nss3}`);
        for (const other of ["libnssutil3.so", "libnss_files.so.2", "libnssckbi.dylib", "libnssutil3.dylib", "libsmime3.so"]) {
            assert.ok(!pattern.test(other), `${file} must not match ${other}`);
        }
    }
});

// --- readSecItemView: { type; data@ptr; len@2*ptr } ---------------------------------------

/** Pointer with real address arithmetic over `cells` (address -> pointer or u32). */
function fp(v: bigint, cells: Map<bigint, any>): any {
    const self: any = {
        v,
        add: (n: any) => fp(v + BigInt(typeof n === "object" ? n.v : n), cells),
        and: () => self,
        isNull: () => v === 0n,
        compare: (o: any) => (v < o.v ? -1 : v > o.v ? 1 : 0),
        toString: () => "0x" + v.toString(16),
        readPointer: () => cells.get(v),
        readU32: () => cells.get(v),
    };
    return self;
}

function secItem(dataAddr: bigint, len: number): any {
    const cells = new Map<bigint, any>();
    const ps = BigInt(Process.pointerSize);
    cells.set(0x1000n + ps, fp(dataAddr, cells));
    cells.set(0x1000n + 2n * ps, len);
    return fp(0x1000n, cells);
}

test("readSecItemView: data/len of a readable SECItem; NULL item / len 0 / NULL data -> null", () => {
    const view = readSecItemView(secItem(0x2000n, 5));
    assert.ok(view);
    assert.equal(view.len, 5);
    assert.equal(view.data.toString(), "0x2000");
    assert.equal(readSecItemView(fp(0n, new Map())), null);
    assert.equal(readSecItemView(secItem(0x2000n, 0)), null);
    assert.equal(readSecItemView(secItem(0n, 5)), null);
});

test("readSecItemView: unreadable header or data -> null instead of a native fault", () => {
    resetReadableCache();   // the previous test cached 0x2000 as readable
    stubRanges(["0x2000"]);
    try {
        assert.equal(readSecItemView(secItem(0x2000n, 5)), null);
    } finally {
        stubRanges(null);
    }
});
