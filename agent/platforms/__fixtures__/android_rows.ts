// Test-only helpers for the Android registry dual-tree tests
// (agent/platforms/android_rows_dual_tree_{legacy,modern}.test.ts). Import AFTER
// agent/shared/frida-test-stubs.ts and the agent entry.

import { test } from "node:test";
import assert from "node:assert/strict";
import { HookRegistry, hookRegistry } from "../../shared/registry.js";
import { hookDynamicLoader } from "../../shared/shared_functions.js";
import { installFizzKeylog, isFizzCandidateModule } from "../../shared/fizz_install.js";
import { nss_hpke_execute_android } from "../../ohttp/platforms/android/nss_hpke_android.js";
import { load_android_hooking_agent, FIZZ_MODULE_PATTERN } from "../android.js";

const G = globalThis as any;

/** A Meta library unpacked to the app-private superpack dir (Facebook's Fizz host). */
const META_LIB = { name: "libcoldstart.so", path: "/data/data/com.facebook.katana/lib-compressed/libcoldstart.so" };

/**
 * The checks that must hold identically in both trees; each test file runs them in its
 * own process (use_modern is fixed when the agent loads), labelled with its tree.
 */
export function defineTreeIndependentRowTests(tree: "legacy" | "modern"): void {
    test(`${tree}: the Fizz row runs the shared installer, supplementary, behind the cheap content filter`, () => {
        const fizz = rowLabelled(androidRegistryRows(), "Fizz (Meta)");
        assert.equal(fizz.hookFn, installFizzKeylog);
        assert.equal(fizz.contentFilter, isFizzCandidateModule);
        assert.equal(fizz.pattern, FIZZ_MODULE_PATTERN);
        assert.equal(fizz.supplementary, true);
        assert.equal(fizz.libraryType, "fizz");
        assert.equal(fizz.protocol, "tls");
    });

    test(`${tree}: a late dlopen() of a Meta library reaches the Fizz row through hookDynamicLoader`, () => {
        const runs = rowsRunOnLateDlopen(androidRegistryRows(), META_LIB.name, META_LIB.path);
        const fizzRuns = runs.filter((r) => r.library === "Fizz (Meta)");
        assert.deepEqual(fizzRuns.map((r) => r.module), [META_LIB.name]);
        assert.equal(fizzRuns[0].hookFn, installFizzKeylog);
    });

    test(`${tree}: the OHTTP (NSS HPKE) row is shared too`, () => {
        assert.equal(rowLabelled(androidRegistryRows(), "NSS HPKE (OHTTP)").hookFn, nss_hpke_execute_android);
    });
}

/** The rows load_android_hooking_agent() registers, captured instead of registered. */
export function androidRegistryRows(): any[] {
    let rows: any[] = [];
    (hookRegistry as any).registerAll = (regs: any[]) => { rows = regs; };
    try {
        load_android_hooking_agent();
    } finally {
        delete (hookRegistry as any).registerAll;   // back to HookRegistry.prototype.registerAll
    }
    return rows;
}

/** The single row labelled `library`. */
export function rowLabelled(rows: any[], library: string): any {
    const found = rows.filter((r) => r.library === library);
    if (found.length !== 1) throw new Error(`expected one "${library}" row, found ${found.length}`);
    return found[0];
}

export interface RowRun { library: string; module: string; hookFn: unknown; }

/**
 * Register `rows` in a fresh registry, hook a fake linker with hookDynamicLoader and fire
 * one late dlopen(`path`) of an arm64 module named `name`. Every row's executor is
 * replaced by a recorder (pattern, contentFilter, supplementary are kept), so the result
 * lists which rows the loader ran for that library, each with its ORIGINAL executor.
 */
export function rowsRunOnLateDlopen(rows: any[], name: string, path: string): RowRun[] {
    const runs: RowRun[] = [];
    const reg = new HookRegistry();
    reg.registerAll(rows.map((r) => ({
        ...r, hookFn: (module: string) => { runs.push({ library: r.library, module, hookFn: r.hookFn }); return true; },
    })));
    const mod = { name, path, base: { isNull: () => false, toString: () => "0x7a00000000" }, size: 0x1000 };
    const savedProcess = { ...G.Process }, savedAttach = G.Interceptor.attach;
    let loader: any = null;
    Object.assign(G.Process, {
        arch: "arm64",
        findModuleByName: (n: string) => (n === name || n === path ? mod : null),
        getModuleByName: (n: string) => ({ name: n, path: `/apex/${n}`, enumerateExports: () => [], getExportByName: () => G.ptr(1) }),
    });
    G.Interceptor.attach = (_target: any, callbacks: any) => { loader = callbacks; return { detach: () => {} }; };
    try {
        hookDynamicLoader({ platform: "linux", platformLabel: "Android", loaderLibrary: /linker64$/,
                            functionName: "dual_tree_test_dlopen" }, reg, ["linker64"], false, "tls");
        const ctx: any = {};
        loader.onEnter.call(ctx, [{ readCString: () => path }]);
        loader.onLeave.call(ctx, G.ptr(1));
    } finally {
        Object.assign(G.Process, savedProcess);
        G.Interceptor.attach = savedAttach;
    }
    return runs;
}
