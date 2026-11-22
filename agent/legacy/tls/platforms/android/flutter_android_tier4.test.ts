// Run: npm run test:agent
//
// Release libflutter.so builds match neither the bundled byte patterns nor any
// ssl_log_secret symbol, so the legacy Flutter key path must fall back to tier 4
// (the anchor locator) like the Cronet rows — but never next to a pattern hook
// that already matched, and never under --pairip-safe.

import { test, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";
import "../../../../shared/frida-test-stubs.js";
// Entry first: the hooker modules sit in an import cycle with the platform tables.
import "../../../../fritap_agent.js";
import { Flutter_Android, scheduleFlutterKeylogFallback } from "./flutter_android.js";
import { PatternBasedHooking } from "../../../tls/shared/pattern_based_hooking.js";
import {
    _resetKeylogOutcomeReportsForTests, registerBoringSSLTier4, claimKeylogHook,
} from "../../../../shared/boringssl_keylog_outcome.js";
import { PATTERN_HOOKING_SETTLE_MS } from "../../../../shared/boringssl_symbol_hook.js";
import { setKeylogEnabled } from "../../../../shared/shared_structures.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });
const MODULE = "libflutter.so";
const noDump = () => { };

let tier4Starts: string[] = [];
beforeEach(() => {
    _resetKeylogOutcomeReportsForTests();
    tier4Starts = [];
    registerBoringSSLTier4((moduleName) => { tier4Starts.push(moduleName); return true; });
});

/** A pattern hooker as the settle timer sees it. */
function patternHooker(matched: boolean): PatternBasedHooking {
    return { no_hooking_success: !matched, found_ssl_log_secret: matched } as unknown as PatternBasedHooking;
}

/** Run `body`, then the settle timer, with no ssl_log_secret symbol to find (real Frida throws). */
function afterSettleWindow(body: () => void): void {
    const originalGet = G.Process.getModuleByName;
    G.Process.getModuleByName = (name: string) => { throw new Error(`unable to find module '${name}'`); };
    mock.timers.enable({ apis: ["setTimeout"] });
    try {
        body();
        mock.timers.tick(PATTERN_HOOKING_SETTLE_MS);
    } finally {
        mock.timers.reset();
        G.Process.getModuleByName = originalGet;
    }
}

test("pattern and symbol miss on libflutter.so starts tier 4", () => {
    afterSettleWindow(() => scheduleFlutterKeylogFallback(MODULE, patternHooker(false), noDump, false));
    assert.deepEqual(tier4Starts, [MODULE]);
});

test("no pattern hooker at all (execute_hooks threw) still reaches tier 4", () => {
    afterSettleWindow(() => scheduleFlutterKeylogFallback(MODULE, null, noDump, false));
    assert.deepEqual(tier4Starts, [MODULE]);
});

test("a pattern that already matched keeps the module: no tier 4", () => {
    afterSettleWindow(() => scheduleFlutterKeylogFallback(MODULE, patternHooker(true), noDump, false));
    assert.deepEqual(tier4Starts, []);
});

test("--pairip-safe runs the symbol tier only, never tier 4", () => {
    afterSettleWindow(() => scheduleFlutterKeylogFallback(MODULE, patternHooker(false), noDump, true));
    afterSettleWindow(() => scheduleFlutterKeylogFallback(MODULE, null, noDump, true));
    assert.deepEqual(tier4Starts, []);
});

test("--pairip-safe schedules the symbol-tier timer exactly as before (no extra keylog gate)", () => {
    const realSetTimeout = G.setTimeout;
    const scheduled: any[] = [];
    G.setTimeout = (_fn: () => void, ms: number) => { scheduled.push(ms); return realSetTimeout(() => { }, 0); };
    setKeylogEnabled(false); // the symbol hook checks this itself
    try {
        scheduleFlutterKeylogFallback(MODULE, patternHooker(false), noDump, true);
    } finally {
        G.setTimeout = realSetTimeout;
        setKeylogEnabled(true);
    }
    assert.deepEqual(scheduled, [1000]);
});

/** Install Flutter's default-pattern hook with a captured callback; hand both to `body`. */
function withFlutterPatternHook(body: (fire: (args: any[]) => void, calls: any[][]) => void): void {
    const proto = PatternBasedHooking.prototype as any;
    const originalHook = proto.hookModuleByPattern;
    const originalFind = G.Process.findModuleByName;
    let callback: ((args: any[]) => void) | null = null;
    proto.hookModuleByPattern = function (_patterns: any, cb: (args: any[]) => void) { callback = cb; };
    G.Process.findModuleByName = () => ({ name: MODULE, base: G.ptr(0), size: 0x1000 });
    try {
        const flutter: any = Object.create(Flutter_Android.prototype);
        flutter.module_name = MODULE;
        flutter.default_pattern = { [G.Process.arch]: { primary: "00", fallback: "00" } };
        const calls: any[][] = [];
        flutter.dumpKeys = (...args: any[]) => calls.push(args);
        flutter.install_key_extraction_hook();
        assert.ok(callback, "no pattern hook installed");
        body(callback!, calls);
    } finally {
        proto.hookModuleByPattern = originalHook;
        G.Process.findModuleByName = originalFind;
    }
}
const SECRET_ARGS = ["ssl", "label", "key", { toUInt32: () => 48 }];

test("a late pattern match after tier 4 installed drops its duplicate secrets", () =>
    withFlutterPatternHook((fire, calls) => {
        claimKeylogHook(MODULE, "anchor");
        fire(SECRET_ARGS);
        assert.deepEqual(calls, []);
    }));

test("the pattern hook still emits (with ssl_log_secret's length) while it owns the module", () =>
    withFlutterPatternHook((fire, calls) => {
        fire(SECRET_ARGS);
        assert.deepEqual(calls, [["label", "ssl", "key", 48]]);
    }));
