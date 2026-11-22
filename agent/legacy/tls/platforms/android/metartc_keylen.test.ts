// Run: npm run test:agent
//
// MetaRTC reuses Flutter.dumpKeys but dropped ssl_log_secret's length (args[3]),
// so SHA-384 secrets were cut to 32 bytes. Its hook callbacks now pass it on.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../../../shared/frida-test-stubs.js";
// Entry first: the hooker modules sit in an import cycle with the platform tables.
import "../../../../fritap_agent.js";
import { MetaRTC_Android } from "./metartc.js";
import { PatternBasedHooking } from "../../../tls/shared/pattern_based_hooking.js";

test("MetaRTC's default-pattern hook passes ssl_log_secret's length to dumpKeys", () => {
    const G = globalThis as any;
    const proto = PatternBasedHooking.prototype as any;
    const originalHook = proto.hookModuleByPattern;
    const originalFind = G.Process.findModuleByName;
    let callback: ((args: any[]) => void) | null = null;
    proto.hookModuleByPattern = function (_patterns: any, cb: (args: any[]) => void) { callback = cb; };
    G.Process.findModuleByName = () => ({ name: "libstartup.so", base: G.ptr(0), size: 0x1000 });
    try {
        const metartc: any = Object.create(MetaRTC_Android.prototype);
        metartc.module_name = "libstartup.so";
        metartc.default_pattern = { [G.Process.arch]: { primary: "00", fallback: "00" } };
        const calls: any[][] = [];
        metartc.dumpKeys = (...args: any[]) => calls.push(args);
        metartc.install_key_extraction_hook();
        assert.ok(callback, "no pattern hook installed");
        callback!(["ssl", "label", "key", { toUInt32: () => 48 }]);
        assert.deepEqual(calls, [["label", "ssl", "key", 48]]);
    } finally {
        proto.hookModuleByPattern = originalHook;
        G.Process.findModuleByName = originalFind;
    }
});
