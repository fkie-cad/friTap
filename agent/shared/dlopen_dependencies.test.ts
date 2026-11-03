// Unit tests for takeNewDependencyModules (shared_functions.ts), the delta logic
// behind DynamicLoaderConfig.hookDependencies.
//
// Run: npm run test:agent
//
// WHY: on macOS, CPython's dlopen(".../_ssl.cpython-3xx-darwin.so") maps
// libssl.3.dylib as a DEPENDENCY. The loader hook only sees the requested name, so
// a spawned Homebrew/python.org Python never had its libssl hooked (no keys, no
// plaintext). The rescan must offer exactly the newly mapped images — and never
// the requested image itself, which the loader hook already handles under its
// requested name (hooking it twice would duplicate every record).

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { takeNewDependencyModules } from "./shared_functions.js";

const m = (path: string) => ({ name: path.split("/").pop()!, path });

const BEFORE = [m("/usr/lib/dyld"), m("/usr/lib/libSystem.B.dylib")];
const SSL_SO = "/opt/homebrew/Cellar/python@3.14/3.14.6/lib/python3.14/lib-dynload/_ssl.cpython-314-darwin.so";
const LIBSSL = "/opt/homebrew/Cellar/openssl@3/3.6.4/lib/libssl.3.dylib";
const LIBCRYPTO = "/opt/homebrew/Cellar/openssl@3/3.6.4/lib/libcrypto.3.dylib";

test("returns the dependencies a dlopen() mapped, not the requested image", () => {
    const known = new Set(BEFORE.map(x => x.path));
    const after = [...BEFORE, m(SSL_SO), m(LIBSSL), m(LIBCRYPTO)];
    assert.deepEqual(takeNewDependencyModules(known, after, SSL_SO), ["libssl.3.dylib", "libcrypto.3.dylib"]);
    // Every image is now known: the next dlopen() reports nothing again.
    assert.deepEqual(takeNewDependencyModules(known, after, "/whatever.dylib"), []);
});

test("excludes the requested image however dlopen() named it", () => {
    for (const requested of [
        LIBSSL,                                              // exact path
        "libssl.3.dylib",                                    // bare name
        "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",    // symlinked path (realpath differs)
    ]) {
        const known = new Set(BEFORE.map(x => x.path));
        const after = [...BEFORE, m(LIBSSL), m(LIBCRYPTO)];
        assert.deepEqual(takeNewDependencyModules(known, after, requested), ["libcrypto.3.dylib"], requested);
    }
});

test("dlopen(NULL) / unknown request: every new image is a candidate", () => {
    const known = new Set(BEFORE.map(x => x.path));
    assert.deepEqual(takeNewDependencyModules(known, [...BEFORE, m(LIBSSL)], undefined), ["libssl.3.dylib"]);
});

test("tracks images by path: a second libssl.3.dylib elsewhere is still new", () => {
    const known = new Set([...BEFORE.map(x => x.path), LIBSSL]);
    const other = "/Applications/App.app/Contents/Frameworks/libssl.3.dylib";
    assert.deepEqual(takeNewDependencyModules(known, [...BEFORE, m(LIBSSL), m(other)], "/x/_foo.so"), ["libssl.3.dylib"]);
    assert.ok(known.has(other));
});
