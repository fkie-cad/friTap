// Unit tests for the hook registry's match/exclusion logic (agent/shared/registry.ts)
// and for the Darwin routing predicates it is driven by
// (agent/shared/darwin_library_patterns.ts).
//
// Run: npm run test:agent  (node --import tsx --test agent/shared/registry.test.ts)
//
// No Frida runtime needed, but the registry's import graph DOES touch Frida
// globals: registry.ts -> util/non_tls_libs.ts (reads Process.platform / Java to
// resolve the OS) -> util/log.ts (devlog sends over the host bridge). So the
// Frida stubs are side-effect imported first and `send` is stubbed below.
//
// WHY THIS FILE EXISTS
// --------------------
// The `libssl*` name spaces are covered by several OVERLAPPING registry
// entries, and `ssl_library_loader` invokes EVERY match returned by
// `findAllMatches` — not just the first. So the correctness property is not
// "some hook matched" but "exactly ONE hook matched, and it is the right one".
// `findMatch` alone hides double-hooks, which is why nearly every assertion
// below goes through `findAllMatches` and asserts the full list.
//
// Three distinct bugs are locked down here:
//
//  1. Case-sensitive string `pathFilter`. A python.org framework Python —
//     /Library/Frameworks/Python.framework/... with a capital "P" — matched NO
//     hook at all and friTap silently logged nothing.
//  2. Homebrew/pyenv/MacPorts OpenSSL matched NO hook either: it is neither
//     under /usr/lib/ nor "python", and the generic entry excluded its
//     basename. The fix is the negative `excludePathFilter`, which turns the
//     old "python only" entry into "every versioned libssl that is not the
//     system LibreSSL".
//  3. Double-hooking. `libssl.1.1.dylib` slipped past the old
//     `/^libssl\.\d+\.dylib$/` excludePattern (`\d+` cannot span the dot), so
//     both the genuine-OpenSSL executor and the Apple BoringSSL one installed
//     on the same module. Likewise on Linux/Windows a Python's own libssl
//     matched both the python and the generic entry.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/Java/etc. BEFORE registry.js loads.
import "./frida-test-stubs.js";
import { HookRegistry } from "./registry.js";
import { registerHookContributor, collectContributedHooks } from "./hook_contributors.js";
import { Platform, PLATFORM_DARWIN, PLATFORM_LINUX, PLATFORM_WINDOWS } from "./shared_structures.js";
// The REAL predicates, not copies. darwin_library_patterns.ts is deliberately
// dependency-free (it has no imports at all), so pulling it in here is safe —
// unlike importing macos.ts/ios.ts, which would drag in every TLS
// implementation and the Frida bridges. Using the shared objects means these
// tests exercise the exact instances the platform agents register with.
import { VERSIONED_LIBSSL_DYLIB, SYSTEM_LIBRESSL_PATH, ANY_LIBSSL_DYLIB } from "./darwin_library_patterns.js";

const G = globalThis as any;
// devlog() (called from _isExcluded for every exclusion reason) publishes via
// the host bridge's send(); stub it so the registry is safe to exercise here.
G.send = G.send ?? ((_msg: any) => { });

const noopHook = (_moduleName: string, _isBaseHook: boolean) => { };

/**
 * Minimal fixture mirroring the overlapping libssl entries from
 * agent/platforms/macos.ts:39-76, agent/platforms/linux.ts:113-114 and
 * agent/platforms/windows.ts:46-47 (same patterns, priorities, path filters and
 * excludePattern). Built by hand rather than importing the platform modules,
 * which would pull in every TLS implementation and the Frida bridges — but the
 * three Darwin predicates ARE the shared originals.
 */
function makeRegistry(): HookRegistry {
    const reg = new HookRegistry();
    reg.registerAll([
        // --- darwin: macos.ts:39-76, verbatim shape ---
        {
            platform: PLATFORM_DARWIN, pattern: /.*libboringssl\.dylib/, hookFn: noopHook,
            library: "BoringSSL", libraryType: "boringssl", protocol: "tls",
        },
        // The three-way partition of libssl*.dylib. LibreSSL and OpenSSL share
        // one pattern and split on ONE predicate (SYSTEM_LIBRESSL_PATH) used
        // positively by the first and negatively by the second; the generic
        // entry takes the non-versioned remainder.
        {
            platform: PLATFORM_DARWIN, pattern: VERSIONED_LIBSSL_DYLIB, hookFn: noopHook,
            library: "LibreSSL", pathFilter: SYSTEM_LIBRESSL_PATH, priority: 150,
            libraryType: "libressl", protocol: "tls",
        },
        {
            platform: PLATFORM_DARWIN, pattern: VERSIONED_LIBSSL_DYLIB, hookFn: noopHook,
            library: "OpenSSL", excludePathFilter: SYSTEM_LIBRESSL_PATH, priority: 120,
            libraryType: "openssl", protocol: "tls",
        },
        {
            platform: PLATFORM_DARWIN, pattern: ANY_LIBSSL_DYLIB, hookFn: noopHook,
            library: "OpenSSL/BoringSSL", excludePattern: VERSIONED_LIBSSL_DYLIB,
            libraryType: "openssl", protocol: "tls",
        },
        // --- linux: linux.ts:113-114 ---
        {
            platform: PLATFORM_LINUX, pattern: /.*libssl\.so/, hookFn: noopHook,
            library: "OpenSSL/BoringSSL", excludePathFilter: "python",
            libraryType: "openssl", protocol: "tls",
        },
        {
            platform: PLATFORM_LINUX, pattern: /.*libssl.*\.so/, hookFn: noopHook,
            library: "Python OpenSSL", pathFilter: "python",
            libraryType: "openssl", protocol: "tls",
        },
        // --- windows: windows.ts:46-47 ---
        {
            platform: PLATFORM_WINDOWS, pattern: /^(libssl|LIBSSL)-[0-9]+(_[0-9]+)?\.dll$/, hookFn: noopHook,
            library: "OpenSSL/BoringSSL", excludePathFilter: "python",
            libraryType: "openssl", protocol: "tls",
        },
        {
            platform: PLATFORM_WINDOWS, pattern: /^.*libssl.*\.dll$/, hookFn: noopHook,
            library: "Python OpenSSL", pathFilter: "python",
            libraryType: "openssl", protocol: "tls",
        },
    ]);
    return reg;
}

/**
 * Fixture for agent/platforms/ios.ts:31-48 ONLY.
 *
 * ios.ts and macos.ts register under the SAME platform key (PLATFORM_DARWIN)
 * into the SAME `hookRegistry` singleton, and ssl_library_loader invokes every
 * match — so the "exactly one platform agent loads per run" selection in
 * fritap_agent.ts is a load-bearing invariant, not a tidiness choice. This
 * fixture therefore mirrors ios.ts in isolation, exactly as it behaves at
 * runtime.
 */
function makeIosRegistry(): HookRegistry {
    const reg = new HookRegistry();
    reg.registerAll([
        {
            platform: PLATFORM_DARWIN, pattern: /.*libboringssl\.dylib/, hookFn: noopHook,
            library: "BoringSSL", libraryType: "boringssl", protocol: "tls",
        },
        {
            platform: PLATFORM_DARWIN, pattern: VERSIONED_LIBSSL_DYLIB, hookFn: noopHook,
            library: "LibreSSL", pathFilter: SYSTEM_LIBRESSL_PATH, priority: 150,
            libraryType: "libressl", protocol: "tls",
        },
        {
            platform: PLATFORM_DARWIN, pattern: VERSIONED_LIBSSL_DYLIB, hookFn: noopHook,
            library: "OpenSSL", excludePathFilter: SYSTEM_LIBRESSL_PATH, priority: 120,
            libraryType: "openssl", protocol: "tls",
        },
        {
            platform: PLATFORM_DARWIN, pattern: ANY_LIBSSL_DYLIB, hookFn: noopHook,
            library: "OpenSSL/BoringSSL", excludePattern: VERSIONED_LIBSSL_DYLIB,
            libraryType: "openssl", protocol: "tls",
        },
        {
            platform: PLATFORM_DARWIN, pattern: /.*cronet.*\.dylib/, hookFn: noopHook,
            library: "Cronet", libraryType: "boringssl", protocol: "tls",
        },
        {
            platform: PLATFORM_DARWIN, pattern: /.*flutter.*\.dylib/, hookFn: noopHook,
            library: "Flutter BoringSSL", libraryType: "boringssl", protocol: "tls",
        },
    ]);
    return reg;
}

function libraryOf(platform: Platform, name: string, path?: string): string | undefined {
    return makeRegistry().findMatch(platform, name, path, "tls")?.library;
}

/** Every hook that would be invoked — the property that actually matters. */
function librariesOf(
    platform: Platform, name: string, path?: string, reg: HookRegistry = makeRegistry(),
): string[] {
    return reg.findAllMatches(platform, name, path, "tls").map(h => h.library);
}

// ---------------------------------------------------------------------------
// The measured bug: capitalised Apple framework path
// ---------------------------------------------------------------------------

test("darwin framework Python (capital 'Python.framework') selects the genuine-OpenSSL hook", () => {
    // The exact live-measured case from a python.org framework Python. Before
    // the case-insensitive pathFilter fix this returned undefined: LibreSSL
    // excluded itself (no "/usr/lib/"), the then "Python OpenSSL" entry excluded
    // itself ("python" !== "Python" under String.includes), and the generic
    // entry excluded itself via its excludePattern — so NO hook installed and
    // nothing was ever logged. The entry is now simply "OpenSSL": a framework
    // Python is no longer a special case, just a versioned libssl outside
    // /usr/lib/.
    const path = "/Library/Frameworks/Python.framework/Versions/3.13/lib/libssl.3.dylib";
    assert.equal(libraryOf(PLATFORM_DARWIN, "libssl.3.dylib", path), "OpenSSL");
});

test("darwin framework Python is matched by findAllMatches too (exactly one hook, no double-install)", () => {
    const path = "/Library/Frameworks/Python.framework/Versions/3.13/lib/libssl.3.dylib";
    assert.deepEqual(librariesOf(PLATFORM_DARWIN, "libssl.3.dylib", path), ["OpenSSL"]);
});

test("Xcode's bundled Python3.framework also selects the genuine-OpenSSL hook", () => {
    const path = "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/"
        + "Python3.framework/Versions/3.9/lib/libssl.3.dylib";
    assert.equal(libraryOf(PLATFORM_DARWIN, "libssl.3.dylib", path), "OpenSSL");
});

test("windows capitalised install directories select the Python OpenSSL hook", () => {
    for (const path of [
        "C:\\Python312\\DLLs\\libssl-3.dll",
        "C:\\Users\\u\\AppData\\Local\\Programs\\Python\\Python312\\DLLs\\libssl-3.dll",
    ]) {
        assert.equal(libraryOf(PLATFORM_WINDOWS, "libssl-3.dll", path), "Python OpenSSL", path);
    }
});

// ---------------------------------------------------------------------------
// No regression: lowercase paths, and the fix must not match everything
// ---------------------------------------------------------------------------

test("lowercase linux python path still selects the Python OpenSSL hook", () => {
    // linux.ts registers a generic /.*libssl\.so/ entry at the same priority, and
    // ssl_library_loader invokes EVERY match — so assert on findAllMatches rather
    // than on findMatch's first-wins result.
    const path = "/usr/lib/python3.11/lib-dynload/../../libssl.so.3";
    const matches = librariesOf(PLATFORM_LINUX, "libssl.so.3", path);
    assert.ok(
        matches.includes("Python OpenSSL"),
        `expected Python OpenSSL among [${matches.join(", ")}]`,
    );
});

test("lowercase darwin python path still selects the genuine-OpenSSL hook", () => {
    const path = "/usr/local/lib/python3.11/site-packages/libssl.3.dylib";
    assert.equal(libraryOf(PLATFORM_DARWIN, "libssl.3.dylib", path), "OpenSSL");
});

test("REGRESSION: Homebrew OpenSSL now routes to the OpenSSL hook (used to match NOTHING)", () => {
    // This assertion is the inverse of the one it replaces. The old fixture
    // codified the bug: with a positive `pathFilter: "python"` on the only
    // non-system entry, /opt/homebrew/... matched no hook at all — LibreSSL
    // wants /usr/lib/, the python entry wants "python" in the path, and the
    // generic entry rejects the versioned basename. Every Homebrew, MacPorts,
    // conda and pyenv OpenSSL was therefore unhookable and friTap logged
    // nothing. The negative `excludePathFilter: SYSTEM_LIBRESSL_PATH` inverts
    // the question from "is this a Python?" to "is this NOT the system
    // LibreSSL?", which is the property the executor choice actually depends on.
    const path = "/opt/homebrew/Cellar/openssl@3/3.4.0/lib/libssl.3.dylib";
    assert.deepEqual(librariesOf(PLATFORM_DARWIN, "libssl.3.dylib", path), ["OpenSSL"]);
});

test("a non-python windows path stays out of the Python OpenSSL hook (and lands on the generic one)", () => {
    // Guards against the case-insensitive comparison degenerating into "matches
    // everything": no "python" component => the python-only entry must not fire.
    const path = "C:\\Program Files\\OpenVPN\\bin\\libssl-3.dll";
    assert.deepEqual(librariesOf(PLATFORM_WINDOWS, "libssl-3.dll", path), ["OpenSSL/BoringSSL"]);
});

// ---------------------------------------------------------------------------
// The LibreSSL pathFilter (now anchored) is unaffected by case-insensitivity
// ---------------------------------------------------------------------------

test("darwin /usr/lib/libssl.48.dylib still routes to the priority-150 LibreSSL hook", () => {
    assert.equal(
        libraryOf(PLATFORM_DARWIN, "libssl.48.dylib", "/usr/lib/libssl.48.dylib"),
        "LibreSSL",
    );
});

test("the LibreSSL hook is still excluded outside /usr/lib/ — and OpenSSL takes over there", () => {
    const matches = librariesOf(PLATFORM_DARWIN, "libssl.48.dylib", "/opt/local/lib/libssl.48.dylib");
    assert.ok(!matches.includes("LibreSSL"), "LibreSSL must not match outside /usr/lib/");
    // The complement: the module is not left unhooked. A MacPorts libssl.48
    // is a real (LibreSSL-named but non-system) versioned dylib and must reach
    // the genuine-OpenSSL executor rather than nothing at all.
    assert.ok(matches.includes("OpenSSL"), `expected OpenSSL among [${matches.join(", ")}]`);
});

// ---------------------------------------------------------------------------
// excludePattern and the fail-closed / fail-open no-path branches
// ---------------------------------------------------------------------------

test("excludePattern still keeps a versioned libssl out of the generic OpenSSL/BoringSSL entry", () => {
    // A versioned name at a path that is neither /usr/lib/ nor python-ish must
    // resolve to EXACTLY the genuine-OpenSSL entry: the generic (Apple
    // BoringSSL) executor would write a BoringSSL struct offset into a real
    // OpenSSL SSL_CTX.
    const libs = librariesOf(PLATFORM_DARWIN, "libssl.3.dylib", "/some/other/place/libssl.3.dylib");
    assert.deepEqual(libs, ["OpenSSL"]);
    // ...while a non-matching basename still reaches the generic entry.
    assert.equal(
        libraryOf(PLATFORM_DARWIN, "libssl_custom.dylib", "/some/other/place/libssl_custom.dylib"),
        "OpenSSL/BoringSSL",
    );
});

test("with no module path, darwin still resolves to exactly one hook (fail-closed xor fail-open)", () => {
    // modulePath undefined is the interesting asymmetry: the positive
    // `pathFilter` fails CLOSED (LibreSSL drops out) while the negative
    // `excludePathFilter` fails OPEN (OpenSSL stays in). That is precisely what
    // keeps the complementary pair resolving to ONE hook instead of zero — the
    // old positive-only arrangement returned undefined here and left the module
    // unhooked whenever extractModulePath could not resolve a path.
    assert.deepEqual(librariesOf(PLATFORM_DARWIN, "libssl.3.dylib", undefined), ["OpenSSL"]);
    // Windows/Linux still exercise fail-closed on a plain string pathFilter.
    assert.equal(libraryOf(PLATFORM_WINDOWS, "libssl-3.dll", undefined), "OpenSSL/BoringSSL");
    assert.ok(
        !librariesOf(PLATFORM_WINDOWS, "libssl-3.dll", undefined).includes("Python OpenSSL"),
        "a string pathFilter must fail closed when no path is available",
    );
    // The linux generic entry has no pathFilter, so it still wins there.
    assert.equal(libraryOf(PLATFORM_LINUX, "libssl.so", undefined), "OpenSSL/BoringSSL");
});

// ---------------------------------------------------------------------------
// A. The darwin libssl*.dylib partition, exhaustively
// ---------------------------------------------------------------------------

interface DarwinCase {
    moduleName: string;
    modulePath: string;
    expected: string;
}

/**
 * One row per real-world libssl*.dylib provenance. The partition claims to be
 * exhaustive AND mutually exclusive, so every row must yield exactly one
 * library — see the two property assertions after the per-row test.
 */
const DARWIN_LIBSSL_CASES: DarwinCase[] = [
    // Apple's system LibreSSL — the one and only /usr/lib/ case.
    { moduleName: "libssl.48.dylib", modulePath: "/usr/lib/libssl.48.dylib", expected: "LibreSSL" },
    // Homebrew arm64: the opt/ symlink and the Cellar realpath it resolves to
    // (Frida reports either, depending on how the module was loaded).
    { moduleName: "libssl.3.dylib", modulePath: "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib", expected: "OpenSSL" },
    { moduleName: "libssl.3.dylib", modulePath: "/opt/homebrew/Cellar/openssl@3/3.6.1/lib/libssl.3.dylib", expected: "OpenSSL" },
    // DOUBLE-HOOK REGRESSION (this row and the 3.9-framework row below): the old
    // generic excludePattern was /^libssl\.\d+\.dylib$/, and `\d+` cannot span
    // the dot in "1.1". So libssl.1.1.dylib matched the generic entry as well,
    // and because ssl_library_loader invokes EVERY match, TWO executors
    // installed on one module — the Apple BoringSSL one writing its struct
    // offset into a genuine OpenSSL SSL_CTX. VERSIONED_LIBSSL_DYLIB's
    // `(\.\d+)*` closes it.
    { moduleName: "libssl.1.1.dylib", modulePath: "/opt/homebrew/opt/openssl@1.1/lib/libssl.1.1.dylib", expected: "OpenSSL" },
    // Homebrew on Intel.
    { moduleName: "libssl.3.dylib", modulePath: "/usr/local/opt/openssl@3/lib/libssl.3.dylib", expected: "OpenSSL" },
    // pyenv.
    { moduleName: "libssl.3.dylib", modulePath: "/Users/u/.pyenv/versions/3.12.1/lib/libssl.3.dylib", expected: "OpenSSL" },
    // python.org framework Python — the capital-P case that matched nothing
    // under the old case-sensitive substring compare.
    { moduleName: "libssl.3.dylib", modulePath: "/Library/Frameworks/Python.framework/Versions/3.13/lib/libssl.3.dylib", expected: "OpenSSL" },
    // ...and its 3.9-era sibling, which is also the libssl.1.1 double-hook row.
    { moduleName: "libssl.1.1.dylib", modulePath: "/Library/Frameworks/Python.framework/Versions/3.9/lib/libssl.1.1.dylib", expected: "OpenSSL" },
    // Xcode's bundled Python3.framework.
    {
        moduleName: "libssl.3.dylib",
        modulePath: "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/"
            + "Python3.framework/Versions/3.9/lib/libssl.3.dylib",
        expected: "OpenSSL",
    },
    // MacPorts.
    { moduleName: "libssl.3.dylib", modulePath: "/opt/local/lib/libssl.3.dylib", expected: "OpenSSL" },
    // SUBSTRING-VS-ANCHORED REGRESSION: an app vendoring its own sysroot. The
    // old LibreSSL pathFilter was the plain substring "/usr/lib/", which this
    // path contains — so a bundled OpenSSL was misrouted to the priority-150
    // LibreSSL hook. SYSTEM_LIBRESSL_PATH is anchored at the real filesystem
    // root, so only the genuine /usr/lib/libssl.<n>.dylib qualifies.
    { moduleName: "libssl.3.dylib", modulePath: "/Applications/MyApp.app/Contents/Frameworks/usr/lib/libssl.3.dylib", expected: "OpenSSL" },
    // The same app without the vendored sysroot directory.
    { moduleName: "libssl.3.dylib", modulePath: "/Applications/MyApp.app/Contents/Frameworks/libssl.3.dylib", expected: "OpenSSL" },
    // Unversioned / oddly-named libssl-shaped dylibs: the generic entry's
    // territory, since its excludePattern IS VERSIONED_LIBSSL_DYLIB.
    { moduleName: "libssl.dylib", modulePath: "/opt/homebrew/lib/libssl.dylib", expected: "OpenSSL/BoringSSL" },
    { moduleName: "libssl_custom.dylib", modulePath: "/opt/x/lib/libssl_custom.dylib", expected: "OpenSSL/BoringSSL" },
    // "mylibssl.3.dylib" is versioned-LOOKING but the `(^|\/)` anchor refuses a
    // name-internal match, so it is not a system/OpenSSL naming form.
    { moduleName: "mylibssl.3.dylib", modulePath: "/opt/x/lib/mylibssl.3.dylib", expected: "OpenSSL/BoringSSL" },
];

for (const { moduleName, modulePath, expected } of DARWIN_LIBSSL_CASES) {
    test(`darwin partition: ${modulePath} -> ${expected}`, () => {
        assert.deepEqual(librariesOf(PLATFORM_DARWIN, moduleName, modulePath), [expected]);
    });
}

test("darwin partition is mutually exclusive: every real-world libssl path yields EXACTLY one hook", () => {
    // The property that findMatch cannot express: ssl_library_loader invokes
    // every match, so two matches means two executors on one module.
    for (const { moduleName, modulePath } of DARWIN_LIBSSL_CASES) {
        const libs = librariesOf(PLATFORM_DARWIN, moduleName, modulePath);
        assert.equal(libs.length, 1, `${modulePath} matched [${libs.join(", ")}]`);
    }
});

test("darwin partition never selects both LibreSSL and OpenSSL for the same module", () => {
    // These two entries share an identical pattern and are separated ONLY by
    // SYSTEM_LIBRESSL_PATH (positive on one, negative on the other). If those
    // two uses ever drift apart this is where it shows.
    for (const { moduleName, modulePath } of DARWIN_LIBSSL_CASES) {
        const libs = librariesOf(PLATFORM_DARWIN, moduleName, modulePath);
        assert.ok(
            !(libs.includes("LibreSSL") && libs.includes("OpenSSL")),
            `${modulePath} matched both LibreSSL and OpenSSL`,
        );
    }
});

// ---------------------------------------------------------------------------
// B. dlopen(3) argument forms — the `(^|\/)` anchor regression
// ---------------------------------------------------------------------------
// The registry is queried with a bare module name (Process.enumerateModules)
// AND with the RAW dlopen argument from the dynamic-loader hook in
// shared_functions.ts. That argument is routinely a full path or an
// @rpath/@loader_path string, so `moduleName` IS the path in these cases. Every
// assertion here fails against a `^`-anchored pattern (the previous
// /^libssl\.\d+\.dylib$/), which is exactly the point: under that pattern the
// dynamic-load path fell through to the generic BoringSSL entry — the wrong
// executor for genuine OpenSSL.

test("dlopen form: an absolute path passed as the module name routes to OpenSSL", () => {
    const arg = "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib";
    assert.deepEqual(librariesOf(PLATFORM_DARWIN, arg, arg), ["OpenSSL"]);
});

test("dlopen form: an absolute path as module name with NO resolved module path routes to OpenSSL", () => {
    // The dlopen hook fires before the module is in the module map, so
    // extractModulePath can legitimately come back empty.
    const arg = "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib";
    assert.deepEqual(librariesOf(PLATFORM_DARWIN, arg, undefined), ["OpenSSL"]);
});

test("dlopen form: @rpath/libssl.3.dylib routes to OpenSSL (excludePathFilter fails open)", () => {
    assert.deepEqual(librariesOf(PLATFORM_DARWIN, "@rpath/libssl.3.dylib", undefined), ["OpenSSL"]);
});

test("dlopen form: @loader_path/../lib/libssl.1.1.dylib routes to OpenSSL", () => {
    // Doubly load-bearing: the `(^|\/)` anchor handles the @loader_path prefix
    // and `(\.\d+)*` handles the "1.1" version form.
    assert.deepEqual(
        librariesOf(PLATFORM_DARWIN, "@loader_path/../lib/libssl.1.1.dylib", undefined),
        ["OpenSSL"],
    );
});

test("dlopen form: the system LibreSSL path as module name still routes to LibreSSL", () => {
    const arg = "/usr/lib/libssl.48.dylib";
    assert.deepEqual(librariesOf(PLATFORM_DARWIN, arg, arg), ["LibreSSL"]);
});

// ---------------------------------------------------------------------------
// C. Registry primitives in isolation
// ---------------------------------------------------------------------------
// Small ad-hoc registries, independent of the platform fixtures, so a change in
// platform routing cannot mask a change in the primitives themselves.

function adhoc(...regs: Array<Record<string, unknown>>): HookRegistry {
    const reg = new HookRegistry();
    reg.registerAll(regs.map(r => ({
        platform: PLATFORM_DARWIN, hookFn: noopHook, protocol: "tls", ...r,
    })) as any);
    return reg;
}

const FRAMEWORK_PY = "/Library/Frameworks/Python.framework/Versions/3.13/lib/libssl.3.dylib";

test("C1: a RegExp pathFilter is tested against the RAW path (no implicit /i)", () => {
    const upper = adhoc({ pattern: /libssl/, library: "H", pathFilter: /Python/ });
    assert.deepEqual(
        upper.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", FRAMEWORK_PY, "tls").map(h => h.library),
        ["H"],
    );
    // Documents the contract: RegExp authors add /i themselves. Silently
    // lower-casing the path for a RegExp would make anchored patterns like
    // SYSTEM_LIBRESSL_PATH behave differently from what they read as.
    const lower = adhoc({ pattern: /libssl/, library: "H", pathFilter: /python/ });
    assert.deepEqual(lower.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", FRAMEWORK_PY, "tls"), []);
    const lowerInsensitive = adhoc({ pattern: /libssl/, library: "H", pathFilter: /python/i });
    assert.deepEqual(
        lowerInsensitive.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", FRAMEWORK_PY, "tls").map(h => h.library),
        ["H"],
    );
});

test("C2: a string pathFilter is a case-INSENSITIVE substring", () => {
    const reg = adhoc({ pattern: /libssl/, library: "H", pathFilter: "python" });
    for (const path of [
        FRAMEWORK_PY,
        "/usr/lib/python3.11/libssl.so.3",
        "C:\\Python312\\DLLs\\libssl-3.dll",
        "/opt/PYTHON/libssl.3.dylib",
    ]) {
        assert.deepEqual(
            reg.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", path, "tls").map(h => h.library),
            ["H"], path,
        );
    }
    assert.deepEqual(
        reg.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", "/opt/homebrew/lib/libssl.3.dylib", "tls"),
        [],
    );
});

test("C3: excludePathFilter accepts a bare string, a bare RegExp, and a mixed array", () => {
    const name = "libssl.3.dylib";
    const hit = (reg: HookRegistry, path: string) =>
        reg.findAllMatches(PLATFORM_DARWIN, name, path, "tls").map(h => h.library);

    // Bare string: case-insensitive substring, same as pathFilter.
    const str = adhoc({ pattern: /libssl/, library: "H", excludePathFilter: "python" });
    assert.deepEqual(hit(str, FRAMEWORK_PY), []);
    assert.deepEqual(hit(str, "/opt/homebrew/lib/libssl.3.dylib"), ["H"]);

    // Bare RegExp: raw path, anchored.
    const re = adhoc({ pattern: /libssl/, library: "H", excludePathFilter: SYSTEM_LIBRESSL_PATH });
    assert.deepEqual(hit(re, "/usr/lib/libssl.3.dylib"), []);
    assert.deepEqual(hit(re, "/Applications/A.app/Contents/Frameworks/usr/lib/libssl.3.dylib"), ["H"]);

    // Array: ANY match excludes; none matching includes.
    const arr = adhoc({
        pattern: /libssl/, library: "H",
        excludePathFilter: ["python", /^\/usr\/lib\//, "conda"],
    });
    assert.deepEqual(hit(arr, FRAMEWORK_PY), [], "first filter (string) must exclude");
    assert.deepEqual(hit(arr, "/usr/lib/libssl.3.dylib"), [], "second filter (RegExp) must exclude");
    assert.deepEqual(hit(arr, "/opt/miniconda3/lib/libssl.3.dylib"), [], "third filter must exclude");
    assert.deepEqual(hit(arr, "/opt/homebrew/lib/libssl.3.dylib"), ["H"], "no filter matches => included");

    // An empty array is inert, not "exclude everything" (it is truthy, so this
    // is a real branch through the exclusion loop).
    const empty = adhoc({ pattern: /libssl/, library: "H", excludePathFilter: [] });
    assert.deepEqual(hit(empty, "/usr/lib/libssl.3.dylib"), ["H"]);
});

test("C4: excludePathFilter FAILS OPEN when no module path is available", () => {
    // An exclusion that cannot be evaluated must not exclude — otherwise the
    // complementary LibreSSL/OpenSSL pair would both drop out on the dlopen
    // path and leave the module entirely unhooked.
    const reg = adhoc({ pattern: /libssl/, library: "H", excludePathFilter: "python" });
    assert.deepEqual(
        reg.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", undefined, "tls").map(h => h.library),
        ["H"],
    );
});

test("C5: pathFilter FAILS CLOSED when no module path is available", () => {
    // A positive requirement that cannot be verified is treated as unmet.
    const reg = adhoc({ pattern: /libssl/, library: "H", pathFilter: "python" });
    assert.deepEqual(reg.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", undefined, "tls"), []);
    const reRe = adhoc({ pattern: /libssl/, library: "H", pathFilter: SYSTEM_LIBRESSL_PATH });
    assert.deepEqual(reRe.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", undefined, "tls"), []);
});

test("C6: a hook carrying BOTH pathFilter and excludePathFilter has BOTH evaluated", () => {
    // THIS is the only test that catches the removed `return excluded`
    // short-circuit. An earlier _isExcluded ended its pathFilter branch with
    // `return excluded`, which made every gate below it dead code for a hook
    // carrying both — the second primitive would ship silently inert, and
    // nothing else in this file would notice. The decisive row is
    // satisfies-pathFilter AND matches-excludePathFilter: a one-gate
    // implementation reports "not excluded" there.
    const reg = () => adhoc({
        pattern: /libssl/, library: "H",
        pathFilter: "/lib/",                 // positive: must be under some lib dir
        excludePathFilter: /^\/usr\/lib\//,  // negative: but not the system one
    });
    const hit = (path?: string) =>
        reg().findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", path, "tls").map(h => h.library);

    // pathFilter satisfied, excludePathFilter matched => EXCLUDED (the decisive case).
    assert.deepEqual(hit("/usr/lib/libssl.3.dylib"), [], "both gates must be evaluated");
    // pathFilter satisfied, excludePathFilter not matched => included.
    assert.deepEqual(hit("/opt/homebrew/lib/libssl.3.dylib"), ["H"]);
    // pathFilter unsatisfied, excludePathFilter not matched => excluded by pathFilter.
    assert.deepEqual(hit("/opt/homebrew/Frameworks/libssl.3.dylib"), []);
    // No path at all: pathFilter fails closed, which is enough to exclude.
    assert.deepEqual(hit(undefined), []);
});

test("C7: excludePattern (name) and excludePathFilter (path) are independent gates", () => {
    const nameExcluded = adhoc({
        pattern: /libssl/, library: "H",
        excludePattern: /^libssl\.3\.dylib$/,
        excludePathFilter: "python",
    });
    // Name excluded even though the path is perfectly fine.
    assert.deepEqual(
        nameExcluded.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", "/opt/homebrew/lib/libssl.3.dylib", "tls"),
        [],
    );
    // ...and a different name passes the name gate.
    assert.deepEqual(
        nameExcluded.findAllMatches(PLATFORM_DARWIN, "libssl.4.dylib", "/opt/homebrew/lib/libssl.4.dylib", "tls")
            .map(h => h.library),
        ["H"],
    );
    // Conversely: name gate fine, path gate excludes.
    assert.deepEqual(
        nameExcluded.findAllMatches(PLATFORM_DARWIN, "libssl.4.dylib", FRAMEWORK_PY, "tls"),
        [],
    );
});

test("C8: the matchNonTLSLibrary denylist short-circuits before any path logic", () => {
    // The denylist is the first gate, so a denylisted module is skipped even
    // when its path satisfies the hook's pathFilter (i.e. the hook would
    // otherwise definitely install). Frida reports Android as "linux" and the
    // test stubs leave Process.platform at "linux", so the linux-scoped
    // WebView entries apply here.
    const reg = new HookRegistry();
    reg.registerAll([{
        platform: PLATFORM_LINUX, pattern: /.*libwebviewchromium.*\.so/, hookFn: noopHook,
        library: "WebView BoringSSL", pathFilter: "/system/", protocol: "tls",
    }] as any);
    const path = "/system/lib64/libwebviewchromium_loader.so";
    assert.deepEqual(reg.findAllMatches(PLATFORM_LINUX, "libwebviewchromium_loader.so", path, "tls"), []);
    // The real monolith (which DOES carry BoringSSL) is unaffected.
    assert.deepEqual(
        reg.findAllMatches(PLATFORM_LINUX, "libwebviewchromium.so", "/system/lib64/libwebviewchromium.so", "tls")
            .map(h => h.library),
        ["WebView BoringSSL"],
    );
});

test("C9: shared RegExp predicates are stateless — repeated queries give identical results", () => {
    // The Darwin partition's correctness rests on several entries consuming the
    // SAME RegExp object (see darwin_library_patterns.ts). A /g or /y flag would
    // make .test() stateful via lastIndex and make matching depend on how many
    // times the registry was queried before. Locked by construction here: one
    // instance used as `pattern` twice and as `excludePathFilter` once.
    const shared = /libssl\.\d+\.dylib$/;
    const reg = adhoc(
        { pattern: shared, library: "A" },
        { pattern: shared, library: "B" },
        { pattern: /.*libssl.*/, library: "C", excludePathFilter: shared },
    );
    const results: string[][] = [];
    for (let i = 0; i < 5; i++) {
        results.push(
            reg.findAllMatches(PLATFORM_DARWIN, "libssl.3.dylib", "/x/libssl.3.dylib", "tls").map(h => h.library),
        );
    }
    for (const r of results) {
        assert.deepEqual(r, ["A", "B"], `run ${results.indexOf(r)} diverged`);
    }
    // And the real shared predicates themselves carry no sticky/global flag.
    for (const re of [VERSIONED_LIBSSL_DYLIB, SYSTEM_LIBRESSL_PATH, ANY_LIBSSL_DYLIB]) {
        assert.ok(!re.global && !re.sticky, `${re} must not carry /g or /y`);
    }
});

// ---------------------------------------------------------------------------
// D. Linux / Windows single-match (the double-hook fix)
// ---------------------------------------------------------------------------
// Before `excludePathFilter: "python"` was added to the generic entries, a
// Python's own libssl matched BOTH the python entry and the generic one, and
// ssl_library_loader installed both executors on the same module.

test("linux: a Python's own libssl matches EXACTLY the Python OpenSSL hook", () => {
    const libs = librariesOf(PLATFORM_LINUX, "libssl.so.3", "/usr/lib/python3.11/lib-dynload/../../libssl.so.3");
    assert.equal(libs.length, 1, `expected one hook, got [${libs.join(", ")}]`);
    assert.deepEqual(libs, ["Python OpenSSL"]);
});

test("linux: a distro libssl matches EXACTLY the generic OpenSSL/BoringSSL hook", () => {
    const libs = librariesOf(PLATFORM_LINUX, "libssl.so.3", "/usr/lib/x86_64-linux-gnu/libssl.so.3");
    assert.equal(libs.length, 1, `expected one hook, got [${libs.join(", ")}]`);
    assert.deepEqual(libs, ["OpenSSL/BoringSSL"]);
});

test("windows: a Python's own libssl matches EXACTLY the Python OpenSSL hook", () => {
    for (const path of [
        "C:\\Python312\\DLLs\\libssl-3.dll",
        // The per-user installer layout, where "Python" appears twice.
        "C:\\Users\\u\\AppData\\Local\\Programs\\Python\\Python312\\DLLs\\libssl-3.dll",
    ]) {
        const libs = librariesOf(PLATFORM_WINDOWS, "libssl-3.dll", path);
        assert.equal(libs.length, 1, `${path} matched [${libs.join(", ")}]`);
        assert.deepEqual(libs, ["Python OpenSSL"], path);
    }
});

test("windows: a standalone OpenSSL install matches EXACTLY the generic OpenSSL/BoringSSL hook", () => {
    const libs = librariesOf(PLATFORM_WINDOWS, "libssl-3.dll", "C:\\Program Files\\OpenSSL\\bin\\libssl-3.dll");
    assert.equal(libs.length, 1, `expected one hook, got [${libs.join(", ")}]`);
    assert.deepEqual(libs, ["OpenSSL/BoringSSL"]);
});

// ---------------------------------------------------------------------------
// E. iOS registers the same partition (agent/platforms/ios.ts)
// ---------------------------------------------------------------------------

test("ios: the system LibreSSL in the shared cache routes to LibreSSL", () => {
    assert.deepEqual(
        librariesOf(PLATFORM_DARWIN, "libssl.48.dylib", "/usr/lib/libssl.48.dylib", makeIosRegistry()),
        ["LibreSSL"],
    );
});

test("ios: an app-bundled versioned libssl routes to OpenSSL", () => {
    // Neither of these had ANY entry in ios.ts before: an app shipping genuine
    // OpenSSL as a versioned dylib went completely unhooked.
    assert.deepEqual(
        librariesOf(
            PLATFORM_DARWIN, "libssl.3.dylib",
            "/private/var/containers/Bundle/Application/1234/MyApp.app/Frameworks/libssl.3.dylib",
            makeIosRegistry(),
        ),
        ["OpenSSL"],
    );
});

test("ios: an unversioned libssl.dylib routes to the generic OpenSSL/BoringSSL hook", () => {
    assert.deepEqual(
        librariesOf(
            PLATFORM_DARWIN, "libssl.dylib",
            "/private/var/containers/Bundle/Application/1234/MyApp.app/Frameworks/libssl.dylib",
            makeIosRegistry(),
        ),
        ["OpenSSL/BoringSSL"],
    );
});

test("ios: libboringssl.dylib still routes to the BoringSSL hook only", () => {
    // The libssl partition must not have started poaching Apple's BoringSSL:
    // "libboringssl" contains no "libssl" substring, so ANY_LIBSSL_DYLIB
    // correctly leaves it alone.
    assert.deepEqual(
        librariesOf(PLATFORM_DARWIN, "libboringssl.dylib", "/usr/lib/libboringssl.dylib", makeIosRegistry()),
        ["BoringSSL"],
    );
});

// ---------------------------------------------------------------------------
// F. findByLibraryType priority lock
// ---------------------------------------------------------------------------

test("findByLibraryType(darwin, 'openssl') deterministically returns the priority-120 OpenSSL entry", () => {
    // The tlsLibHunter scan path resolves a hook by libraryType, and TWO darwin
    // entries declare libraryType "openssl": the genuine-OpenSSL one and the
    // generic Apple-BoringSSL one. getHooks sorts by descending priority and
    // findByLibraryType takes the first hit, so at EQUAL priority the winner
    // depended on Array#sort stability and registration order. Priority 120 on
    // the OpenSSL entry is what makes it deterministic — so a future "priority
    // cleanup" that flattens it back to 100 fails loudly right here rather than
    // silently sending scanned OpenSSL modules to the BoringSSL executor.
    const hook = makeRegistry().findByLibraryType(PLATFORM_DARWIN, "openssl", "tls");
    assert.equal(hook?.library, "OpenSSL");
    assert.equal(hook?.priority, 120);
    // The libressl type still resolves to the priority-150 system entry.
    const libressl = makeRegistry().findByLibraryType(PLATFORM_DARWIN, "libressl", "tls");
    assert.equal(libressl?.library, "LibreSSL");
});

// ---------------------------------------------------------------------------
// G. Foundation F1 — multi-protocol selection (set-based protocolMatches)
// ---------------------------------------------------------------------------
//
// `protocolMatches` is private, so its contract is asserted through
// `findAllMatches`, which the loaders actually call. A hook tagged
// protocol:"tls" must install when the requested SET contains "tls" (alone or
// alongside another protocol), but NOT when the set contains only an unrelated
// protocol with no implication. A single string and a Set of one behave
// identically, and a comma-joined string parses to the same set.

function makeMultiProtocolRegistry(): HookRegistry {
    const reg = new HookRegistry();
    reg.registerAll([
        { platform: PLATFORM_LINUX, pattern: /libfoo\.so/, hookFn: noopHook, library: "Foo-TLS", protocol: "tls" },
        // An unrelated companion protocol with no implication to/from tls.
        { platform: PLATFORM_LINUX, pattern: /libfoo\.so/, hookFn: noopHook, library: "Foo-X", protocol: "xproto" },
    ]);
    return reg;
}

test("multiselect: tls hook installs for {tls}, {tls,xproto}; not for {xproto}", () => {
    const reg = makeMultiProtocolRegistry();
    const libs = (p: any) =>
        reg.findAllMatches(PLATFORM_LINUX, "libfoo.so", undefined, p).map(h => h.library).sort();

    // {tls} → only the tls hook.
    assert.deepEqual(libs(new Set(["tls"])), ["Foo-TLS"]);
    // {tls, xproto} → BOTH hooks (each selected protocol is independent).
    assert.deepEqual(libs(new Set(["tls", "xproto"])), ["Foo-TLS", "Foo-X"]);
    // {xproto} → the tls hook does NOT install (x is not tls, no implication).
    assert.deepEqual(libs(new Set(["xproto"])), ["Foo-X"]);
});

test("multiselect: single string, one-element set and comma-joined string agree", () => {
    const reg = makeMultiProtocolRegistry();
    const libs = (p: any) =>
        reg.findAllMatches(PLATFORM_LINUX, "libfoo.so", undefined, p).map(h => h.library).sort();

    // Legacy single string and its one-element set are identical.
    assert.deepEqual(libs("tls"), ["Foo-TLS"]);
    assert.deepEqual(libs("tls"), libs(new Set(["tls"])));
    // A comma-joined string is split into the same multi-protocol set.
    assert.deepEqual(libs("tls,xproto"), ["Foo-TLS", "Foo-X"]);
    assert.deepEqual(libs("tls,xproto"), libs(new Set(["tls", "xproto"])));
});

test("multiselect: auto/all and a set containing them install everything (no filter)", () => {
    const reg = makeMultiProtocolRegistry();
    const libs = (p: any) =>
        reg.findAllMatches(PLATFORM_LINUX, "libfoo.so", undefined, p).map(h => h.library).sort();

    assert.deepEqual(libs("auto"), ["Foo-TLS", "Foo-X"]);
    assert.deepEqual(libs("all"), ["Foo-TLS", "Foo-X"]);
    assert.deepEqual(libs(new Set(["all"])), ["Foo-TLS", "Foo-X"]);
    // A meta value anywhere in the set collapses to "install everything".
    assert.deepEqual(libs(new Set(["tls", "auto"])), ["Foo-TLS", "Foo-X"]);
});

// ---------------------------------------------------------------------------
// G'. RC4 as an INDEPENDENT protocol (Workstream 1)
// ---------------------------------------------------------------------------
//
// A `protocol:"rc4"` hook must install when the requested set contains `rc4`
// (alone or alongside `tls`) but NOT for `{tls}` — RC4 neither implies nor is
// implied by TLS. This mirrors the `agent/rc4/` contributor's rows (which tag
// their key-setup hooks `protocol:"rc4"`), asserted through `findAllMatches`.

function makeRc4Registry(): HookRegistry {
    const reg = new HookRegistry();
    reg.registerAll([
        { platform: PLATFORM_LINUX, pattern: /libcrypto\.so/, hookFn: noopHook, library: "TLS-openssl", protocol: "tls" },
        { platform: PLATFORM_LINUX, pattern: /libcrypto\.so/, hookFn: noopHook, library: "RC4-set-key", protocol: "rc4" },
    ]);
    return reg;
}

test("rc4: a protocol:'rc4' hook installs for {rc4} and {tls,rc4} but NOT {tls}", () => {
    const reg = makeRc4Registry();
    const libs = (p: any) =>
        reg.findAllMatches(PLATFORM_LINUX, "libcrypto.so", undefined, p).map(h => h.library).sort();

    // {rc4} → only the rc4 hook (no TLS hooks: rc4 does not imply tls).
    assert.deepEqual(libs(new Set(["rc4"])), ["RC4-set-key"]);
    // {tls, rc4} → BOTH (each explicitly selected; independent).
    assert.deepEqual(libs(new Set(["tls", "rc4"])), ["RC4-set-key", "TLS-openssl"]);
    // {tls} → the rc4 hook does NOT install (no implication tls → rc4).
    assert.deepEqual(libs(new Set(["tls"])), ["TLS-openssl"]);
    // A comma-joined string parses to the same set.
    assert.deepEqual(libs("tls,rc4"), ["RC4-set-key", "TLS-openssl"]);
});

// ---------------------------------------------------------------------------
// G''. RC4 as a SECONDARY protocol behind a non-TLS primary
// ---------------------------------------------------------------------------
//
// The CLI/TUI can send e.g. `protocol_select: "ssh,rc4"` or "mtproto,rc4" (the
// primary first). Every platform loader registers its core table PLUS
// `...collectContributedHooks()` and installs through the registry filtered by
// the FULL selection set — there is no ssh/mtproto early-return path — so the
// contributed RC4 rows must install alongside the primary's hooks regardless of
// which protocol is primary. Built the way the platform loaders build it: core
// rows + the contributor seam (`registerHookContributor` →
// `collectContributedHooks`).

// Registered ONCE at module scope: contributor state is process-global (as it
// is in the agent, where agent/rc4/index.ts registers at import time).
registerHookContributor({
    platform: PLATFORM_LINUX, pattern: /libcrypto.*\.so/, hookFn: noopHook,
    library: "RC4 (contributed)", libraryType: "rc4", protocol: "rc4",
});

function makePrimaryPlusRc4Registry(): HookRegistry {
    const reg = new HookRegistry();
    reg.registerAll([
        { platform: PLATFORM_LINUX, pattern: /.*libssl\.so/, hookFn: noopHook, library: "TLS-openssl", protocol: "tls" },
        { platform: PLATFORM_LINUX, pattern: /.*libssh2?\.so/, hookFn: noopHook, library: "libssh", protocol: "ssh" },
        { platform: PLATFORM_LINUX, pattern: /^(\/.+\/)?(ssh|sshd)$/, hookFn: noopHook, library: "OpenSSH", protocol: "ssh" },
        { platform: PLATFORM_LINUX, pattern: /libtmessages.*\.so/, hookFn: noopHook, library: "Telegram tgnet", protocol: "mtproto" },
        { platform: PLATFORM_LINUX, pattern: /libtmessages.*\.so/, hookFn: noopHook, library: "Telegram Secret Chat", protocol: "telegram" },
        { platform: PLATFORM_LINUX, pattern: /.*libringrtc_rffi.*\.so/, hookFn: noopHook, library: "Cronet (RingRTC)", protocol: "tls", excludeProtocols: ["signal"] },
        ...collectContributedHooks(),
    ]);
    return reg;
}

test("rc4 secondary: contributed rc4 hooks install behind ssh/mtproto/telegram/signal primaries", () => {
    const reg = makePrimaryPlusRc4Registry();
    const libs = (p: any) => reg.getHooks(PLATFORM_LINUX, p).map(h => h.library).sort();

    assert.deepEqual(libs("ssh,rc4"), ["OpenSSH", "RC4 (contributed)", "libssh"]);
    assert.deepEqual(libs("mtproto,rc4"), ["RC4 (contributed)", "Telegram tgnet"]);
    // telegram implies mtproto; rc4 still rides along.
    assert.deepEqual(libs("telegram,rc4"), ["RC4 (contributed)", "Telegram Secret Chat", "Telegram tgnet"]);
    // No public signal rows; rc4 still installs, and nothing TLS leaks in.
    assert.deepEqual(libs("signal,rc4"), ["RC4 (contributed)"]);
    // Order-insensitive: rc4 as primary yields the same set.
    assert.deepEqual(libs("rc4,ssh"), libs("ssh,rc4"));
});

test("rc4 secondary: ssh/mtproto alone are unchanged (no rc4 rows)", () => {
    const reg = makePrimaryPlusRc4Registry();
    const libs = (p: any) => reg.getHooks(PLATFORM_LINUX, p).map(h => h.library).sort();

    assert.deepEqual(libs("ssh"), ["OpenSSH", "libssh"]);
    assert.deepEqual(libs("mtproto"), ["Telegram tgnet"]);
    assert.deepEqual(libs("telegram"), ["Telegram Secret Chat", "Telegram tgnet"]);
    assert.deepEqual(libs("signal"), []);
});

test("rc4 secondary: module-level match on libcrypto under ssh,rc4 / mtproto,rc4", () => {
    const reg = makePrimaryPlusRc4Registry();
    const libs = (p: any, mod: string) =>
        reg.findAllMatches(PLATFORM_LINUX, mod, undefined, p).map(h => h.library);

    assert.deepEqual(libs("ssh,rc4", "libcrypto.so.3"), ["RC4 (contributed)"]);
    assert.deepEqual(libs("mtproto,rc4", "libcrypto.so.3"), ["RC4 (contributed)"]);
    assert.deepEqual(libs("ssh", "libcrypto.so.3"), []);
    // The primary's own module still matches alongside.
    assert.deepEqual(libs("ssh,rc4", "sshd"), ["OpenSSH"]);
});
