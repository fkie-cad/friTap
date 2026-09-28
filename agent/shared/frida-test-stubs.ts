// Minimal Frida global stubs for running pure agent helpers under Node (node:test
// + tsx). Import this module BEFORE any agent module so the Frida globals its
// import graph references at load time are defined. Provides setPlatform() to
// flip Process.platform per test (readSockaddrFamily reads it at call time).

const G = globalThis as any;
const noop = () => {};
/** Page-sized readable mapping handed out by the default findRangeByAddress(). */
const STUB_RANGE_SIZE = 0x1000;

/** Addresses treated as UNMAPPED by findRangeByAddress. Set by stubRanges(). */
let unmappedAddresses: Set<string> | null = null;

function defaultRangeFor(address: any): any {
    if (unmappedAddresses && unmappedAddresses.has(String(address))) return null;
    return { base: address, size: STUB_RANGE_SIZE, protection: "r-x" };
}

/**
 * Declare specific addresses as unmapped, so a range check can actually fail.
 *
 * The default stub reports EVERY address as mapped. That is deliberate — see
 * findRangeByAddress below — but it means `isReadable()` is unconditionally
 * true under Node, so a guard that rejects unmapped addresses is unreachable in
 * tests and would still pass if it were deleted. Opt in here to exercise the
 * rejection branch:
 *
 *   stubRanges(["0x0"])        // this address is not mapped
 *   stubRanges(null)           // restore the permissive default
 */
export function stubRanges(unmapped: string[] | null): void {
    unmappedAddresses = unmapped === null ? null : new Set(unmapped);
}
G.Process = {
    platform: "linux", arch: "x64", pointerSize: 8,
    getCurrentThreadId: () => 0,
    enumerateModules: () => [],
    enumerateThreads: () => [],
    findModuleByName: () => null,
    findModuleByAddress: () => null,
    getModuleByName: () => null,
    // agent/util/safe_memory.ts's isReadable() consults this before EVERY
    // dereference. Without it the lookup throws, isReadable() hits its catch and
    // reports false for every address under Node — so a test of a guarded read
    // path (e.g. the symbol-table-hit range check in shared_functions.ts's
    // readAddresses) would fail for the stub's reason rather than a real bug.
    // Deliberately "r-x" and not "rw-": that restores isReadable() without also
    // flipping isWritable(), which every existing test still sees as false.
    // Overridable per test via stubRanges() -- see the note there on why the
    // permissive default cannot itself verify a range check.
    findRangeByAddress: (address: any) => defaultRangeFor(address),
    setExceptionHandler: noop,
    id: 0,
};
G.Java = { available: false, perform: noop, use: noop, scheduleOnMainThread: noop };
// `perform` must be a function: agent/shared/objclib.ts treats a global ObjC with
// a callable perform() as the pre-v17 legacy bridge and re-exports it. Without it
// objclib falls through to the real frida-objc-bridge module, and a test's ObjC
// stubbing silently has no effect on the module under test.
G.ObjC = { available: false, classes: {}, schedule: noop, perform: noop };
G.Module = {
    findGlobalExportByName: () => null, findExportByName: () => null,
    getGlobalExportByName: () => null, load: noop,
};
G.Memory = { alloc: () => ({ isNull: () => false }), protect: noop, scan: noop, scanSync: () => [] };
G.Interceptor = { attach: () => ({ detach: noop }), replace: noop, revert: noop, flush: noop };
G.NativePointer = function () { return { isNull: () => true }; };
G.NULL = { isNull: () => true };
G.NativeFunction = function () { return () => 0; };
G.NativeCallback = function () { return { isNull: () => true }; };
G.ApiResolver = function () { return { enumerateMatches: () => [] }; };
// frida-java-bridge evaluates `ptr(1).not()` in its MODULE BODY
// (node_modules/frida-java-bridge/lib/android.js:41 builds THUMB_BIT_REMOVAL_MASK),
// i.e. before any statement in the importing test can run. A fake pointer carrying
// only isNull() therefore aborted the whole file with "ptr(...).not is not a
// function" — which is why wine_keylog_pattern_hook.test.ts never ran its subtests.
// Self-chaining so follow-on arithmetic (`.and(...).shl(...)`, as in
// frida-java-bridge/lib/alloc.js:76-77) stays safe if a future path reaches it.
function fakePointer(): any {
    const p: any = {
        isNull: () => true,
        toInt32: () => 0,
        toUInt32: () => 0,
        toString: () => "0x0",
        equals: () => false,
        compare: () => 0,
        readPointer: () => fakePointer(),
    };
    for (const op of ["not", "and", "or", "xor", "add", "sub", "shl", "shr", "sign", "strip", "blend"]) {
        p[op] = () => p;
    }
    return p;
}
G.ptr = (_value?: any) => fakePointer();
G.Script = { nextTick: (fn: () => void) => fn(), bindWeak: noop, runtime: "QJS" };
// The frida bridges devlog() from their MODULE BODIES (agent/shared/objclib.ts,
// javalib.ts), i.e. before any statement in the importing test can run. A test
// that assigns globalThis.send after its import list is therefore too late, so
// the stub has to be here.
G.send = G.send || noop;
G.recv = G.recv || ((_channel: string, _cb: (value: any) => void) => ({ wait: noop }));
// fritap_agent.ts touches the Frida `rpc` global at module-evaluation time, so
// any test that imports the loader/definition graph needs it defined up front.
G.rpc = G.rpc || { exports: {} };
G.setTimeout = G.setTimeout || ((fn: () => void) => { fn(); return 0; });

export function setPlatform(p: string): void { G.Process.platform = p; }

// ---------------------------------------------------------------------------
// sysctlbyname() — OPT-IN, see stubSysctl().
// ---------------------------------------------------------------------------

/** Current fake sysctl answers: key -> string value. Swapped by stubSysctl(). */
let sysctlValues: Record<string, string> = {};

/** Stand-in for the resolved sysctlbyname() address; only its identity matters. */
const SYSCTL_ADDRESS = { isNull: () => false, toString: () => "0x5359534354" };

let sysctlStubbed = false;

/**
 * One Memory.alloc()/allocUtf8String() block: just enough NativePointer surface
 * for the sysctl two-call protocol — a size_t out-parameter and a C string buffer.
 */
function fakeMemoryBlock(text: string): any {
    const block: any = {
        text,
        u64: 0,
        isNull: () => false,
        writeU64(value: any) { block.u64 = Number(value); return block; },
        // darwin_sysctl.ts does `sizePtr.readU64().valueOf() as number`, so this has
        // to behave like Frida's UInt64 rather than be a bare number.
        readU64: () => ({
            valueOf: () => block.u64,
            toNumber: () => block.u64,
            toString: () => String(block.u64),
        }),
        writeUtf8String(value: string) { block.text = value; return block; },
        readUtf8String: () => block.text,
    };
    return block;
}

/**
 * The real two-call protocol: sysctl(name, NULL, &size, NULL, 0) reports the size
 * the value needs, and only the second call — with a right-sized buffer — fills it.
 * Returning success without writing the size back is what makes darwin_sysctl.ts's
 * `size <= 0 || size > MAX_SYSCTL_STRING` guard reject the read.
 */
function fakeSysctlbyname(namePtr: any, oldp: any, oldlenp: any, _newp: any, _newlen: number): number {
    const name = namePtr.readUtf8String();
    const value = sysctlValues[name];
    if (value === undefined) return -1;                     // ENOENT, as sysctlbyname reports
    const needed = value.length + 1;                        // NUL-terminated; every key here is ASCII
    if (oldp === null || oldp.isNull()) {                   // size query
        oldlenp.writeU64(needed);
        return 0;
    }
    if (oldlenp.readU64().valueOf() < needed) return -1;    // ENOMEM: buffer too small
    oldp.writeUtf8String(value);
    oldlenp.writeU64(needed);
    return 0;
}

/**
 * Make sysctlbyname() resolvable and answer from `values`, e.g.
 *   stubSysctl({ "kern.osproductversion": "26.3.1", "hw.product": "MacBookPro18,4" })
 *
 * OPT-IN on purpose. sysctl is friTap's PRIMARY Apple OS-version source — asking
 * Foundation instead kills a suspended spawn (fkie-cad/friTap#65, see the header of
 * agent/util/darwin_sysctl.ts) — and apple_keylog_offset.test.ts covers the
 * NSProcessInfo FALLBACK by relying on sysctlbyname being unresolvable. So this
 * module's default state must stay "no sysctlbyname"; only a test that asks gets one.
 *
 * Safe to call from inside a test body: getSysctl() resolves lazily on first use,
 * not at import. Calling it again only swaps the answers — the four globals the
 * real code path needs (Module.findGlobalExportByName, Memory.allocUtf8String,
 * Memory.alloc, NativeFunction) are patched once, and every non-sysctl use still
 * reaches the original stub. Note that darwin_sysctl.ts memoizes its answers per
 * process, so swapping values cannot un-memoize an already-read key.
 */
export function stubSysctl(values: Record<string, string>): void {
    sysctlValues = values;
    if (sysctlStubbed) return;
    sysctlStubbed = true;

    // NOTE: the resolution API is findGlobalExportByName, NOT findExportByName.
    const findGlobalExportByName = G.Module.findGlobalExportByName;
    G.Module.findGlobalExportByName = (name: string) =>
        (name === "sysctlbyname" ? SYSCTL_ADDRESS : findGlobalExportByName(name));

    G.Memory.allocUtf8String = (text: string) => fakeMemoryBlock(text);
    G.Memory.alloc = (_size: number) => fakeMemoryBlock("");

    const nativeFunctionStub = G.NativeFunction;
    G.NativeFunction = function (address: any, ...rest: any[]) {
        return address === SYSCTL_ADDRESS ? fakeSysctlbyname : nativeFunctionStub(address, ...rest);
    };
}
