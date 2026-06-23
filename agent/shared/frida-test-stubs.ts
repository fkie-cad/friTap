// Minimal Frida global stubs for running pure agent helpers under Node (node:test
// + tsx). Import this module BEFORE any agent module so the Frida globals its
// import graph references at load time are defined. Provides setPlatform() to
// flip Process.platform per test (readSockaddrFamily reads it at call time).

const G = globalThis as any;
const noop = () => {};
G.Process = {
    platform: "linux", arch: "x64", pointerSize: 8,
    getCurrentThreadId: () => 0,
    enumerateModules: () => [],
    enumerateThreads: () => [],
    findModuleByName: () => null,
    findModuleByAddress: () => null,
    getModuleByName: () => null,
    setExceptionHandler: noop,
    id: 0,
};
G.Java = { available: false, perform: noop, use: noop, scheduleOnMainThread: noop };
G.ObjC = { available: false, classes: {}, schedule: noop };
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
G.ptr = () => ({ isNull: () => true });
G.Script = { nextTick: (fn: () => void) => fn(), bindWeak: noop, runtime: "QJS" };
G.setTimeout = G.setTimeout || ((fn: () => void) => { fn(); return 0; });

export function setPlatform(p: string): void { G.Process.platform = p; }
