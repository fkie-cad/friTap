import { devlog } from "../util/log.js";

/**
 * Identity of a loaded image for hook bookkeeping: its BASE ADDRESS.
 *
 * A module can reach the loaders under several spellings — the bare name the
 * initial scan sees (`libssl.3.dylib`), the real path a dependency scan reports,
 * or whatever string an app hands to dlopen(), e.g. a symlinked path such as
 * `/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib` that Frida's name lookup does
 * not resolve. All of them are the same mapped image, so only the base address
 * is a reliable key; keying by the spelling re-ran the hook executor per alias
 * and duplicated every record.
 */

let realpathFn: NativeFunction<NativePointer, [NativePointer, NativePointer]> | null | undefined;

/** libc realpath(3), resolved once; null where it does not exist (Windows). */
function libcRealpath(): NativeFunction<NativePointer, [NativePointer, NativePointer]> | null {
    if (realpathFn !== undefined) return realpathFn;
    realpathFn = null;
    try {
        const address = Module.findGlobalExportByName("realpath");
        if (address !== null && !address.isNull()) {
            realpathFn = new NativeFunction(address, "pointer", ["pointer", "pointer"]);
        }
    } catch (error) {
        devlog(`[module-identity] realpath unavailable: ${error}`);
    }
    return realpathFn;
}

/** Canonical (symlink-free) form of a filesystem path, or null. */
function canonicalPath(path: string): string | null {
    const realpath = libcRealpath();
    if (realpath === null) return null;
    try {
        const resolved = Memory.alloc(4096);
        const result = realpath(Memory.allocUtf8String(path), resolved);
        return result.isNull() ? null : resolved.readUtf8String();
    } catch (_) {
        return null;
    }
}

/** The loaded module `nameOrPath` refers to, following symlinked paths; null if not loaded. */
export function findLoadedModule(nameOrPath: string): Module | null {
    let module: Module | null = null;
    try { module = Process.findModuleByName(nameOrPath); } catch (_) { /* fall through */ }
    if (module === null && nameOrPath.includes("/")) {
        const canonical = canonicalPath(nameOrPath);
        if (canonical !== null && canonical !== nameOrPath) {
            try { module = Process.findModuleByName(canonical); } catch (_) { /* not loaded */ }
        }
    }
    return module;
}

/**
 * Bookkeeping key for `nameOrPath`: `base:<address>` while the image is loaded,
 * else `name:<spelling>` (e.g. a Wine PE image that is not a Frida module).
 */
export function moduleIdentityKey(nameOrPath: string): string {
    const module = findLoadedModule(nameOrPath);
    return module !== null ? baseKey(module.base) : nameKey(nameOrPath);
}

export function baseKey(base: NativePointer | string): string {
    return `base:${base.toString()}`;
}

export function nameKey(nameOrPath: string): string {
    return `name:${nameOrPath}`;
}
