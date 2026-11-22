// agent/shared/fizz_install.ts
//
// The ONE Fizz (Meta TLS 1.3 / mvfst QUIC) install path. Both agent trees use it
// directly as the Android registry row's executor (platforms/android.ts
// fizzAndroidRow): Fizz has no symbols to resolve and no plaintext hooks. Two pieces:
//
//   isFizzCandidateModule  the registry row's contentFilter. Fizz is statically
//      linked into arbitrarily named Meta libraries (Facebook libcoldstart.so,
//      Instagram libstartup.so / libscrollmerged.so / libstreamingmerged.so), so a
//      name cannot identify it. The filter runs on the dlopen path and therefore
//      accepts by CHEAP criteria only (no memory scan): arm64 only; system/APEX
//      paths rejected; the module's own `fizz_probe_secret_available` export, an
//      app-private path (Meta's superpack/xz libs unpack to
//      /data/data/<pkg>/lib-compressed/) or a known Meta host name accepts. The
//      verdict is cached per path, so late dlopen() calls cost a map lookup. The
//      row is `supplementary`, so accepting a non-Fizz app library hides nothing.
//
//   installFizzKeylog  asynchronous: yields to the event loop first, confirms Fizz
//      (own probe export, or the RTTI name "N4fizz17KeyDerivationImplE" in the
//      non-writable .rodata ranges, r-- before r-x, yielding between ranges), then locates (fizz_locator.ts: label
//      vote, RTTI relative vtable, learned cache) and installs the read-only key
//      hooks (fizz_keylog.ts). A module without Fizz resolves false quietly. This
//      is the ONE memo: at most once per loaded mapping.

import { devlog } from "../util/log.js";
import { toHexPattern } from "../util/hex.js";
import { keylog_enabled } from "./shared_structures.js";
import { yieldToEventLoop } from "./arm64_xref.js";
import { memoizePerMapping } from "./module_mapping.js";
import { findLoadedModule } from "./module_identity.js";
import { FIZZ_KDF_RTTI_NAME, locateFizzCached, moduleRodataRanges } from "./fizz_locator.js";
import { findProbeExport, installFizzKeyHooks } from "./fizz_keylog.js";

// ---- candidate detection (registry contentFilter) ---------------------------------

/** Read-only OS images: never Fizz hosts, never scanned. */
const SYSTEM_PATH_PREFIXES = ["/system/", "/system_ext/", "/apex/", "/vendor/", "/product/", "/odm/", "/data/dalvik-cache/"];

/** App-private data dirs (/data/data/<pkg>/..., /data/user[_de]/<n>/<pkg>/...): where Meta unpacks its compressed libs. */
const APP_PRIVATE_PATH = /^\/data\/(?:data|user(?:_de)?\/\d+)\/[^/]+\//;

/** Meta libraries known to carry Fizz; accepted wherever they are mapped from (e.g. an uncompressed APK). */
const FIZZ_HOST_NAME_HINT = /^lib(?:coldstart|startup|scrollmerged|streamingmerged)\.so$/;

export type FizzPathClass = "reject" | "export-only" | "scan";

/**
 * How a module at `path` named `name` is judged (pure, unit-tested):
 * "reject" (no path / system image), "scan" (app-private or known Meta host:
 * accepted by the filter; the installer runs the RTTI scan asynchronously),
 * "export-only" (any other app library: accepted only with its own probe export).
 */
export function classifyFizzModulePath(name: string, path: string): FizzPathClass {
    if (!path) return "reject";
    if (SYSTEM_PATH_PREFIXES.some((prefix) => path.startsWith(prefix))) return "reject";
    if (APP_PRIVATE_PATH.test(path) || FIZZ_HOST_NAME_HINT.test(name)) return "scan";
    return "export-only";
}

const RTTI_PATTERN = toHexPattern(FIZZ_KDF_RTTI_NAME);

/**
 * Whether `mod`'s .rodata ranges contain the KeyDerivationImpl RTTI name (one native
 * scan per range, r-- first, stops at the first hit, yields between ranges). Writable
 * ranges are never scanned; r-x ones are, because builds without -z separate-code
 * (Meta's libcoldstart / libstartup) keep .rodata in the first, r-x segment. Runs only
 * inside the asynchronous installer.
 */
async function hasFizzRtti(mod: Module): Promise<boolean> {
    for (const range of moduleRodataRanges(mod)) {
        try {
            if (Memory.scanSync(range.base, range.size, RTTI_PATTERN).length > 0) return true;
        } catch (_e) { /* range vanished or unreadable: next */ }
        await yieldToEventLoop();
    }
    return false;
}

/** The cheap candidate verdict for a resolved module: no memory scan (dlopen path). */
function fizzVerdict(mod: Module): boolean {
    const cls = classifyFizzModulePath(mod.name, mod.path);
    if (cls === "reject") return false;
    return cls === "scan" || findProbeExport(mod) !== null;
}

const verdictByPath = new Map<string, boolean>();

/**
 * Registry contentFilter of the Fizz row. Fails closed (non-arm64, unresolvable
 * module, any error). Cached per module path.
 */
export function isFizzCandidateModule(moduleName: string, modulePath?: string): boolean {
    if (Process.arch !== "arm64") return false;
    if (modulePath) {
        if (classifyFizzModulePath(moduleName, modulePath) === "reject") return false;
        const known = verdictByPath.get(modulePath);
        if (known !== undefined) return known; // late dlopen() of a judged library: no module lookup
    }
    const mod = findLoadedModule(moduleName);
    if (mod === null) return false;
    const cached = verdictByPath.get(mod.path);
    if (cached !== undefined) return cached;
    let verdict = false;
    try { verdict = fizzVerdict(mod); } catch (_e) { verdict = false; }
    verdictByPath.set(mod.path, verdict);
    if (verdict) devlog(`[fizz] ${moduleName}: Fizz candidate (${mod.path})`);
    return verdict;
}

// ---- install (both trees) -------------------------------------------------------

/** The ONE Fizz memo: locate + hook at most once per loaded mapping (the hooks dedupe per address). */
const installByMapping = new Map<string, Promise<boolean>>();

/** Fizz confirmed in `mod`: its own probe export, else the RTTI name in its .rodata ranges. */
async function confirmFizz(mod: Module): Promise<boolean> {
    return findProbeExport(mod) !== null || await hasFizzRtti(mod);
}

async function locateThenHook(mod: Module): Promise<boolean> {
    await yieldToEventLoop(); // never scan inside the loader's install phase
    if (!await confirmFizz(mod)) {
        devlog(`[fizz] ${mod.name}: no Fizz RTTI, skipped`);
        return false;
    }
    const located = await locateFizzCached(mod);
    return installFizzKeyHooks(mod, located);
}

/**
 * Locate Fizz in `moduleName` and install its read-only key hooks, asynchronously.
 * Resolves true iff this module installed at least one hook. Keys only: resolves
 * false at once without -k (nothing to extract). At most once per loaded mapping.
 */
export function installFizzKeylog(moduleName: string): Promise<boolean> {
    if (!keylog_enabled) {
        devlog(`[fizz] ${moduleName}: keylog disabled, Fizz hooks skipped`);
        return Promise.resolve(false);
    }
    const mod = findLoadedModule(moduleName);
    if (mod === null) return Promise.resolve(false);
    return memoizePerMapping(installByMapping, mod, () => locateThenHook(mod).catch((e) => {
        devlog(`[fizz] ${moduleName}: install failed: ${e}`);
        return false;
    }));
}

/** Test seam: forget cached verdicts and installs. */
export function resetFizzInstallStateForTests(): void {
    verdictByPath.clear();
    installByMapping.clear();
}
