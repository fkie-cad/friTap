import { hookRegistry } from "../shared/registry.js";
import { selected_protocol, use_modern, getParsedPatterns } from "../fritap_agent.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames } from "../shared/shared_functions.js";
import { Platform, PLATFORM_WINE } from "../shared/shared_structures.js";
import { load_linux_hooking_agent } from "./linux.js";
import { installWineKeylogPatternHooks } from "../shared/wine_keylog_pattern_hook.js";

// Import Windows-style TLS library hooks (reuse existing implementations)
// Legacy v1 executors from legacy copies
import { boring_execute as boring_execute_windows } from "../legacy/tls/platforms/windows/openssl_boringssl_windows.js";
import { gnutls_execute as gnutls_execute_windows } from "../legacy/tls/platforms/windows/gnutls_windows.js";
import { mbedTLS_execute as mbedTLS_execute_windows } from "../legacy/tls/platforms/windows/mbedTLS_windows.js";
import { nss_execute as nss_execute_windows } from "../legacy/tls/platforms/windows/nss_windows.js";
import { wolfssl_execute as wolfssl_execute_windows } from "../legacy/tls/platforms/windows/wolfssl_windows.js";
import { cronet_execute as cronet_execute_windows } from "../legacy/tls/platforms/windows/cronet_windows.js";
// Modern v2 executors from modern files
import { boring_execute_modern as boring_execute_modern_windows } from "../tls/platforms/windows/openssl_boringssl_windows.js";
import { gnutls_execute_modern as gnutls_execute_modern_windows } from "../tls/platforms/windows/gnutls_windows.js";
import { mbedTLS_execute_modern as mbedTLS_execute_modern_windows } from "../tls/platforms/windows/mbedTLS_windows.js";
import { nss_execute_modern as nss_execute_modern_windows } from "../tls/platforms/windows/nss_windows.js";
import { wolfssl_execute_modern as wolfssl_execute_modern_windows } from "../tls/platforms/windows/wolfssl_windows.js";

var platform_name: Platform = PLATFORM_WINE;
var moduleNames: Array<string> = getModuleNames();

// Wine uses Linux sockets (libc), not Windows sockets (WS2_32.dll)
export const socket_library = "libc";

/**
 * Resolve a libc symbol via `Module.getGlobalExportByName`, returning null
 * when unavailable instead of throwing. Frida 17 removed the legacy static
 * `Module.findExportByName(null, name)` overload; this replicates the old
 * nullable-lookup semantics in one place so the pre-flight check and the
 * /proc/self/maps reader share a single helper.
 */
function tryGlobalExport(name: string): NativePointer | null {
    try { return Module.getGlobalExportByName(name); } catch (_e) { return null; }
}

/**
 * Rank Wine ntdll module names in the order we want to try them.
 * Preference: Wine ≥9 PE (`ntdll.dll`) → Wine ≤8 PE wrapper (`ntdll.dll.so`)
 * → Wine Unix-side stub (`ntdll.so`, last resort — no LdrLoadDll export).
 * Hoisted to module scope so the closure isn't allocated per call.
 */
function _ntdllPreferenceRank(name: string): number {
    const ln = name.toLowerCase();
    if (ln.endsWith("ntdll.dll")) return 0;
    if (ln.endsWith("ntdll.dll.so")) return 1;
    if (ln.endsWith("ntdll.so")) return 2;
    return 3;
}

/**

 * Hook Wine's LdrLoadDll function to intercept Windows DLL loading.
 * Wine loads DLLs through ntdll.dll.so's LdrLoadDll export.
 *
 * LdrLoadDll signature (Wine/Windows):
 * NTSTATUS LdrLoadDll(LPCWSTR path_name, DWORD flags, UNICODE_STRING* libname, HMODULE* hModule)
 *
 * UNICODE_STRING structure:
 * struct {
 *     USHORT Length;        // Length of the string in bytes (not including null terminator)
 *     USHORT MaximumLength; // Total size of the buffer in bytes
 *     PWSTR  Buffer;        // Pointer to UTF-16 string
 * }
 */

function hook_Wine_LdrLoadDll(is_base_hook: boolean): boolean {
    try {
        // Re-enumerate modules every call so deferred attempts (after the module
        // observer fires on a fresh ntdll load) see the up-to-date list, not the
        // snapshot taken at agent load.
        // Wine has at least three ntdll variants across versions/builds:
        //   - "ntdll.so"        : Wine ≥9 Unix side (no LdrLoadDll export)
        //   - "ntdll.dll.so"    : Older Wine PE wrapper (has LdrLoadDll)
        //   - "ntdll.dll"       : Wine ≥9 PE side (has LdrLoadDll)
        // On Wine ≥9 the PE ntdll.dll is loaded by Wine's own PE loader and is
        // NOT enumerated by Frida 17's Process.enumerateModules() (which only
        // walks ELF modules). Fall back to /proc/self/maps + hand-rolled PE
        // export parsing for that case.
        const liveModuleNames = getModuleNames();
        const ntdllCandidates = liveModuleNames
            .filter(m => m.toLowerCase().includes("ntdll"))
            .sort((a, b) => _ntdllPreferenceRank(a) - _ntdllPreferenceRank(b));

        // Path 1: try the ELF module table. Works on Wine ≤8 and on any build
        // where Frida enumerates the PE wrapper.
        let ntdllModule: string | undefined;
        let ldrLoadDll: NativePointer | null = null;
        for (const candidate of ntdllCandidates) {
            try {
                const mod = Process.getModuleByName(candidate);
                const exp = mod.findExportByName("LdrLoadDll");
                if (exp && !exp.isNull()) {
                    ntdllModule = candidate;
                    ldrLoadDll = exp;
                    break;
                }
            } catch (e) {
                devlog(`[Wine] candidate ${candidate} lookup failed: ${e}`);
            }
        }

        // Path 2: Wine ≥9 fallback — locate PE ntdll.dll base from /proc/self/maps
        // and walk its PE export directory in memory to resolve LdrLoadDll. This
        // is the ONLY path that works on modern Wine because Frida 17 does not
        // enumerate PE-mapped modules.
        if (!ldrLoadDll || ldrLoadDll.isNull()) {
            const peResult = find_pe_ntdll_ldr_load_dll();
            if (peResult) {
                ntdllModule = peResult.path;
                ldrLoadDll = peResult.address;
                devlog(`[Wine] Resolved LdrLoadDll via PE export parsing (${peResult.path} @ ${peResult.base}, export @ ${peResult.address})`);
            }
        }

        if (!ntdllModule || !ldrLoadDll || ldrLoadDll.isNull()) {
            if (ntdllCandidates.length === 0) {
                devlog("[Wine] no ntdll-named module loaded yet (ELF or PE), deferring DLL hooking");
            } else {
                devlog(`[Wine] none of [${ntdllCandidates.join(", ")}] exports LdrLoadDll and PE ntdll.dll not yet mapped; deferring`);
            }
            return false;
        }

        devlog(`[Wine] Found LdrLoadDll in ${ntdllModule} at ${ldrLoadDll}`);

        Interceptor.attach(ldrLoadDll, {
            onEnter: function(args) {
                // args[2] is UNICODE_STRING* containing the DLL name
                try {
                    const unicodeStr = args[2];
                    if (!unicodeStr.isNull()) {
                        // UNICODE_STRING layout:
                        // offset 0: USHORT Length (2 bytes)
                        // offset 2: USHORT MaximumLength (2 bytes)
                        // offset 4/8: PWSTR Buffer (pointer, 4 or 8 bytes depending on arch)
                        const length = unicodeStr.readU16();
                        if (length > 0 && length < 1024) { // Sanity check
                            const bufferOffset = Process.pointerSize === 8 ? 8 : 4;
                            const bufferPtr = unicodeStr.add(bufferOffset).readPointer();
                            if (!bufferPtr.isNull()) {
                                this.dllName = bufferPtr.readUtf16String(length / 2);
                            }
                        }
                    }
                } catch (e) {
                    devlog(`[Wine] Error reading DLL name in onEnter: ${e}`);
                }
            },
            onLeave: function(retval) {
                // NTSTATUS success is >= 0
                if (this.dllName && retval.toInt32() >= 0) {
                    const dllName = this.dllName as string;
                    const dllBaseName = dllName.split(/[/\\]/).pop() || dllName;

                    const matches = hookRegistry.findAllMatches(platform_name, dllBaseName, undefined, selected_protocol);
                    for (const match of matches) {
                        log(`[Wine] ${dllBaseName} loaded & will be hooked (${match.library})!`);
                        try {
                            match.hookFn(dllBaseName, is_base_hook);
                        } catch (error) {
                            devlog(`[Wine] DLL hook error for ${dllBaseName}: ${error}`);
                        }
                        break; // Only hook first matching registration per DLL
                    }

                    // Also scan the freshly-loaded DLL for the dual-ABI keylog
                    // signatures (catches PE-bundled gnutls/openssl and schannel's
                    // internal gnutls even when no export-based hook matched).
                    try {
                        installWineKeylogPatternHooks(dllBaseName, getParsedPatterns());
                    } catch (error) {
                        devlog(`[Wine] keylog pattern scan error for ${dllBaseName}: ${error}`);
                    }
                }
            }
        });

        log("[*] Wine LdrLoadDll hooked for DLL interception");
        return true;
    } catch (error) {
        devlog(`[Wine] Loader hook error: ${error}`);
        log("[Wine] Could not hook LdrLoadDll - DLL hooking disabled");
        return false;
    }
}

/**
 * Read /proc/self/maps into a string via libc open/read/close. Frida can't
 * enumerate PE modules on Wine ≥9, so we need the raw mapping list to locate
 * ntdll.dll's base address. Bounded read: /proc/self/maps for a Wine process
 * is typically 200–500 KB; we cap the returned buffer at 4 MB defensively.
 */
function read_proc_self_maps(): string | null {
    try {
        const openPtr = tryGlobalExport("open");
        const readPtr = tryGlobalExport("read");
        const closePtr = tryGlobalExport("close");
        if (!openPtr || !readPtr || !closePtr) return null;

        const open = new NativeFunction(openPtr, "int", ["pointer", "int"]);
        const read = new NativeFunction(readPtr, "long", ["int", "pointer", "ulong"]);
        const close = new NativeFunction(closePtr, "int", ["int"]);

        const path = Memory.allocUtf8String("/proc/self/maps");
        const fd = open(path, 0 /* O_RDONLY */) as number;
        if (fd < 0) return null;

        const chunkSize = 65536;
        const buf = Memory.alloc(chunkSize);
        const chunks: string[] = [];
        let total = 0;
        const cap = 4 * 1024 * 1024;
        while (total < cap) {
            const n = (read(fd, buf, chunkSize) as any).valueOf() as number;
            if (n <= 0) break;
            const chunk = buf.readUtf8String(n);
            if (chunk === null) break;
            chunks.push(chunk);
            total += n;
        }
        close(fd);
        return chunks.join("");
    } catch (e) {
        devlog(`[Wine] read_proc_self_maps error: ${e}`);
        return null;
    }
}

interface PeNtdllResolution {
    base: NativePointer;
    address: NativePointer;
    path: string;
}

/**
 * Locate Wine's PE-side ntdll.dll base address by scanning /proc/self/maps,
 * then walk the in-memory PE headers to find the LdrLoadDll export.
 *
 * PE layout at base (relevant fields only):
 *   base[0]         : MZ magic "MZ" (0x5A4D, little-endian)
 *   base[0x3C..]    : e_lfanew — file offset (also memory offset since Wine
 *                     maps the PE headers 1:1) of the NT header
 *   NT header:
 *     +0            : "PE\0\0" (0x00004550)
 *     +4            : COFF file header (20 bytes)
 *     +24           : optional header magic (0x10B PE32, 0x20B PE32+)
 *     +24+ (96/112) : DataDirectory[0] = Export Table (RVA, size)
 *   Export Directory (relative RVAs from image base):
 *     0x14  NumberOfFunctions (u32)
 *     0x18  NumberOfNames (u32)
 *     0x1C  AddressOfFunctions RVA
 *     0x20  AddressOfNames RVA
 *     0x24  AddressOfNameOrdinals RVA
 */
function find_pe_ntdll_ldr_load_dll(): PeNtdllResolution | null {
    const maps = read_proc_self_maps();
    if (!maps) return null;

    // Each line looks like:
    //   7f00abc00000-7f00abd00000 r--p 00000000 00:1e 12345 /usr/lib/.../ntdll.dll
    // We want the FIRST mapping (offset 00000000) of the file whose path ends
    // with "/ntdll.dll". That mapping starts at the PE image base.
    const lines = maps.split("\n");
    for (const line of lines) {
        // Cheap prefilter first
        if (!line.includes("ntdll.dll")) continue;
        if (line.includes("ntdll.dll.so")) continue; // old wrapper form
        const parts = line.split(/\s+/);
        if (parts.length < 6) continue;
        const range = parts[0];
        const perms = parts[1];
        const offset = parts[2];
        // Reconstruct path (may contain spaces in principle, though unlikely for /usr/lib)
        const path = parts.slice(5).join(" ");
        if (!path.endsWith("/ntdll.dll")) continue;
        // Only interested in the header mapping (offset 00000000 and readable)
        if (offset !== "00000000" && offset !== "0") continue;
        if (!perms.startsWith("r")) continue;
        const baseHex = range.split("-")[0];
        try {
            const base = ptr("0x" + baseHex);
            const addr = parse_pe_find_export(base, "LdrLoadDll");
            if (addr) {
                return { base, address: addr, path };
            }
        } catch (e) {
            devlog(`[Wine] PE parse failed for ${path} @ 0x${baseHex}: ${e}`);
        }
    }
    return null;
}

function parse_pe_find_export(base: NativePointer, exportName: string): NativePointer | null {
    // MZ check
    const mz = base.readU16();
    if (mz !== 0x5A4D) return null;
    // e_lfanew (offset 0x3C, u32) points to PE header
    const peOffset = base.add(0x3C).readU32();
    if (peOffset <= 0 || peOffset > 0x10000) return null;
    const peSig = base.add(peOffset).readU32();
    if (peSig !== 0x00004550) return null; // "PE\0\0"
    // Optional header starts at peOffset + 4 (PE sig) + 20 (COFF file header)
    const optHdrOffset = peOffset + 24;
    const magic = base.add(optHdrOffset).readU16();
    let dataDirOffset: number;
    if (magic === 0x20B) {
        dataDirOffset = optHdrOffset + 112; // PE32+
    } else if (magic === 0x10B) {
        dataDirOffset = optHdrOffset + 96;  // PE32
    } else {
        return null;
    }
    // DataDirectory[0] = Export Table: (RVA:u32, Size:u32)
    const exportRva = base.add(dataDirOffset).readU32();
    if (exportRva === 0) return null;
    const exportDir = base.add(exportRva);

    const numFunctions = exportDir.add(0x14).readU32();
    const numNames = exportDir.add(0x18).readU32();
    const funcsRva = exportDir.add(0x1C).readU32();
    const namesRva = exportDir.add(0x20).readU32();
    const ordinalsRva = exportDir.add(0x24).readU32();
    if (numNames === 0 || numFunctions === 0) return null;

    // Binary search would be faster (names are sorted) but numNames is small
    // (~2500 for ntdll) and we do this at most once per DLL load.
    for (let i = 0; i < numNames; i++) {
        const nameRva = base.add(namesRva).add(i * 4).readU32();
        let name: string | null = null;
        try {
            name = base.add(nameRva).readCString();
        } catch (_e) {
            continue;
        }
        if (name !== exportName) continue;
        const ordinal = base.add(ordinalsRva).add(i * 2).readU16();
        if (ordinal >= numFunctions) return null;
        const funcRva = base.add(funcsRva).add(ordinal * 4).readU32();
        if (funcRva === 0) return null;
        // If the export is a forwarder, funcRva points inside the export
        // directory's RVA range — skip that case (rare for LdrLoadDll).
        // (LdrLoadDll is a real code export.)
        return base.add(funcRva);
    }
    return null;
}

/**
 * One-shot pre-flight check for the common WINEPREFIX vs. running-euid mismatch.
 *
 * Modern Wine (≥7) hard-aborts wineserver startup when the prefix is owned by a
 * different uid (binary evidence: ntdll.so@0x39cac compares getuid() against the
 * prefix owner uid and on inequality prints "...is not owned by you, refusing
 * to create a configuration directory there" and returns failure into the
 * server-connect chain). The most common way to trigger that under friTap is
 * launching friTap with `sudo` while ~/.wine is owned by the desktop user — wine
 * then dies ~10–25 ms after resume() and the python error handler used to
 * misattribute it to PairIP (#64). Catch this BEFORE installing any hooks,
 * surface a self-explaining log line, and skip all hook installation so the
 * inevitable termination is unambiguously not friTap's fault.
 *
 * Returns true if hook installation should continue.
 */
function preflight_wine_prefix_ownership(): boolean {
    try {
        const geteuidPtr = tryGlobalExport("geteuid");
        const statPtr = tryGlobalExport("stat");
        const getenvPtr = tryGlobalExport("getenv");
        if (!geteuidPtr || !statPtr || !getenvPtr) {
            devlog("[Wine] pre-flight: libc geteuid/stat/getenv not all resolvable; skipping check");
            return true;
        }

        const geteuid = new NativeFunction(geteuidPtr, "uint", []);
        const stat = new NativeFunction(statPtr, "int", ["pointer", "pointer"]);
        const getenv = new NativeFunction(getenvPtr, "pointer", ["pointer"]);

        const readEnvCString = (name: string): string | null => {
            const namePtr = Memory.allocUtf8String(name);
            const valPtr = getenv(namePtr) as NativePointer;
            if (valPtr.isNull()) return null;
            return valPtr.readUtf8String();
        };

        let prefix = readEnvCString("WINEPREFIX");
        if (!prefix || prefix.length === 0) {
            const home = readEnvCString("HOME");
            if (home && home.length > 0) {
                prefix = home + (home.endsWith("/") ? "" : "/") + ".wine";
            }
        }
        if (!prefix) {
            devlog("[Wine] pre-flight: could not resolve WINEPREFIX or HOME; skipping check");
            return true;
        }

        const euid = (geteuid() as number) >>> 0;

        // 144 bytes covers glibc's 64-bit `struct stat` (sizeof ≈ 144 on Linux
        // x86_64). st_uid is at offset 28.
        const buf = Memory.alloc(144);
        const pathPtr = Memory.allocUtf8String(prefix);
        const rc = stat(pathPtr, buf) as number;
        if (rc !== 0) {
            log(`[Wine] euid=${euid}, WINEPREFIX=${prefix} (does not exist or stat failed; rc=${rc})`);
            // Wine itself will fail to create the prefix dir if its parent is
            // unwritable to this euid — surface a hint but do not block.
            return true;
        }

        const prefixUid = buf.add(28).readU32();
        log(`[Wine] euid=${euid}, WINEPREFIX=${prefix}, prefix uid=${prefixUid}`);

        if (euid !== prefixUid) {
            log(`[Wine] FATAL: euid=${euid} but WINEPREFIX ${prefix} is owned by uid=${prefixUid}.`);
            log("[Wine]        Wine will refuse this prefix and exit (\"is not owned by you\").");
            log("[Wine]        Fix: run friTap WITHOUT sudo (recommended on Linux desktop);");
            log("[Wine]        ensure `sysctl kernel.yama.ptrace_scope=0` so Frida can attach.");
            log("[Wine]        Alternative: set WINEPREFIX to a directory owned by your current uid,");
            log("[Wine]        e.g. WINEPREFIX=/root/.wine when you must run as root.");
            log("[Wine] Skipping all hook installation — the process termination that follows is Wine's own choice, not a friTap hook crash.");
            return false;
        }
        return true;
    } catch (e) {
        devlog(`[Wine] pre-flight check threw (continuing): ${e}`);
        return true;
    }
}

/**
 * Defer ntdll-dependent installation (LdrLoadDll hook + full-module keylog
 * pattern scan) until Wine's loader has actually mapped ntdll. At spawn time
 * ntdll.dll.so is not yet in the module list, so installing eagerly silently
 * no-ops (the old bug: spawn-mode Wine got zero DLL interception, forever).
 * Reuses the same Process.attachModuleObserver pattern as installPairipSafeWatcher.
 */
function arm_wine_late_install(): void {
    let installed = false;
    let pollHandle: any = null;
    let observerHandle: any = null;

    const tearDown = () => {
        if (pollHandle !== null) { try { clearInterval(pollHandle); } catch (_e) {} pollHandle = null; }
        if (observerHandle !== null) { try { observerHandle.detach(); } catch (_e) {} observerHandle = null; }
    };

    const installNow = () => {
        if (installed) return;
        if (!hook_Wine_LdrLoadDll(false)) return;
        installed = true;
        // Now that ntdll is up, the broader module set is meaningful — run
        // the dual-ABI keylog pattern scan once over everything currently
        // mapped. Subsequent late-loaded DLLs are scanned per-DLL inside the
        // LdrLoadDll onLeave (hook_Wine_LdrLoadDll above).
        try {
            installWineKeylogPatternHooks(undefined, getParsedPatterns());
        } catch (error) {
            devlog(`[Wine] deferred keylog pattern scan error: ${error}`);
        }
        tearDown();
    };

    // A loaded module name that *could* be the ntdll we care about. Frida's
    // preloader stub `ntdll.so` doesn't export LdrLoadDll but Wine's later
    // `ntdll.dll.so` (Wine ≤8) or `ntdll.dll` (Wine ≥9 PE-side) does. Also
    // any `.dll.so` / `.dll` load is worth a retry because those are events
    // that surface only after Wine's loader has made real progress. The
    // actual gate is `hook_Wine_LdrLoadDll()` succeeding.
    const isCandidate = (name: string | undefined): boolean => {
        if (!name) return false;
        const n = name.toLowerCase();
        return n.includes("ntdll") || n.endsWith(".dll.so") || n.endsWith(".dll");
    };

    const P: any = Process as any;
    if (typeof P.attachModuleObserver === "function") {
        try {
            observerHandle = P.attachModuleObserver({
                onAdded(m: any) { if (m && isCandidate(m.name)) installNow(); },
            });
            devlog("[Wine] late-install watcher armed via Process.attachModuleObserver");
        } catch (_e) { /* fall through to polling */ }
    }

    // Polling is required regardless of the observer because on Wine ≥9 the
    // PE-side ntdll.dll is NOT enumerated by Frida (it's mapped by Wine's PE
    // loader, not by dlopen). We locate it via /proc/self/maps + PE export
    // parsing in find_pe_ntdll_ldr_load_dll(). 40 ticks @ 250 ms = 10 s
    // ceiling. installNow() calls tearDown() on success, so we stop as soon
    // as the observer fires too.
    let ticks = 0;
    pollHandle = setInterval(() => {
        if (++ticks >= 40) tearDown();
        installNow();
    }, 250);
    devlog("[Wine] late-install watcher polling every 250 ms (up to 10 s)");
}

/**
 * Check already-loaded modules for Windows DLLs that should be hooked.
 * This handles cases where the DLL was loaded before we attached.
 */
function hook_Wine_Existing_DLLs(is_base_hook: boolean): void {
    const modules = Process.enumerateModules();

    for (const mod of modules) {
        // Skip non-DLL modules
        if (!mod.name.toLowerCase().endsWith('.dll')) {
            continue;
        }

        const matches = hookRegistry.findAllMatches(platform_name, mod.name, mod.path, selected_protocol);
        if (matches.length > 0) {
            const match = matches[0];
            log(`[Wine] Found pre-loaded DLL ${mod.name} (${match.library}), hooking...`);
            try {
                match.hookFn(mod.name, is_base_hook);
            } catch (error) {
                devlog(`[Wine] Pre-loaded DLL hook error for ${mod.name}: ${error}`);
            }
        }
    }
}

/**
 * Main Wine hooking agent loader.
 *
 * Strategy:
 * 1. Load the standard Linux agent to hook native .so TLS libraries
 *    (Wine applications often use Wine's built-in GnuTLS/OpenSSL)
 * 2. Hook Wine's LdrLoadDll to intercept Windows DLL loading
 *    (for applications that bundle their own Windows TLS libraries)
 */
export function load_wine_hooking_agent(): void {
    log("Running Script on Wine (Linux + Windows DLLs)");

    // Catch the common sudo-vs-user-owned-WINEPREFIX trap before installing
    // anything; surface the cause and bail so the inevitable wine64 exit is not
    // misattributed to a friTap hook crash (#64-style false positive).
    if (!preflight_wine_prefix_ownership()) {
        return;
    }

    // First, load the standard Linux agent for .so libraries (registry + library
    // scan + already-loaded TLS hooks). skipLoaderHook=true: Wine uses its own
    // preloader, not glibc dlopen, so the inline libdl trampoline adds spawn-time
    // footprint without catching anything Wine actually loads. DLL interception
    // is handled below via hook_Wine_LdrLoadDll (armed once ntdll appears).
    log("[Wine] Loading Linux agent for native .so libraries...");
    load_linux_hooking_agent(true);


    // Then add Wine-specific DLL hooking
    hookRegistry.registerAll([
        { platform: platform_name, pattern: /^(libssl|LIBSSL)-[0-9]+(_[0-9]+)?\.dll$/i, hookFn: (use_modern ? boring_execute_modern_windows : boring_execute_windows), library: "OpenSSL/BoringSSL", libraryType: "openssl" },
        { platform: platform_name, pattern: /^.*libssl.*\.dll$/i, hookFn: (use_modern ? boring_execute_modern_windows : boring_execute_windows), library: "OpenSSL/BoringSSL", libraryType: "openssl" },
        { platform: platform_name, pattern: /^.*(wolfssl|WOLFSSL).*\.dll$/i, hookFn: (use_modern ? wolfssl_execute_modern_windows : wolfssl_execute_windows), library: "WolfSSL", libraryType: "wolfssl" },
        { platform: platform_name, pattern: /^.*(libgnutls|LIBGNUTLS)-[0-9]+\.dll$/i, hookFn: (use_modern ? gnutls_execute_modern_windows : gnutls_execute_windows), library: "GnuTLS", libraryType: "gnutls" },
        { platform: platform_name, pattern: /^(nspr|NSPR)[0-9]*\.dll/i, hookFn: (use_modern ? nss_execute_modern_windows : nss_execute_windows), library: "NSS", libraryType: "nss" },
        { platform: platform_name, pattern: /mbedTLS\.dll/i, hookFn: (use_modern ? mbedTLS_execute_modern_windows : mbedTLS_execute_windows), library: "mbedTLS", libraryType: "mbedtls" },
        { platform: platform_name, pattern: /^.*(cronet|CRONET).*\.dll/i, hookFn: cronet_execute_windows, library: "Cronet", libraryType: "boringssl" },
    ]);


    // Hook existing Windows DLLs that are already loaded. At spawn time this
    // is almost always empty (Wine's preloader hasn't loaded ntdll yet); the
    // late-install watcher below catches everything that loads after resume().
    log("[Wine] Checking for pre-loaded Windows DLLs...");
    hook_Wine_Existing_DLLs(true);

    // Try LdrLoadDll once eagerly — succeeds in attach mode (ntdll already up)
    // and is a no-op in spawn mode (ntdll not yet mapped). If it fails to install,
    // arm a one-shot module observer that re-runs install + the keylog pattern
    // scan as soon as ntdll appears (and re-runs the per-DLL pattern scan inside
    // the LdrLoadDll onLeave from then on). This is the spawn-mode fix: previously
    // hook_Wine_LdrLoadDll silently returned and DLL interception never happened.
    log("[Wine] Setting up LdrLoadDll hook for future DLL loads...");
    const installed = hook_Wine_LdrLoadDll(false);

    if (installed) {
        // Attach-mode path: ntdll is already mapped, so the dual-ABI keylog
        // pattern scan over already-mapped modules is meaningful right now.
        log("[Wine] Scanning loaded modules for dual-ABI TLS keylog signatures (experimental)...");
        try {
            installWineKeylogPatternHooks(undefined, getParsedPatterns());
        } catch (error) {
            devlog(`[Wine] keylog pattern scan error: ${error}`);
        }
    } else {
        log("[Wine] ntdll not yet mapped — arming late-install watcher for LdrLoadDll + keylog pattern scan.");
        arm_wine_late_install();
    }
}