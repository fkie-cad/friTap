import { devlog, devlog_error, devlog_debug, log, devlog_info } from "../../util/log.js";
import { isAndroid, isiOS,isMacOS } from "../../util/process_infos.js"

const IS_ARM64 = Process.arch === "arm64";

/*
 * On aarch64, accept the match only if the first 4 bytes look like a
 * plausible function prologue. A loose-wildcard Memory.scan can otherwise
 * land mid-function on arbitrary bytes; Interceptor.attach at a non-entry
 * address corrupts the code region and crashes the target on execution.
 * Returns true unconditionally on non-aarch64 (no validation done) so x86
 * / arm32 behavior is unchanged.
 */
function isLikelyArm64Prologue(address: NativePointer): boolean {
    if (!IS_ARM64) return true;

    let insn: number;
    try {
        insn = address.readU32();
    } catch (_) {
        return false;
    }

    if (insn === 0x00000000 || insn === 0xFFFFFFFF) return false;

    // paciasp / pacibsp — PAC landing pads, strong function-entry signal
    if (insn === 0xD503233F) return true;
    if (insn === 0xD503237F) return true;

    // bti {c|j|jc} — branch target identification, function-entry hint
    if ((insn & 0xFFFFFF1F) === 0xD503241F) return true;

    // stp x29, x30, [sp, #imm] — frame setup, signed offset
    if ((insn & 0xFFC07FFF) === 0xA9007BFD) return true;
    // stp x29, x30, [sp, #-imm]! — frame setup, pre-indexed
    if ((insn & 0xFFC07FFF) === 0xA9807BFD) return true;

    // sub sp, sp, #imm — stack pointer adjustment, typical prologue start
    if ((insn & 0xFF8003FF) === 0xD10003FF) return true;

    return false;
}

/*
 * Gate Interceptor.attach behind the prologue check. Returns false (and
 * logs at debug level) when the match looks like data or mid-function
 * bytes; callers early-return so the surrounding scan keeps running and
 * the fallback pattern chain still has a chance.
 */
function acceptPrologueMatch(address: NativePointer, patternName: string, moduleName?: string): boolean {
    if (isLikelyArm64Prologue(address)) return true;
    const where = moduleName ? ` on ${moduleName}` : "";
    devlog_debug(`Pattern match at ${address} (${patternName})${where} skipped: not a function prologue`);
    return false;
}

type Pattern = {
    primary: string;
    fallback: string;
    second_fallback?: string; // Optionales zweites Fallback
};

type ActionPatterns = {
    "Dump-Keys": Pattern;
    "SSL_Read": Pattern;
    "SSL_Write": Pattern;
    "Install-Key-Log-Callback": Pattern;
    "KeyLogCallback-Function": Pattern;
    // SSH action types — used by agent/ssh/* hooks (v1 ships placeholder
    // entries in pattern.json; contributors derive real prologues per the
    // procedure in EXTENDING.md).
    "SSH_Packet_Send"?: Pattern;
    "SSH_Packet_Read"?: Pattern;
    "SSH_Cipher_Init"?: Pattern;
    "SSH_Cipher_Crypt"?: Pattern;
    "SSH_Kex_Derive_Keys"?: Pattern;
};

export { hasModulePatterns, hasUsablePatternsFor } from "./cronet_patterns.js";

export function get_CPU_specific_pattern(
    default_pattern: { [arch: string]: { primary: string; fallback: string; second_fallback?: string } }
): { primary: string; fallback: string; second_fallback?: string } | null {
    let arch = Process.arch.toString(); // Get architecture, e.g., "x64", "arm64"

    if (arch === "ia32") {
        arch = "x86";
    }
    devlog("Trying Pattern: " + JSON.stringify(default_pattern[arch]));

    if (default_pattern[arch]) {
        return default_pattern[arch]; // Return the pattern for the architecture
    }
    // No shipped hardcoded pattern for this architecture. Return null instead of
    // throwing so a missing-arch fallback does not abort sibling hook installs for
    // the same library (the loader's try/catch would otherwise swallow the throw and
    // skip the whole module). Callers (hookModuleByPattern / hookModuleByPatternOnReturn)
    // treat null/empty as "nothing to scan" and no-op.
    devlog_error(`No shipped hardcoded pattern for CPU architecture: ${arch}`);
    return null;
}

export class PatternBasedHooking {
    found_ssl_log_secret: boolean;
    no_hooking_success: boolean;
    // Flips to true ONLY when every outer-cascade branch (primary → fallback →
    // second_fallback) has resolved. Distinguishes the initial pre-scan state
    // (no_hooking_success === true from the constructor, cascade hasn't even
    // started) from "scan finished, nothing matched". Read by
    // agent/shared/boringssl_pattern_hook.ts:pollPatternOutcome so it stops
    // emitting a premature "tier 3 exhausted" before Memory.scan has had a
    // chance to run on slow targets like libmonochrome_64.so (~200 MB).
    cascadeCompleted: boolean = false;
    module: Module;
    private patterns: any = {};
    // Keyed as `${range.base}-${range.size}|${pattern_name}` so each pattern
    // variant gets its own dedup namespace. Otherwise the primary pass
    // populates the cache for every readable range, and fallback /
    // second_fallback inner-cascade passes immediately resolve "no match"
    // (every range gets skipped) — the bug that caused --modern to miss
    // ssl_log_secret in libmonochrome_64.so even with correct patterns.
    private rescannedRanges: Set<string> = new Set();

    constructor(module: Module) {
        this.found_ssl_log_secret = false;
        this.module = module;
        if (this.module === null) {
            devlog_error("PatternBasedHooking Error: Unable to find module: " + this.module.name);
            devlog_error("PatternBasedHooking Error: Abborting...");
            return;
        }
        this.no_hooking_success = true;
    }

    private createRegexFromModule(moduleName: string): RegExp {
        // Match the base name and ensure it ends with .so
        const baseName = moduleName.replace(/\d+(\.\d+)*\.so$/, '.so');
        // Create the regex to match the base name with any version numbers
        const regexPattern = `.*${baseName.replace(/\./g, '\\.')}$`;
        return new RegExp(regexPattern);
    }

    private hookByPatternOnReturn(
        patterns: { primary: string; fallback: string },
        pattern_name: string,
        userCallback: (args: any[], retval?: NativePointer) => void,
        maxArgs: number,
        onCompleteCallback: (found: boolean) => void
    ): void {
        const moduleBase = this.module.base;
        const moduleSize = this.module.size;
        const moduleName = this.module?.name;
        this.found_ssl_log_secret = false;

        let pattern: string;
        if (pattern_name === "primary_pattern") {
            pattern = patterns.primary;
        } else {
            pattern = patterns.fallback;
        }

        Memory.scan(moduleBase, moduleSize, pattern, {
            onMatch: (address) => {
                if (!acceptPrologueMatch(address, pattern_name)) return;
                this.found_ssl_log_secret = true;
                this.no_hooking_success = false;
                var module_by_address = Process.findModuleByAddress(address);

                devlog_info(`Pattern found at (${pattern_name}) address: ${address} in module ${module_by_address.name}`);
                log(`[*] ${module_by_address?.name ?? "<unknown>"}: keylog hooks installed via pattern (${pattern_name}, onReturn @ ${address})`);

                Interceptor.attach(address, {
                    onEnter: function (args) {
                        // store the arguments so we can use them onLeave
                        //(this as any).storedArgs = Array.from(args);
                        const stored: NativePointer[] = [];
                        // We do a small loop up to maxArgs
                        for (let i = 0; i <= maxArgs; i++) {
                            try {
                                stored.push(args[i]);
                            } catch (_e) {
                                devlog_error("error :"+i+ " with error :"+_e);
                                // Possibly out-of-range => break
                                break;
                            }
                        }
                        (this as any).storedArgs = stored;
                    },
                    onLeave: function (retval) {
                        const storedArgs = (this as any).storedArgs || [];
                        userCallback(storedArgs, retval);
                    },
                });
            },
            onError: (reason) => {
                if (!this.found_ssl_log_secret) {
                    devlog_error("There was an error scanning memory: " + reason);
                    devlog_error("Trying to rescan memory with permissions in mind");
                    this.hookByPatternOnlyReadablePartsOnReturn(
                        patterns,
                        pattern_name,
                        userCallback,
                        (patternSuccess) => {
                            if (!patternSuccess) {
                                devlog("Primary pattern failed, trying fallback pattern (onReturn)...");
                                this.hookByPatternOnlyReadablePartsOnReturn(
                                    patterns,
                                    "fallback_pattern",
                                    userCallback,
                                    (patternSuccessAlt) => {
                                        if (!patternSuccessAlt && !this.found_ssl_log_secret) {
                                            // Guard: don't overwrite success state set by a parallel
                                            // cascade (see plan Iteration 3). Only mark failure if no
                                            // match was ever attached.
                                            devlog_debug(`None of the patterns worked. You may need to adjust the patterns for ${moduleName}`);
                                            this.no_hooking_success = true;
                                        }
                                    },
                                    maxArgs
                                );
                            }
                        },
                        maxArgs
                    );
                }
            },
            onComplete: () => {
                onCompleteCallback(this.found_ssl_log_secret);
            },
        });
    }

        /**
     *  For hooking modules with either the primary or fallback pattern (onReturn)
     */
        public hookModuleByPatternOnReturn(
            patterns: { primary: string; fallback: string } | null | undefined,
            userCallback: (args: any[], retval?: NativePointer) => void,
            maxArgs: number
        ): void {
            if (!patterns || (!patterns.primary && !patterns.fallback)) {
                // No usable pattern (e.g. get_CPU_specific_pattern found no shipped
                // pattern for this arch, or a JSON entry was empty). Skip the scan
                // rather than driving Memory.scan with an empty pattern.
                devlog_debug("hookModuleByPatternOnReturn: no usable pattern, skipping scan");
                this.no_hooking_success = true;
                return;
            }
            const moduleBase = this.module.base;
            const moduleSize = this.module.size;
            devlog(`Module Base Address: ${moduleBase}`);
            devlog(`Module Size: ${moduleSize}`);
    
            this.hookByPatternOnReturn(patterns, "primary_pattern", userCallback, maxArgs, (pattern_success) => {
                if (!pattern_success) {
                    devlog("Primary pattern failed, trying fallback pattern (onReturn)...");
                    this.hookByPatternOnReturn(
                        patterns,
                        "fallback_pattern",
                        userCallback,
                        maxArgs, 
                        (pattern_success_alt) => {
                            if (!pattern_success_alt && !this.found_ssl_log_secret) {
                                // Guard: success may have been set by a parallel cascade.
                                devlog("None of the onReturn patterns worked. Adjust patterns as needed.");
                                this.no_hooking_success = true;
                            }
                        }
                    );
                }
            });
        }

    private invoke_pattern_based_hooking_onReturn(
        action: keyof ActionPatterns,
        module_name: string,
        platform: string,
        arch: string,
        userCallback: (args: any[], retval?: NativePointer) => void,
        maxArgs: number
    ) {
        const action_specific_patterns = this.get_action_specific_pattern(module_name, platform, arch, action);
        devlog_debug(`Using ${action} patterns for ${platform} on ${arch} (onReturn)`);
        this.hookModuleByPatternOnReturn(action_specific_patterns, userCallback, maxArgs);
    }

    public hook_with_pattern_from_json_onReturn(
        action_type: keyof ActionPatterns,
        module_name: string,
        json_module_name: string,
        jsonContent: string,
        userCallback: (args: any[], retval?: NativePointer) => void,
        maxArgs: number
    ): void {
        this.loadPatternsFromJSON(jsonContent);

        let platform = Process.platform.toString(); // e.g., "linux", "android"
        if (isAndroid()) platform = "android";
        else if (isiOS()) platform = "ios";
        else if (isMacOS()) platform = "macos";

        let arch = Process.arch.toString(); // e.g., "x64", "arm64"
        if (arch === "ia32") arch = "x86";

        const regex = this.createRegexFromModule(module_name);

        if (
            this.patterns.modules[module_name] &&
            this.patterns.modules[module_name][platform] &&
            this.patterns.modules[module_name][platform][arch]
        ) {
            this.invoke_pattern_based_hooking_onReturn(
                action_type,
                module_name,
                platform,
                arch,
                userCallback,
                maxArgs
            );
        } else if (
            this.patterns.modules[json_module_name] &&
            this.patterns.modules[json_module_name][platform] &&
            this.patterns.modules[json_module_name][platform][arch]
        ) {
            this.invoke_pattern_based_hooking_onReturn(
                action_type,
                json_module_name,
                platform,
                arch,
                userCallback,
                maxArgs
            );
        } else {
            for (const jsonModuleName in this.patterns.modules) {
                if (regex.test(module_name)) {
                    if (
                        this.patterns.modules[jsonModuleName][platform] &&
                        this.patterns.modules[jsonModuleName][platform][arch]
                    ) {
                        this.invoke_pattern_based_hooking_onReturn(
                            action_type,
                            jsonModuleName,
                            platform,
                            arch,
                            userCallback,
                            maxArgs
                        );
                    }
                } else {
                    devlog_debug("No patterns available for the current platform or architecture.");
                }
            }
        }
    }


    // Method to hook by pattern, with a custom function to handle onEnter and onLeave
    hookByPattern(
        patterns: { primary: string; fallback: string; second_fallback?: string },
        pattern_name: string,
        onMatchCallback: (args: any[]) => void,
        onCompleteCallback: (found: boolean) => void
    ): void {
        const moduleName = this.module?.name;
        devlog(`Trying to scan ${moduleName} ...`);
        const moduleBase = this.module.base;
        const moduleSize = this.module.size;
        this.found_ssl_log_secret = false;

        let pattern: string;
        if (pattern_name === "primary_pattern") {
            pattern = patterns.primary;
        } else if (pattern_name === "fallback_pattern") {
            pattern = patterns.fallback;
        } else if (pattern_name === "second_fallback_pattern" && patterns.second_fallback) {
            pattern = patterns.second_fallback;
        } else {
            devlog_error(`Pattern ${pattern_name} not found or not provided.`);
            onCompleteCallback(false);
            return;
        }

        Memory.scan(moduleBase, moduleSize, pattern, {
            onMatch: (address) => {
                if (!acceptPrologueMatch(address, pattern_name, moduleName)) return;
                this.found_ssl_log_secret = true;
                this.no_hooking_success = false;

                if (moduleName) {
                    devlog_info(`Pattern found at (${pattern_name}) address: ${address} for module ${moduleName}`);
                }else{
                    devlog_info(`Pattern found at (${pattern_name}) address: ${address}`);
                }

                log(`[*] ${moduleName ?? "<unknown>"}: keylog hooks installed via pattern (${pattern_name} @ ${address})`);

                // Attach the hook using the provided onMatchCallback
                Interceptor.attach(address, {
                    onEnter: function (args) {
                        onMatchCallback(args);
                    },
                });
            },
            onError: (reason) => {
                if (this.found_ssl_log_secret) return;
                devlog_error('There was an error scanning memory: ' + reason);
                devlog_error(`Trying to rescan memory with permissions in mind on ${moduleName}`);
                this.hookByPatternOnlyReadableParts(patterns, pattern_name, onMatchCallback, (primary_success) => {
                    if (this.found_ssl_log_secret) return;
                    if (!primary_success) {
                        devlog(`Primary pattern failed, trying fallback pattern on ${moduleName}`);
                        this.hookByPatternOnlyReadableParts(patterns, "fallback_pattern", onMatchCallback, (fallback_success) => {
                            if (this.found_ssl_log_secret) return;
                            if (!fallback_success) {
                                devlog(`Fallback pattern failed, trying second fallback pattern on ${moduleName}`);
                                this.hookByPatternOnlyReadableParts(patterns, "second_fallback_pattern", onMatchCallback, (second_fallback_success) => {
                                    if (this.found_ssl_log_secret) return;
                                    if (second_fallback_success) {
                                        this.no_hooking_success = false;
                                    } else {
                                        // Race guard kept from prior iteration: an outer whole-module
                                        // match can flip `found_ssl_log_secret` between this callback
                                        // firing and our early-return; the guard above covers it, so
                                        // it's safe to set no_hooking_success unconditionally here.
                                        this.no_hooking_success = true;
                                    }
                                });
                            }
                        });
                    }
                });
            },
            onComplete: () => {
                onCompleteCallback(this.found_ssl_log_secret);
            },
        });
    }

    // Method to hook by pattern, with a custom function to handle onEnter and onLeave
    hookByPatternOnlyReadableParts(
        patterns: { primary: string; fallback: string; second_fallback?: string },
        pattern_name: string,
        onMatchCallback: (args: any[]) => void,
        onCompleteCallback: (found: boolean) => void
        ): void {
        if (this.found_ssl_log_secret) {
            onCompleteCallback(true);
            return;
        }
        const mod = this.module;
        const moduleName = mod?.name;
        const protSets = ["r-x", "r--", "rw-", "rwx"] as const;

        devlog(`trying to scan only readable parts of ${moduleName} ...`);

        var pattern: string = "";
        if (pattern_name === "primary_pattern") {
            pattern = patterns.primary;
        } else if (pattern_name === "fallback_pattern") {
            pattern = patterns.fallback;
        } else if (pattern_name === "second_fallback_pattern" && patterns.second_fallback) {
            pattern = patterns.second_fallback;
        }else{
            pattern = patterns.fallback;
        }

          // Guard
        if (!mod) {
            devlog_error("hookByPatternOnlyReadableParts: module is null");
            onCompleteCallback(false);
            return;
        }

        const start = mod.base;
        const end = mod.base.add(mod.size);

        let patternFound = false;
        let callbackDone = false;

        const executeOnce = (ok: boolean) => {
            if (!callbackDone) {
            callbackDone = true;
            onCompleteCallback(ok);
            }
        };

        // Shared scanner over a list of ranges
        const scanRanges = (ranges: MemoryRange[], tag: string, done: () => void) => {
            if (patternFound || callbackDone) return done();
            if (!ranges || ranges.length === 0) return done();

            let completed = 0;

            for (const range of ranges) {
            if (patternFound || callbackDone) break;

            const rangeKey = `${range.base}-${range.size}|${pattern_name}`;
            if (this.rescannedRanges && this.rescannedRanges.has(rangeKey)) {
                completed++;
                if (completed === ranges.length && !patternFound) done();
                continue;
            }
            // remember we touched this range — keyed per pattern so fallback /
            // second_fallback passes still get to scan ranges the primary touched.
            try { this.rescannedRanges?.add(rangeKey); } catch { /* noop */ }

            Memory.scan(range.base, range.size, pattern, {
                onMatch: (address: NativePointer, _size: number) => {
                if (patternFound || callbackDone) return "stop";
                if (!acceptPrologueMatch(address, pattern_name, moduleName)) return;
                patternFound = true;
                this.found_ssl_log_secret = true;
                this.no_hooking_success = false;

                devlog_info(`Pattern found at (${pattern_name}) address: ${address} on ${moduleName}`);
                log(`[*] ${moduleName ?? "<unknown>"}: keylog hooks installed via pattern (${pattern_name}, readable-ranges @ ${address})`);

                try {
                    Interceptor.attach(address, {
                    onEnter: function (args) { onMatchCallback(args); },
                    });
                } catch (e) {
                    devlog_error(`Interceptor.attach failed at ${address}: ${e}`);
                }

                executeOnce(true);
                return "stop"; // stop scanning this range
                },
                onError: (_reason: string) => {
                // You can log per-range errors here if needed
                },
                onComplete: () => {
                completed++;
                if (completed === ranges.length && !patternFound && !callbackDone) {
                    done();
                }
                }
            });
            }
        };

        // Phase 1: module-local ranges by protection
        const scanModuleLocal = (i: number, after: () => void) => {
            if (patternFound || callbackDone) return after();
            if (i >= protSets.length) return after();

            let ranges: MemoryRange[] = [];
            try { ranges = mod.enumerateRanges(protSets[i]); } catch { ranges = []; }

            scanRanges(ranges, protSets[i], () => scanModuleLocal(i + 1, after));
        };

        // Phase 2: process-wide ranges filtered to the module window - only if phase 1 failed
        const scanProcessWide = (i: number, after: () => void) => {
            if (patternFound || callbackDone) return after();
            if (i >= protSets.length) return after();

            let ranges: MemoryRange[] = [];
            try {
            const all = Process.enumerateRanges(protSets[i]);
            // keep overlapping [start, end)
            ranges = all.filter(r => r.base.compare(end) < 0 && r.base.add(r.size).compare(start) > 0);
            } catch { ranges = []; }

            scanRanges(ranges, protSets[i], () => scanProcessWide(i + 1, after));
        };

        // Run phases
        scanModuleLocal(0, () => {
            if (patternFound || callbackDone) return;
            devlog_debug(`Module-local scan failed for ${moduleName}, falling back to process-wide filtered ranges...`);
            scanProcessWide(0, () => {
            if (!patternFound) executeOnce(false);
            });
        });
    }

    private hookByPatternOnlyReadablePartsOnReturn(
        patterns: { primary: string; fallback: string; second_fallback?: string },
        pattern_name: string,
        userCallback: (args: any[], retval?: NativePointer) => void,
        onCompleteCallback: (found: boolean) => void,
        maxArgs: number = 8
    ): void {
        const mod = this.module;
        const moduleName = mod?.name;
        const protSets = ["r-x", "r--", "rw-", "rwx"] as const;

        devlog(`Trying to scan only readable parts of ${this.module.name} ...`);

        let pattern: string = "";;
         if (pattern_name === "primary_pattern") {
            pattern = patterns.primary;
        } else if (pattern_name === "fallback_pattern") {
            pattern = patterns.fallback;
        } else if (pattern_name === "second_fallback_pattern" && patterns.second_fallback) {
            pattern = patterns.second_fallback;
        }else{
            pattern = patterns.fallback;
        }

        if (!mod) {
            devlog_error("hookByPatternOnlyReadablePartsOnReturn: module is null");
            onCompleteCallback(false);
            return;
        }

        const start = mod.base;
        const end = mod.base.add(mod.size);

        let patternFound = false;
        let callbackDone = false;

        const executeOnce = (ok: boolean) => {
            if (!callbackDone) {
            callbackDone = true;
            onCompleteCallback(ok);
            }
        };

          // Scan a list of ranges; on first match attach and stop
        const scanRanges = (ranges: MemoryRange[], tag: string, done: () => void) => {
            if (patternFound || callbackDone) return done();
            if (!ranges || ranges.length === 0) return done();

            let completed = 0;

            for (const range of ranges) {
            if (patternFound || callbackDone) break;

            const rangeKey = `${range.base}-${range.size}|${pattern_name}`;
            if (this.rescannedRanges?.has(rangeKey)) {
                completed++;
                if (completed === ranges.length && !patternFound && !callbackDone) done();
                continue;
            }
            try { this.rescannedRanges?.add(rangeKey); } catch {}

            Memory.scan(range.base, range.size, pattern, {
                onMatch: (address: NativePointer) => {
                if (patternFound || callbackDone) return "stop";
                if (!acceptPrologueMatch(address, pattern_name, moduleName)) return;
                patternFound = true;
                this.found_ssl_log_secret = true;
                this.no_hooking_success = false;

                const m = Process.findModuleByAddress(address);
                if (m) {
                    log(`Pattern found at (${pattern_name}) address: ${address} in module ${m.name}`);
                    const local_offset = address.sub(m.base);
                    log(`Ghidra offset (Base 0x0): ${local_offset}`);
                } else {
                    log(`Pattern found at (${pattern_name}) address: ${address} in module <name_not_found>`);
                    log(`Could not get Ghidra offset`);
                }
                devlog_info(`Pattern found for module ${moduleName}`);
                log(`[*] ${moduleName ?? "<unknown>"}: keylog hooks installed via pattern (${pattern_name}, readable-ranges, onReturn @ ${address})`);

                try {
                    Interceptor.attach(address, {
                    onEnter: function (args) {
                        const stored: NativePointer[] = [];
                        for (let i = 0; i <= maxArgs; i++) {
                        try { stored.push(args[i]); } catch { break; }
                        }
                        (this as any).storedArgs = stored;
                    },
                    onLeave: function (retval) {
                        const storedArgs = (this as any).storedArgs || [];
                        try { userCallback(storedArgs, retval); } catch (e) { devlog_error(`userCallback error: ${e}`); }
                    }
                    });
                } catch (e) {
                    devlog_error(`Interceptor.attach failed at ${address}: ${e}`);
                }

                executeOnce(true);
                return "stop"; // stop scanning this range
                },
                onError: (_reason: string) => {
                // optionally log per-range errors
                },
                onComplete: () => {
                completed++;
                if (completed === ranges.length && !patternFound && !callbackDone) {
                    done();
                }
                }
            });
            }
        };

        // Phase 1: module-local ranges by protection
        const scanModuleLocal = (i: number, after: () => void) => {
            if (patternFound || callbackDone) return after();
            if (i >= protSets.length) return after();

            let ranges: MemoryRange[] = [];
            try { ranges = mod.enumerateRanges(protSets[i]); } catch { ranges = []; }
            scanRanges(ranges, protSets[i], () => scanModuleLocal(i + 1, after));
        };

        // Phase 2: process-wide ranges filtered to the module window
        const scanProcessWide = (i: number, after: () => void) => {
            if (patternFound || callbackDone) return after();
            if (i >= protSets.length) return after();

            let ranges: MemoryRange[] = [];
            try {
            const all = Process.enumerateRanges(protSets[i]);
            ranges = all.filter(r => r.base.compare(end) < 0 && r.base.add(r.size).compare(start) > 0);
            } catch { ranges = []; }

            scanRanges(ranges, protSets[i], () => scanProcessWide(i + 1, after));
        };

        // Kick off
        scanModuleLocal(0, () => {
            if (patternFound || callbackDone) {
            devlog_debug("Module-local match found; skipping process-wide scan.");
            return;
            }
            devlog_debug(`Module-local scan failed for ${moduleName}, falling back to process-wide filtered ranges...`);
            scanProcessWide(0, () => {
            if (!patternFound) executeOnce(false);
            });
        });
    }

    // Method to hook the module with patterns provided as arguments.
    //
    // Outer cascade: each pattern variant kicks a fresh whole-module
    // Memory.scan. Even when the primary's onError already drove the
    // readable-parts inner cascade through every variant, we still re-try
    // fallback (and second_fallback) here — the legacy executor relied on
    // exactly this re-try to match ssl_log_secret in stripped Cronet
    // monoliths like libmonochrome_64.so. cascadeCompleted is set true at
    // every terminal branch so pollPatternOutcome can tell "scan still
    // running" from "scan done, nothing matched".
    hookModuleByPattern(
        patterns: { primary: string; fallback: string; second_fallback?: string } | null | undefined,
        onMatchCallback: (args: any[]) => void
    ): void {
        if (!patterns || (!patterns.primary && !patterns.fallback)) {
            // No usable pattern (missing-arch shipped pattern, or empty JSON entry).
            // Skip rather than scanning the whole module with an empty pattern.
            devlog_debug("hookModuleByPattern: no usable pattern, skipping scan");
            this.no_hooking_success = true;
            return;
        }
        const moduleName = this.module?.name;
        this.hookByPattern(patterns, "primary_pattern", onMatchCallback, (primary_success) => {
            if (primary_success) {
                this.cascadeCompleted = true;
                return;
            }
            devlog("Primary pattern failed, trying fallback pattern...");
            this.hookByPattern(patterns, "fallback_pattern", onMatchCallback, (fallback_success) => {
                if (fallback_success) {
                    this.cascadeCompleted = true;
                    return;
                }
                if (patterns.second_fallback) {
                    devlog("Fallback pattern failed, trying second fallback pattern...");
                    this.hookByPattern(patterns, "second_fallback_pattern", onMatchCallback, (second_fallback_success) => {
                        if (!second_fallback_success && !this.found_ssl_log_secret) {
                            // Race guard (plan Iteration 3): don't claim failure if a parallel
                            // cascade has already installed the hook.
                            devlog_debug(`None of the patterns worked. You may need to adjust the patterns for ${moduleName}`);
                            this.no_hooking_success = true;
                        }
                        this.cascadeCompleted = true;
                    });
                } else {
                    if (!this.found_ssl_log_secret) {
                        // Race guard (plan Iteration 3): same rationale as above.
                        devlog_debug(`None of the patterns worked. You may need to adjust the patterns for ${moduleName}`);
                        this.no_hooking_success = true;
                    }
                    this.cascadeCompleted = true;
                }
            });
        });
    }



    private loadPatternsFromJSON(jsonContent: string): void {
        try {
            this.patterns = JSON.parse(jsonContent);
            devlog("Patterns loaded successfully from JSON.");
        } catch (error) {
            devlog_error("Error loading or parsing JSON pattern:  "+ error);
        }
    }

    private invoke_pattern_based_hooking(action: keyof ActionPatterns, module_name: string, platform: string, arch: string, hookCallback: (args: any[]) => void){
        var action_specific_patterns = this.get_action_specific_pattern(module_name, platform, arch,action);

        devlog(`Using ${action} patterns for ${platform} on ${arch}`);
        this.hookModuleByPattern(action_specific_patterns, hookCallback);
    }

     // Function to retrieve patterns based on the current CPU architecture and action
     private get_action_specific_pattern(module_name: string, platform: string, arch: string, action: keyof ActionPatterns): Pattern {
            const archPatterns = this.patterns.modules[module_name][platform][arch];
            if (archPatterns[action]) {
                return archPatterns[action];
            } else {
                devlog(`No patterns found for action: ${action} on architecture: ${arch}`);
            }    
    }


    public hook_DumpKeys(module_name: string, json_module_name: string, jsonContent: string, hookCallback: (args: any[], retval?: NativePointer) => void, onReturn: boolean = false, maxArgs: number = 8): void {
        //this.hook_with_pattern_from_json("Dump-Keys",module_name, json_module_name, jsonContent, hookCallback);
        if (!onReturn) {
            // Hook onEnter: callback gets (args, undefined)
            this.hook_with_pattern_from_json(
                "Dump-Keys",
                module_name,
                json_module_name,
                jsonContent,
                hookCallback
            );
        } else {
            // Hook onReturn: callback gets (args, retval)
            this.hook_with_pattern_from_json_onReturn(
                "Dump-Keys",
                module_name,
                json_module_name,
                jsonContent,
                hookCallback,
                maxArgs
            );
        }
    }

    public hook_tls_keylog_callback(module_name: string, json_module_name: string, jsonContent: string, hookCallback: (args: any[]) => void): void {
        this.hook_with_pattern_from_json("KeyLogCallback-Function",module_name, json_module_name, jsonContent, hookCallback);
        this.hook_with_pattern_from_json("Install-Key-Log-Callback",module_name, json_module_name, jsonContent, hookCallback);
    }

    public hook_ssl_read_and_write(module_name: string, json_module_name: string, jsonContent: string, hookCallback: (args: any[]) => void): void {
        this.hook_with_pattern_from_json("SSL_Read",module_name, json_module_name, jsonContent, hookCallback);
        this.hook_with_pattern_from_json("SSL_Write",module_name, json_module_name, jsonContent, hookCallback);
    }

    // Method to hook functions using patterns from JSON
    private hook_with_pattern_from_json(action_type:keyof ActionPatterns, module_name: string, json_module_name: string, jsonContent: string, hookCallback: (args: any[]) => void): void {
        // Load patterns from the JSON file
        this.loadPatternsFromJSON(jsonContent);

        let platform = Process.platform.toString(); // e.g., linux, android
        if (isAndroid()){
            platform = "android";
        }else if(isiOS()){
            platform = "ios";
        }else if(isMacOS()){
            platform = "macos";
        }
        let arch = Process.arch.toString(); // e.g., x64, arm64
        if(arch == "ia32"){
            arch = "x86"
        }
        const regex = this.createRegexFromModule(module_name);

        // Access the relevant pattern for the module based on platform and architecture
        if (this.patterns.modules[module_name] && 
            this.patterns.modules[module_name][platform] && 
            this.patterns.modules[module_name][platform][arch]) {
                this.invoke_pattern_based_hooking(action_type, module_name, platform, arch, hookCallback);
        }else if (this.patterns.modules[json_module_name] && 
            this.patterns.modules[json_module_name][platform] && 
            this.patterns.modules[json_module_name][platform][arch]) {
                this.invoke_pattern_based_hooking(action_type, json_module_name, platform, arch, hookCallback);
        }else {
            for (const jsonModuleName in this.patterns.modules) {
                if (regex.test(module_name)) {
                    if (this.patterns.modules[jsonModuleName][platform] && this.patterns.modules[jsonModuleName][platform][arch]) {
                        this.invoke_pattern_based_hooking(action_type, jsonModuleName, platform, arch, hookCallback);   
                    }
                }else{
                    devlog_debug("No patterns available for the current platform or architecture.");
                }
            }
            
        }
    }
}
