import { devlog, devlog_error, log } from "../util/log.js";
import { isAndroid, isiOS,isMacOS } from "../util/process_infos.js"

type Pattern = {
    primary: string;
    fallback: string;
};

type ActionPatterns = {
    "Dump-Keys": Pattern;
    "SSL_Read": Pattern;
    "SSL_Write": Pattern;
    "Install-Key-Log-Callback": Pattern;
    "KeyLogCallback-Function": Pattern;
};

export function get_CPU_specific_pattern(default_pattern : { [arch: string]: { primary: string; fallback: string } }): { primary: string; fallback: string } {
    let arch = Process.arch.toString(); // Get architecture, e.g., "x64", "arm64"
    
    if(arch == "ia32"){
        arch = "x86"
    }
    devlog("Trying Pattern: "+JSON.stringify(default_pattern[arch]));
    
    if (default_pattern[arch]) {
        return default_pattern[arch];  // Return the pattern for the architecture
    } else {
        throw new Error(`No patterns found for CPU architecture: ${arch}`);
    }
}

export class PatternBasedHooking {
    found_ssl_log_secret: boolean;
    no_hooking_success: boolean;
    module: Module;
    private patterns: any = {};
    private rescannedRanges: Set<string> = new Set(); // Set to keep track of memory ranges that have been rescanned

    constructor(module: Module) {
        this.found_ssl_log_secret = false;
        this.module = module;
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
        this.found_ssl_log_secret = false;

        let pattern: string;
        if (pattern_name === "primary_pattern") {
            pattern = patterns.primary;
        } else {
            pattern = patterns.fallback;
        }

        Memory.scan(moduleBase, moduleSize, pattern, {
            onMatch: (address) => {
                this.found_ssl_log_secret = true;
                this.no_hooking_success = false;
                var module_by_address = Process.findModuleByAddress(address);

                log(`Pattern found at (${pattern_name}) address: ${address} in module ${module_by_address.name}`);
                log(`Pattern-based hooks installed (onReturn).`);

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
                                console.log("error :"+i+ " with error :"+_e);
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
                                        if (!patternSuccessAlt) {
                                            devlog(
                                                "None of the patterns worked. Adjust or fallback."
                                            );
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
            patterns: { primary: string; fallback: string },
            userCallback: (args: any[], retval?: NativePointer) => void,
            maxArgs: number
        ): void {
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
                            if (!pattern_success_alt) {
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
        devlog(`Using ${action} patterns for ${platform} on ${arch} (onReturn)`);
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
                    devlog("[-] No patterns available for the current platform or architecture.");
                }
            }
        }
    }


    // Method to hook by pattern, with a custom function to handle onEnter and onLeave
    hookByPattern(
        patterns: { primary: string; fallback: string },
        pattern_name: string,
        onMatchCallback: (args: any[]) => void,
        onCompleteCallback: (found: boolean) => void
    ): void {
        const moduleBase = this.module.base;
        const moduleSize = this.module.size;
        this.found_ssl_log_secret = false;

        var pattern: string = "";
        if (pattern_name === "primary_pattern") {
            pattern = patterns.primary;
        }else{
            pattern = patterns.fallback;
        }

        Memory.scan(moduleBase, moduleSize, pattern, {
            onMatch: (address) => {
                this.found_ssl_log_secret = true;
                this.no_hooking_success = false;
                log(`Pattern found at (${pattern_name}) address: ${address}`);
                log(`Pattern based hooks installed.`);

                // Attach the hook using the provided onMatchCallback
                Interceptor.attach(address, {
                    onEnter: function (args) {
                        onMatchCallback(args);
                    },
                    onLeave: function (retval) {
                        // Optionally handle return value or additional behavior
                    }
                });
            },
            onError: (reason) => {
                if(!this.found_ssl_log_secret){
                    devlog_error('There was an error scanning memory: '+reason);
                    devlog_error('Trying to rescan memory with permissions in mind');
                    this.hookByPatternOnlyReadableParts(patterns, pattern_name, onMatchCallback,(pattern_success) => {
                        // If the primary pattern doesn't work, try the fallback pattern
                        if (!pattern_success) {
                            devlog("Primary pattern failed, trying fallback pattern...");
                            this.hookByPatternOnlyReadableParts(patterns, "fallback_pattern", onMatchCallback, (pattern_success_alt) => {
                                if (!pattern_success_alt) {
                                    devlog("None of the patterns worked. You may need to adjust the patterns.");
                                    this.no_hooking_success = true;
                                }
                            });
                        }

                    });
                }
            },
            onComplete: () => {
                onCompleteCallback(this.found_ssl_log_secret);
            }
        });
    }

    // Method to hook by pattern, with a custom function to handle onEnter and onLeave
    hookByPatternOnlyReadableParts(
        patterns: { primary: string; fallback: string },
        pattern_name: string,
        onMatchCallback: (args: any[]) => void,
        onCompleteCallback: (found: boolean) => void
    ): void {
        devlog(`trying to scan only readable parts of ${this.module.name} ...`);

        var pattern: string = "";
        if (pattern_name === "primary_pattern") {
            pattern = patterns.primary;
        }else{
            pattern = patterns.fallback;
        }


        // Enumerate all readable memory ranges of the specified module and scan each one
        this.module.enumerateRanges('r--').forEach((range: MemoryRange) => {
            const rangeKey = `${range.base}-${range.size}`; // Unique key for each memory range
            
            devlog(`Scanning readable memory range in module: ${this.module.name}, Range: ${range.base} - ${range.base.add(range.size)}, Size: ${range.size}`);
    

            Memory.scan(range.base, range.size, pattern, {
                onMatch: (address: NativePointer, size: number) => {
                    this.found_ssl_log_secret = true;
                    log(`Pattern found at (${pattern_name}) address: ${address.toString()}`);
                    log(`Pattern based hooks installed.`);

                    // Attach the hook using the provided onMatchCallback
                    Interceptor.attach(address, {
                        onEnter: function (args) {
                            onMatchCallback(args);
                        },
                        onLeave: function (retval) {
                            // Optionally handle return value or additional behavior
                        }
                    });
                },
                onError: (reason: string) => {
                    devlog_error(`Error scanning memory for range: ${range.base} - ${range.base.add(range.size)}, Reason: ${reason}`);
                },
                onComplete: () => {
                    if (this.rescannedRanges.has(rangeKey)) {
                        return;
                    }else{
                        onCompleteCallback(this.found_ssl_log_secret);
                    }
                }
            });
        });

    }

    private hookByPatternOnlyReadablePartsOnReturn(
        patterns: { primary: string; fallback: string },
        pattern_name: string,
        userCallback: (args: any[], retval?: NativePointer) => void,
        onCompleteCallback: (found: boolean) => void,
        maxArgs: number = 8
    ): void {
        devlog(`Trying to scan only readable parts of ${this.module.name} ...`);

        let pattern: string;
        if (pattern_name === "primary_pattern") {
            pattern = patterns.primary;
        } else {
            pattern = patterns.fallback;
        }
        var ranges = Process.enumerateRanges('r--');
        let found = false;

        //ranges.forEach((range: MemoryRange) => {
        for (let i = 0; i < ranges.length; i++) {
            

            if (found) {
                // If a match was found, stop iterating the ranges altogether.
                break;
            }

            const range = ranges[i];
            const rangeKey = `${range.base}-${range.size}`;

            /*devlog(
                `Scanning readable memory range in module: ${this.module.name}, Range: ${range.base} - ${range.base.add(
                    range.size
                )}, Size: ${range.size}`
            );*/

            Memory.scan(range.base, range.size, pattern, {
                onMatch: (address: NativePointer) => {
                    this.found_ssl_log_secret = true;
                    var module_by_address = Process.findModuleByAddress(address);
                    // In some case findModuleByAddress might return null
                    //devlog(`Pattern: ${pattern}`);
                    if (module_by_address) {
                        log(`Pattern found at (${pattern_name}) address: ${address} in module ${module_by_address.name}`);
                        let local_offset = address.sub(module_by_address.base);
                        log(`Ghidra offset (Base 0x0): ${local_offset}` );
                    }
                    log(`Pattern found at (${pattern_name}) address: ${address} in module <name_not_found>`);
                    log(`Could not get Ghidra offset`);
                    log(`Pattern-based hooks installed (onReturn).`);

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
                                    console.log("i = "+i+"  error: "+_e);
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
                    found = true;    // So we know to break out of the outer loop
                    return "stop";   // Stop scanning the current range immediately
                },
                onError: (reason: string) => {
                    // only for debugging purpose
                    /* 
                    devlog_error(
                        `Error scanning memory for range: ${range.base} - ${range.base.add(
                            range.size
                        )}, Reason: ${reason}`
                    );
                    */
                },
                onComplete: () => {
                    if (this.rescannedRanges.has(rangeKey)) {
                        return;
                    } else {
                        //onCompleteCallback(this.found_ssl_log_secret);
                    }
                },
            });
        }
    //);
    }

    // Method to hook the module with patterns provided as arguments
    hookModuleByPattern(
        patterns: { primary: string; fallback: string },
        onMatchCallback: (args: any[]) => void
    ): void {
        const moduleBase = this.module.base;
        const moduleSize = this.module.size;
        devlog(`Module Base Address: ${moduleBase}`);
        devlog(`Module Size: ${moduleSize}`);

        // Start by hooking using the primary pattern
        this.hookByPattern(patterns, "primary_pattern", onMatchCallback, (pattern_success) => {
            // If the primary pattern doesn't work, try the fallback pattern
            if (!pattern_success) {
                devlog("Primary pattern failed, trying fallback pattern...");
                this.hookByPattern(patterns, "fallback_pattern", onMatchCallback, (pattern_success_alt) => {
                    if (!pattern_success_alt) {
                        devlog("None of the patterns worked. You may need to adjust the patterns.");
                        this.no_hooking_success = true;
                    }
                });
            }
        });
    }



    private loadPatternsFromJSON(jsonContent: string): void {
        try {
            this.patterns = JSON.parse(jsonContent);
            devlog("Patterns loaded successfully from JSON.");
        } catch (error) {
            devlog("[-] Error loading or parsing JSON pattern:  "+ error);
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
                    devlog("[-] No patterns available for the current platform or architecture.");
                }
            }
            
        }
    }
}
