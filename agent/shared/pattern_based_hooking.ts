import { devlog, log } from "../util/log.js";

export class PatternBasedHooking {
    found_ssl_log_secret: boolean;
    module: Module;
    private patterns: any = {};

    constructor(module: Module) {
        this.found_ssl_log_secret = false;
        this.module = module;
    }

    // Method to hook by pattern, with a custom function to handle onEnter and onLeave
    hookByPattern(
        pattern: string,
        pattern_name: string,
        onMatchCallback: (args: any[]) => void,
        onCompleteCallback: (found: boolean) => void
    ): void {
        const moduleBase = this.module.base;
        const moduleSize = this.module.size;
        this.found_ssl_log_secret = false;

        Memory.scan(moduleBase, moduleSize, pattern, {
            onMatch: (address) => {
                this.found_ssl_log_secret = true;
                log(`Pattern found at (${pattern_name}): ${address}`);

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
            onComplete: () => {
                onCompleteCallback(this.found_ssl_log_secret);
            }
        });
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
        this.hookByPattern(patterns.primary, "primary_pattern", onMatchCallback, (pattern_success) => {
            // If the primary pattern doesn't work, try the fallback pattern
            if (!pattern_success) {
                devlog("Primary pattern failed, trying fallback pattern...");
                this.hookByPattern(patterns.fallback, "fallback_pattern", onMatchCallback, (pattern_success_alt) => {
                    if (!pattern_success_alt) {
                        devlog("None of the patterns worked. You may need to adjust the patterns.");
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

    // Method to hook functions using patterns from JSON
    hook_with_pattern_from_json( jsonContent: string, hookCallback: (args: any[]) => void): void {
        // Load patterns from the JSON file
        this.loadPatternsFromJSON(jsonContent);

        const platform = Process.platform; // e.g., linux, android
        const arch = Process.arch; // e.g., x64, arm64

        // Access the relevant pattern for the module based on platform and architecture
        if (this.patterns[platform] && this.patterns[platform][arch]) {
            const modulePatterns = this.patterns[platform][arch];
            const primaryPattern = modulePatterns.primary;
            const fallbackPattern = modulePatterns.fallback;

            devlog(`Using patterns for ${platform} and ${arch}`);

            // Hook the module using the patterns
            this.hookModuleByPattern({ primary: primaryPattern, fallback: fallbackPattern }, hookCallback);
        } else {
            devlog("[-] No patterns available for the current platform or architecture.");
        }
    }
}
