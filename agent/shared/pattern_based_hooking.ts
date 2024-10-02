import { devlog, log } from "../util/log.js";
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

export class PatternBasedHooking {
    found_ssl_log_secret: boolean;
    module: Module;
    private patterns: any = {};

    constructor(module: Module) {
        this.found_ssl_log_secret = false;
        this.module = module;
    }

    private createRegexFromModule(moduleName: string): RegExp {
        // Match the base name and ensure it ends with .so
        const baseName = moduleName.replace(/\d+(\.\d+)*\.so$/, '.so');
        // Create the regex to match the base name with any version numbers
        const regexPattern = `.*${baseName.replace(/\./g, '\\.')}$`;
        return new RegExp(regexPattern);
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

    private invoke_pattern_based_hooking(action: keyof ActionPatterns, module_name: string, platform: string, arch: string, hookCallback: (args: any[]) => void){
        /*const modulePatterns = this.patterns.modules[module_name][platform][0];
        const primaryPattern = modulePatterns.primary;
        const fallbackPattern = modulePatterns.fallback;*/

        var action_specific_patterns = this.get_action_specific_pattern(module_name, platform, arch,action);

        devlog(`Using ${action} patterns for ${platform} and ${arch}`);

        // Hook the module using the patterns
        //this.hookModuleByPattern({ primary: primaryPattern, fallback: fallbackPattern }, hookCallback);
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


    public hook_DumpKeys(module_name: string, json_module_name: string, jsonContent: string, hookCallback: (args: any[]) => void): void {
        this.hook_with_pattern_from_json("Dump-Keys",module_name, json_module_name, jsonContent, hookCallback);
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
