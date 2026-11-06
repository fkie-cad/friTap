// --- Module watcher ---

(function() {
    var libraryPatterns = %%LIBRARY_PATTERNS%%;
    var allowedPlatforms = %%ALLOWED_PLATFORMS%%;
    var allowedArchitectures = %%ALLOWED_ARCHITECTURES%%;

    // Platform check
    if (allowedPlatforms.length > 0 && allowedPlatforms.indexOf(Process.platform) === -1) {
        devlog("Platform " + Process.platform + " not in allowed list, skipping");
        return;
    }

    // Architecture check
    if (allowedArchitectures.length > 0 && allowedArchitectures.indexOf(Process.arch) === -1) {
        devlog("Architecture " + Process.arch + " not in allowed list, skipping");
        return;
    }

    // Pre-compile regex patterns once
    var compiledPatterns = [];
    for (var i = 0; i < libraryPatterns.length; i++) {
        compiledPatterns.push(new RegExp(libraryPatterns[i], "i"));
    }

    function matchesPatterns(moduleName) {
        for (var i = 0; i < compiledPatterns.length; i++) {
            if (compiledPatterns[i].test(moduleName)) {
                return true;
            }
        }
        return false;
    }

    // Check already-loaded modules
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var mod = modules[i];
        if (matchesPatterns(mod.name) || matchesPatterns(mod.path)) {
            devlog("Found already-loaded module: " + mod.name);
            installHooks(mod.name, mod.base);
        }
    }

    // Watch for newly loaded modules
    try {
        var observer = new ModuleLoadMonitor({
            onModuleLoaded: function(module) {
                if (matchesPatterns(module.name) || matchesPatterns(module.path)) {
                    devlog("Module loaded: " + module.name);
                    installHooks(module.name, module.base);
                }
            }
        });
        devlog("Module load monitor installed for " + _protocol);
    } catch (e) {
        // ModuleLoadMonitor may not be available on all Frida versions
        // Fall back to polling — reuse _hooked_modules to avoid double-hooking
        devlog("ModuleLoadMonitor not available, using polling fallback");

        setInterval(function() {
            var mods = Process.enumerateModules();
            for (var i = 0; i < mods.length; i++) {
                var mod = mods[i];
                if (!_hooked_modules[mod.name] && (matchesPatterns(mod.name) || matchesPatterns(mod.path))) {
                    devlog("Module detected (poll): " + mod.name);
                    installHooks(mod.name, mod.base);
                }
            }
        }, 1000);
    }

    devlog("CustomProtocolPlugin initialized for " + _protocol);
})();
