// --- Function resolution ---

function resolveFunction(moduleName, moduleBase, hookDef) {
    // Try symbol first
    if (hookDef.symbol) {
        var addr = Module.findExportByName(moduleName, hookDef.symbol);
        if (addr) {
            devlog("Resolved " + hookDef.symbol + " via export in " + moduleName);
            return addr;
        }
    }

    // Try byte pattern
    if (hookDef.pattern) {
        var arch = Process.arch;
        var patterns = hookDef.pattern[arch];
        if (patterns && patterns.length > 0) {
            var mod = Process.findModuleByName(moduleName);
            if (mod) {
                for (var i = 0; i < patterns.length; i++) {
                    var syncMatches = Memory.scanSync(mod.base, mod.size, patterns[i]);
                    if (syncMatches.length > 0) {
                        devlog("Resolved via pattern in " + moduleName + " at " + syncMatches[0].address);
                        return syncMatches[0].address;
                    }
                }
            }
        }
    }

    // Try offset from module base
    if (hookDef.offset) {
        var offsetVal = parseInt(hookDef.offset, 16);
        if (!isNaN(offsetVal)) {
            var addr = moduleBase.add(offsetVal);
            devlog("Resolved via offset " + hookDef.offset + " in " + moduleName);
            return addr;
        }
    }

    devlog("Failed to resolve function for hook in " + moduleName);
    return null;
}
