// agent/shared/module_exports.ts
//
// Frida 17 removed the static Module.findExportByName(moduleName, symbol); calling it
// throws "not a function". Resolve a module-scoped export through the Module instance
// instead, keeping the static API only as a fallback for older Frida runtimes. Never
// falls back to a global (any-module) lookup: the caller asked for this module.
//
// Module#findExportByName misses a main executable's own exports (an OpenSSH `ssh`
// linked with --export-dynamic) while the process is still suspended at spawn, although
// Module#enumerateExports lists them; the export table is therefore the second source.

const exportTables = new Map<string, Map<string, NativePointer>>();

function exportTableOf(module: any): Map<string, NativePointer> {
    const key = `${module.path}@${module.base}`;
    let table = exportTables.get(key);
    if (table === undefined) {
        table = new Map();
        try {
            for (const exp of module.enumerateExports()) table.set(exp.name, exp.address);
        } catch (_) { /* no export table: leave it empty */ }
        exportTables.set(key, table);
    }
    return table;
}

/** The address of `symbol` exported by `moduleName`, or null when it is not exported. */
export function findModuleExport(moduleName: string, symbol: string): NativePointer | null {
    const module = (Process as any).findModuleByName?.(moduleName);
    if (module && typeof module.findExportByName === "function") {
        return module.findExportByName(symbol)
            ?? (typeof module.enumerateExports === "function" ? exportTableOf(module).get(symbol) ?? null : null);
    }
    const legacyFind = (Module as any).findExportByName;
    return typeof legacyFind === "function" ? legacyFind(moduleName, symbol) ?? null : null;
}
