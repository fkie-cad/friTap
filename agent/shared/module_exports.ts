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
//
// Module#findExportByName resolves through dlsym on the module handle, which also
// searches the module's DT_NEEDED dependencies (on Facebook every small library that
// links libcoldstart.so "exports" its symbols). `ownModuleOnly` keeps only an address
// inside the module's own mapped image.

import { inModule } from "./arm64_xref.js";
import { moduleImageBounds } from "../util/safe_memory.js";

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

export interface ModuleExportOptions {
    /**
     * Accept only an address inside the module's own image (bounds from
     * moduleImageBounds, not Module.size). Uses the module's dlsym lookup only:
     * no export-table enumeration (kept cheap for per-library content filters) and
     * no pre-17 static fallback (an unresolved module cannot be bounds-checked).
     */
    ownModuleOnly?: boolean;
}

/** `symbol` as dlsym finds it from `module`, kept only when it lies in the module's own image. */
function findOwnExport(module: any, symbol: string): NativePointer | null {
    try {
        const p: NativePointer | null = module.findExportByName(symbol);
        if (p === null || p.isNull()) return null;
        const [start, end] = moduleImageBounds(module);
        return inModule(p, start, end) ? p : null;
    } catch (_) {
        return null;
    }
}

/** The address of `symbol` exported by `moduleName`, or null when it is not exported. */
export function findModuleExport(moduleName: string, symbol: string, options: ModuleExportOptions = {}): NativePointer | null {
    const module = (Process as any).findModuleByName?.(moduleName);
    if (options.ownModuleOnly) {
        return module && typeof module.findExportByName === "function" ? findOwnExport(module, symbol) : null;
    }
    if (module && typeof module.findExportByName === "function") {
        return module.findExportByName(symbol)
            ?? (typeof module.enumerateExports === "function" ? exportTableOf(module).get(symbol) ?? null : null);
    }
    const legacyFind = (Module as any).findExportByName;
    return typeof legacyFind === "function" ? legacyFind(moduleName, symbol) ?? null : null;
}
