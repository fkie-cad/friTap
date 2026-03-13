/**
 * Legacy v1 entry points extracted from shared_functions.ts.
 * These are only used by the legacy (class-based) hooking path.
 */

import { devlog } from "../../util/log.js";

/**
 * Standard wrapper for SSL library execute functions.
 * Instantiates the library class, calls execute_hooks(), and stores init_addresses if base hook.
 */
export function executeSSLLibrary(
    LibClass: new (moduleName: string, socket_library: string, is_base_hook: boolean) => any,
    moduleName: string,
    socket_library: string,
    is_base_hook: boolean,
    options?: { tryCatch?: boolean }
): void {
    const instance = new LibClass(moduleName, socket_library, is_base_hook);

    if (options?.tryCatch) {
        try {
            instance.execute_hooks();
        } catch (error_msg) {
            devlog(`executeSSLLibrary error: ${error_msg}`);
        }
    } else {
        instance.execute_hooks();
    }

    if (is_base_hook) {
        try {
            const init_addresses = instance.addresses[moduleName];
            if (init_addresses && Object.keys(init_addresses).length > 0) {
                (globalThis as any).init_addresses[moduleName] = init_addresses;
            }
        } catch (error_msg) {
            if (options?.tryCatch) {
                devlog(`executeSSLLibrary base-hook error: ${error_msg}`);
            }
        }
    }
}

/**
 * Check the number of exports a module has.
 */
export function checkNumberOfExports(moduleName: string): number {
    try {
        const module = Process.getModuleByName(moduleName);
        const exports = module.enumerateExports();
        const numberOfExports = exports.length;
        devlog(`The module "${moduleName}" has ${numberOfExports} exports.`);
        return numberOfExports;
    } catch (error) {
        devlog(`Error checking exports for module "${moduleName}": ${error}`);
        return -1;
    }
}

export function hasMoreThanFiveExports(moduleName: string): boolean {
    return checkNumberOfExports(moduleName) > 5;
}
