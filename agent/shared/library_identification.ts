import { devlog } from "../util/log.js";
import { invokeHookingFunction } from "../shared/shared_functions.js";

type ModuleHookingType = (...args: any[]) => void;


export function findModulesWithSSLKeyLogCallback(): string[] {
    const modules = Process.enumerateModules();
    const matchedModules: string[] = [];

    for (const mod of modules) {
        // Skip modules we are already hooking
        if (/.*libssl_sb\.so/.test(mod.name) || /.*libssl\.so/.test(mod.name) || /ibconscrypt_jni.so/.test(mod.name) || /libconscrypt_gmscore_jni.so/.test(mod.name)) {
            continue;
        }

        const targetModule = Process.getModuleByName(mod.name);

        const exports = targetModule.enumerateExports();
        for (const exp of exports) {
            if (exp.name === "SSL_CTX_set_keylog_callback") {
                matchedModules.push(mod.name);
                // Once we know it has the symbol, no need to check other exports
                break;
            }
        }
    }

    return matchedModules;
}

export function createModuleLibraryMappingExtend(
    matchedModules: string[],
    hookingFunction: ModuleHookingType
  ): Array<[RegExp, ModuleHookingType]> {

    const moduleLibraryMappingExtend: Array<[RegExp, ModuleHookingType]> = [];
  
    for (const mod of matchedModules) {
        devlog("[!] Installing BoringSSL hooks for " + mod);
    
        moduleLibraryMappingExtend.push([
            new RegExp(`.*${mod}`),
            invokeHookingFunction(hookingFunction)
        ]);
    }
    
    return moduleLibraryMappingExtend;
  }

