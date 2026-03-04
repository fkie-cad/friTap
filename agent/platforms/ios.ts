import { hookRegistry } from "../shared/registry.js";
import { selected_protocol } from "../fritap_agent.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader_v2, invokeHookingFunction } from "../shared/shared_functions.js";
import { boring_execute } from "../tls/platforms/ios/openssl_boringssl_ios.js";
import { cronet_execute } from "../tls/platforms/ios/cronet_ios.js"
import { flutter_execute } from "../tls/platforms/ios/flutter_ios.js"


var plattform_name = "darwin";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_iOS_Dynamic_Loader(hookRegistry: any, is_base_hook: boolean): void {
    try {
        const regex_libdl = /libSystem.B.dylib/
        const libdl = moduleNames.find(element => element.match(regex_libdl))
        if (libdl === undefined) {
            throw "Darwin Dynamic loader not found!"
        }

        var dlopen = "dlopen"

        Interceptor.attach(Process.getModuleByName(libdl).getExportByName(dlopen), {
            onEnter: function (args) {
                this.moduleName = args[0].readCString()
            },
            onLeave: function (retval: any) {
                if (this.moduleName != undefined) {
                    const matches = hookRegistry.findAllMatches(plattform_name, this.moduleName, undefined, selected_protocol);
                    for (let match of matches) {
                        log(`${this.moduleName} was loaded & will be hooked on iOS!`)
                        try {
                            match.hookFn(this.moduleName, is_base_hook)
                        } catch (error_msg) {
                            devlog(`iOS dynamic loader error: ${error_msg}`)
                        }
                    }
                }
            }


        })

        log(`[*] iOS dynamic loader hooked.`)
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking on iOS.")
    }
}


function hook_iOS_SSL_Libs(hookRegistry: any, is_base_hook: boolean) {
    ssl_library_loader_v2(plattform_name, hookRegistry, moduleNames, "iOS", is_base_hook, selected_protocol)
}



export function load_ios_hooking_agent() {
    // LEGACY: module_library_mapping[plattform_name] = [
    //     [/.*libboringssl\.dylib/, invokeHookingFunction(boring_execute)],
    //     [/.*cronet.*\.dylib/, invokeHookingFunction(cronet_execute)],
    //     [/.*flutter.*\.dylib/, invokeHookingFunction(flutter_execute)]
    // ]
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /.*libboringssl\.dylib/, hookFn: invokeHookingFunction(boring_execute), library: "BoringSSL" },
        { platform: plattform_name, pattern: /.*cronet.*\.dylib/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet" },
        { platform: plattform_name, pattern: /.*flutter.*\.dylib/, hookFn: invokeHookingFunction(flutter_execute), library: "Flutter BoringSSL" },
    ]);

    hook_iOS_SSL_Libs(hookRegistry, true);
    hook_iOS_Dynamic_Loader(hookRegistry, false);
}