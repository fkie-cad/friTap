import { hookRegistry } from "../shared/registry.js";
import { selected_protocol } from "../fritap_agent.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader_v2, invokeHookingFunction } from "../shared/shared_functions.js";
import { boring_execute, ssl_python_execute } from "../tls/platforms/macos/openssl_boringssl_macos.js";
import { cronet_execute } from "../tls/platforms/macos/cronet_macos.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";


var plattform_name = "darwin";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_macOS_Dynamic_Loader(hookRegistry: any, is_base_hook: boolean): void {
    try {
        const regex_libdl = /libSystem.B.dylib/
        const libdl = moduleNames.find(element => element.match(regex_libdl))
        if (libdl === undefined) {
            throw "Darwin Dynamic loader not found!"
        }

        var dlopen = "dlopen"

        Interceptor.attach(Process.getModuleByName("libSystem.B.dylib").getExportByName(dlopen), {
            onEnter: function (args) {
                this.moduleName = args[0].readCString()
            },
            onLeave: function (retval: any) {
                if (this.moduleName != undefined) {
                    const matches = hookRegistry.findAllMatches(plattform_name, this.moduleName, undefined, selected_protocol);
                    for (let match of matches) {
                        log(`${this.moduleName} was loaded & will be hooked on MacOS!`)
                        try {
                            match.hookFn(this.moduleName, is_base_hook);
                        } catch (error_msg) {
                            devlog(`MacOS dynamic loader error: ${error_msg}`)
                        }
                    }
                }
            }


        })

        log("MacOS dynamic loader hooked.")
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking on MacOS.")
    }
}


function hook_macOS_SSL_Libs(hookRegistry: any, is_base_hook: boolean) {
    ssl_library_loader_v2(plattform_name, hookRegistry, moduleNames, "MacOS", is_base_hook, selected_protocol)
}



export function load_macos_hooking_agent() {
    // LEGACY: module_library_mapping[plattform_name] = [
    //     [/.*libboringssl\.dylib/, invokeHookingFunction(boring_execute)],
    //     [/.*libssl.*\.dylib/, invokeHookingFunction(ssl_python_execute), "python"], // Python-specific OpenSSL
    //     [/.*libssl.*\.dylib/, invokeHookingFunction(boring_execute)],
    //     [/.*cronet.*\.dylib/, invokeHookingFunction(cronet_execute)]
    // ]
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /.*libboringssl\.dylib/, hookFn: invokeHookingFunction(boring_execute), library: "BoringSSL" },
        { platform: plattform_name, pattern: /.*libssl.*\.dylib/, hookFn: invokeHookingFunction(ssl_python_execute), library: "Python OpenSSL", pathFilter: "python" },
        { platform: plattform_name, pattern: /.*libssl.*\.dylib/, hookFn: invokeHookingFunction(boring_execute), library: "OpenSSL/BoringSSL" },
        { platform: plattform_name, pattern: /.*cronet.*\.dylib/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet" },
        // SSH libraries
        { platform: plattform_name, pattern: /.*libssh2?\.dylib/, hookFn: invokeHookingFunction(ssh_detect_execute), library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /.*sshd/, hookFn: invokeHookingFunction(ssh_detect_execute), library: "OpenSSH", protocol: "ssh" },
    ]);

    hook_macOS_SSL_Libs(hookRegistry, true); // actually we are using the same implementation as we did on iOS, therefore this needs addtional testing
    hook_macOS_Dynamic_Loader(hookRegistry, false);
}