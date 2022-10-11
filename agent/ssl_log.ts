import { load_android_hooking_agent } from "./android/android_agent.js";
import { load_ios_hooking_agent } from "./ios/ios_agent.js";
import { load_macos_hooking_agent } from "./macos/macos_agent.js";
import { load_linux_hooking_agent } from "./linux/linux_agent.js";
import { load_windows_hooking_agent } from "./windows/windows_agent.js";
import { isWindows, isLinux, isAndroid, isiOS, isMacOS } from "./util/process_infos.js";
import { log } from "./util/log.js"

export let offsets = "{OFFSETS}";
/*

create the TLS library for your first prototpye as a lib in ./ssl_lib and than extend this class for the OS where this new lib was tested.

Further keep in mind, that properties of an class only visible inside the Interceptor-onEnter/onLeave scope when they are static. 
As an alternative you could make a local variable inside the calling functions which holds an reference to the class property.

*/


export function getOffsets(){
    return offsets;
}



function load_os_specific_agent() {
    if(isWindows()){
        load_windows_hooking_agent()
    }else if(isAndroid()){
        load_android_hooking_agent()
    }else if(isLinux()){
        load_linux_hooking_agent()
    }else if(isiOS()){
        load_ios_hooking_agent()
    }else if(isMacOS()){
        load_macos_hooking_agent()
    }else{
        log("Error: not supported plattform!\nIf you want to have support for this plattform please make an issue at our github page.")
    }

}

load_os_specific_agent()












