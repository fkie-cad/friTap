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
        log('Running Script on Windows')
        load_windows_hooking_agent()
    }else if(isAndroid()){
        log('Running Script on Android')
        load_android_hooking_agent()
    }else if(isLinux()){
        log('Running Script on Linux')
        load_linux_hooking_agent()
    }else if(isiOS()){
        log('Running Script on iOS')
        load_ios_hooking_agent()
    }else if(isMacOS()){
        log('Running Script on MacOS')
        load_macos_hooking_agent()
    }else{
        log('Running Script on unknown plattform')
        log("Error: not supported plattform!\nIf you want to have support for this plattform please make an issue at our github page.")
    }

}

load_os_specific_agent()












