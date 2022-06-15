import { load_android_hooking_agent } from "./android/android_agent";
import { load_ios_hooking_agent } from "./ios/ios_agent";
import { load_macos_hooking_agent } from "./macos/macos_agent";
import { load_linux_hooking_agent } from "./linux/linux_agent";
import { load_windows_hooking_agent } from "./windows/windows_agent";
import { isWindows, isLinux, isAndroid, isiOS, isMacOS } from "./util/process_infos";
import { exit } from "process"
import { log } from "./util/log"


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
        exit(2)
    }

}

load_os_specific_agent()












