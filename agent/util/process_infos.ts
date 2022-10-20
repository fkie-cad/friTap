
export function get_process_architecture() : string{
        return Process.arch;
}


export function isAndroid(): boolean{
    if(Java.available && Process.platform == "linux"){
        try{
            Java.androidVersion // this will raise an error when we are not under Android
            return true
        }catch(error){
            return false
        }
    }else{
        return false
    }
}


export function isiOS(): boolean{
    if(get_process_architecture() === "arm64" && Process.platform == "darwin"){
        try{
             // check if iOS or MacOS (currently we handle MacOS with ARM Processor as an iOS device)
            return true
        }catch(error){
            return false
        }
    }else{
        return false
    }
}


export function isMacOS(): boolean{
    if(get_process_architecture() === "x64" && Process.platform == "darwin"){
        return true
    }else{
        return false
    }
}


export function isLinux(): boolean {
    if (Process.platform == "linux") {

        if (Java.available == false && Process.platform == "linux") {
            return true
        } else {
            try {
                Java.androidVersion // this will raise an error when we are not under Android
                return false
            } catch (error) {
                return true
            }

        }
    }else{
        return false
    }
}

export function isWindows(): boolean{
    if( Process.platform == "windows"){
        return true
    }else{
        return false
    }
}


