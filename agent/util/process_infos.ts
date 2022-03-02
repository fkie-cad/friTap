


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