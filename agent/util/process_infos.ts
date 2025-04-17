import { devlog } from "./log.js";

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

function is_macos_based_version_string(): boolean{
    // Check if NSProcessInfo is available (indicating macOS or iOS)
    if (ObjC.classes.NSProcessInfo !== undefined) {
        try {
            // Get the operating system version string
            const NSProcessInfo = ObjC.classes.NSProcessInfo;

            
            const version = NSProcessInfo.processInfo()
                .operatingSystemVersionString()
                .toString().toLowerCase();

            
            // https://developer.apple.com/documentation/appkit/nsapplication
            // should only available on MacOS
            const isMacOSCheck = ObjC.classes.NSApplication !== undefined;
            
            if (version.includes("ios")) {
                return false;
            } else if (version.includes("macos") || version.includes("os x") || isMacOSCheck) {
                return true;
            }
        } catch (error) {
            devlog("[!] error:"+error);
            return false;
        }
    }

    return false;

}


export function isiOS(): boolean{
    if(get_process_architecture() === "arm64" && Process.platform == "darwin"){
        try{
            if(is_macos_based_version_string()){
                return false;
            }else{
                return true;
            }
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
        if(Process.platform == "darwin"){
            if(is_macos_based_version_string()){
                return true;
            }
        }
            return false;
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


export function getAndroidVersion(): number{
    var version = "-1"
    Java.perform(function () {
        version = Java.androidVersion; // this will return a value like 12 for Android version 12
        });

        var casted_version : number = +version;
        return casted_version;
    
        
}

/**
 * Returns the current Android package name that the script is running inside.
 *
 * Works on all modern Android versions (API 21 +).  Uses ActivityThread first;
 * falls back to any available Context if necessary.
 */
export function getPackageName(): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      Java.perform(() => {
        try {
          // Preferred: ActivityThread.currentPackageName() (SDK ≈ 23 +)
          const ActivityThread = Java.use('android.app.ActivityThread');
          const currentPkg = ActivityThread.currentPackageName();
          if (currentPkg && currentPkg.length > 0) {
            return resolve(currentPkg);
          }
  
          // Fallback: grab a Context and call getPackageName()
          const Context = Java.use('android.content.Context');
          const ActivityThread$ = Java.use('android.app.ActivityThread');
          const app = ActivityThread$.currentApplication();
          if (app && Context.isInstance(app)) {
            // @ts-ignore
            return resolve(app.getPackageName());
          }
  
          return reject(new Error('Unable to obtain package name'));
        } catch (err) {
          return reject(err);
        }
      });
    });
  }