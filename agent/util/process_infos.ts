import { devlog } from "./log.js";
import { Java } from "../shared/javalib.js";
import { ObjC } from "../shared/objclib.js";

export function get_process_architecture() : string{
        return Process.arch;
}


export function isAndroid(): boolean{
    if(typeof Java !== "undefined" && Java.available && Process.platform == "linux"){
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

/**
 * Enhanced version string detection with multiple detection methods
 */
function is_macos_based_version_string(): boolean{
    // Check if NSProcessInfo is available (indicating macOS or iOS)
    if (typeof ObjC !== "undefined" && ObjC.classes.NSProcessInfo !== undefined) {
        try {
            // Get the operating system version string
            const NSProcessInfo = ObjC.classes.NSProcessInfo;
            const version = NSProcessInfo.processInfo()
                .operatingSystemVersionString()
                .toString().toLowerCase();

            //devlog(`[OS Detection] Version string: ${version}`); // uncomment for debugging
            
            // Primary framework check - most reliable
            const isMacOSFramework = ObjC.classes.NSApplication !== undefined;
            const isiOSFramework = ObjC.classes.UIApplication !== undefined;
            
            // If we have clear framework indicators, use those
            if (isMacOSFramework && !isiOSFramework) {
                devlog("[OS Detection] AppKit without UIKit -> macOS");
                return true;
            }
            
            if (isiOSFramework && !isMacOSFramework) {
                devlog("[OS Detection] UIKit without AppKit -> iOS");
                return false;
            }
            
            // Version string analysis
            if (version.includes("ios") || version.includes("iphone") || version.includes("ipad")) {
                devlog("[OS Detection] iOS indicators in version string");
                return false;
            } 
            
            if (version.includes("macos") || version.includes("os x") || version.includes("mac os x")) {
                devlog("[OS Detection] macOS indicators in version string");
                return true;
            }

            // Additional checks for edge cases
            try {
                // Check for macOS-specific paths
                const fileManager = ObjC.classes.NSFileManager.defaultManager();
                if (fileManager.fileExistsAtPath_("/Applications/Safari.app")) {
                    // devlog("[OS Detection] macOS Safari app found"); // uncomment for debugging
                    return true;
                }
                
                if (fileManager.fileExistsAtPath_("/Applications/MobileSafari.app")) {
                    //devlog("[OS Detection] iOS MobileSafari app found"); // uncomment for debugging
                    return false;
                }
            } catch (pathError) {
                devlog(`[OS Detection] Path check error: ${pathError}`);
            }

            // If we have AppKit but version string is ambiguous, assume macOS
            if (isMacOSFramework) {
                devlog("[OS Detection] Fallback to AppKit presence -> macOS");
                return true;
            }
            
        } catch (error) {
            devlog(`[OS Detection] Version string detection error: ${error}`);
            return false;
        }
    }

    return false;
}


/**
 */
export function isiOS(): boolean{
    // Must be darwin platform first
    if(Process.platform !== "darwin"){
        return false;
    }

    // Use framework-based detection instead of architecture guessing
    if (typeof ObjC !== "undefined" && ObjC.available) {
        try {
            // UIKit (UIApplication) is iOS/iPadOS-exclusive
            if (ObjC.classes.UIApplication !== undefined) {
                devlog("[OS Detection] UIKit found -> iOS");
                return true;
            }

            // If we have AppKit (NSApplication), it's definitely macOS
            if (ObjC.classes.NSApplication !== undefined) {
                devlog("[OS Detection] AppKit found -> macOS (not iOS)");
                return false;
            }

            // Fallback to improved version string check
            return !is_macos_based_version_string();
        } catch(error) {
            devlog(`[OS Detection] iOS detection error: ${error}`);
            return false;
        }
    }

    return false;
}

/**
 * FIXED: macOS detection that properly handles Apple Silicon Macs
 * The old logic assumed x64 = macOS, but Apple Silicon Macs use arm64
 */
export function isMacOS(): boolean{
    // Must be darwin platform first
    if(Process.platform !== "darwin"){
        return false;
    }

    // Use framework-based detection instead of architecture guessing
    if (typeof ObjC !== "undefined" && ObjC.available) {
        try {
            // AppKit (NSApplication) is macOS-exclusive
            if (ObjC.classes.NSApplication !== undefined) {
                devlog("[OS Detection] AppKit found -> macOS");
                return true;
            }

            // If we have UIKit (UIApplication), it's definitely iOS
            if (ObjC.classes.UIApplication !== undefined) {
                devlog("[OS Detection] UIKit found -> iOS (not macOS)");
                return false;
            }

            // Fallback to version string check
            return is_macos_based_version_string();
        } catch(error) {
            devlog(`[OS Detection] macOS detection error: ${error}`);
            // Fallback for x64 Macs when ObjC detection fails
            return get_process_architecture() === "x64";
        }
    }

    // Final fallback: x64 on darwin is likely Intel Mac
    return get_process_architecture() === "x64";
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


/**
 * Detect if we're running inside a Wine process on Linux.
 * Wine processes are Linux processes that load Windows DLLs via Wine's loader.
 *
 * Detection strategy:
 * 1. At spawn time, Wine hasn't loaded ntdll.dll.so yet, but the main process
 *    module is "wine64" or "wine-preloader"
 * 2. After initialization, Wine-specific modules like ntdll.dll.so are loaded
 *
 * We check for both early (wine64/wine-preloader) and late (ntdll.dll.so) indicators.
 */
export function isWine(): boolean {
    if (Process.platform !== "linux") {
        return false;
    }

    try {
        const modules = Process.enumerateModules();
        const moduleNames = modules.map(m => m.name.toLowerCase());

        // Early indicators: Wine process loader (available at spawn time)
        const earlyIndicators = [
            "wine64",
            "wine-preloader",
            "wine64-preloader"
        ];

        // Late indicators: Wine DLL wrappers (available after Wine initializes)
        const lateIndicators = [
            "ntdll.dll.so",
            "ntdll.so",
            "kernelbase.dll.so",
            "kernel32.dll.so"
        ];

        // Check early indicators first (exact match for main module)
        const hasEarlyIndicator = earlyIndicators.some(indicator =>
            moduleNames.some(mod => mod === indicator || mod.includes(indicator))
        );

        if (hasEarlyIndicator) {
            devlog("[Wine Detection] Detected Wine via process loader");
            return true;
        }

        // Check late indicators (substring match for .dll.so modules)
        const hasLateIndicator = lateIndicators.some(indicator =>
            moduleNames.some(mod => mod.includes(indicator))
        );

        if (hasLateIndicator) {
            devlog("[Wine Detection] Detected Wine via DLL modules");
            return true;
        }

        return false;
    } catch (error) {
        devlog(`[Wine Detection] Error checking for Wine: ${error}`);
        return false;
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
 * Debug function to get detailed platform information
 * Useful for troubleshooting OS detection issues
 */
export function getDetailedPlatformInfo(): any {
    const info: any = {
        platform: Process.platform,
        architecture: Process.arch,
        isAndroid: isAndroid(),
        isiOS: isiOS(),
        isMacOS: isMacOS(),
        isLinux: isLinux(),
        isWindows: isWindows(),
        objcAvailable: typeof ObjC !== "undefined" && ObjC.available,
        javaAvailable: typeof Java !== "undefined" && Java.available
    };

    // Add detailed Apple platform info
    if (Process.platform === "darwin" && info.objcAvailable) {
        try {
            const processInfo = ObjC.classes.NSProcessInfo.processInfo();
            info.appleDetails = {
                versionString: processInfo.operatingSystemVersionString().toString(),
                processName: processInfo.processName().toString(),
                frameworks: {
                    UIKit: ObjC.classes.UIApplication !== undefined,
                    AppKit: ObjC.classes.NSApplication !== undefined,
                    Foundation: ObjC.classes.NSString !== undefined
                },
                paths: {}
            };

            // Check key paths
            const fileManager = ObjC.classes.NSFileManager.defaultManager();
            const pathsToCheck = [
                "/Applications/Safari.app",
                "/Applications/MobileSafari.app", 
                "/System/Library/Frameworks/AppKit.framework",
                "/System/Library/Frameworks/UIKit.framework",
                "/Users",
                "/var/mobile"
            ];

            for (const path of pathsToCheck) {
                info.appleDetails.paths[path] = fileManager.fileExistsAtPath_(path);
            }

        } catch (error) {
            info.appleDetailsError = error.toString();
        }
    }

    return info;
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