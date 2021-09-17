const resolver:ApiResolver = new ApiResolver('module');

hookDynamicLoader()




function hookDynamicLoader():void{
    switch(Process.platform){
        case "windows":
            console.log("Windows dynamic loader found!")
            hookWindowsDynamicLoader()
            break;
        case "linux":
            console.log("Linux dynamic loader found!")
            hookLinuxDynamicLoader()
            break;
        default:
            console.log("No dynamic loader found!");
    }
}

function hookWindowsDynamicLoader():void{
    var loaderFunctions: string[] =  ["LoadLibraryExW","LoadlLibraryA", "LoadLibraryW", "LoadlLibraryExA"]
    var kernelbase_exports = resolver.enumerateMatches("exports:KERNELBASE.dll!*")

    loaderFunctions.forEach((func:string)=>{
        for(let index:number = 0; index < kernelbase_exports.length; index++){
            if(kernelbase_exports[index].name.indexOf(func) != -1){;
                for(let j:number = 0; j < 10; j++){
                    Interceptor.attach(kernelbase_exports[index].address, {
                        onLeave(retval: NativePointer){
                        
                        let map = new ModuleMap();
                        let moduleName = map.findName(retval)
                        console.log(moduleName);


                        if(moduleName.indexOf("libssl-1_1.dll")){
                               //Run some OpenSSL routine
                        }
                       
                        //More module comparisons
                        }
                    })
                }
            }
        }
    })
    console.log("Done Windows dynamic loader hooking!")
}

