# Extending friTap



This project is based on [frida](https://frida.re/) and utilize [frida-compile](https://github.com/frida/frida-compile) in order to generate the frida javascript payload.



## Compiling

For this run our docker compiling instance from the repo root folder:

```bash
$ ./compile_agent.sh
```
Alternative just run frida-compile after setting up your environment to work with frida-compile:


```bash
$ frida-compile agent/ssl_log.ts -o _ssl_log.js
```

In order to debug your contribution you can use the debug feature of friTap. Have a look into [our wiki for more information](https://github.com/fkie-cad/friTap/wiki/Debugging-friTap).


## Verifying a socket read or write function

In order to identify shared libaries which could use functions for reading or writing we have serveral possibilites when we attach to the process of interest with frida:
```bash
sudo frida --no-pause thunderbird
```

At first we can look for modules (shared libries) with functions that looks intereseting for our purpose:

```javascript
Process.getModuleByName("libnspr4.so").enumerateExports().filter(exports => exports.name.toLowerCase().includes("read"))
```

Then we can create a simple hook which print us a hexdump of the traffic which  comes through this function
```javascript

Interceptor.attach(Module.getExportByName('libnspr4.so', 'PR_Read'), { 
  onEnter(args) { 
    console.log("hooking read func"); 
    var addr = Memory.alloc(128); 
    var getpeername = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetPeerName'), "int", ["pointer", "pointer"]) 
    getpeername(args[0],addr); 
     
    if(addr === null){ 
        return; 
    } 
    console.log("ip: "+addr.ip); 
  }, 
  onLeave(retval) { 
 
  } 
}); 
```


Another possibility is to use frida-trace or a debugger of our choice. Besides this we are currently working on adding new library by a known offset(currently under development).

## Looking for SSL objects in a process

Sometimes when adding a new library or a library to a new platform it might help to have a look for certain functions names in all modules loaded from the process we are analyzing. In those cases the following snipped might help:

```javascript
modules = Process.enumerateModules()
for(let i=0; i < modules.length; i++){
  ssl_object = JSON.stringify(Process.getModuleByName(modules[i].name).enumerateExports().filter(exports => exports.name.toLowerCase().includes("ssl")));
  if(ssl_object.length > 2){
    console.log(modules[i].name + " :\n" + ssl_object+ "\n");
  }
}
```

This is just a one-line to do the same:

```javascript
Process.enumerateModules().forEach( (element) => { if(JSON.stringify(Process.getModuleByName(element.name).enumerateExports().filter(exports => exports.name.toLowerCase().includes("ssl"))).length > 2){ console.log(element.name + " : \n" + JSON.string
ify(Process.getModuleByName(element.name).enumerateExports().filter(exports => exports.name.toLowerCase().includes("ssl"))));} });
```


## Common errors when compiling changes

- **util missing error**:

```bash
$ frida-compile agent/ssl_log.ts -o _ssl_log.js
[TypeScript error: /...../fritap/agent/bouncycastle.ts(3,25): Error TS2307: Cannot find module 'util' or its corresponding type declarations.] {

```

as this message indicates the util package is missing. Simply install it with npm:

```bash
$ npm install util
```

- **Java missing error**:

```bash
$ frida-compile agent/ssl_log.ts -o _ssl_log.js
[TypeScript error: ../fritap/agent/bouncycastle.ts(4,5): Error TS2304: Cannot find name 'Java'.] {
....
```

in this case the dependencies for the development are missing. This can easily fixed by invoking the following command inside the folder friTap:

```bash
$ npm install .
```

