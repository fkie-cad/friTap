# Extending friTap



This project is based on [frida](https://frida.re/) and utilize [frida-compile](https://github.com/frida/frida-compile) in order to generate the frida javascript payload.



## Compiling

After setting up your environment to work with frida-compile just invoke the following to compile your new changes:

```bash
$ frida-compile agent/ssl_log.ts -o _ssl_log.js
```


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


Another possiblites is to use frida-trace or a debugger of our choice.


## Common errors when compiling changes

This is a common error:

```bash
$ frida-compile agent/ssl_log.ts -o _ssl_log.js
[TypeScript error: /...../fritap/agent/bouncycastle.ts(3,25): Error TS2307: Cannot find module 'util' or its corresponding type declarations.] {

```

as this message indicates the util package is missung. Simply install it with npm:

```bash
$ sudo npm install util
```

