# Extending friTap



This project is based on [frida](https://frida.re/) and utlize [frida-compile](https://github.com/frida/frida-compile) in order to generate the frida javascript payload.



## Compiling

After setting up your environment to work with frida-compile just invoke the following to compile your new changes:

```bash
$ frida-compile agent/ssl_log.ts -o _ssl_log.js
```


## Verifying a socket read or write function

TBD



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

