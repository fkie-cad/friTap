# CONTRIBUTION Guidlines

- when adding a new SSL/TLS library it should be created inside the [agent/ssl_lib](https://github.com/fkie-cad/friTap/tree/main/) folder as  `<library-name>.ts`. Than the actual invocation should be done for the appropriate operating system. This means when creating boringssl support for Android we develop our approach inside [agent/ssl_lib](https://github.com/fkie-cad/friTap/tree/main/) folder, but its invocation will be handled by the [android_agent.ts](https://github.com/fkie-cad/friTap/blob/main/agent/android/android_agent.ts) inside the `angent/android/` folder. In order to invocate our new library we need to extend from its superclass ([s. openssl_boringssl_android.ts](https://github.com/fkie-cad/friTap/blob/main/agent/android/openssl_boringssl_android.ts)). All classes of a "library-hook" for an operating system following the same structure and get registered in [android_agent.ts](https://github.com/fkie-cad/friTap/blob/main/agent/android/android_agent.ts).
- for each new library we want to build a ground truth so that we can ensure that the library is working at least when it is compiled by default
- to get a better understanding of the internals of friTap have look at [this blog post](https://lolcads.github.io/posts/2022/08/fritap/#program-flow) explaining the program flow
- while debugging your new library we suggest using the debugging feature of friTap.  [Moure about this in our wiki](https://github.com/fkie-cad/friTap/wiki/Debugging-friTap) 

**Note:**  

Starting with **Frida version 17 and above**, language-specific bridges must be installed manually.  
For **friTap**, the following bridges are required:

- [`frida-java-bridge`](https://github.com/frida/frida-java-bridge) – for interacting with Java-based apps on Android
- [`frida-objc-bridge`](https://github.com/frida/frida-objc-bridge) – for interacting with Objective-C code on iOS/macOS

You can install both bridges using the official `frida-pm` package manager:

```bash
 frida-pm install frida-objc-bridge frida-java-bridge
```
