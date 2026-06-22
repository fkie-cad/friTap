# Extending friTap

This project is based on [Frida](https://frida.re/) and uses `frida-compile` (shipped with the official [`frida-tools`](https://github.com/frida/frida-tools) package) to build the Frida JavaScript agent payload.

## Compiling

There are serveral ways how we can invoke `frida-compile` in order to generate our friTap hooks.

### Recommended: local build via `frida-tools`

Install/update Frida tooling and compile the agent:

```bash
python -m pip install -U frida frida-tools
frida-compile agent/fritap_agent.ts -o fritap_agent.js
```

### Deprecated: Docker-based compiler

> **Deprecated:** The Docker-based compile flow is kept for compatibility only and may be removed in a future release.
> Prefer the local `frida-compile` workflow above.

From the repo root:

```bash
./compile_agent.sh
```

## Debugging

To debug your contribution, use the debug feature of friTap. See the
[friTap wiki](https://github.com/fkie-cad/friTap/wiki/Debugging-friTap) for details.

---

**Note:**

Starting with **Frida 17+**, language-specific bridges must be installed manually.  
For **friTap**, the following bridges are required:

- [`frida-java-bridge`](https://github.com/frida/frida-java-bridge) – for interacting with Java-based apps on Android
- [`frida-objc-bridge`](https://github.com/frida/frida-objc-bridge) – for interacting with Objective-C code on iOS/macOS

Install both bridges using the official `frida-pm` package manager:

```bash
frida-pm install frida-objc-bridge frida-java-bridge
```


## Verifying a socket read or write function

> Only do this on systems you own or have explicit permission to test.

When identifying candidate I/O functions inside a process, a pragmatic workflow is:

1) attach to the process with the Frida CLI,  
2) enumerate exports of likely networking libraries (e.g., NSPR, OpenSSL, BoringSSL, libc),  
3) hook a read/write function and dump the buffers.

### Attach to the process

Attach to an already running process (recommended for quick exploration):

```bash
sudo frida -n thunderbird
```

(You can also load a script file directly with `-l`, and Frida CLI supports reloading while iterating.)

### Enumerate “read/write” candidates in a module

Example: NSPR on Linux (`libnspr4.so`):

```javascript
const m = Process.getModuleByName("libnspr4.so");
m.enumerateExports()
  .filter(e => e.type === "function" && /read|write/i.test(e.name))
  .forEach(e => console.log(`${e.name} @ ${e.address}`));
```

### Hook `PR_Read` and print a hexdump of inbound data

NSPR `PR_Read(fd, buf, amount)` fills `buf` and returns the number of bytes read. That means: capture pointers in `onEnter()`, and dump in `onLeave()` using the returned length.

```javascript
const PR_Read = Module.getExportByName("libnspr4.so", "PR_Read");

Interceptor.attach(PR_Read, {
  onEnter(args) {
    this.buf = args[1];
    this.requested = args[2].toInt32();
  },
  onLeave(retval) {
    const n = retval.toInt32();
    if (n <= 0) return;

    const dumpLen = Math.min(n, 256); // avoid huge logs
    console.log(`PR_Read(requested=${this.requested}) -> ${n} bytes`);
    console.log(hexdump(this.buf, { length: dumpLen, header: true, ansi: true }));
  }
});
```

### Hook `PR_Write` and print a hexdump of outbound data

For a write call, the buffer already contains the bytes being sent, so dumping in `onEnter()` is usually enough:

```javascript
const PR_Write = Module.getExportByName("libnspr4.so", "PR_Write");

Interceptor.attach(PR_Write, {
  onEnter(args) {
    const buf = args[1];
    const n = args[2].toInt32();
    if (n <= 0) return;

    const dumpLen = Math.min(n, 256);
    console.log(`PR_Write(${n} bytes)`);
    console.log(hexdump(buf, { length: dumpLen, header: true, ansi: true }));
  }
});
```

### Notes / alternatives

- Dumping at `PR_Read`/`PR_Write` level may show **encrypted TLS records** (depending on where you hook). If you want plaintext, you typically hook *above* the encryption boundary (library-specific).
- For a quick “is this function even called?” sanity check, you can also use `frida-trace` to generate handlers and observe call frequency.
- If your target library is stripped or doesn’t export what you expect, `enumerateExports()` won’t help; consider `enumerateSymbols()` (availability depends on platform).

---

## Looking for SSL-related exports in a process

If you’re bringing up a new library/platform, it can help to scan loaded modules for exported symbol names containing `ssl` (or `tls`, `handshake`, etc.). Keep in mind: **exports only**; stripped libs often won’t expose much.

```javascript
for (const mod of Process.enumerateModules()) {
  const hits = mod.enumerateExports()
    .filter(e => e.type === "function" && /ssl/i.test(e.name));

  if (hits.length > 0) {
    console.log(`\n${mod.name}:`);
    hits.forEach(h => console.log(`  ${h.name}`));
  }
}
```

This is clearer and faster than repeatedly `JSON.stringify()`-ing results.

---

## Common errors when compiling changes

### TS2307: Cannot find module `util` (or types)

Example:

```text
Error TS2307: Cannot find module 'util' or its corresponding type declarations.
```

What’s going on:
- TypeScript can’t resolve the module and/or its typings.
- In Frida agents, **Node built-ins aren’t guaranteed** at runtime unless you bundle/polyfill them.

Practical fixes (pick what matches your actual usage):

**A) You only need TypeScript typings for Node core modules**
```bash
npm i -D @types/node
```

Then ensure your `tsconfig.json` includes Node types, e.g.:
```json
{
  "compilerOptions": {
    "types": ["frida-gum", "node"]
  }
}
```

**B) You need a runtime polyfill/bundled module**
```bash
npm i util
```

(That installs a userland `util` package that bundlers can include.)

### TS2304 / runtime error: `Java` is not defined

You can hit this in two different ways:

**A) Compile-time (TypeScript): `Cannot find name 'Java'`**  
This usually means your Frida typings are missing. Ensure typings are installed and enabled:

```bash
npm i -D @types/frida-gum
```

And in `tsconfig.json`:
```json
{
  "compilerOptions": {
    "types": ["frida-gum"]
  }
}
```

**B) Runtime (Frida 17+): `ReferenceError: 'Java' is not defined`**  
Starting with **Frida 17**, bridges are no longer bundled in GumJS for *agent bundles*; you must install/import them explicitly (REPL / `frida-trace` are special-cased for compatibility).

Fix (agent bundle):
```bash
frida-pm install frida-java-bridge
```

And in your agent:
```ts
import Java from "frida-java-bridge";
```

(Analogous for ObjC: `frida-objc-bridge`.)
