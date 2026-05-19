// agent/ssh/platforms/macos/libssh_macos.ts
//
// macOS libssh ships as libssh.<n>.dylib (Homebrew, MacPorts, or Qt
// frameworks) — same Linux-style ABI; the wrapper just re-exports the
// Linux executor.

export { libssh_execute_modern } from "../linux/libssh_linux.js";
