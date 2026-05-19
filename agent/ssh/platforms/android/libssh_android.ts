// agent/ssh/platforms/android/libssh_android.ts
//
// Re-export of the Linux libssh executor — see openssh_android.ts for
// the rationale. Android-hosted libssh consumers (Termux, NDK apps)
// share the same userspace ABI as Linux.

export { libssh_execute_modern } from "../linux/libssh_linux.js";
