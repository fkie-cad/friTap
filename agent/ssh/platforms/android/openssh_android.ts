// agent/ssh/platforms/android/openssh_android.ts
//
// Android (incl. Termux) ships the same Linux-userspace OpenSSH binary
// distribution, so the executor is a simple re-export of the Linux entry
// point. Keeping a per-platform module gives android.ts a stable
// import path even if an Android-specific override is introduced later.

export { openssh_execute_modern } from "../linux/openssh_linux.js";
