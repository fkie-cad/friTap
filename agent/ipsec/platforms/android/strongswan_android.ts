// agent/ipsec/platforms/android/strongswan_android.ts
//
// Android strongSwan apps (e.g. the official strongSwan VPN Client) load
// libcharon.so / libstrongswan.so with the same libcharon symbols as the
// Linux userspace build, so the executor is a simple re-export of the Linux
// entry point. Keeping a per-platform module gives android.ts a stable
// import path even if an Android-specific override is introduced later.

export { strongswan_execute_modern } from "../linux/strongswan_linux.js";
