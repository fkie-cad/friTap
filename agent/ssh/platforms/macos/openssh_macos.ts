// agent/ssh/platforms/macos/openssh_macos.ts
//
// macOS bundles OpenSSH at /usr/bin/ssh (sshd, scp, sftp-server, etc.).
// Hooking is functionally identical to Linux because the OpenSSH source
// tree is shared — only the dyld vs ld.so loader differs and that is
// already abstracted by executeFromDefinition().

export { openssh_execute_modern } from "../linux/openssh_linux.js";
