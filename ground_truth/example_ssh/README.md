# example_ssh — OpenSSH ground-truth fixture

A throwaway OpenSSH server + client pair for validating friTap's SSH
plaintext capture and Wireshark side-car keylog production.

Designed for the local integration test
(`tests/integration/test_ssh_plaintext.py`) and for ad-hoc reproduction on
Linux x86_64. Not used in CI by default (requires `sshd` and a writable port).

## What it produces

`start_sshd.sh <port>` spawns a sandboxed sshd in the current shell:

* Generates an ed25519 hostkey and a matching ed25519 client key in `/tmp/fritap_ssh_<port>/`.
* Writes a minimal `sshd_config` accepting public-key auth from the generated key.
* Forks `sshd -D -f <config> -p <port> -o PidFile=…` and prints its PID.
* Cleans up on `Ctrl+C` or when the parent shell exits.

Once running you can connect with:

    ssh -p <port> \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -i /tmp/fritap_ssh_<port>/client_key \
        $USER@127.0.0.1 'echo HELLO_FRITAP'

…or wrap the client invocation in friTap:

    fritap --protocol ssh --include-loopback \
        -p /tmp/fritap_ssh_<port>/out.pcapng \
        -k /tmp/fritap_ssh_<port>/keys.log \
        -- /usr/bin/ssh -p <port> \
           -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -i /tmp/fritap_ssh_<port>/client_key \
           $USER@127.0.0.1 'echo HELLO_FRITAP'

After the run:

* `out.pcapng` contains synthetic TCP/127.0.0.1:<port> frames carrying the
  SSH binary packet protocol in cleartext.
* `keys.log` contains per-direction SSH key material with `SSH_ENC_KEY_C2S`
  / `SSH_ENC_KEY_S2C` / `SSH_IV_*` labels (friTap's own debug format).
* `out.ssh-keys.log` (auto-derived) holds Wireshark SSH dissector input —
  one `<cookie> SHARED_SECRET <hex>` line per (re)keying.

## Why no Dockerfile

The fixture deliberately uses the host's `sshd`/`ssh` so it exercises real
Debian/Ubuntu/Fedora binaries. Containerised tests would either drop
symbols (musl/Alpine) or pin to a specific OpenSSH minor and obscure the
version-portability story friTap is built on.

## Limitations

* The fixture grants login as `$USER` (current shell user). It works only
  on systems where that user has a home directory and a shell.
* `sshd` is started with `UsePrivilegeSeparation no` to avoid needing the
  `sshd` system user. Real-world sshd runs WITH privsep — that path is
  exercised by the system's distribution-shipped sshd in a separate test.
* Cleanup is best-effort. If you `kill -9` the parent shell, the
  `tmp/fritap_ssh_<port>/` directory and the sshd process may linger.
