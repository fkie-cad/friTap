#!/usr/bin/env bash
# Spawn a throwaway sshd for friTap SSH plaintext-capture testing.
#
# Usage: ./start_sshd.sh <port>
# Output:
#   /tmp/fritap_ssh_<port>/host_key{,.pub}      generated ed25519 hostkey
#   /tmp/fritap_ssh_<port>/client_key{,.pub}    generated ed25519 client key
#   /tmp/fritap_ssh_<port>/authorized_keys      client_key.pub installed
#   /tmp/fritap_ssh_<port>/sshd_config          minimal config
#   /tmp/fritap_ssh_<port>/sshd.pid             PID of running sshd
#
# Exits non-zero if any required tool is missing or sshd refuses to start.
# Foregrounds the sshd process so Ctrl+C cleans up.
set -euo pipefail

PORT="${1:-0}"
if [[ "${PORT}" == "0" || ! "${PORT}" =~ ^[0-9]+$ ]]; then
    echo "usage: $0 <port>" >&2
    exit 2
fi

SSHD_BIN=$(command -v sshd || true)
SSH_KEYGEN_BIN=$(command -v ssh-keygen || true)
if [[ -z "${SSHD_BIN}" || -z "${SSH_KEYGEN_BIN}" ]]; then
    echo "sshd and ssh-keygen must be installed and on PATH" >&2
    exit 3
fi

DIR="/tmp/fritap_ssh_${PORT}"
mkdir -p "${DIR}"
chmod 700 "${DIR}"

if [[ ! -f "${DIR}/host_key" ]]; then
    "${SSH_KEYGEN_BIN}" -q -t ed25519 -N "" -f "${DIR}/host_key"
fi
if [[ ! -f "${DIR}/client_key" ]]; then
    "${SSH_KEYGEN_BIN}" -q -t ed25519 -N "" -f "${DIR}/client_key"
fi
cp -f "${DIR}/client_key.pub" "${DIR}/authorized_keys"
chmod 600 "${DIR}/host_key" "${DIR}/client_key" "${DIR}/authorized_keys"

cat > "${DIR}/sshd_config" <<EOF
Port ${PORT}
ListenAddress 127.0.0.1
HostKey ${DIR}/host_key
PidFile ${DIR}/sshd.pid
LogLevel VERBOSE
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile ${DIR}/authorized_keys
PermitUserEnvironment no
StrictModes no
UsePrivilegeSeparation no
EOF

# absolute path required by sshd
ABS_SSHD=$(readlink -f "${SSHD_BIN}" 2>/dev/null || echo "${SSHD_BIN}")

cleanup() {
    if [[ -f "${DIR}/sshd.pid" ]]; then
        local pid
        pid=$(cat "${DIR}/sshd.pid" 2>/dev/null || echo "")
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
            sleep 0.2
            kill -KILL "${pid}" 2>/dev/null || true
        fi
        rm -f "${DIR}/sshd.pid"
    fi
}
trap cleanup EXIT INT TERM

echo "[ground_truth] launching sshd on 127.0.0.1:${PORT} with config ${DIR}/sshd_config"
echo "[ground_truth] connect with:"
echo "  ssh -p ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\"
echo "      -i ${DIR}/client_key ${USER:-$(id -un)}@127.0.0.1 'echo HELLO_FRITAP'"

exec "${ABS_SSHD}" -D -e -f "${DIR}/sshd_config"
