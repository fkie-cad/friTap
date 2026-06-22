#!/bin/bash
# Install friTap extcap plugin for Wireshark

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTCAP_SCRIPT="$SCRIPT_DIR/fritap-extcap"

# Detect Wireshark extcap directory
if [ "$(uname)" = "Darwin" ]; then
    # macOS
    EXTCAP_DIR="$HOME/.local/lib/wireshark/extcap"
    if [ ! -d "$EXTCAP_DIR" ]; then
        EXTCAP_DIR="/Applications/Wireshark.app/Contents/MacOS/extcap"
    fi
elif [ "$(uname)" = "Linux" ]; then
    # Linux
    EXTCAP_DIR="$HOME/.local/lib/wireshark/extcap"
    if [ ! -d "$EXTCAP_DIR" ]; then
        EXTCAP_DIR="/usr/lib/x86_64-linux-gnu/wireshark/extcap"
    fi
else
    # Windows (Git Bash / MSYS2)
    EXTCAP_DIR="$APPDATA/Wireshark/extcap"
fi

echo "Installing friTap extcap plugin..."
echo "Source: $EXTCAP_SCRIPT"
echo "Target: $EXTCAP_DIR"

mkdir -p "$EXTCAP_DIR"
cp "$EXTCAP_SCRIPT" "$EXTCAP_DIR/fritap-extcap"
chmod +x "$EXTCAP_DIR/fritap-extcap"

echo "Done! Restart Wireshark to see the friTap capture interface."
