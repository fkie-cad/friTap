#!/bin/bash
set -e
frida-pm install frida-objc-bridge frida-java-bridge
frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js