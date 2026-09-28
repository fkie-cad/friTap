@echo off
cd /d "%~dp0\.."
REM Entry/output are parameterized (defaults reproduce the historical, public
REM behavior exactly, so a bare `dev\compile_agent.bat` is unchanged):
REM   ENTRY  build entry .ts     (default: agent/fritap_agent.ts   -- the PUBLIC bundle)
REM   OUT    output bundle .js   (default: friTap/fritap_agent.js  -- the shipped bundle)
REM To build the standalone memory-scan agent (independent bundle):
REM   set ENTRY=agent/memory_scan_agent.ts
REM   set OUT=friTap/fritap_memscan.js
REM   dev\compile_agent.bat
if "%ENTRY%"=="" set ENTRY=agent/fritap_agent.ts
if "%OUT%"=="" set OUT=friTap/fritap_agent.js
frida-pm install frida-objc-bridge frida-java-bridge
frida-compile %ENTRY% -o %OUT%
