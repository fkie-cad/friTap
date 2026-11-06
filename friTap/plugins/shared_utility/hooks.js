function installHooks(moduleName, moduleBase) {
    if (_hooked_modules[moduleName]) {
        devlog("Already hooked: " + moduleName);
        return;
    }
    _hooked_modules[moduleName] = true;

    devlog("Installing hooks in " + moduleName);

    for (var i = 0; i < HOOK_DEFS.length; i++) {
        var hookDef = HOOK_DEFS[i];
        var addr = resolveFunction(moduleName, moduleBase, hookDef);
        if (!addr) {
            devlog("Skipping hook " + i + " (" + (hookDef.symbol || hookDef.offset || "pattern") + "): could not resolve");
            continue;
        }

        try {
            attachHook(addr, hookDef, i);
            devlog("Attached hook " + i + " (" + (hookDef.symbol || hookDef.offset || "pattern") + ") at " + addr);
        } catch (e) {
            devlog("Failed to attach hook " + i + ": " + e.message);
        }
    }
}

function attachHook(addr, hookDef, index) {
    var hookType = hookDef.hook_type;

    if (hookType === "key_on_enter") {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    var argVal = args[hookDef.arg];
                    var byteOffset = _resolveByteOffset(hookDef.byte_offset);
                    var ptr = argVal.add(byteOffset);
                    var keyData = readBytes(ptr, hookDef.size);
                    sendKey(hookDef.label, keyData, hookDef.encoding);
                } catch (e) {
                    devlog("key_on_enter hook " + index + " error: " + e.message);
                }
            }
        });
    } else if (hookType === "key_on_leave") {
        Interceptor.attach(addr, {
            onLeave: function(retval) {
                try {
                    var byteOffset = _resolveByteOffset(hookDef.byte_offset);
                    var ptr = retval.add(byteOffset);
                    var keyData = readBytes(ptr, hookDef.size);
                    sendKey(hookDef.label, keyData, hookDef.encoding);
                } catch (e) {
                    devlog("key_on_leave hook " + index + " error: " + e.message);
                }
            }
        });
    } else if (hookType === "data_read" || hookType === "data_write") {
        var direction = hookDef.direction;
        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    var dataPtr = args[hookDef.data_arg];
                    var length = args[hookDef.length_arg].toInt32();
                    if (length > 0 && length < 1048576) {
                        var data = readBytes(dataPtr, length);
                        sendData(data, direction);
                    }
                } catch (e) {
                    devlog("data hook " + index + " error: " + e.message);
                }
            }
        });
    } else if (hookType === "custom") {
        var callbacks = {};
        if (hookDef.on_enter_js) {
            callbacks.onEnter = new Function("args", hookDef.on_enter_js);
        }
        if (hookDef.on_leave_js) {
            callbacks.onLeave = new Function("retval", hookDef.on_leave_js);
        }
        Interceptor.attach(addr, callbacks);
    }
}

function _resolveByteOffset(byteOffset) {
    if (typeof byteOffset === "object" && byteOffset !== null) {
        return byteOffset[Process.arch] || 0;
    }
    return byteOffset || 0;
}
