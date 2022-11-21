(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.load_android_hooking_agent = exports.socket_library = void 0;
const shared_structures_1 = require("../shared/shared_structures");
const shared_functions_1 = require("../shared/shared_functions");
const log_1 = require("../util/log");
const gnutls_android_1 = require("./gnutls_android");
const wolfssl_android_1 = require("./wolfssl_android");
const nss_android_1 = require("./nss_android");
const mbedTLS_android_1 = require("./mbedTLS_android");
const openssl_boringssl_android_1 = require("./openssl_boringssl_android");
const android_java_tls_libs_1 = require("./android_java_tls_libs");
var plattform_name = "linux";
var moduleNames = (0, shared_functions_1.getModuleNames)();
exports.socket_library = "libc";
function install_java_hooks() {
    (0, android_java_tls_libs_1.java_execute)();
}
function hook_Android_Dynamic_Loader(module_library_mapping) {
    try {
        const regex_libdl = /.*libdl.*\.so/;
        const libdl = moduleNames.find(element => element.match(regex_libdl));
        if (libdl === undefined) {
            throw "Android Dynamic loader not found!";
        }
        let dl_exports = Process.getModuleByName(libdl).enumerateExports();
        var dlopen = "dlopen";
        for (var ex of dl_exports) {
            if (ex.name === "android_dlopen_ext") {
                dlopen = "android_dlopen_ext";
                break;
            }
        }
        Interceptor.attach(Module.getExportByName(libdl, dlopen), {
            onEnter: function (args) {
                this.moduleName = args[0].readCString();
            },
            onLeave: function (retval) {
                if (this.moduleName != undefined) {
                    for (let map of module_library_mapping[plattform_name]) {
                        let regex = map[0];
                        let func = map[1];
                        if (regex.test(this.moduleName)) {
                            (0, log_1.log)(`${this.moduleName} was loaded & will be hooked on Android!`);
                            func(this.moduleName);
                        }
                    }
                }
            }
        });
        console.log(`[*] Android dynamic loader hooked.`);
    }
    catch (error) {
        (0, log_1.devlog)("Loader error: " + error);
        (0, log_1.log)("No dynamic loader present for hooking on Android.");
    }
}
function hook_native_Android_SSL_Libs(module_library_mapping) {
    (0, shared_functions_1.ssl_library_loader)(plattform_name, module_library_mapping, moduleNames, "Android");
}
function load_android_hooking_agent() {
    shared_structures_1.module_library_mapping[plattform_name] = [[/.*libssl_sb.so/, openssl_boringssl_android_1.boring_execute], [/.*libssl\.so/, openssl_boringssl_android_1.boring_execute], [/.*libgnutls\.so/, gnutls_android_1.gnutls_execute], [/.*libwolfssl\.so/, wolfssl_android_1.wolfssl_execute], [/.*libnspr[0-9]?\.so/, nss_android_1.nss_execute], [/libmbedtls\.so.*/, mbedTLS_android_1.mbedTLS_execute]];
    install_java_hooks();
    hook_native_Android_SSL_Libs(shared_structures_1.module_library_mapping);
    hook_Android_Dynamic_Loader(shared_structures_1.module_library_mapping);
}
exports.load_android_hooking_agent = load_android_hooking_agent;

},{"../shared/shared_functions":20,"../shared/shared_structures":21,"../util/log":29,"./android_java_tls_libs":2,"./gnutls_android":5,"./mbedTLS_android":6,"./nss_android":7,"./openssl_boringssl_android":8,"./wolfssl_android":9}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.java_execute = exports.SSL_Java_Android = void 0;
const log_1 = require("../util/log");
const bouncycastle_1 = require("./bouncycastle");
const java_ssl_libs_1 = require("../ssl_lib/java_ssl_libs");
class SSL_Java_Android extends java_ssl_libs_1.SSL_Java {
    install_java_android_hooks() {
        if (Java.available) {
            Java.perform(function () {
                // Bouncycastle/Spongycastle
                try {
                    //If we can load a class of spongycastle, we know its present and we have to hook it
                    var testLoad = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect");
                    (0, log_1.log)("Bouncycastle/Spongycastle detected.");
                    (0, bouncycastle_1.execute)();
                }
                catch (error) {
                    //On error, just do nothing
                }
            });
        }
    }
    execute_hooks() {
        this.install_java_android_hooks();
        this.install_java_hooks();
    }
}
exports.SSL_Java_Android = SSL_Java_Android;
function java_execute() {
    var java_ssl = new SSL_Java_Android();
    java_ssl.execute_hooks();
}
exports.java_execute = java_execute;

},{"../ssl_lib/java_ssl_libs":23,"../util/log":29,"./bouncycastle":3}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const log_1 = require("../util/log");
const shared_functions_1 = require("../shared/shared_functions");
function execute() {
    Java.perform(function () {
        //Hook the inner class "AppDataOutput/input" of ProvSSLSocketDirect, so we can access the 
        //socket information in its outer class by accessing this.this$0
        var appDataOutput = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect$AppDataOutput");
        appDataOutput.write.overload('[B', 'int', 'int').implementation = function (buf, offset, len) {
            var result = [];
            for (var i = 0; i < len; ++i) {
                result.push(buf[i] & 0xff);
            }
            var message = {};
            message["contentType"] = "datalog";
            message["src_port"] = this.this$0.value.getLocalPort();
            message["dst_port"] = this.this$0.value.getPort();
            var localAddress = this.this$0.value.getLocalAddress().getAddress();
            var inetAddress = this.this$0.value.getInetAddress().getAddress();
            if (localAddress.length == 4) {
                message["src_addr"] = (0, shared_functions_1.byteArrayToNumber)(localAddress);
                message["dst_addr"] = (0, shared_functions_1.byteArrayToNumber)(inetAddress);
                message["ss_family"] = "AF_INET";
            }
            else {
                message["src_addr"] = (0, shared_functions_1.byteArrayToString)(localAddress);
                message["dst_addr"] = (0, shared_functions_1.byteArrayToString)(inetAddress);
                message["ss_family"] = "AF_INET6";
            }
            message["ssl_session_id"] = (0, shared_functions_1.byteArrayToString)(this.this$0.value.getConnection().getSession().getId());
            //log(message["ssl_session_id"])
            message["function"] = "writeApplicationData";
            send(message, result);
            return this.write(buf, offset, len);
        };
        var appDataInput = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect$AppDataInput");
        appDataInput.read.overload('[B', 'int', 'int').implementation = function (buf, offset, len) {
            var bytesRead = this.read(buf, offset, len);
            var result = [];
            for (var i = 0; i < bytesRead; ++i) {
                result.push(buf[i] & 0xff);
            }
            var message = {};
            message["contentType"] = "datalog";
            message["ss_family"] = "AF_INET";
            message["src_port"] = this.this$0.value.getPort();
            message["dst_port"] = this.this$0.value.getLocalPort();
            var localAddress = this.this$0.value.getLocalAddress().getAddress();
            var inetAddress = this.this$0.value.getInetAddress().getAddress();
            if (localAddress.length == 4) {
                message["src_addr"] = (0, shared_functions_1.byteArrayToNumber)(inetAddress);
                message["dst_addr"] = (0, shared_functions_1.byteArrayToNumber)(localAddress);
                message["ss_family"] = "AF_INET";
            }
            else {
                message["src_addr"] = (0, shared_functions_1.byteArrayToString)(inetAddress);
                message["dst_addr"] = (0, shared_functions_1.byteArrayToString)(localAddress);
                message["ss_family"] = "AF_INET6";
            }
            message["ssl_session_id"] = (0, shared_functions_1.byteArrayToString)(this.this$0.value.getConnection().getSession().getId());
            (0, log_1.log)(message["ssl_session_id"]);
            message["function"] = "readApplicationData";
            send(message, result);
            return bytesRead;
        };
        //Hook the handshake to read the client random and the master key
        var ProvSSLSocketDirect = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect");
        ProvSSLSocketDirect.notifyHandshakeComplete.implementation = function (x) {
            var protocol = this.protocol.value;
            var securityParameters = protocol.securityParameters.value;
            var clientRandom = securityParameters.clientRandom.value;
            var masterSecretObj = (0, shared_functions_1.getAttribute)(securityParameters, "masterSecret");
            //The key is in the AbstractTlsSecret, so we need to access the superclass to get the field
            var clazz = Java.use("java.lang.Class");
            var masterSecretRawField = Java.cast(masterSecretObj.getClass(), clazz).getSuperclass().getDeclaredField("data");
            masterSecretRawField.setAccessible(true);
            var masterSecretReflectArray = masterSecretRawField.get(masterSecretObj);
            var message = {};
            message["contentType"] = "keylog";
            message["keylog"] = "CLIENT_RANDOM " + (0, shared_functions_1.byteArrayToString)(clientRandom) + " " + (0, shared_functions_1.reflectionByteArrayToString)(masterSecretReflectArray);
            send(message);
            return this.notifyHandshakeComplete(x);
        };
    });
}
exports.execute = execute;

},{"../shared/shared_functions":20,"../util/log":29}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const log_1 = require("../util/log");
function findProviderInstallerFromClassloaders(currentClassLoader, backupImplementation) {
    var providerInstallerImpl = null;
    var classLoaders = Java.enumerateClassLoadersSync();
    for (var cl of classLoaders) {
        try {
            var classFactory = Java.ClassFactory.get(cl);
            providerInstallerImpl = classFactory.use("com.google.android.gms.common.security.ProviderInstallerImpl");
            break;
        }
        catch (error) {
            // On error we return null
        }
    }
    //Revert the implementation to avoid an infinitloop of "Loadclass"
    currentClassLoader.loadClass.overload("java.lang.String").implementation = backupImplementation;
    return providerInstallerImpl;
}
function execute() {
    //We have to hook multiple entrypoints: ProviderInstallerImpl and ProviderInstaller
    Java.perform(function () {
        //Part one: Hook ProviderInstallerImpl
        var javaClassLoader = Java.use("java.lang.ClassLoader");
        var backupImplementation = javaClassLoader.loadClass.overload("java.lang.String").implementation;
        //The classloader for ProviderInstallerImpl might not be present on startup, so we hook the loadClass method.  
        javaClassLoader.loadClass.overload("java.lang.String").implementation = function (className) {
            let retval = this.loadClass(className);
            if (className.endsWith("ProviderInstallerImpl")) {
                (0, log_1.log)("Process is loading ProviderInstallerImpl");
                var providerInstallerImpl = findProviderInstallerFromClassloaders(javaClassLoader, backupImplementation);
                if (providerInstallerImpl === null) {
                    (0, log_1.log)("ProviderInstallerImpl could not be found, although it has been loaded");
                }
                else {
                    providerInstallerImpl.insertProvider.implementation = function () {
                        (0, log_1.log)("ProviderinstallerImpl redirection/blocking");
                    };
                }
            }
            return retval;
        };
        //Part two: Hook Providerinstaller
        try {
            var providerInstaller = Java.use("com.google.android.gms.security.ProviderInstaller");
            providerInstaller.installIfNeeded.implementation = function (context) {
                (0, log_1.log)("Providerinstaller redirection/blocking");
            };
            providerInstaller.installIfNeededAsync.implementation = function (context, callback) {
                (0, log_1.log)("Providerinstaller redirection/blocking");
                callback.onProviderInstalled();
            };
        }
        catch (error) {
            // As it is not available, do nothing
        }
    });
}
exports.execute = execute;

},{"../util/log":29}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.gnutls_execute = exports.GnuTLS_Linux = void 0;
const gnutls_1 = require("../ssl_lib/gnutls");
const android_agent_1 = require("./android_agent");
class GnuTLS_Linux extends gnutls_1.GnuTLS {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }
    install_tls_keys_callback_hook() {
        Interceptor.attach(this.addresses["gnutls_init"], {
            onEnter: function (args) {
                this.session = args[0];
            },
            onLeave: function (retval) {
                console.log(this.session);
                gnutls_1.GnuTLS.gnutls_session_set_keylog_function(this.session.readPointer(), gnutls_1.GnuTLS.keylog_callback);
            }
        });
    }
}
exports.GnuTLS_Linux = GnuTLS_Linux;
function gnutls_execute(moduleName) {
    var gnutls_ssl = new GnuTLS_Linux(moduleName, android_agent_1.socket_library);
    gnutls_ssl.execute_hooks();
}
exports.gnutls_execute = gnutls_execute;

},{"../ssl_lib/gnutls":22,"./android_agent":1}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mbedTLS_execute = exports.mbed_TLS_Android = void 0;
const mbedTLS_1 = require("../ssl_lib/mbedTLS");
const android_agent_1 = require("./android_agent");
class mbed_TLS_Android extends mbedTLS_1.mbed_TLS {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    /*
    SSL_CTX_set_keylog_callback not exported by default on windows.

    We need to find a way to install the callback function for doing that

    Alternatives?:SSL_export_keying_material, SSL_SESSION_get_master_key
    */
    install_tls_keys_callback_hook() {
        // install hooking for windows
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
    }
}
exports.mbed_TLS_Android = mbed_TLS_Android;
function mbedTLS_execute(moduleName) {
    var mbedTLS_ssl = new mbed_TLS_Android(moduleName, android_agent_1.socket_library);
    mbedTLS_ssl.execute_hooks();
}
exports.mbedTLS_execute = mbedTLS_execute;

},{"../ssl_lib/mbedTLS":24,"./android_agent":1}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nss_execute = exports.NSS_Android = void 0;
const nss_1 = require("../ssl_lib/nss");
const android_agent_1 = require("./android_agent");
class NSS_Android extends nss_1.NSS {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        var library_method_mapping = {};
        library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType"];
        library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"];
        library_method_mapping["*libssl*.so"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"];
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        super(moduleName, socket_library, library_method_mapping);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        //this.install_tls_keys_callback_hook() // might fail 
    }
}
exports.NSS_Android = NSS_Android;
function nss_execute(moduleName) {
    var nss_ssl = new NSS_Android(moduleName, android_agent_1.socket_library);
    nss_ssl.execute_hooks();
}
exports.nss_execute = nss_execute;

},{"../ssl_lib/nss":25,"./android_agent":1}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.boring_execute = exports.OpenSSL_BoringSSL_Android = void 0;
const openssl_boringssl_1 = require("../ssl_lib/openssl_boringssl");
const android_agent_1 = require("./android_agent");
class OpenSSL_BoringSSL_Android extends openssl_boringssl_1.OpenSSL_BoringSSL {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }
    install_tls_keys_callback_hook() {
        openssl_boringssl_1.OpenSSL_BoringSSL.SSL_CTX_set_keylog_callback = ObjC.available ? new NativeFunction(this.addresses["SSL_CTX_set_info_callback"], "void", ["pointer", "pointer"]) : new NativeFunction(this.addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        Interceptor.attach(this.addresses["SSL_new"], {
            onEnter: function (args) {
                openssl_boringssl_1.OpenSSL_BoringSSL.SSL_CTX_set_keylog_callback(args[0], openssl_boringssl_1.OpenSSL_BoringSSL.keylog_callback);
            }
        });
    }
}
exports.OpenSSL_BoringSSL_Android = OpenSSL_BoringSSL_Android;
function boring_execute(moduleName) {
    var boring_ssl = new OpenSSL_BoringSSL_Android(moduleName, android_agent_1.socket_library);
    boring_ssl.execute_hooks();
}
exports.boring_execute = boring_execute;

},{"../ssl_lib/openssl_boringssl":26,"./android_agent":1}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.wolfssl_execute = exports.WolfSSL_Android = void 0;
const wolfssl_1 = require("../ssl_lib/wolfssl");
const android_agent_1 = require("./android_agent");
const shared_functions_1 = require("../shared/shared_functions");
class WolfSSL_Android extends wolfssl_1.WolfSSL {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }
    install_tls_keys_callback_hook() {
        wolfssl_1.WolfSSL.wolfSSL_get_client_random = new NativeFunction(this.addresses["wolfSSL_get_client_random"], "int", ["pointer", "pointer", "int"]);
        wolfssl_1.WolfSSL.wolfSSL_get_server_random = new NativeFunction(this.addresses["wolfSSL_get_server_random"], "int", ["pointer", "pointer", "int"]);
        //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
        wolfssl_1.WolfSSL.wolfSSL_SESSION_get_master_key = new NativeFunction(this.addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"]);
        Interceptor.attach(this.addresses["wolfSSL_connect"], {
            onEnter: function (args) {
                this.ssl = args[0];
            },
            onLeave: function (retval) {
                this.session = wolfssl_1.WolfSSL.wolfSSL_get_session(this.ssl);
                var keysString = "";
                //https://www.wolfssl.com/doxygen/group__Setup.html#ga927e37dc840c228532efa0aa9bbec451
                var requiredClientRandomLength = wolfssl_1.WolfSSL.wolfSSL_get_client_random(this.session, NULL, 0);
                var clientBuffer = Memory.alloc(requiredClientRandomLength);
                wolfssl_1.WolfSSL.wolfSSL_get_client_random(this.ssl, clientBuffer, requiredClientRandomLength);
                var clientBytes = clientBuffer.readByteArray(requiredClientRandomLength);
                keysString = `${keysString}CLIENT_RANDOM: ${(0, shared_functions_1.toHexString)(clientBytes)}\n`;
                //https://www.wolfssl.com/doxygen/group__Setup.html#ga987035fc600ba9e3b02e2b2718a16a6c
                var requiredServerRandomLength = wolfssl_1.WolfSSL.wolfSSL_get_server_random(this.session, NULL, 0);
                var serverBuffer = Memory.alloc(requiredServerRandomLength);
                wolfssl_1.WolfSSL.wolfSSL_get_server_random(this.ssl, serverBuffer, requiredServerRandomLength);
                var serverBytes = serverBuffer.readByteArray(requiredServerRandomLength);
                keysString = `${keysString}SERVER_RANDOM: ${(0, shared_functions_1.toHexString)(serverBytes)}\n`;
                //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
                var requiredMasterKeyLength = wolfssl_1.WolfSSL.wolfSSL_SESSION_get_master_key(this.session, NULL, 0);
                var masterBuffer = Memory.alloc(requiredMasterKeyLength);
                wolfssl_1.WolfSSL.wolfSSL_SESSION_get_master_key(this.session, masterBuffer, requiredMasterKeyLength);
                var masterBytes = masterBuffer.readByteArray(requiredMasterKeyLength);
                keysString = `${keysString}MASTER_KEY: ${(0, shared_functions_1.toHexString)(masterBytes)}\n`;
                var message = {};
                message["contentType"] = "keylog";
                message["keylog"] = keysString;
                send(message);
            }
        });
    }
}
exports.WolfSSL_Android = WolfSSL_Android;
function wolfssl_execute(moduleName) {
    var wolf_ssl = new WolfSSL_Android(moduleName, android_agent_1.socket_library);
    wolf_ssl.execute_hooks();
}
exports.wolfssl_execute = wolfssl_execute;

},{"../shared/shared_functions":20,"../ssl_lib/wolfssl":27,"./android_agent":1}],10:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.load_ios_hooking_agent = exports.socket_library = void 0;
const shared_structures_1 = require("../shared/shared_structures");
const log_1 = require("../util/log");
const shared_functions_1 = require("../shared/shared_functions");
const openssl_boringssl_ios_1 = require("./openssl_boringssl_ios");
var plattform_name = "darwin";
var moduleNames = (0, shared_functions_1.getModuleNames)();
exports.socket_library = "libSystem.B.dylib";
function hook_iOS_Dynamic_Loader(module_library_mapping) {
    try {
        const regex_libdl = /libSystem.B.dylib/;
        const libdl = moduleNames.find(element => element.match(regex_libdl));
        if (libdl === undefined) {
            throw "Darwin Dynamic loader not found!";
        }
        var dlopen = "dlopen";
        Interceptor.attach(Module.getExportByName(libdl, dlopen), {
            onEnter: function (args) {
                this.moduleName = args[0].readCString();
            },
            onLeave: function (retval) {
                if (this.moduleName != undefined) {
                    for (let map of module_library_mapping[plattform_name]) {
                        let regex = map[0];
                        let func = map[1];
                        if (regex.test(this.moduleName)) {
                            (0, log_1.log)(`${this.moduleName} was loaded & will be hooked on iOS!`);
                            func(this.moduleName);
                        }
                    }
                }
            }
        });
        console.log(`[*] iOS dynamic loader hooked.`);
    }
    catch (error) {
        (0, log_1.devlog)("Loader error: " + error);
        (0, log_1.log)("No dynamic loader present for hooking on iOS.");
    }
}
function hook_iOS_SSL_Libs(module_library_mapping) {
    (0, shared_functions_1.ssl_library_loader)(plattform_name, module_library_mapping, moduleNames, "iOS");
}
function load_ios_hooking_agent() {
    shared_structures_1.module_library_mapping[plattform_name] = [[/.*libboringssl\.dylib/, openssl_boringssl_ios_1.boring_execute]];
    hook_iOS_SSL_Libs(shared_structures_1.module_library_mapping);
    hook_iOS_Dynamic_Loader(shared_structures_1.module_library_mapping);
}
exports.load_ios_hooking_agent = load_ios_hooking_agent;

},{"../shared/shared_functions":20,"../shared/shared_structures":21,"../util/log":29,"./openssl_boringssl_ios":11}],11:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.boring_execute = exports.OpenSSL_BoringSSL_iOS = void 0;
const openssl_boringssl_1 = require("../ssl_lib/openssl_boringssl");
const ios_agent_1 = require("./ios_agent");
const log_1 = require("../util/log");
class OpenSSL_BoringSSL_iOS extends openssl_boringssl_1.OpenSSL_BoringSSL {
    moduleName;
    socket_library;
    install_tls_keys_callback_hook() {
        //console.log(this.addresses) // currently only for debugging purposes will be removed in future releases
        if (ObjC.available) { // inspired from https://codeshare.frida.re/@andydavies/ios-tls-keylogger/
            var CALLBACK_OFFSET = 0x2A8;
            var foundationNumber = Module.findExportByName('CoreFoundation', 'kCFCoreFoundationVersionNumber')?.readDouble();
            if (foundationNumber == undefined) {
                (0, log_1.devlog)("Installing callback for iOS < 14");
                CALLBACK_OFFSET = 0x2A8;
            }
            else if (foundationNumber >= 1751.108) {
                (0, log_1.devlog)("Installing callback for iOS >= 14");
                CALLBACK_OFFSET = 0x2B8; // >= iOS 14.x 
            }
            Interceptor.attach(this.addresses["SSL_CTX_set_info_callback"], {
                onEnter: function (args) {
                    ptr(args[0]).add(CALLBACK_OFFSET).writePointer(openssl_boringssl_1.OpenSSL_BoringSSL.keylog_callback);
                }
            });
        }
    }
    constructor(moduleName, socket_library) {
        var library_method_mapping = {};
        // the iOS implementation needs some further improvements - currently we are not able to get the sockfd from an SSL_read/write invocation
        library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "BIO_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_info_callback"];
        library_method_mapping[`*${socket_library}*`] = ["getpeername*", "getsockname*", "ntohs*", "ntohl*"]; // currently those functions gets only identified if we at an asterisk at the end 
        super(moduleName, socket_library, library_method_mapping);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        /*
        currently these function hooks aren't implemented
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        */
        this.install_tls_keys_callback_hook();
    }
}
exports.OpenSSL_BoringSSL_iOS = OpenSSL_BoringSSL_iOS;
function boring_execute(moduleName) {
    var boring_ssl = new OpenSSL_BoringSSL_iOS(moduleName, ios_agent_1.socket_library);
    boring_ssl.execute_hooks();
}
exports.boring_execute = boring_execute;

},{"../ssl_lib/openssl_boringssl":26,"../util/log":29,"./ios_agent":10}],12:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.gnutls_execute = exports.GnuTLS_Linux = void 0;
const gnutls_1 = require("../ssl_lib/gnutls");
const linux_agent_1 = require("./linux_agent");
class GnuTLS_Linux extends gnutls_1.GnuTLS {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }
    install_tls_keys_callback_hook() {
        Interceptor.attach(this.addresses["gnutls_init"], {
            onEnter: function (args) {
                this.session = args[0];
            },
            onLeave: function (retval) {
                console.log(this.session);
                gnutls_1.GnuTLS.gnutls_session_set_keylog_function(this.session.readPointer(), gnutls_1.GnuTLS.keylog_callback);
            }
        });
    }
}
exports.GnuTLS_Linux = GnuTLS_Linux;
function gnutls_execute(moduleName) {
    var gnutls_ssl = new GnuTLS_Linux(moduleName, linux_agent_1.socket_library);
    gnutls_ssl.execute_hooks();
}
exports.gnutls_execute = gnutls_execute;

},{"../ssl_lib/gnutls":22,"./linux_agent":13}],13:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.load_linux_hooking_agent = exports.socket_library = void 0;
const shared_structures_1 = require("../shared/shared_structures");
const log_1 = require("../util/log");
const shared_functions_1 = require("../shared/shared_functions");
const gnutls_linux_1 = require("./gnutls_linux");
const wolfssl_linux_1 = require("./wolfssl_linux");
const nss_linux_1 = require("./nss_linux");
const mbedTLS_linux_1 = require("./mbedTLS_linux");
const openssl_boringssl_linux_1 = require("./openssl_boringssl_linux");
var plattform_name = "linux";
var moduleNames = (0, shared_functions_1.getModuleNames)();
exports.socket_library = "libc";
function hook_Linux_Dynamic_Loader(module_library_mapping) {
    try {
        const regex_libdl = /.*libdl.*\.so/;
        const libdl = moduleNames.find(element => element.match(regex_libdl));
        if (libdl === undefined) {
            throw "Linux Dynamic loader not found!";
        }
        var dlopen = "dlopen";
        Interceptor.attach(Module.getExportByName(libdl, dlopen), {
            onEnter: function (args) {
                this.moduleName = args[0].readCString();
            },
            onLeave: function (retval) {
                if (this.moduleName != undefined) {
                    for (let map of module_library_mapping[plattform_name]) {
                        let regex = map[0];
                        let func = map[1];
                        if (regex.test(this.moduleName)) {
                            (0, log_1.log)(`${this.moduleName} was loaded & will be hooked on Linux!`);
                            func(this.moduleName);
                        }
                    }
                }
            }
        });
        console.log(`[*] Linux dynamic loader hooked.`);
    }
    catch (error) {
        (0, log_1.devlog)("Loader error: " + error);
        (0, log_1.log)("No dynamic loader present for hooking.");
    }
}
function hook_Linux_SSL_Libs(module_library_mapping) {
    (0, shared_functions_1.ssl_library_loader)(plattform_name, module_library_mapping, moduleNames, "Linux");
}
function load_linux_hooking_agent() {
    shared_structures_1.module_library_mapping[plattform_name] = [[/.*libssl_sb.so/, openssl_boringssl_linux_1.boring_execute], [/.*libssl\.so/, openssl_boringssl_linux_1.boring_execute], [/.*libgnutls\.so/, gnutls_linux_1.gnutls_execute], [/.*libwolfssl\.so/, wolfssl_linux_1.wolfssl_execute], [/.*libnspr[0-9]?\.so/, nss_linux_1.nss_execute], [/libmbedtls\.so.*/, mbedTLS_linux_1.mbedTLS_execute]];
    hook_Linux_SSL_Libs(shared_structures_1.module_library_mapping);
    hook_Linux_Dynamic_Loader(shared_structures_1.module_library_mapping);
}
exports.load_linux_hooking_agent = load_linux_hooking_agent;

},{"../shared/shared_functions":20,"../shared/shared_structures":21,"../util/log":29,"./gnutls_linux":12,"./mbedTLS_linux":14,"./nss_linux":15,"./openssl_boringssl_linux":16,"./wolfssl_linux":17}],14:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mbedTLS_execute = exports.mbed_TLS_Linux = void 0;
const mbedTLS_1 = require("../ssl_lib/mbedTLS");
const linux_agent_1 = require("./linux_agent");
class mbed_TLS_Linux extends mbedTLS_1.mbed_TLS {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    /*
    SSL_CTX_set_keylog_callback not exported by default on windows.

    We need to find a way to install the callback function for doing that

    Alternatives?:SSL_export_keying_material, SSL_SESSION_get_master_key
    */
    install_tls_keys_callback_hook() {
        // install hooking for windows
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
    }
}
exports.mbed_TLS_Linux = mbed_TLS_Linux;
function mbedTLS_execute(moduleName) {
    var mbedTLS_ssl = new mbed_TLS_Linux(moduleName, linux_agent_1.socket_library);
    mbedTLS_ssl.execute_hooks();
}
exports.mbedTLS_execute = mbedTLS_execute;

},{"../ssl_lib/mbedTLS":24,"./linux_agent":13}],15:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nss_execute = exports.NSS_Linux = void 0;
const nss_1 = require("../ssl_lib/nss");
const linux_agent_1 = require("./linux_agent");
const log_1 = require("../util/log");
class NSS_Linux extends nss_1.NSS {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        var library_method_mapping = {};
        library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType"];
        library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"];
        library_method_mapping["*libssl*.so"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"];
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        super(moduleName, socket_library, library_method_mapping);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }
    install_tls_keys_callback_hook() {
        nss_1.NSS.getDescType = new NativeFunction(this.addresses['PR_GetDescType'], "int", ["pointer"]);
        // SSL Handshake Functions:
        nss_1.NSS.PR_GetNameForIdentity = new NativeFunction(this.addresses['PR_GetNameForIdentity'], "pointer", ["pointer"]);
        /*
                SECStatus SSL_HandshakeCallback(PRFileDesc *fd, SSLHandshakeCallback cb, void *client_data);
                more at https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/sslfnc#1112702
        */
        nss_1.NSS.get_SSL_Callback = new NativeFunction(this.addresses["SSL_HandshakeCallback"], "int", ["pointer", "pointer", "pointer"]);
        // SSL Key helper Functions 
        nss_1.NSS.PK11_ExtractKeyValue = new NativeFunction(this.addresses["PK11_ExtractKeyValue"], "int", ["pointer"]);
        nss_1.NSS.PK11_GetKeyData = new NativeFunction(this.addresses["PK11_GetKeyData"], "pointer", ["pointer"]);
        Interceptor.attach(this.addresses["SSL_ImportFD"], {
            onEnter(args) {
                this.fd = args[1];
            },
            onLeave(retval) {
                if (retval.isNull()) {
                    (0, log_1.devlog)("[-] SSL_ImportFD error: unknow null");
                    return;
                }
                var retValue = nss_1.NSS.get_SSL_Callback(retval, nss_1.NSS.keylog_callback, NULL);
                nss_1.NSS.register_secret_callback(retval);
                // typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;
                if (retValue < 0) {
                    (0, log_1.devlog)("Callback Error");
                    var getErrorText = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetErrorText'), "int", ["pointer"]);
                    var outbuffer = Memory.alloc(200); // max out size
                    console.log("typeof outbuffer: " + typeof outbuffer);
                    console.log("outbuffer: " + outbuffer); // should be a pointer
                    getErrorText(outbuffer.readPointer());
                    (0, log_1.devlog)("Error msg: " + outbuffer);
                }
                else {
                    (0, log_1.devlog)("[*] keylog callback successfull installed");
                }
            }
        });
        /*
            SECStatus SSL_HandshakeCallback(
                PRFileDesc *fd,
                SSLHandshakeCallback cb,
                void *client_data
            );
         */
        Interceptor.attach(this.addresses["SSL_HandshakeCallback"], {
            onEnter(args) {
                this.originalCallback = args[1];
                Interceptor.attach(ptr(this.originalCallback), {
                    onEnter(args) {
                        var sslSocketFD = args[0];
                        (0, log_1.devlog)("[*] keylog callback successfull installed via applications callback function");
                        nss_1.NSS.ssl_RecordKeyLog(sslSocketFD);
                    },
                    onLeave(retval) {
                    }
                });
            },
            onLeave(retval) {
            }
        });
    }
}
exports.NSS_Linux = NSS_Linux;
function nss_execute(moduleName) {
    var nss_ssl = new NSS_Linux(moduleName, linux_agent_1.socket_library);
    nss_ssl.execute_hooks();
}
exports.nss_execute = nss_execute;

},{"../ssl_lib/nss":25,"../util/log":29,"./linux_agent":13}],16:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.boring_execute = exports.OpenSSL_BoringSSL_Linux = void 0;
const openssl_boringssl_1 = require("../ssl_lib/openssl_boringssl");
const linux_agent_1 = require("./linux_agent");
class OpenSSL_BoringSSL_Linux extends openssl_boringssl_1.OpenSSL_BoringSSL {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }
    install_tls_keys_callback_hook() {
        openssl_boringssl_1.OpenSSL_BoringSSL.SSL_CTX_set_keylog_callback = ObjC.available ? new NativeFunction(this.addresses["SSL_CTX_set_info_callback"], "void", ["pointer", "pointer"]) : new NativeFunction(this.addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        Interceptor.attach(this.addresses["SSL_new"], {
            onEnter: function (args) {
                openssl_boringssl_1.OpenSSL_BoringSSL.SSL_CTX_set_keylog_callback(args[0], openssl_boringssl_1.OpenSSL_BoringSSL.keylog_callback);
            }
        });
    }
}
exports.OpenSSL_BoringSSL_Linux = OpenSSL_BoringSSL_Linux;
function boring_execute(moduleName) {
    var boring_ssl = new OpenSSL_BoringSSL_Linux(moduleName, linux_agent_1.socket_library);
    boring_ssl.execute_hooks();
}
exports.boring_execute = boring_execute;

},{"../ssl_lib/openssl_boringssl":26,"./linux_agent":13}],17:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.wolfssl_execute = exports.WolfSSL_Linux = void 0;
const wolfssl_1 = require("../ssl_lib/wolfssl");
const linux_agent_1 = require("./linux_agent");
const shared_functions_1 = require("../shared/shared_functions");
class WolfSSL_Linux extends wolfssl_1.WolfSSL {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }
    install_tls_keys_callback_hook() {
        wolfssl_1.WolfSSL.wolfSSL_get_client_random = new NativeFunction(this.addresses["wolfSSL_get_client_random"], "int", ["pointer", "pointer", "int"]);
        wolfssl_1.WolfSSL.wolfSSL_get_server_random = new NativeFunction(this.addresses["wolfSSL_get_server_random"], "int", ["pointer", "pointer", "int"]);
        //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
        wolfssl_1.WolfSSL.wolfSSL_SESSION_get_master_key = new NativeFunction(this.addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"]);
        Interceptor.attach(this.addresses["wolfSSL_connect"], {
            onEnter: function (args) {
                this.ssl = args[0];
            },
            onLeave: function (retval) {
                this.session = wolfssl_1.WolfSSL.wolfSSL_get_session(this.ssl);
                var keysString = "";
                //https://www.wolfssl.com/doxygen/group__Setup.html#ga927e37dc840c228532efa0aa9bbec451
                var requiredClientRandomLength = wolfssl_1.WolfSSL.wolfSSL_get_client_random(this.session, NULL, 0);
                var clientBuffer = Memory.alloc(requiredClientRandomLength);
                wolfssl_1.WolfSSL.wolfSSL_get_client_random(this.ssl, clientBuffer, requiredClientRandomLength);
                var clientBytes = clientBuffer.readByteArray(requiredClientRandomLength);
                keysString = `${keysString}CLIENT_RANDOM: ${(0, shared_functions_1.toHexString)(clientBytes)}\n`;
                //https://www.wolfssl.com/doxygen/group__Setup.html#ga987035fc600ba9e3b02e2b2718a16a6c
                var requiredServerRandomLength = wolfssl_1.WolfSSL.wolfSSL_get_server_random(this.session, NULL, 0);
                var serverBuffer = Memory.alloc(requiredServerRandomLength);
                wolfssl_1.WolfSSL.wolfSSL_get_server_random(this.ssl, serverBuffer, requiredServerRandomLength);
                var serverBytes = serverBuffer.readByteArray(requiredServerRandomLength);
                keysString = `${keysString}SERVER_RANDOM: ${(0, shared_functions_1.toHexString)(serverBytes)}\n`;
                //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
                var requiredMasterKeyLength = wolfssl_1.WolfSSL.wolfSSL_SESSION_get_master_key(this.session, NULL, 0);
                var masterBuffer = Memory.alloc(requiredMasterKeyLength);
                wolfssl_1.WolfSSL.wolfSSL_SESSION_get_master_key(this.session, masterBuffer, requiredMasterKeyLength);
                var masterBytes = masterBuffer.readByteArray(requiredMasterKeyLength);
                keysString = `${keysString}MASTER_KEY: ${(0, shared_functions_1.toHexString)(masterBytes)}\n`;
                var message = {};
                message["contentType"] = "keylog";
                message["keylog"] = keysString;
                send(message);
            }
        });
    }
}
exports.WolfSSL_Linux = WolfSSL_Linux;
function wolfssl_execute(moduleName) {
    var wolf_ssl = new WolfSSL_Linux(moduleName, linux_agent_1.socket_library);
    wolf_ssl.execute_hooks();
}
exports.wolfssl_execute = wolfssl_execute;

},{"../shared/shared_functions":20,"../ssl_lib/wolfssl":27,"./linux_agent":13}],18:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.load_macos_hooking_agent = exports.socket_library = void 0;
const shared_structures_1 = require("../shared/shared_structures");
const log_1 = require("../util/log");
const shared_functions_1 = require("../shared/shared_functions");
const openssl_boringssl_macos_1 = require("./openssl_boringssl_macos");
var plattform_name = "darwin";
var moduleNames = (0, shared_functions_1.getModuleNames)();
exports.socket_library = "libSystem.B.dylib";
function hook_macOS_Dynamic_Loader(module_library_mapping) {
    try {
        const regex_libdl = /libSystem.B.dylib/;
        const libdl = moduleNames.find(element => element.match(regex_libdl));
        if (libdl === undefined) {
            throw "Darwin Dynamic loader not found!";
        }
        var dlopen = "dlopen";
        Interceptor.attach(Module.getExportByName("libSystem.B.dylib", dlopen), {
            onEnter: function (args) {
                this.moduleName = args[0].readCString();
            },
            onLeave: function (retval) {
                if (this.moduleName != undefined) {
                    for (let map of module_library_mapping[plattform_name]) {
                        let regex = map[0];
                        let func = map[1];
                        if (regex.test(this.moduleName)) {
                            (0, log_1.log)(`${this.moduleName} was loaded & will be hooked on MacOS!`);
                            func(this.moduleName);
                        }
                    }
                }
            }
        });
        (0, log_1.log)("MacOS dynamic loader hooked.");
    }
    catch (error) {
        (0, log_1.devlog)("Loader error: " + error);
        (0, log_1.log)("No dynamic loader present for hooking on MacOS.");
    }
}
function hook_macOS_SSL_Libs(module_library_mapping) {
    (0, shared_functions_1.ssl_library_loader)(plattform_name, module_library_mapping, moduleNames, "MacOS");
}
function load_macos_hooking_agent() {
    shared_structures_1.module_library_mapping[plattform_name] = [[/.*libboringssl\.dylib/, openssl_boringssl_macos_1.boring_execute]];
    hook_macOS_SSL_Libs(shared_structures_1.module_library_mapping); // actually we are using the same implementation as we did on iOS, therefore this needs addtional testing
    hook_macOS_Dynamic_Loader(shared_structures_1.module_library_mapping);
}
exports.load_macos_hooking_agent = load_macos_hooking_agent;

},{"../shared/shared_functions":20,"../shared/shared_structures":21,"../util/log":29,"./openssl_boringssl_macos":19}],19:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.boring_execute = exports.OpenSSL_BoringSSL_MacOS = void 0;
const openssl_boringssl_1 = require("../ssl_lib/openssl_boringssl");
const macos_agent_1 = require("./macos_agent");
class OpenSSL_BoringSSL_MacOS extends openssl_boringssl_1.OpenSSL_BoringSSL {
    moduleName;
    socket_library;
    install_tls_keys_callback_hook() {
        console.log(this.addresses); // currently only for debugging purposes will be removed in future releases
        if (ObjC.available) { // inspired from https://codeshare.frida.re/@andydavies/ios-tls-keylogger/
            var CALLBACK_OFFSET = 0x2A8;
            var foundationNumber = Module.findExportByName('CoreFoundation', 'kCFCoreFoundationVersionNumber')?.readDouble();
            if (foundationNumber == undefined) {
                CALLBACK_OFFSET = 0x2A8;
            }
            else if (foundationNumber >= 1751.108) {
                CALLBACK_OFFSET = 0x2B8; // >= iOS 14.x 
            }
            Interceptor.attach(this.addresses["SSL_CTX_set_info_callback"], {
                onEnter: function (args) {
                    ptr(args[0]).add(CALLBACK_OFFSET).writePointer(this.keylog_callback);
                }
            });
        }
    }
    constructor(moduleName, socket_library) {
        var library_method_mapping = {};
        // the iOS implementation needs some further improvements - currently we are not able to get the sockfd from an SSL_read/write invocation
        library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "BIO_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_info_callback"];
        library_method_mapping[`*${socket_library}*`] = ["getpeername*", "getsockname*", "ntohs*", "ntohl*"]; // currently those functions gets only identified if we at an asterisk at the end 
        super(moduleName, socket_library, library_method_mapping);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        /*
        currently these function hooks aren't implemented
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        */
        this.install_tls_keys_callback_hook();
    }
}
exports.OpenSSL_BoringSSL_MacOS = OpenSSL_BoringSSL_MacOS;
function boring_execute(moduleName) {
    var boring_ssl = new OpenSSL_BoringSSL_MacOS(moduleName, macos_agent_1.socket_library);
    boring_ssl.execute_hooks();
}
exports.boring_execute = boring_execute;

},{"../ssl_lib/openssl_boringssl":26,"./macos_agent":18}],20:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAttribute = exports.byteArrayToNumber = exports.reflectionByteArrayToString = exports.toHexString = exports.byteArrayToString = exports.getPortsAndAddresses = exports.getBaseAddress = exports.readAddresses = exports.getModuleNames = exports.getSocketLibrary = exports.ssl_library_loader = void 0;
const log_1 = require("../util/log");
const shared_structures_1 = require("./shared_structures");
function wait_for_library_loaded(module_name) {
    let timeout_library = 5;
    let module_adress = Module.findBaseAddress(module_name);
    if (module_adress === NULL || module_adress === null) {
        (0, log_1.log)("[*] Waiting " + timeout_library + " milliseconds for the loading of " + module_name);
        setTimeout(wait_for_library_loaded, timeout_library);
    }
}
/**
 * This file contains methods which are shared for reading
 * secrets/data from different libraries. These methods are
 * indipendent from the implementation of ssl/tls, but they depend
 * on libc.
 */
function ssl_library_loader(plattform_name, module_library_mapping, moduleNames, plattform_os) {
    for (let map of module_library_mapping[plattform_name]) {
        let regex = map[0];
        let func = map[1];
        for (let module of moduleNames) {
            if (regex.test(module)) {
                try {
                    (0, log_1.log)(`${module} found & will be hooked on ${plattform_os}!`);
                    try {
                        Module.ensureInitialized(module);
                    }
                    catch (error) {
                        wait_for_library_loaded(module);
                    }
                    func(module); // on some Android Apps we encounterd the problem of multiple SSL libraries but only one is used for the SSL encryption/decryption
                }
                catch (error) {
                    (0, log_1.log)(`error: skipping module ${module}`);
                    // when we enable the logging of devlogs we can print the error message as well for further improving this part
                    (0, log_1.devlog)("Loader error: " + error);
                    //  {'description': 'Could not find *libssl*.so!SSL_ImportFD', 'type': 'error'}
                }
            }
        }
    }
}
exports.ssl_library_loader = ssl_library_loader;
//TODO: 
function getSocketLibrary() {
    var moduleNames = getModuleNames();
    var socket_library_name = "";
    switch (Process.platform) {
        case "linux":
            return moduleNames.find(element => element.match(/libc.*\.so/));
        case "windows":
            return "WS2_32.dll";
        case "darwin":
            return "libSystem.B.dylib";
        default:
            (0, log_1.log)(`Platform "${Process.platform} currently not supported!`);
            return "";
    }
}
exports.getSocketLibrary = getSocketLibrary;
function getModuleNames() {
    var moduleNames = [];
    Process.enumerateModules().forEach(item => moduleNames.push(item.name));
    return moduleNames;
}
exports.getModuleNames = getModuleNames;
/**
 * Read the addresses for the given methods from the given modules
 * @param {{[key: string]: Array<String> }} library_method_mapping A string indexed list of arrays, mapping modules to methods
 * @return {{[key: string]: NativePointer }} A string indexed list of NativePointers, which point to the respective methods
 */
function readAddresses(library_method_mapping) {
    var resolver = new ApiResolver("module");
    var addresses = {};
    for (let library_name in library_method_mapping) {
        library_method_mapping[library_name].forEach(function (method) {
            var matches = resolver.enumerateMatches("exports:" + library_name + "!" + method);
            var match_number = 0;
            var method_name = method.toString();
            if (method_name.endsWith("*")) { // this is for the temporary iOS bug using fridas ApiResolver
                method_name = method_name.substring(0, method_name.length - 1);
            }
            if (matches.length == 0) {
                throw "Could not find " + library_name + "!" + method;
            }
            else if (matches.length == 1) {
                (0, log_1.devlog)("Found " + method + " " + matches[0].address);
            }
            else {
                // Sometimes Frida returns duplicates or it finds more than one result.
                for (var k = 0; k < matches.length; k++) {
                    if (matches[k].name.endsWith(method_name)) {
                        match_number = k;
                        (0, log_1.devlog)("Found " + method + " " + matches[match_number].address);
                        break;
                    }
                }
            }
            addresses[method_name] = matches[match_number].address;
        });
    }
    return addresses;
}
exports.readAddresses = readAddresses;
/**
 * Returns the base address of a given module
 * @param {string} moduleName Name of module to return base address from
 * @returns
 */
function getBaseAddress(moduleName) {
    console.log("Module to find:", moduleName);
    const modules = Process.enumerateModules();
    for (const module of modules) {
        if (module.name == moduleName) {
            return module.base;
        }
    }
    return null;
}
exports.getBaseAddress = getBaseAddress;
/**
* Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
* "dst_port".
* @param {int} sockfd The file descriptor of the socket to inspect.
* @param {boolean} isRead If true, the context is an SSL_read call. If
*     false, the context is an SSL_write call.
* @param {{ [key: string]: NativePointer}} methodAddresses Dictionary containing (at least) addresses for getpeername, getsockname, ntohs and ntohl
* @return {{ [key: string]: string | number }} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
*     and "dst_port".
*/
function getPortsAndAddresses(sockfd, isRead, methodAddresses) {
    var getpeername = new NativeFunction(methodAddresses["getpeername"], "int", ["int", "pointer", "pointer"]);
    var getsockname = new NativeFunction(methodAddresses["getsockname"], "int", ["int", "pointer", "pointer"]);
    var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"]);
    var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"]);
    var message = {};
    var addrlen = Memory.alloc(4);
    var addr = Memory.alloc(128);
    var src_dst = ["src", "dst"];
    for (var i = 0; i < src_dst.length; i++) {
        addrlen.writeU32(128);
        if ((src_dst[i] == "src") !== isRead) {
            (0, log_1.devlog)("src");
            getsockname(sockfd, addr, addrlen);
        }
        else {
            (0, log_1.devlog)("dst");
            getpeername(sockfd, addr, addrlen);
        }
        if (addr.readU16() == shared_structures_1.AF_INET) {
            message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
            message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32());
            message["ss_family"] = "AF_INET";
        }
        else if (addr.readU16() == shared_structures_1.AF_INET6) {
            message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
            message[src_dst[i] + "_addr"] = "";
            var ipv6_addr = addr.add(8);
            for (var offset = 0; offset < 16; offset += 1) {
                message[src_dst[i] + "_addr"] += ("0" + ipv6_addr.add(offset).readU8().toString(16).toUpperCase()).substr(-2);
            }
            if (message[src_dst[i] + "_addr"].toString().indexOf("00000000000000000000FFFF") === 0) {
                message[src_dst[i] + "_addr"] = ntohl(ipv6_addr.add(12).readU32());
                message["ss_family"] = "AF_INET";
            }
            else {
                message["ss_family"] = "AF_INET6";
            }
        }
        else {
            (0, log_1.devlog)("[-] getPortsAndAddresses resolving error:" + addr.readU16());
            throw "Only supporting IPv4/6";
        }
    }
    return message;
}
exports.getPortsAndAddresses = getPortsAndAddresses;
/**
 * Convert a Java byte array to string
 * @param byteArray The array to convert
 * @returns {string} The resulting string
 */
function byteArrayToString(byteArray) {
    return Array.from(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}
exports.byteArrayToString = byteArrayToString;
function toHexString(byteArray) {
    const byteToHex = [];
    for (let n = 0; n <= 0xff; ++n) {
        const hexOctet = n.toString(16).padStart(2, "0");
        byteToHex.push(hexOctet);
    }
    return Array.prototype.map.call(new Uint8Array(byteArray), n => byteToHex[n]).join("");
}
exports.toHexString = toHexString;
/**
 * Convert a Java Reflection array to string
 * @param byteArray The array to convert
 * @returns {string} The resulting string
 */
function reflectionByteArrayToString(byteArray) {
    var result = "";
    var arrayReflect = Java.use("java.lang.reflect.Array");
    for (var i = 0; i < arrayReflect.getLength(byteArray); i++) {
        result += ('0' + (arrayReflect.get(byteArray, i) & 0xFF).toString(16)).slice(-2);
    }
    return result;
}
exports.reflectionByteArrayToString = reflectionByteArrayToString;
/**
 * Convert a Java byte arry to number (Big Endian)
 * @param byteArray The array to convert
 * @returns {number} The resulting number
 */
function byteArrayToNumber(byteArray) {
    var value = 0;
    for (var i = 0; i < byteArray.length; i++) {
        value = (value * 256) + (byteArray[i] & 0xFF);
    }
    return value;
}
exports.byteArrayToNumber = byteArrayToNumber;
/**
 * Access an attribute of a Java Class
 * @param Instance The instace you want to access
 * @param fieldName The name of the attribute
 * @returns The value of the attribute of the requested field
 */
function getAttribute(Instance, fieldName) {
    var clazz = Java.use("java.lang.Class");
    var field = Java.cast(Instance.getClass(), clazz).getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.get(Instance);
}
exports.getAttribute = getAttribute;

},{"../util/log":29,"./shared_structures":21}],21:[function(require,module,exports){
"use strict";
/* In this file we store global variables and structures */
Object.defineProperty(exports, "__esModule", { value: true });
exports.pointerSize = exports.AF_INET6 = exports.AF_INET = exports.module_library_mapping = void 0;
exports.module_library_mapping = {};
exports.AF_INET = 2;
exports.AF_INET6 = 10;
exports.pointerSize = Process.pointerSize;

},{}],22:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GnuTLS = void 0;
const shared_functions_1 = require("../shared/shared_functions");
const log_1 = require("../util/log");
const ssl_log_1 = require("../ssl_log");
class GnuTLS {
    moduleName;
    socket_library;
    passed_library_method_mapping;
    // global variables
    library_method_mapping = {};
    addresses;
    static gnutls_transport_get_int;
    static gnutls_session_get_id;
    static gnutls_session_get_random;
    static gnutls_session_set_keylog_function;
    constructor(moduleName, socket_library, passed_library_method_mapping) {
        this.moduleName = moduleName;
        this.socket_library = socket_library;
        this.passed_library_method_mapping = passed_library_method_mapping;
        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        }
        else {
            this.library_method_mapping[`*${moduleName}*`] = ["gnutls_record_recv", "gnutls_record_send", "gnutls_session_set_keylog_function", "gnutls_transport_get_int", "gnutls_session_get_id", "gnutls_init", "gnutls_handshake", "gnutls_session_get_keylog_function", "gnutls_session_get_random"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        }
        this.addresses = (0, shared_functions_1.readAddresses)(this.library_method_mapping);
        // @ts-ignore
        if (ssl_log_1.offsets != "{OFFSETS}" && ssl_log_1.offsets.gnutls != null) {
            if (ssl_log_1.offsets.sockets != null) {
                const socketBaseAddress = (0, shared_functions_1.getBaseAddress)(socket_library);
                for (const method of Object.keys(ssl_log_1.offsets.sockets)) {
                    //@ts-ignore
                    this.addresses[`${method}`] = ssl_log_1.offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(ssl_log_1.offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(ssl_log_1.offsets.sockets[`${method}`].address));
                }
            }
            const libraryBaseAddress = (0, shared_functions_1.getBaseAddress)(moduleName);
            if (libraryBaseAddress == null) {
                (0, log_1.log)("Unable to find library base address! Given address values will be interpreted as absolute ones!");
            }
            for (const method of Object.keys(ssl_log_1.offsets.gnutls)) {
                //@ts-ignore
                this.addresses[`${method}`] = ssl_log_1.offsets.gnutls[`${method}`].absolute || libraryBaseAddress == null ? ptr(ssl_log_1.offsets.gnutls[`${method}`].address) : libraryBaseAddress.add(ptr(ssl_log_1.offsets.gnutls[`${method}`].address));
            }
        }
        GnuTLS.gnutls_transport_get_int = new NativeFunction(this.addresses["gnutls_transport_get_int"], "int", ["pointer"]);
        GnuTLS.gnutls_session_get_id = new NativeFunction(this.addresses["gnutls_session_get_id"], "int", ["pointer", "pointer", "pointer"]);
        GnuTLS.gnutls_session_set_keylog_function = new NativeFunction(this.addresses["gnutls_session_set_keylog_function"], "void", ["pointer", "pointer"]);
        GnuTLS.gnutls_session_get_random = new NativeFunction(this.addresses["gnutls_session_get_random"], "pointer", ["pointer", "pointer", "pointer"]);
    }
    //NativeCallback
    static keylog_callback = new NativeCallback(function (session, label, secret) {
        var message = {};
        message["contentType"] = "keylog";
        var secret_len = secret.add(Process.pointerSize).readUInt();
        var secret_str = "";
        var p = secret.readPointer();
        for (var i = 0; i < secret_len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to secret_str.
            secret_str +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        var server_random_ptr = Memory.alloc(Process.pointerSize + 4);
        var client_random_ptr = Memory.alloc(Process.pointerSize + 4);
        if (typeof this !== "undefined") {
            GnuTLS.gnutls_session_get_random(session, client_random_ptr, server_random_ptr);
        }
        else {
            console.log("[-] Error while installing keylog callback");
        }
        var client_random_str = "";
        var client_random_len = 32;
        p = client_random_ptr.readPointer();
        for (i = 0; i < client_random_len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to client_random_str.
            client_random_str +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        message["keylog"] = label.readCString() + " " + client_random_str + " " + secret_str;
        send(message);
        return 0;
    }, "int", ["pointer", "pointer", "pointer"]);
    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    static getSslSessionId(session) {
        var len_pointer = Memory.alloc(4);
        var err = GnuTLS.gnutls_session_get_id(session, NULL, len_pointer);
        if (err != 0) {
            return "";
        }
        var len = len_pointer.readU32();
        var p = Memory.alloc(len);
        err = GnuTLS.gnutls_session_get_id(session, p, len_pointer);
        if (err != 0) {
            return "";
        }
        var session_id = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
    }
    install_plaintext_read_hook() {
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["gnutls_record_recv"], {
            onEnter: function (args) {
                var message = (0, shared_functions_1.getPortsAndAddresses)(GnuTLS.gnutls_transport_get_int(args[0]), true, lib_addesses);
                message["ssl_session_id"] = GnuTLS.getSslSessionId(args[0]);
                message["function"] = "SSL_read";
                this.message = message;
                this.buf = args[1];
            },
            onLeave: function (retval) {
                retval |= 0; // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return;
                }
                this.message["contentType"] = "datalog";
                send(this.message, this.buf.readByteArray(retval));
            }
        });
    }
    install_plaintext_write_hook() {
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["gnutls_record_send"], {
            onEnter: function (args) {
                var message = (0, shared_functions_1.getPortsAndAddresses)(GnuTLS.gnutls_transport_get_int(args[0]), false, lib_addesses);
                message["ssl_session_id"] = GnuTLS.getSslSessionId(args[0]);
                message["function"] = "SSL_write";
                message["contentType"] = "datalog";
                send(message, args[1].readByteArray(parseInt(args[2])));
            },
            onLeave: function (retval) {
            }
        });
    }
    install_tls_keys_callback_hook() {
    }
}
exports.GnuTLS = GnuTLS;

},{"../shared/shared_functions":20,"../ssl_log":28,"../util/log":29}],23:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SSL_Java = void 0;
const log_1 = require("../util/log");
const conscrypt_1 = require("../android/conscrypt");
const process_infos_1 = require("../util/process_infos");
class SSL_Java {
    install_java_hooks() {
        if (Java.available) {
            Java.perform(function () {
                //Conscrypt needs early instrumentation as we block the provider installation
                var Security = Java.use("java.security.Security");
                if (Security.getProviders().toString().includes("GmsCore_OpenSSL")) {
                    (0, log_1.log)("WARNING: PID " + Process.id + " Detected GmsCore_OpenSSL Provider. This can be a bit unstable. If you having issues, rerun with -spawn for early instrumentation. Trying to remove it to fall back on default Provider");
                    Security.removeProvider("GmsCore_OpenSSL");
                    (0, log_1.log)("Removed GmsCore_OpenSSL");
                }
                //As the classloader responsible for loading ProviderInstaller sometimes is not present from the beginning on,
                //we always have to watch the classloader activity
                (0, conscrypt_1.execute)();
                //Now do the same for Ssl_guard
                if (Security.getProviders().toString().includes("Ssl_Guard")) {
                    (0, log_1.log)("Ssl_Guard deteced, removing it to fall back on default Provider");
                    Security.removeProvider("Ssl_Guard");
                    (0, log_1.log)("Removed Ssl_Guard");
                }
                //Same thing for Conscrypt provider which has been manually inserted (not by providerinstaller)
                if (Security.getProviders().toString().includes("Conscrypt version")) {
                    (0, log_1.log)("Conscrypt detected");
                    Security.removeProvider("Conscrypt");
                    (0, log_1.log)("Removed Conscrypt");
                }
                //Uncomment this line to show all remaining providers
                //log("Remaining: " + Security.getProviders().toString())
                //Hook insertProviderAt/addprovider for dynamic provider blocking
                Security.insertProviderAt.implementation = function (provider, position) {
                    if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                        (0, log_1.log)("Blocking provider registration of " + provider.getName());
                        return position;
                    }
                    else {
                        return this.insertProviderAt(provider, position);
                    }
                };
                //Same for addProvider
                Security.insertProviderAt.implementation = function (provider) {
                    if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                        (0, log_1.log)("Blocking provider registration of " + provider.getName());
                        return 1;
                    }
                    else {
                        if ((0, process_infos_1.isAndroid)()) {
                            /*
                            When a NetworkProvider will be installed it is only allow at position 1
                            s. https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/security/net/config/NetworkSecurityConfigProvider.java
                            */
                            if (provider.getName() === "AndroidNSSP") {
                                return this.insertProviderAt(provider, 1);
                            }
                            // when the "Failed to install provider as highest priority provider. Provider was installed at position"-error is prompted on logcat please uncomment the following line, recompile the typescript and reopen the following
                            // https://github.com/fkie-cad/friTap/issues/1
                            // var android_Version = Java.androidVersion
                            // devlog("highest priority provider error with: "+provider.getName())
                        }
                        return this.addProvider(provider);
                    }
                };
            });
        }
    }
}
exports.SSL_Java = SSL_Java;

},{"../android/conscrypt":4,"../util/log":29,"../util/process_infos":30}],24:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mbed_TLS = void 0;
const shared_functions_1 = require("../shared/shared_functions");
const ssl_log_1 = require("../ssl_log");
const log_1 = require("../util/log");
class mbed_TLS {
    moduleName;
    socket_library;
    passed_library_method_mapping;
    // global variables
    library_method_mapping = {};
    addresses;
    constructor(moduleName, socket_library, passed_library_method_mapping) {
        this.moduleName = moduleName;
        this.socket_library = socket_library;
        this.passed_library_method_mapping = passed_library_method_mapping;
        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        }
        else {
            this.library_method_mapping[`*${moduleName}*`] = ["mbedtls_ssl_read", "mbedtls_ssl_write"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        }
        this.addresses = (0, shared_functions_1.readAddresses)(this.library_method_mapping);
        // @ts-ignore
        if (ssl_log_1.offsets != "{OFFSETS}" && ssl_log_1.offsets.mbedtls != null) {
            if (ssl_log_1.offsets.sockets != null) {
                const socketBaseAddress = (0, shared_functions_1.getBaseAddress)(socket_library);
                for (const method of Object.keys(ssl_log_1.offsets.sockets)) {
                    //@ts-ignore
                    this.addresses[`${method}`] = ssl_log_1.offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(ssl_log_1.offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(ssl_log_1.offsets.sockets[`${method}`].address));
                }
            }
            const libraryBaseAddress = (0, shared_functions_1.getBaseAddress)(moduleName);
            if (libraryBaseAddress == null) {
                (0, log_1.log)("Unable to find library base address! Given address values will be interpreted as absolute ones!");
            }
            for (const method of Object.keys(ssl_log_1.offsets.mbedtls)) {
                //@ts-ignore
                this.addresses[`${method}`] = ssl_log_1.offsets.mbedtls[`${method}`].absolute || libraryBaseAddress == null ? ptr(ssl_log_1.offsets.mbedtls[`${method}`].address) : libraryBaseAddress.add(ptr(ssl_log_1.offsets.mbedtls[`${method}`].address));
            }
        }
    }
    static parse_mbedtls_ssl_context_struct(sslcontext) {
        return {
            conf: sslcontext.readPointer(),
            state: sslcontext.add(Process.pointerSize).readS32(),
            renego_status: sslcontext.add(Process.pointerSize + 4).readS32(),
            renego_records_seen: sslcontext.add(Process.pointerSize + 4 + 4).readS32(),
            major_ver: sslcontext.add(Process.pointerSize + 4 + 4 + 4).readS32(),
            minor_ver: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4).readS32(),
            badmac_seen: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4).readU32(),
            f_send: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4).readPointer(),
            f_recv: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + Process.pointerSize).readPointer(),
            f_recv_timeout: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 2 * Process.pointerSize).readPointer(),
            p_bio: sslcontext.add(Process.platform == 'windows' ? 48 : 56).readPointer(),
            session_in: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 4 * Process.pointerSize).readPointer(),
            session_out: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 5 * Process.pointerSize).readPointer(),
            session: {
                start: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().readPointer(),
                ciphersuite: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8).readS32(),
                compression: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4).readS32(),
                id_len: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4).readU32(),
                id: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4 + 4).readByteArray(sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4).readU32())
            }
        };
    }
    static getSocketDescriptor(sslcontext) {
        var ssl_context = mbed_TLS.parse_mbedtls_ssl_context_struct(sslcontext);
        return ssl_context.p_bio.readS32();
    }
    static getSessionId(sslcontext) {
        var ssl_context = mbed_TLS.parse_mbedtls_ssl_context_struct(sslcontext);
        var session_id = '';
        for (var byteCounter = 0; byteCounter < ssl_context.session.id_len; byteCounter++) {
            session_id = `${session_id}${ssl_context.session.id?.unwrap().add(byteCounter).readU8().toString(16).toUpperCase()}`;
        }
        return session_id;
    }
    install_plaintext_read_hook() {
        var lib_addesses = this.addresses;
        //https://tls.mbed.org/api/ssl_8h.html#aa2c29eeb1deaf5ad9f01a7515006ede5
        Interceptor.attach(this.addresses["mbedtls_ssl_read"], {
            onEnter: function (args) {
                this.buffer = args[1];
                this.len = args[2];
                this.sslContext = args[0];
                var message = (0, shared_functions_1.getPortsAndAddresses)(mbed_TLS.getSocketDescriptor(args[0]), true, lib_addesses);
                message["ssl_session_id"] = mbed_TLS.getSessionId(args[0]);
                message["function"] = "mbedtls_ssl_read";
                this.message = message;
            },
            onLeave: function (retval) {
                retval |= 0; // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return;
                }
                var data = this.buffer.readByteArray(retval);
                this.message["contentType"] = "datalog";
                send(this.message, data);
            }
        });
    }
    install_plaintext_write_hook() {
        var lib_addesses = this.addresses;
        //https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
        Interceptor.attach(this.addresses["mbedtls_ssl_write"], {
            onEnter: function (args) {
                var buffer = args[1];
                var len = args[2];
                len |= 0; // Cast retval to 32-bit integer.
                if (len <= 0) {
                    return;
                }
                var data = buffer.readByteArray(len);
                var message = (0, shared_functions_1.getPortsAndAddresses)(mbed_TLS.getSocketDescriptor(args[0]), false, lib_addesses);
                message["ssl_session_id"] = mbed_TLS.getSessionId(args[0]);
                message["function"] = "mbedtls_ssl_write";
                message["contentType"] = "datalog";
                send(message, data);
            }
        });
    }
    install_tls_keys_callback_hook() {
        // TBD
    }
}
exports.mbed_TLS = mbed_TLS;

},{"../shared/shared_functions":20,"../ssl_log":28,"../util/log":29}],25:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NSS = exports.PRDescType = exports.SECStatus = void 0;
const shared_functions_1 = require("../shared/shared_functions");
const shared_structures_1 = require("../shared/shared_structures");
const log_1 = require("../util/log");
const ssl_log_1 = require("../ssl_log");
const { readU32, readU64, readPointer, writeU32, writeU64, writePointer } = NativePointer.prototype;
// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/ssltyp#1026722
var SECStatus;
(function (SECStatus) {
    SECStatus[SECStatus["SECWouldBlock"] = -2] = "SECWouldBlock";
    SECStatus[SECStatus["SECFailure"] = -1] = "SECFailure";
    SECStatus[SECStatus["SECSuccess"] = 0] = "SECSuccess";
})(SECStatus = exports.SECStatus || (exports.SECStatus = {}));
;
var PRDescType;
(function (PRDescType) {
    PRDescType[PRDescType["PR_DESC_FILE"] = 1] = "PR_DESC_FILE";
    PRDescType[PRDescType["PR_DESC_SOCKET_TCP"] = 2] = "PR_DESC_SOCKET_TCP";
    PRDescType[PRDescType["PR_DESC_SOCKET_UDP"] = 3] = "PR_DESC_SOCKET_UDP";
    PRDescType[PRDescType["PR_DESC_LAYERED"] = 4] = "PR_DESC_LAYERED";
    PRDescType[PRDescType["PR_DESC_PIPE"] = 5] = "PR_DESC_PIPE";
})(PRDescType = exports.PRDescType || (exports.PRDescType = {}));
PRDescType;
class NSS {
    moduleName;
    socket_library;
    passed_library_method_mapping;
    // global definitions
    static doTLS13_RTT0 = -1;
    static SSL3_RANDOM_LENGTH = 32;
    // global variables
    library_method_mapping = {};
    addresses;
    static SSL_SESSION_get_id;
    static getsockname;
    static getpeername;
    static getDescType;
    static PR_GetNameForIdentity;
    static get_SSL_Callback;
    static PK11_ExtractKeyValue;
    static PK11_GetKeyData;
    constructor(moduleName, socket_library, passed_library_method_mapping) {
        this.moduleName = moduleName;
        this.socket_library = socket_library;
        this.passed_library_method_mapping = passed_library_method_mapping;
        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        }
        else {
            this.library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType"];
            this.library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"];
            this.library_method_mapping["*libssl*.so"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        }
        this.addresses = (0, shared_functions_1.readAddresses)(this.library_method_mapping);
        // @ts-ignore
        if (ssl_log_1.offsets != "{OFFSETS}" && ssl_log_1.offsets.nss != null) {
            if (ssl_log_1.offsets.sockets != null) {
                const socketBaseAddress = (0, shared_functions_1.getBaseAddress)(socket_library);
                for (const method of Object.keys(ssl_log_1.offsets.sockets)) {
                    //@ts-ignore
                    this.addresses[`${method}`] = ssl_log_1.offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(ssl_log_1.offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(ssl_log_1.offsets.sockets[`${method}`].address));
                }
            }
            const libraryBaseAddress = (0, shared_functions_1.getBaseAddress)(moduleName);
            if (libraryBaseAddress == null) {
                (0, log_1.log)("Unable to find library base address! Given address values will be interpreted as absolute ones!");
            }
            for (const method of Object.keys(ssl_log_1.offsets.nss)) {
                //@ts-ignore
                this.addresses[`${method}`] = ssl_log_1.offsets.nss[`${method}`].absolute || libraryBaseAddress == null ? ptr(ssl_log_1.offsets.nss[`${method}`].address) : libraryBaseAddress.add(ptr(ssl_log_1.offsets.nss[`${method}`].address));
            }
        }
        NSS.SSL_SESSION_get_id = new NativeFunction(this.addresses["SSL_GetSessionID"], "pointer", ["pointer"]);
        NSS.getsockname = new NativeFunction(this.addresses["PR_GetSockName"], "int", ["pointer", "pointer"]);
        NSS.getpeername = new NativeFunction(this.addresses["PR_GetPeerName"], "int", ["pointer", "pointer"]);
    }
    /* PARSING functions */
    static parse_struct_SECItem(secitem) {
        /*
         * struct SECItemStr {
         * SECItemType type;
         * unsigned char *data;
         * unsigned int len;
         * }; --> size = 20
        */
        return {
            "type": secitem.readU64(),
            "data": secitem.add(shared_structures_1.pointerSize).readPointer(),
            "len": secitem.add(shared_structures_1.pointerSize * 2).readU32()
        };
    }
    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L971
    static parse_struct_sslSocketStr(sslSocketFD) {
        return {
            "fd": sslSocketFD.readPointer(),
            "version": sslSocketFD.add(160),
            "handshakeCallback": sslSocketFD.add(464),
            "secretCallback": sslSocketFD.add(568),
            "ssl3": sslSocketFD.add(1432)
        };
    }
    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L771
    static parse_struct_ssl3Str(ssl3_struct) {
        /*
        struct ssl3StateStr {
    
        ssl3CipherSpec *crSpec; // current read spec.
        ssl3CipherSpec *prSpec; // pending read spec.
        ssl3CipherSpec *cwSpec; // current write spec.
        ssl3CipherSpec *pwSpec; // pending write spec.
        
        PRBool peerRequestedKeyUpdate;                     --> enum type
        
        PRBool keyUpdateDeferred;                          --> enum type
        tls13KeyUpdateRequest deferredKeyUpdateRequest;    --> enum type
       
        PRBool clientCertRequested;                        --> enum type
    
        CERTCertificate *clientCertificate;
        SECKEYPrivateKey *clientPrivateKey;
        CERTCertificateList *clientCertChain;
        PRBool sendEmptyCert;
    
        PRUint8 policy;
        PLArenaPool *peerCertArena;
        
        void *peerCertChain;
        
        CERTDistNames *ca_list;
        
        SSL3HandshakeState hs;
        ...
        }
        */
        return {
            "crSpec": ssl3_struct.readPointer(),
            "prSpec": ssl3_struct.add(shared_structures_1.pointerSize).readPointer(),
            "cwSpec": ssl3_struct.add(shared_structures_1.pointerSize * 2).readPointer(),
            "pwSpec": ssl3_struct.add(shared_structures_1.pointerSize * 3).readPointer(),
            "peerRequestedKeyUpdate": ssl3_struct.add(shared_structures_1.pointerSize * 4).readU32(),
            "keyUpdateDeferred": ssl3_struct.add(shared_structures_1.pointerSize * 4 + 4).readU32(),
            "deferredKeyUpdateRequest": ssl3_struct.add(shared_structures_1.pointerSize * 4 + 8).readU32(),
            "clientCertRequested": ssl3_struct.add(shared_structures_1.pointerSize * 4 + 12).readU32(),
            "clientCertificate": ssl3_struct.add(shared_structures_1.pointerSize * 4 + 16).readPointer(),
            "clientPrivateKey": ssl3_struct.add(shared_structures_1.pointerSize * 5 + 16).readPointer(),
            "clientCertChain": ssl3_struct.add(shared_structures_1.pointerSize * 6 + 16).readPointer(),
            "sendEmptyCert": ssl3_struct.add(shared_structures_1.pointerSize * 7 + 16).readU32(),
            "policy": ssl3_struct.add(shared_structures_1.pointerSize * 7 + 20).readU32(),
            "peerCertArena": ssl3_struct.add(shared_structures_1.pointerSize * 7 + 24).readPointer(),
            "peerCertChain": ssl3_struct.add(shared_structures_1.pointerSize * 8 + 24).readPointer(),
            "ca_list": ssl3_struct.add(shared_structures_1.pointerSize * 9 + 24).readPointer(),
            "hs": {
                "server_random": ssl3_struct.add(shared_structures_1.pointerSize * 10 + 24),
                "client_random": ssl3_struct.add(shared_structures_1.pointerSize * 10 + 56),
                "client_inner_random": ssl3_struct.add(shared_structures_1.pointerSize * 10 + 88),
                "ws": ssl3_struct.add(shared_structures_1.pointerSize * 10 + 120).readU32(),
                "hashType": ssl3_struct.add(shared_structures_1.pointerSize * 10 + 124).readU32(),
                "messages": {
                    "data": ssl3_struct.add(shared_structures_1.pointerSize * 10 + 128).readPointer(),
                    "len": ssl3_struct.add(shared_structures_1.pointerSize * 11 + 128).readU32(),
                    "space": ssl3_struct.add(shared_structures_1.pointerSize * 11 + 132).readU32(),
                    "fixed": ssl3_struct.add(shared_structures_1.pointerSize * 11 + 136).readU32(),
                },
                "echInnerMessages": {
                    "data": ssl3_struct.add(shared_structures_1.pointerSize * 11 + 140).readPointer(),
                    "len": ssl3_struct.add(shared_structures_1.pointerSize * 12 + 140).readU32(),
                    "space": ssl3_struct.add(shared_structures_1.pointerSize * 12 + 144).readU32(),
                    "fixed": ssl3_struct.add(shared_structures_1.pointerSize * 12 + 148).readU32(),
                },
                "md5": ssl3_struct.add(shared_structures_1.pointerSize * 12 + 152).readPointer(),
                "sha": ssl3_struct.add(shared_structures_1.pointerSize * 13 + 152).readPointer(),
                "shaEchInner": ssl3_struct.add(shared_structures_1.pointerSize * 14 + 152).readPointer(),
                "shaPostHandshake": ssl3_struct.add(shared_structures_1.pointerSize * 15 + 152).readPointer(),
                "signatureScheme": ssl3_struct.add(shared_structures_1.pointerSize * 16 + 152).readU32(),
                "kea_def": ssl3_struct.add(shared_structures_1.pointerSize * 16 + 156).readPointer(),
                "cipher_suite": ssl3_struct.add(shared_structures_1.pointerSize * 17 + 156).readU32(),
                "suite_def": ssl3_struct.add(shared_structures_1.pointerSize * 17 + 160).readPointer(),
                "msg_body": {
                    "data": ssl3_struct.add(shared_structures_1.pointerSize * 18 + 160).readPointer(),
                    "len": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 160).readU32(),
                    "space": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 164).readU32(),
                    "fixed": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 168).readU32(),
                },
                "header_bytes": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 172).readU32(),
                "msg_type": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 176).readU32(),
                "msg_len": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 180).readU32(),
                "isResuming": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 184).readU32(),
                "sendingSCSV": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 188).readU32(),
                "receivedNewSessionTicket": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 192).readU32(),
                "newSessionTicket": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 196),
                "finishedBytes": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 240).readU32(),
                "finishedMsgs": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 244),
                "authCertificatePending": ssl3_struct.add(shared_structures_1.pointerSize * 18 + 316).readU32(),
                "restartTarget": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 320).readU32(),
                "canFalseStart": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 324).readU32(),
                "preliminaryInfo": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 328).readU32(),
                "remoteExtensions": {
                    "next": ssl3_struct.add(shared_structures_1.pointerSize * 19 + 332).readPointer(),
                    "prev": ssl3_struct.add(shared_structures_1.pointerSize * 20 + 332).readPointer(),
                },
                "echOuterExtensions": {
                    "next": ssl3_struct.add(shared_structures_1.pointerSize * 21 + 332).readPointer(),
                    "prev": ssl3_struct.add(shared_structures_1.pointerSize * 22 + 332).readPointer(),
                },
                "sendMessageSeq": ssl3_struct.add(shared_structures_1.pointerSize * 23 + 332).readU32(),
                "lastMessageFlight": {
                    "next": ssl3_struct.add(shared_structures_1.pointerSize * 23 + 336).readPointer(),
                    "prev": ssl3_struct.add(shared_structures_1.pointerSize * 24 + 336).readPointer(),
                },
                "maxMessageSent": ssl3_struct.add(shared_structures_1.pointerSize * 25 + 336).readU16(),
                "recvMessageSeq": ssl3_struct.add(shared_structures_1.pointerSize * 25 + 338).readU16(),
                "recvdFragments": {
                    "data": ssl3_struct.add(shared_structures_1.pointerSize * 25 + 340).readPointer(),
                    "len": ssl3_struct.add(shared_structures_1.pointerSize * 26 + 340).readU32(),
                    "space": ssl3_struct.add(shared_structures_1.pointerSize * 26 + 344).readU32(),
                    "fixed": ssl3_struct.add(shared_structures_1.pointerSize * 26 + 348).readU32(),
                },
                "recvdHighWater": ssl3_struct.add(shared_structures_1.pointerSize * 26 + 352).readU32(),
                "cookie": {
                    "type": ssl3_struct.add(shared_structures_1.pointerSize * 26 + 356).readU64(),
                    "data": ssl3_struct.add(shared_structures_1.pointerSize * 27 + 356).readPointer(),
                    "len": ssl3_struct.add(shared_structures_1.pointerSize * 28 + 356).readU32(),
                },
                "times_array": ssl3_struct.add(shared_structures_1.pointerSize * 28 + 360).readU32(),
                "rtTimer": ssl3_struct.add(shared_structures_1.pointerSize * 28 + 432).readPointer(),
                "ackTimer": ssl3_struct.add(shared_structures_1.pointerSize * 29 + 432).readPointer(),
                "hdTimer": ssl3_struct.add(shared_structures_1.pointerSize * 30 + 432).readPointer(),
                "rtRetries": ssl3_struct.add(shared_structures_1.pointerSize * 31 + 432).readU32(),
                "srvVirtName": {
                    "type": ssl3_struct.add(shared_structures_1.pointerSize * 31 + 436).readU64(),
                    "data": ssl3_struct.add(shared_structures_1.pointerSize * 32 + 436).readPointer(),
                    "len": ssl3_struct.add(shared_structures_1.pointerSize * 33 + 436).readU32(),
                },
                "currentSecret": ssl3_struct.add(shared_structures_1.pointerSize * 33 + 440).readPointer(),
                "resumptionMasterSecret": ssl3_struct.add(shared_structures_1.pointerSize * 34 + 440).readPointer(),
                "dheSecret": ssl3_struct.add(shared_structures_1.pointerSize * 35 + 440).readPointer(),
                "clientEarlyTrafficSecret": ssl3_struct.add(shared_structures_1.pointerSize * 36 + 440).readPointer(),
                "clientHsTrafficSecret": ssl3_struct.add(shared_structures_1.pointerSize * 37 + 440).readPointer(),
                "serverHsTrafficSecret": ssl3_struct.add(shared_structures_1.pointerSize * 38 + 440).readPointer(),
                "clientTrafficSecret": ssl3_struct.add(shared_structures_1.pointerSize * 39 + 440).readPointer(),
                "serverTrafficSecret": ssl3_struct.add(shared_structures_1.pointerSize * 40 + 440).readPointer(),
                "earlyExporterSecret": ssl3_struct.add(shared_structures_1.pointerSize * 41 + 440).readPointer(),
                "exporterSecret": ssl3_struct.add(shared_structures_1.pointerSize * 42 + 440).readPointer()
            } // end of hs struct
            /*
            typedef struct SSL3HandshakeStateStr {
        SSL3Random server_random;
        SSL3Random client_random;
        SSL3Random client_inner_random;
        SSL3WaitState ws;                       --> enum type
    
        
        SSL3HandshakeHashType hashType;         --> enum type
        sslBuffer messages;                     --> struct of 20 bytes (1 ptr + 12 bytes;see lib/ssl/sslencode.h)
        sslBuffer echInnerMessages;
        
        PK11Context *md5;
        PK11Context *sha;
        PK11Context *shaEchInner;
        PK11Context *shaPostHandshake;
        SSLSignatureScheme signatureScheme;     --> enum type( see lib/ssl/sslt.h)
        const ssl3KEADef *kea_def;
        ssl3CipherSuite cipher_suite;           --> typedef PRUint16 ssl3CipherSuite (see lib/ssl/ssl3prot.h)
        const ssl3CipherSuiteDef *suite_def;
        sslBuffer msg_body;
                            
        unsigned int header_bytes;
        
        SSLHandshakeType msg_type;
        unsigned long msg_len;
        PRBool isResuming;
        PRBool sendingSCSV;
    
        
        PRBool receivedNewSessionTicket;
        NewSessionTicket newSessionTicket;      --> (see lib/ssl/ssl3prot.h)
    
        PRUint16 finishedBytes;
        union {
            TLSFinished tFinished[2];           --> 12 bytes
            SSL3Finished sFinished[2];          --> 36 bytes
            PRUint8 data[72];
        } finishedMsgs;                         --> 72
    
        PRBool authCertificatePending;
        
        sslRestartTarget restartTarget;
    
        PRBool canFalseStart;
        
        PRUint32 preliminaryInfo;
    
        
        PRCList remoteExtensions;
        PRCList echOuterExtensions;
    
        
        PRUint16 sendMessageSeq;
        PRCList lastMessageFlight;
        PRUint16 maxMessageSent;
        PRUint16 recvMessageSeq;
        sslBuffer recvdFragments;
        PRInt32 recvdHighWater;
        SECItem cookie;
        dtlsTimer timers[3];       24 * 3
        dtlsTimer *rtTimer;
        dtlsTimer *ackTimer;
        dtlsTimer *hdTimer;
        PRUint32 rtRetries;
        SECItem srvVirtName;
                                        
    
        // This group of values is used for TLS 1.3 and above
        PK11SymKey *currentSecret;            // The secret down the "left hand side"   --> ssl3_struct.add(704)
                                                //of the TLS 1.3 key schedule.
        PK11SymKey *resumptionMasterSecret;   // The resumption_master_secret.          --> ssl3_struct.add(712)
        PK11SymKey *dheSecret;                // The (EC)DHE shared secret.             --> ssl3_struct.add(720)
        PK11SymKey *clientEarlyTrafficSecret; // The secret we use for 0-RTT.           --> ssl3_struct.add(728)
        PK11SymKey *clientHsTrafficSecret;    // The source keys for handshake          --> ssl3_struct.add(736)
        PK11SymKey *serverHsTrafficSecret;    // traffic keys.                          --> ssl3_struct.add(744)
        PK11SymKey *clientTrafficSecret;      // The source keys for application        --> ssl3_struct.add(752)
        PK11SymKey *serverTrafficSecret;      // traffic keys                           --> ssl3_struct.add(760)
        PK11SymKey *earlyExporterSecret;      // for 0-RTT exporters                    --> ssl3_struct.add(768)
        PK11SymKey *exporterSecret;           // for exporters                          --> ssl3_struct.add(776)
        ...
    
    
        typedef struct {
        const char *label; 8
        DTLSTimerCb cb; 8
        PRIntervalTime started; 4
        PRUint32 timeout; 4
    } dtlsTimer;
    
            */
        };
    }
    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslspec.h#L140 
    static parse_struct_sl3CipherSpecStr(cwSpec) {
        /*
        truct ssl3CipherSpecStr {
            PRCList link;
            PRUint8 refCt;
    
            SSLSecretDirection direction;
            SSL3ProtocolVersion version;
            SSL3ProtocolVersion recordVersion;
    
            const ssl3BulkCipherDef *cipherDef;
            const ssl3MACDef *macDef;
    
            SSLCipher cipher;
            void *cipherContext;
    
            PK11SymKey *masterSecret;
            ...
        */
        return {
            "link": cwSpec.add,
            "refCt": cwSpec.add(shared_structures_1.pointerSize * 2),
            "direction": cwSpec.add(shared_structures_1.pointerSize * 2 + 4),
            "version": cwSpec.add(shared_structures_1.pointerSize * 2 + 8),
            "recordVersion": cwSpec.add(shared_structures_1.pointerSize * 2 + 12),
            "cipherDef": cwSpec.add(shared_structures_1.pointerSize * 2 + 16).readPointer(),
            "macDef": cwSpec.add(shared_structures_1.pointerSize * 3 + 16).readPointer(),
            "cipher": cwSpec.add(shared_structures_1.pointerSize * 4 + 16),
            "cipherContext": cwSpec.add(shared_structures_1.pointerSize * 4 + 24).readPointer(),
            "master_secret": cwSpec.add(shared_structures_1.pointerSize * 5 + 24).readPointer()
        };
    }
    /********* NSS Callbacks ************/
    /*
    This callback gets called whenever a SSL Handshake completed
    
    typedef void (*SSLHandshakeCallback)(
            PRFileDesc *fd,
            void *client_data);
    */
    static keylog_callback = new NativeCallback(function (sslSocketFD, client_data) {
        if (typeof this !== "undefined") {
            NSS.ssl_RecordKeyLog(sslSocketFD);
        }
        else {
            console.log("[-] Error while installing ssl_RecordKeyLog() callback");
        }
        return 0;
    }, "void", ["pointer", "pointer"]);
    /**
     * SSL_SetSecretCallback installs a callback that TLS calls when it installs new
     * traffic secrets.
     *
     *
     *
     * SSLSecretCallback is called with the current epoch and the corresponding
     * secret; this matches the epoch used in DTLS 1.3, even if the socket is
     * operating in stream mode:
     *
     * - client_early_traffic_secret corresponds to epoch 1
     * - {client|server}_handshake_traffic_secret is epoch 2
     * - {client|server}_application_traffic_secret_{N} is epoch 3+N
     *
     * The callback is invoked separately for read secrets (client secrets on the
     * server; server secrets on the client), and write secrets.
     *
     * This callback is only called if (D)TLS 1.3 is negotiated.
     *
     * typedef void(PR_CALLBACK *SSLSecretCallback)(
     *   PRFileDesc *fd, PRUint16 epoch, SSLSecretDirection dir, PK11SymKey *secret,
     *   void *arg);
     *
     *  More: https://github.com/nss-dev/nss/blob/master/lib/ssl/sslexp.h#L614
     *
     */
    static secret_callback = new NativeCallback(function (sslSocketFD, epoch, dir, secret, arg_ptr) {
        if (typeof this !== "undefined") {
            NSS.parse_epoch_value_from_SSL_SetSecretCallback(sslSocketFD, epoch);
        }
        else {
            console.log("[-] Error while installing parse_epoch_value_from_SSL_SetSecretCallback()");
        }
        return;
    }, "void", ["pointer", "uint16", "uint16", "pointer", "pointer"]);
    /********* NSS helper functions  ********/
    /**
* Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
* "dst_port".
* @param {pointer} sockfd The file descriptor of the socket to inspect as PRFileDesc.
* @param {boolean} isRead If true, the context is an SSL_read call. If
*     false, the context is an SSL_write call.
* @param {{ [key: string]: NativePointer}} methodAddresses Dictionary containing (at least) addresses for getpeername, getsockname, ntohs and ntohl
* @return {{ [key: string]: string | number }} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
*     and "dst_port".

  PRStatus PR_GetPeerName(
PRFileDesc *fd,
PRNetAddr *addr);

PRStatus PR_GetSockName(
PRFileDesc *fd,
PRNetAddr *addr);

PRStatus PR_NetAddrToString(
const PRNetAddr *addr,
char *string,
PRUint32 size);


union PRNetAddr {
struct {
   PRUint16 family;
   char data[14];
} raw;
struct {
   PRUint16 family;
   PRUint16 port;
   PRUint32 ip;
   char pad[8];
} inet;
#if defined(_PR_INET6)
struct {
   PRUint16 family;
   PRUint16 port;
   PRUint32 flowinfo;
   PRIPv6Addr ip;
} ipv6;
#endif // defined(_PR_INET6)
};

typedef union PRNetAddr PRNetAddr;

*/
    static getPortsAndAddressesFromNSS(sockfd, isRead, methodAddresses) {
        var getpeername = new NativeFunction(methodAddresses["PR_GetPeerName"], "int", ["pointer", "pointer"]);
        var getsockname = new NativeFunction(methodAddresses["PR_GetSockName"], "int", ["pointer", "pointer"]);
        var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"]);
        var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"]);
        var message = {};
        var addrType = Memory.alloc(2); // PRUint16 is a 2 byte (16 bit) value on all plattforms
        //var prNetAddr = Memory.alloc(Process.pointerSize)
        var addrlen = Memory.alloc(4);
        var addr = Memory.alloc(128);
        var src_dst = ["src", "dst"];
        for (var i = 0; i < src_dst.length; i++) {
            addrlen.writeU32(128);
            if ((src_dst[i] == "src") !== isRead) {
                getsockname(sockfd, addr);
            }
            else {
                getpeername(sockfd, addr);
            }
            if (addr.readU16() == shared_structures_1.AF_INET) {
                message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
                message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32());
                message["ss_family"] = "AF_INET";
            }
            else if (addr.readU16() == shared_structures_1.AF_INET6) {
                message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
                message[src_dst[i] + "_addr"] = "";
                var ipv6_addr = addr.add(8);
                for (var offset = 0; offset < 16; offset += 1) {
                    message[src_dst[i] + "_addr"] += ("0" + ipv6_addr.add(offset).readU8().toString(16).toUpperCase()).substr(-2);
                }
                if (message[src_dst[i] + "_addr"].toString().indexOf("00000000000000000000FFFF") === 0) {
                    message[src_dst[i] + "_addr"] = ntohl(ipv6_addr.add(12).readU32());
                    message["ss_family"] = "AF_INET";
                }
                else {
                    message["ss_family"] = "AF_INET6";
                }
            }
            else {
                (0, log_1.devlog)("[-] PIPE descriptor error");
                //FIXME: Sometimes addr.readU16() will be 0 when a PIPE Read oder Write gets interpcepted, thus this error will be thrown.
                throw "Only supporting IPv4/6";
            }
        }
        return message;
    }
    /**
    * This functions tests if a given address is a readable pointer
    *
    * @param {*} ptr_addr is a pointer to the memory location where we want to check if there is already an address
    * @returns 1 to indicate that there is a ptr at
    */
    static is_ptr_at_mem_location(ptr_addr) {
        try {
            // an exception is thrown if there isn't a readable address
            ptr_addr.readPointer();
            return 1;
        }
        catch (error) {
            return -1;
        }
    }
    /**
    *
    * typedef struct PRFileDesc {
    *       const struct PRIOMethods *methods;
    *       PRFilePrivate *secret;
    *       PRFileDesc *lower;
    *       PRFileDesc *higher;
    *       void (*dtor) (PRFileDesc *);
    *       PRDescIdentity identity;
    *  } PRFileDesc;
    *
    * @param {*} pRFileDesc
    * @param {*} layer_name
    * @returns
    */
    static NSS_FindIdentityForName(pRFileDesc, layer_name) {
        var lower_ptr = pRFileDesc.add(shared_structures_1.pointerSize * 2).readPointer();
        var higher_ptr = pRFileDesc.add(shared_structures_1.pointerSize * 3).readPointer();
        var identity = pRFileDesc.add(shared_structures_1.pointerSize * 5).readPointer();
        if (!identity.isNull()) {
            var nameptr = NSS.PR_GetNameForIdentity(identity).readCString();
            if (nameptr == layer_name) {
                return pRFileDesc;
            }
        }
        if (!lower_ptr.isNull()) {
            return this.NSS_FindIdentityForName(lower_ptr, layer_name);
        }
        if (!higher_ptr.isNull()) {
            (0, log_1.devlog)('Have upper');
        }
        // when we reach this we have some sort of error 
        (0, log_1.devlog)("[-] error while getting SSL layer");
        return NULL;
    }
    static getSessionIdString(session_id_ptr, len) {
        var session_id = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + session_id_ptr.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
    }
    static getSSL_Layer(pRFileDesc) {
        var ssl_layer_id = 3; // SSL has the Layer ID 3 normally.
        var getIdentitiesLayer = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetIdentitiesLayer'), "pointer", ["pointer", "int"]);
        var ssl_layer = getIdentitiesLayer(pRFileDesc, ssl_layer_id);
        if (ptr(ssl_layer.toString()).isNull()) {
            (0, log_1.devlog)("PR_BAD_DESCRIPTOR_ERROR: " + ssl_layer);
            return -1;
        }
        return ssl_layer;
    }
    /**
    *
    * @param {*} readAddr is the address where we start reading the bytes
    * @param {*} len is the length of bytes we want to convert to a hex string
    * @returns a hex string with the length of len
    */
    static getHexString(readAddr, len) {
        var secret_str = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xab ==> "ab"), and append
            // it to secret_str.
            secret_str +=
                ("0" + readAddr.add(i).readU8().toString(16).toLowerCase()).substr(-2);
        }
        return secret_str;
    }
    /**
 * Get the session_id of SSL object and return it as a hex string.
 * @param {!NativePointer} ssl A pointer to an SSL object.
 * @return {dict} A string representing the session_id of the SSL object's
 *     SSL_SESSION. For example,
 *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
 *
 * On NSS the return type of SSL_GetSessionID is a SECItem:
      typedef enum {
 * siBuffer = 0,
 * siClearDataBuffer = 1,
 * siCipherDataBuffer = 2,
 * siDERCertBuffer = 3,
 * siEncodedCertBuffer = 4,
 * siDERNameBuffer = 5,
 * siEncodedNameBuffer = 6,
 * siAsciiNameString = 7,
 * siAsciiString = 8,
 * siDEROID = 9,
 * siUnsignedInteger = 10,
 * siUTCTime = 11,
 * siGeneralizedTime = 12,
 * siVisibleString = 13,
 * siUTF8String = 14,
 * siBMPString = 15
 * } SECItemType;
 *
 * typedef struct SECItemStr SECItem;
 *
 * struct SECItemStr {
 * SECItemType type;
 * unsigned char *data;
 * unsigned int len;
 * }; --> size = 20
 *
 *
 */
    static getSslSessionIdFromFD(pRFileDesc) {
        var dummySSL_SessionID = "3E8ABF58649A1A1C58824D704173BA9AAFA2DA33B45FFEA341D218B29BBACF8F";
        var fdType = NSS.getDescType(pRFileDesc);
        //log("pRFileDescType: "+ fdType)
        /*if(fdType == 4){ // LAYERED
            pRFileDesc = ptr(getSSL_Layer(pRFileDesc).toString())
            if(pRFileDesc.toString() == "-1"){
                log("error")
        
            }
        }*/
        var layer = NSS.NSS_FindIdentityForName(pRFileDesc, 'SSL');
        if (!layer) {
            return dummySSL_SessionID;
        }
        var sslSessionIdSECItem = ptr(NSS.SSL_SESSION_get_id(layer).toString());
        if (sslSessionIdSECItem == null || sslSessionIdSECItem.isNull()) {
            try {
                (0, log_1.devlog)("---- getSslSessionIdFromFD -----");
                (0, log_1.devlog)("ERROR");
                (0, log_1.devlog)("pRFileDescType: " + NSS.getDescType(pRFileDesc));
                if (fdType == 2) {
                    var c = Memory.dup(pRFileDesc, 32);
                    //log(hexdump(c))
                    var getLayersIdentity = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetLayersIdentity'), "uint32", ["pointer"]);
                    var getNameOfIdentityLayer = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetNameForIdentity'), "pointer", ["uint32"]);
                    var layerID = getLayersIdentity(pRFileDesc);
                    (0, log_1.devlog)("LayerID: " + layerID);
                    var nameIDentity = getNameOfIdentityLayer(layerID);
                    (0, log_1.devlog)("name address: " + nameIDentity);
                    (0, log_1.devlog)("name: " + ptr(nameIDentity.toString()).readCString());
                    var sslSessionIdSECItem2 = ptr(NSS.getSSL_Layer(pRFileDesc).toString());
                    (0, log_1.devlog)("sslSessionIdSECItem2 =" + sslSessionIdSECItem2);
                    if (sslSessionIdSECItem2.toString().startsWith("0x7f")) {
                        var aa = Memory.dup(sslSessionIdSECItem2, 32);
                        //log(hexdump(aa))
                        var sslSessionIdSECItem3 = ptr(NSS.SSL_SESSION_get_id(sslSessionIdSECItem2).toString());
                        (0, log_1.devlog)("sslSessionIdSECItem3 =" + sslSessionIdSECItem3);
                    }
                    var sslSessionIdSECItem4 = ptr(NSS.SSL_SESSION_get_id(pRFileDesc).toString());
                    (0, log_1.devlog)("sslSessionIdSECItem4 =" + sslSessionIdSECItem4);
                    (0, log_1.devlog)("Using Dummy Session ID");
                    (0, log_1.devlog)("");
                }
                else if (fdType == 4) {
                    pRFileDesc = ptr(NSS.getSSL_Layer(pRFileDesc).toString());
                    var sslSessionIdSECItem = ptr(NSS.SSL_SESSION_get_id(pRFileDesc).toString());
                    (0, log_1.devlog)("new sessionid_ITEM: " + sslSessionIdSECItem);
                }
                else {
                    (0, log_1.devlog)("---- SSL Session Analysis ------------");
                    var c = Memory.dup(sslSessionIdSECItem, 32);
                    (0, log_1.devlog)(hexdump(c));
                }
                (0, log_1.devlog)("---- getSslSessionIdFromFD finished -----");
                (0, log_1.devlog)("");
            }
            catch (error) {
                (0, log_1.devlog)("Error:" + error);
            }
            return dummySSL_SessionID;
        }
        var len = sslSessionIdSECItem.add(shared_structures_1.pointerSize * 2).readU32();
        var session_id_ptr = sslSessionIdSECItem.add(shared_structures_1.pointerSize).readPointer();
        var session_id = NSS.getSessionIdString(session_id_ptr, len);
        return session_id;
    }
    static get_SSL_FD(pRFileDesc) {
        var ssl_layer = NSS.NSS_FindIdentityForName(pRFileDesc, 'SSL');
        if (!ssl_layer) {
            (0, log_1.devlog)("error: couldn't get SSL Layer from pRFileDesc");
            return NULL;
        }
        var sslSocketFD = NSS.get_SSL_Socket(ssl_layer);
        if (!sslSocketFD) {
            (0, log_1.devlog)("error: couldn't get sslSocketFD");
            return NULL;
        }
        return sslSocketFD;
    }
    /**
    *
    *
    *
    *
    *
    *
    * /* This function tries to find the SSL layer in the stack.
    * It searches for the first SSL layer at or below the argument fd,
    * and failing that, it searches for the nearest SSL layer above the
    * argument fd.  It returns the private sslSocket from the found layer.
    *
    sslSocket *
    ssl_FindSocket(PRFileDesc *fd)
    {
    PRFileDesc *layer;
    sslSocket *ss;
    
    PORT_Assert(fd != NULL);
    PORT_Assert(ssl_layer_id != 0);
    
    layer = PR_GetIdentitiesLayer(fd, ssl_layer_id);
    if (layer == NULL) {
    PORT_SetError(PR_BAD_DESCRIPTOR_ERROR);
    return NULL;
    }
    
    ss = (sslSocket *)layer->secret;
    /* Set ss->fd lazily. We can't rely on the value of ss->fd set by
    * ssl_PushIOLayer because another PR_PushIOLayer call will switch the
    * contents of the PRFileDesc pointed by ss->fd and the new layer.
    * See bug 807250.
    *
    ss->fd = layer;
    return ss;
    }
    
    *
    *
    */
    static get_SSL_Socket(ssl_layer) {
        var sslSocket = ssl_layer.add(shared_structures_1.pointerSize * 1).readPointer();
        return sslSocket;
    }
    /******** NSS Encryption Keys *******/
    /**
     *
     * ss->ssl3.cwSpec->masterSecret
     *
     * @param {*} ssl3  the parsed ssl3 struct
     * @returns the client_random as hex string (lower case)
     */
    static getMasterSecret(ssl3) {
        var cwSpec = ssl3.cwSpec;
        var masterSecret_Ptr = NSS.parse_struct_sl3CipherSpecStr(cwSpec).master_secret;
        var master_secret = NSS.get_Secret_As_HexString(masterSecret_Ptr);
        return master_secret;
    }
    /**
     * ss->ssl3.hs.client_random
     *
     * @param {*} ssl3 is a ptr to current parsed ssl3 struct
     * @returns the client_random as hex string (lower case)
     */
    static getClientRandom(ssl3) {
        var client_random = NSS.getHexString(ssl3.hs.client_random, NSS.SSL3_RANDOM_LENGTH);
        return client_random;
    }
    /**
    
     
    typedef struct sslSocketStr sslSocket;
     *
    
        SSL Socket struct (https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L971)
    struct sslSocketStr {
    PRFileDesc *fd;                                                                     +8
    
    /* Pointer to operations vector for this socket *
    const sslSocketOps *ops;                                                            +8
    
    /* SSL socket options *
    sslOptions opt;                                                                     sizeOf(sslOptions) --> 40
    /* Enabled version range *
    SSLVersionRange vrange;                                                             + 4
    
    /* A function that returns the current time. *
    SSLTimeFunc now;                                                                    +8
    void *nowArg;                                                                       +8
    
    /* State flags *
    unsigned long clientAuthRequested;                                                  +8
    unsigned long delayDisabled;     /* Nagle delay disabled *                          +8
    unsigned long firstHsDone;       /* first handshake is complete. *                  +8
    unsigned long enoughFirstHsDone; /* enough of the first handshake is                +8
                                      * done for callbacks to be able to
                                      * retrieve channel security
                                      * parameters from the SSL socket. *
    unsigned long handshakeBegun;                                                       +8
    unsigned long lastWriteBlocked;                                                     +8
    unsigned long recvdCloseNotify; /* received SSL EOF. *                              +8
    unsigned long TCPconnected;                                                         +8
    unsigned long appDataBuffered;                                                      +8
    unsigned long peerRequestedProtection; /* from old renegotiation *                  +8
    
    /* version of the protocol to use *
    SSL3ProtocolVersion version;                                                        +4
    SSL3ProtocolVersion clientHelloVersion; /* version sent in client hello. *          --> at offset 160
     */
    static get_SSL_Version(pRFileDesc) {
        var ssl_version_internal_Code = -1;
        var sslSocket = NSS.get_SSL_FD(pRFileDesc);
        if (sslSocket.isNull()) {
            return -1;
        }
        var sslVersion_pointerSize = 160;
        ssl_version_internal_Code = sslSocket.add((sslVersion_pointerSize)).readU16();
        return ssl_version_internal_Code;
    }
    static get_Secret_As_HexString(secret_key_Ptr) {
        var rv = NSS.PK11_ExtractKeyValue(secret_key_Ptr);
        if (rv != SECStatus.SECSuccess) {
            //log("[**] ERROR access the secret key");
            return "";
        }
        var keyData = NSS.PK11_GetKeyData(secret_key_Ptr); // return value is a SECItem
        var keyData_SECITem = NSS.parse_struct_SECItem(keyData);
        var secret_as_hexString = NSS.getHexString(keyData_SECITem.data, keyData_SECITem.len);
        return secret_as_hexString;
    }
    /**
     *
     * @param {*} ssl_version_internal_Code
     * @returns
     *
     *      https://github.com/nss-dev/nss/blob/c989bde00fe64c1b37df13c773adf3e91cc258c7/lib/ssl/sslproto.h#L16
     *      #define SSL_LIBRARY_VERSION_TLS_1_2             0x0303
     *      #define SSL_LIBRARY_VERSION_TLS_1_3             0x0304
     *
     *      0x0303 -->  771
     *      0x0304 -->  772
     *
     */
    static is_TLS_1_3(ssl_version_internal_Code) {
        if (ssl_version_internal_Code > 771) {
            return true;
        }
        else {
            return false;
        }
    }
    //see nss/lib/ssl/sslinfo.c for details */
    static get_Keylog_Dump(type, client_random, key) {
        return type + " " + client_random + " " + key;
    }
    /**
     *
     * @param {*} pRFileDesc
     * @param {*} dumping_handshake_secrets  a zero indicates an false and that the handshake just completed. A 1 indicates a true so that we are during the handshake itself
     * @returns
     */
    static getTLS_Keys(pRFileDesc, dumping_handshake_secrets) {
        var message = {};
        message["contentType"] = "keylog";
        (0, log_1.devlog)("[*] trying to log some keying materials ...");
        var sslSocketFD = NSS.get_SSL_FD(pRFileDesc);
        if (sslSocketFD.isNull()) {
            return;
        }
        var sslSocketStr = NSS.parse_struct_sslSocketStr(sslSocketFD);
        var ssl3_struct = sslSocketStr.ssl3;
        var ssl3 = NSS.parse_struct_ssl3Str(ssl3_struct);
        // the client_random is used to identify the diffrent SSL streams with their corresponding secrets
        var client_random = NSS.getClientRandom(ssl3);
        if (NSS.doTLS13_RTT0 == 1) {
            //var early_exporter_secret = get_Secret_As_HexString(ssl3_struct.add(768).readPointer()); //EARLY_EXPORTER_SECRET
            var early_exporter_secret = NSS.get_Secret_As_HexString(ssl3.hs.earlyExporterSecret); //EARLY_EXPORTER_SECRET
            (0, log_1.devlog)(NSS.get_Keylog_Dump("EARLY_EXPORTER_SECRET", client_random, early_exporter_secret));
            message["keylog"] = NSS.get_Keylog_Dump("EARLY_EXPORTER_SECRET", client_random, early_exporter_secret);
            send(message);
            NSS.doTLS13_RTT0 = -1;
        }
        if (dumping_handshake_secrets == 1) {
            (0, log_1.devlog)("[*] exporting TLS 1.3 handshake keying material");
            /*
             * Those keys are computed in the beginning of a handshake
             */
            //var client_handshake_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(736).readPointer()); //CLIENT_HANDSHAKE_TRAFFIC_SECRET
            var client_handshake_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.clientHsTrafficSecret); //CLIENT_HANDSHAKE_TRAFFIC_SECRET
            //parse_struct_ssl3Str(ssl3_struct)
            (0, log_1.devlog)(NSS.get_Keylog_Dump("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, client_handshake_traffic_secret));
            message["keylog"] = NSS.get_Keylog_Dump("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, client_handshake_traffic_secret);
            send(message);
            //var server_handshake_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(744).readPointer()); //SERVER_HANDSHAKE_TRAFFIC_SECRET
            var server_handshake_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.serverHsTrafficSecret); //SERVER_HANDSHAKE_TRAFFIC_SECRET
            (0, log_1.devlog)(NSS.get_Keylog_Dump("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, server_handshake_traffic_secret));
            message["keylog"] = NSS.get_Keylog_Dump("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, server_handshake_traffic_secret);
            send(message);
            return;
        }
        else if (dumping_handshake_secrets == 2) {
            (0, log_1.devlog)("[*] exporting TLS 1.3 RTT0 handshake keying material");
            var client_early_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.clientEarlyTrafficSecret); //CLIENT_EARLY_TRAFFIC_SECRET
            (0, log_1.devlog)(NSS.get_Keylog_Dump("CLIENT_EARLY_TRAFFIC_SECRET", client_random, client_early_traffic_secret));
            message["keylog"] = NSS.get_Keylog_Dump("CLIENT_EARLY_TRAFFIC_SECRET", client_random, client_early_traffic_secret);
            send(message);
            NSS.doTLS13_RTT0 = 1; // there is no callback for the EARLY_EXPORTER_SECRET
            return;
        }
        var ssl_version_internal_Code = NSS.get_SSL_Version(pRFileDesc);
        if (NSS.is_TLS_1_3(ssl_version_internal_Code)) {
            (0, log_1.devlog)("[*] exporting TLS 1.3 keying material");
            var client_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.clientTrafficSecret); //CLIENT_TRAFFIC_SECRET_0
            (0, log_1.devlog)(NSS.get_Keylog_Dump("CLIENT_TRAFFIC_SECRET_0", client_random, client_traffic_secret));
            message["keylog"] = NSS.get_Keylog_Dump("CLIENT_TRAFFIC_SECRET_0", client_random, client_traffic_secret);
            send(message);
            var server_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.serverTrafficSecret); //SERVER_TRAFFIC_SECRET_0
            (0, log_1.devlog)(NSS.get_Keylog_Dump("SERVER_TRAFFIC_SECRET_0", client_random, server_traffic_secret));
            message["keylog"] = NSS.get_Keylog_Dump("SERVER_TRAFFIC_SECRET_0", client_random, server_traffic_secret);
            send(message);
            var exporter_secret = NSS.get_Secret_As_HexString(ssl3.hs.exporterSecret); //EXPORTER_SECRET 
            (0, log_1.devlog)(NSS.get_Keylog_Dump("EXPORTER_SECRET", client_random, exporter_secret));
            message["keylog"] = NSS.get_Keylog_Dump("EXPORTER_SECRET", client_random, exporter_secret);
            send(message);
        }
        else {
            (0, log_1.devlog)("[*] exporting TLS 1.2 keying material");
            var master_secret = NSS.getMasterSecret(ssl3);
            (0, log_1.devlog)(NSS.get_Keylog_Dump("CLIENT_RANDOM", client_random, master_secret));
            message["keylog"] = NSS.get_Keylog_Dump("CLIENT_RANDOM", client_random, master_secret);
            send(message);
        }
        NSS.doTLS13_RTT0 = -1;
        return;
    }
    static ssl_RecordKeyLog(sslSocketFD) {
        NSS.getTLS_Keys(sslSocketFD, 0);
    }
    /***** Installing the hooks *****/
    install_plaintext_read_hook() {
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["PR_Read"], {
            onEnter: function (args) {
                // ab hier nicht mehr
                this.fd = ptr(args[0]);
                this.buf = ptr(args[1]);
            },
            onLeave: function (retval) {
                if (retval.toInt32() <= 0 || NSS.getDescType(this.fd) == PRDescType.PR_DESC_FILE) {
                    return;
                }
                var addr = Memory.alloc(8);
                var res = NSS.getpeername(this.fd, addr);
                // peername return -1 this is due to the fact that a PIPE descriptor is used to read from the SSL socket
                if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                    var message = NSS.getPortsAndAddressesFromNSS(this.fd, true, lib_addesses);
                    (0, log_1.devlog)("Session ID: " + NSS.getSslSessionIdFromFD(this.fd));
                    message["ssl_session_id"] = NSS.getSslSessionIdFromFD(this.fd);
                    message["function"] = "NSS_read";
                    this.message = message;
                    this.message["contentType"] = "datalog";
                    var data = this.buf.readByteArray((new Uint32Array([retval]))[0]);
                }
                else {
                    var temp = this.buf.readByteArray((new Uint32Array([retval]))[0]);
                    (0, log_1.devlog)(JSON.stringify(temp));
                }
            }
        });
    }
    install_plaintext_write_hook() {
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["PR_Write"], {
            onEnter: function (args) {
                this.fd = ptr(args[0]);
                this.buf = args[1];
                this.len = args[2];
            },
            onLeave: function (retval) {
                if (retval.toInt32() <= 0) { //|| NSS.getDescType(this.fd) == PRDescType.PR_DESC_FILE) {
                    return;
                }
                var addr = Memory.alloc(8);
                NSS.getsockname(this.fd, addr);
                if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                    var message = NSS.getPortsAndAddressesFromNSS(this.fd, false, lib_addesses);
                    message["ssl_session_id"] = NSS.getSslSessionIdFromFD(this.fd);
                    message["function"] = "NSS_write";
                    message["contentType"] = "datalog";
                    send(message, this.buf.readByteArray((parseInt(this.len))));
                }
            }
        });
    }
    /***** install callbacks for key logging ******/
    /**
 *
 * This callback gets only called in TLS 1.3 and newer versions
 *
 * @param {*} pRFileDesc
 * @param {*} secret_label
 * @param {*} secret
 * @returns
 *
function tls13_RecordKeyLog(pRFileDesc, secret_label, secret){

    var sslSocketFD = get_SSL_FD(pRFileDesc);
    if(sslSocketFD == -1){
        return;
    }

    var sslSocketStr = parse_struct_sslSocketStr(sslSocketFD);

    var ssl3_struct = sslSocketStr.ssl3;
    var ssl3 = parse_struct_ssl3Str(ssl3_struct);
    

    var secret_as_hexString = get_Secret_As_HexString(secret);
    

    log(get_Keylog_Dump(secret_label,getClientRandom(ssl3),secret_as_hexString));


    return 0;
}

// our old way to get the diffrent secrets from TLS 1.3 and above
*/
    static parse_epoch_value_from_SSL_SetSecretCallback(sslSocketFD, epoch) {
        if (epoch == 1) { // client_early_traffic_secret
            NSS.getTLS_Keys(sslSocketFD, 2);
        }
        else if (epoch == 2) { // client|server}_handshake_traffic_secret
            NSS.getTLS_Keys(sslSocketFD, 1);
            /* our old way to get the diffrent secrets from TLS 1.3 and above
    
            per default we assume we are intercepting a TLS client therefore
            dir == 1 --> SERVER_HANDSHAKE_TRAFFIC_SECRET
            dir == 2 --> CLIENT_HANDSHAKE_TRAFFIC_SECRET
            typedef enum {
                ssl_secret_read = 1,
                ssl_secret_write = 2,
            } SSLSecretDirection;
            
            if(dir == 1){
                tls13_RecordKeyLog(sslSocketFD,"SERVER_HANDSHAKE_TRAFFIC_SECRET",secret);
            }else{
                tls13_RecordKeyLog(sslSocketFD,"CLIENT_HANDSHAKE_TRAFFIC_SECRET",secret);
            }*/
        }
        else if (epoch >= 3) { // {client|server}_application_traffic_secret_{N}
            return;
            // we intercept this through the handshake_callback
        }
        else {
            (0, log_1.devlog)("[-] secret_callback invocation: UNKNOWN");
        }
    }
    static insert_hook_into_secretCallback(addr_of_installed_secretCallback) {
        Interceptor.attach(addr_of_installed_secretCallback, {
            onEnter(args) {
                this.sslSocketFD = args[0];
                this.epoch = args[1];
                NSS.parse_epoch_value_from_SSL_SetSecretCallback(this.sslSocketFD, this.epoch);
            },
            onLeave(retval) {
            }
        });
    }
    /**
         * Registers a secret_callback through inserting the address to our TLS 1.3 callback function at the apprioate offset of the  SSL Socket struct
         * This is neccassy because the computed handshake secrets are already freed after the handshake is completed.
         *
         *
         * @param {*} pRFileDesc a file descriptor (NSS PRFileDesc) to a SSL socket
         * @returns
         */
    static register_secret_callback(pRFileDesc) {
        var sslSocketFD = NSS.get_SSL_FD(pRFileDesc);
        if (sslSocketFD.isNull()) {
            (0, log_1.devlog)("[-] error while installing secret callback: unable get SSL socket descriptor");
            return;
        }
        var sslSocketStr = NSS.parse_struct_sslSocketStr(sslSocketFD);
        if (NSS.is_ptr_at_mem_location(sslSocketStr.secretCallback.readPointer()) == 1) {
            NSS.insert_hook_into_secretCallback(sslSocketStr.secretCallback.readPointer());
        }
        else {
            sslSocketStr.secretCallback.writePointer(NSS.secret_callback);
        }
        (0, log_1.devlog)("[**] secret callback (" + NSS.secret_callback + ") installed to address: " + sslSocketStr.secretCallback);
    }
    install_tls_keys_callback_hook() {
    }
}
exports.NSS = NSS;

},{"../shared/shared_functions":20,"../shared/shared_structures":21,"../ssl_log":28,"../util/log":29}],26:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OpenSSL_BoringSSL = void 0;
const shared_functions_1 = require("../shared/shared_functions");
const ssl_log_1 = require("../ssl_log");
const log_1 = require("../util/log");
/**
 *
 * ToDO
 *  We need to find a way to calculate the offsets in a automated manner.
 *  Darwin: SSL_read/write need improvments
 *  Windows: how to extract the key material?
 *  Android: We need to find a way, when on some Android Apps the fd is below 0
 */
class OpenSSL_BoringSSL {
    moduleName;
    socket_library;
    passed_library_method_mapping;
    // global variables
    library_method_mapping = {};
    addresses;
    static SSL_SESSION_get_id;
    static SSL_CTX_set_keylog_callback;
    static SSL_get_fd;
    static SSL_get_session;
    static keylog_callback = new NativeCallback(function (ctxPtr, linePtr) {
        (0, log_1.devlog)("invoking keylog_callback from OpenSSL_BoringSSL");
        var message = {};
        message["contentType"] = "keylog";
        message["keylog"] = linePtr.readCString();
        send(message);
    }, "void", ["pointer", "pointer"]);
    constructor(moduleName, socket_library, passed_library_method_mapping) {
        this.moduleName = moduleName;
        this.socket_library = socket_library;
        this.passed_library_method_mapping = passed_library_method_mapping;
        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        }
        else {
            this.library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        }
        this.addresses = (0, shared_functions_1.readAddresses)(this.library_method_mapping);
        // @ts-ignore
        if (ssl_log_1.offsets != "{OFFSETS}" && ssl_log_1.offsets.openssl != null) {
            if (ssl_log_1.offsets.sockets != null) {
                const socketBaseAddress = (0, shared_functions_1.getBaseAddress)(socket_library);
                for (const method of Object.keys(ssl_log_1.offsets.sockets)) {
                    //@ts-ignore
                    this.addresses[`${method}`] = ssl_log_1.offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(ssl_log_1.offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(ssl_log_1.offsets.sockets[`${method}`].address));
                }
            }
            const libraryBaseAddress = (0, shared_functions_1.getBaseAddress)(moduleName);
            if (libraryBaseAddress == null)
                (0, log_1.log)("Unable to find library base address! Given address values will be interpreted as absolute ones!");
            for (const method of Object.keys(ssl_log_1.offsets.openssl)) {
                //@ts-ignore
                this.addresses[`${method}`] = ssl_log_1.offsets.openssl[`${method}`].absolute || libraryBaseAddress == null ? ptr(ssl_log_1.offsets.openssl[`${method}`].address) : libraryBaseAddress.add(ptr(ssl_log_1.offsets.openssl[`${method}`].address));
            }
        }
        OpenSSL_BoringSSL.SSL_SESSION_get_id = new NativeFunction(this.addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
        OpenSSL_BoringSSL.SSL_get_fd = ObjC.available ? new NativeFunction(this.addresses["BIO_get_fd"], "int", ["pointer"]) : new NativeFunction(this.addresses["SSL_get_fd"], "int", ["pointer"]);
        OpenSSL_BoringSSL.SSL_get_session = new NativeFunction(this.addresses["SSL_get_session"], "pointer", ["pointer"]);
    }
    install_plaintext_read_hook() {
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["SSL_read"], {
            onEnter: function (args) {
                this.fd = OpenSSL_BoringSSL.SSL_get_fd(args[0]);
                if (this.fd < 0) {
                    return;
                }
                var message = (0, shared_functions_1.getPortsAndAddresses)(this.fd, true, lib_addesses);
                message["ssl_session_id"] = OpenSSL_BoringSSL.getSslSessionId(args[0]);
                message["function"] = "SSL_read";
                this.message = message;
                this.buf = args[1];
            },
            onLeave: function (retval) {
                retval |= 0; // Cast retval to 32-bit integer.
                if (retval <= 0 || this.fd < 0) {
                    return;
                }
                this.message["contentType"] = "datalog";
                send(this.message, this.buf.readByteArray(retval));
            }
        });
    }
    install_plaintext_write_hook() {
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["SSL_write"], {
            onEnter: function (args) {
                if (!ObjC.available) {
                    this.fd = OpenSSL_BoringSSL.SSL_get_fd(args[0]);
                    if (this.fd < 0) {
                        return;
                    }
                    var message = (0, shared_functions_1.getPortsAndAddresses)(this.fd, false, lib_addesses);
                    message["ssl_session_id"] = OpenSSL_BoringSSL.getSslSessionId(args[0]);
                    message["function"] = "SSL_write";
                    message["contentType"] = "datalog";
                    send(message, args[1].readByteArray(parseInt(args[2])));
                } // this is a temporary workaround for the fd problem on iOS
            },
            onLeave: function (retval) {
            }
        });
    }
    install_tls_keys_callback_hook() {
        (0, log_1.log)("Error: TLS key extraction not implemented yet.");
    }
    /**
      * Get the session_id of SSL object and return it as a hex string.
      * @param {!NativePointer} ssl A pointer to an SSL object.
      * @return {dict} A string representing the session_id of the SSL object's
      *     SSL_SESSION. For example,
      *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
      */
    static getSslSessionId(ssl) {
        var session = OpenSSL_BoringSSL.SSL_get_session(ssl);
        if (session.isNull()) {
            (0, log_1.log)("Session is null");
            return 0;
        }
        var len_pointer = Memory.alloc(4);
        var p = OpenSSL_BoringSSL.SSL_SESSION_get_id(session, len_pointer);
        var len = len_pointer.readU32();
        var session_id = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
    }
}
exports.OpenSSL_BoringSSL = OpenSSL_BoringSSL;

},{"../shared/shared_functions":20,"../ssl_log":28,"../util/log":29}],27:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WolfSSL = void 0;
const shared_functions_1 = require("../shared/shared_functions");
const log_1 = require("../util/log");
const ssl_log_1 = require("../ssl_log");
class WolfSSL {
    moduleName;
    socket_library;
    passed_library_method_mapping;
    // global variables
    library_method_mapping = {};
    addresses;
    static wolfSSL_get_server_random;
    static wolfSSL_get_client_random;
    static wolfSSL_get_fd;
    static wolfSSL_get_session;
    static wolfSSL_SESSION_get_master_key;
    constructor(moduleName, socket_library, passed_library_method_mapping) {
        this.moduleName = moduleName;
        this.socket_library = socket_library;
        this.passed_library_method_mapping = passed_library_method_mapping;
        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        }
        else {
            this.library_method_mapping[`*${moduleName}*`] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_KeepArrays", "wolfSSL_SESSION_get_master_key", "wolfSSL_get_client_random", "wolfSSL_get_server_random"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        }
        this.addresses = (0, shared_functions_1.readAddresses)(this.library_method_mapping);
        // @ts-ignore
        if (ssl_log_1.offsets != "{OFFSETS}" && ssl_log_1.offsets.wolfssl != null) {
            if (ssl_log_1.offsets.sockets != null) {
                const socketBaseAddress = (0, shared_functions_1.getBaseAddress)(socket_library);
                for (const method of Object.keys(ssl_log_1.offsets.sockets)) {
                    //@ts-ignore
                    this.addresses[`${method}`] = ssl_log_1.offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(ssl_log_1.offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(ssl_log_1.offsets.sockets[`${method}`].address));
                }
            }
            const libraryBaseAddress = (0, shared_functions_1.getBaseAddress)(moduleName);
            if (libraryBaseAddress == null) {
                (0, log_1.log)("Unable to find library base address! Given address values will be interpreted as absolute ones!");
            }
            for (const method of Object.keys(ssl_log_1.offsets.wolfssl)) {
                //@ts-ignore
                this.addresses[`${method}`] = ssl_log_1.offsets.wolfssl[`${method}`].absolute || libraryBaseAddress == null ? ptr(ssl_log_1.offsets.wolfssl[`${method}`].address) : libraryBaseAddress.add(ptr(ssl_log_1.offsets.wolfssl[`${method}`].address));
            }
        }
        WolfSSL.wolfSSL_get_fd = new NativeFunction(this.addresses["wolfSSL_get_fd"], "int", ["pointer"]);
        WolfSSL.wolfSSL_get_session = new NativeFunction(this.addresses["wolfSSL_get_session"], "pointer", ["pointer"]);
    }
    install_tls_keys_callback_hook() {
        (0, log_1.log)("Error: TLS key extraction not implemented yet.");
    }
    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    static getSslSessionId(ssl) {
        var session = WolfSSL.wolfSSL_get_session(ssl);
        if (session.isNull()) {
            (0, log_1.log)("Session is null");
            return 0;
        }
        var p = session.add(8);
        var len = 32; // This comes from internals.h. It is untested!
        var session_id = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
    }
    install_plaintext_read_hook() {
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["wolfSSL_read"], {
            onEnter: function (args) {
                var message = (0, shared_functions_1.getPortsAndAddresses)(WolfSSL.wolfSSL_get_fd(args[0]), true, lib_addesses);
                message["function"] = "wolfSSL_read";
                message["ssl_session_id"] = WolfSSL.getSslSessionId(args[0]);
                this.message = message;
                this.buf = args[1];
            },
            onLeave: function (retval) {
                retval |= 0; // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return;
                }
                this.message["contentType"] = "datalog";
                send(this.message, this.buf.readByteArray(retval));
            }
        });
    }
    install_plaintext_write_hook() {
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["wolfSSL_write"], {
            onEnter: function (args) {
                var message = (0, shared_functions_1.getPortsAndAddresses)(WolfSSL.wolfSSL_get_fd(args[0]), false, lib_addesses);
                message["ssl_session_id"] = WolfSSL.getSslSessionId(args[0]);
                message["function"] = "wolfSSL_write";
                message["contentType"] = "datalog";
                send(message, args[1].readByteArray(parseInt(args[2])));
            },
            onLeave: function (retval) {
            }
        });
    }
}
exports.WolfSSL = WolfSSL;

},{"../shared/shared_functions":20,"../ssl_log":28,"../util/log":29}],28:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getOffsets = exports.experimental = exports.offsets = void 0;
const android_agent_1 = require("./android/android_agent");
const ios_agent_1 = require("./ios/ios_agent");
const macos_agent_1 = require("./macos/macos_agent");
const linux_agent_1 = require("./linux/linux_agent");
const windows_agent_1 = require("./windows/windows_agent");
const process_infos_1 = require("./util/process_infos");
const log_1 = require("./util/log");
//@ts-ignore
exports.offsets = "{OFFSETS}";
//@ts-ignore
exports.experimental = "{EXPERIMENTAL}";
/*

create the TLS library for your first prototpye as a lib in ./ssl_lib and than extend this class for the OS where this new lib was tested.

Further keep in mind, that properties of an class only visible inside the Interceptor-onEnter/onLeave scope when they are static.
As an alternative you could make a local variable inside the calling functions which holds an reference to the class property.

*/
function getOffsets() {
    return exports.offsets;
}
exports.getOffsets = getOffsets;
function load_os_specific_agent() {
    if ((0, process_infos_1.isWindows)()) {
        (0, log_1.log)('Running Script on Windows');
        (0, windows_agent_1.load_windows_hooking_agent)();
    }
    else if ((0, process_infos_1.isAndroid)()) {
        (0, log_1.log)('Running Script on Android');
        (0, android_agent_1.load_android_hooking_agent)();
    }
    else if ((0, process_infos_1.isLinux)()) {
        (0, log_1.log)('Running Script on Linux');
        (0, linux_agent_1.load_linux_hooking_agent)();
    }
    else if ((0, process_infos_1.isiOS)()) {
        (0, log_1.log)('Running Script on iOS');
        (0, ios_agent_1.load_ios_hooking_agent)();
    }
    else if ((0, process_infos_1.isMacOS)()) {
        (0, log_1.log)('Running Script on MacOS');
        (0, macos_agent_1.load_macos_hooking_agent)();
    }
    else {
        (0, log_1.log)('Running Script on unknown plattform');
        (0, log_1.log)("Error: not supported plattform!\nIf you want to have support for this plattform please make an issue at our github page.");
    }
}
load_os_specific_agent();

},{"./android/android_agent":1,"./ios/ios_agent":10,"./linux/linux_agent":13,"./macos/macos_agent":18,"./util/log":29,"./util/process_infos":30,"./windows/windows_agent":36}],29:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.devlog = exports.log = void 0;
function log(str) {
    var message = {};
    message["contentType"] = "console";
    message["console"] = str;
    send(message);
}
exports.log = log;
function devlog(str) {
    var message = {};
    message["contentType"] = "console_dev";
    message["console_dev"] = str;
    send(message);
}
exports.devlog = devlog;

},{}],30:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isWindows = exports.isLinux = exports.isMacOS = exports.isiOS = exports.isAndroid = exports.get_process_architecture = void 0;
function get_process_architecture() {
    return Process.arch;
}
exports.get_process_architecture = get_process_architecture;
function isAndroid() {
    if (Java.available && Process.platform == "linux") {
        try {
            Java.androidVersion; // this will raise an error when we are not under Android
            return true;
        }
        catch (error) {
            return false;
        }
    }
    else {
        return false;
    }
}
exports.isAndroid = isAndroid;
function isiOS() {
    if (get_process_architecture() === "arm64" && Process.platform == "darwin") {
        try {
            // check if iOS or MacOS (currently we handle MacOS with ARM Processor as an iOS device)
            return true;
        }
        catch (error) {
            return false;
        }
    }
    else {
        return false;
    }
}
exports.isiOS = isiOS;
function isMacOS() {
    if (get_process_architecture() === "x64" && Process.platform == "darwin") {
        return true;
    }
    else {
        return false;
    }
}
exports.isMacOS = isMacOS;
function isLinux() {
    if (Process.platform == "linux") {
        if (Java.available == false && Process.platform == "linux") {
            return true;
        }
        else {
            try {
                Java.androidVersion; // this will raise an error when we are not under Android
                return false;
            }
            catch (error) {
                return true;
            }
        }
    }
    else {
        return false;
    }
}
exports.isLinux = isLinux;
function isWindows() {
    if (Process.platform == "windows") {
        return true;
    }
    else {
        return false;
    }
}
exports.isWindows = isWindows;

},{}],31:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.gnutls_execute = exports.GnuTLS_Windows = void 0;
const gnutls_1 = require("../ssl_lib/gnutls");
const windows_agent_1 = require("./windows_agent");
class GnuTLS_Windows extends gnutls_1.GnuTLS {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        //this.install_tls_keys_callback_hook();
    }
    install_tls_keys_callback_hook() {
        //Not implemented yet
    }
}
exports.GnuTLS_Windows = GnuTLS_Windows;
function gnutls_execute(moduleName) {
    var gnu_ssl = new GnuTLS_Windows(moduleName, windows_agent_1.socket_library);
    gnu_ssl.execute_hooks();
}
exports.gnutls_execute = gnutls_execute;

},{"../ssl_lib/gnutls":22,"./windows_agent":36}],32:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mbedTLS_execute = exports.mbed_TLS_Windows = void 0;
const mbedTLS_1 = require("../ssl_lib/mbedTLS");
const windows_agent_1 = require("./windows_agent");
class mbed_TLS_Windows extends mbedTLS_1.mbed_TLS {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        super(moduleName, socket_library);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    /*
    SSL_CTX_set_keylog_callback not exported by default on windows.

    We need to find a way to install the callback function for doing that

    Alternatives?:SSL_export_keying_material, SSL_SESSION_get_master_key
    */
    install_tls_keys_callback_hook() {
        // install hooking for windows
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
    }
}
exports.mbed_TLS_Windows = mbed_TLS_Windows;
function mbedTLS_execute(moduleName) {
    var mbedTLS_ssl = new mbed_TLS_Windows(moduleName, windows_agent_1.socket_library);
    mbedTLS_ssl.execute_hooks();
}
exports.mbedTLS_execute = mbedTLS_execute;

},{"../ssl_lib/mbedTLS":24,"./windows_agent":36}],33:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nss_execute = exports.NSS_Windows = void 0;
const nss_1 = require("../ssl_lib/nss");
const windows_agent_1 = require("./windows_agent");
class NSS_Windows extends nss_1.NSS {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        var library_method_mapping = {};
        library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity"];
        // library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"]
        library_method_mapping["*ssl*.dll"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"];
        super(moduleName, socket_library, library_method_mapping);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    install_tls_keys_callback_hook() {
        // TBD
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        // this.install_tls_keys_callback_hook(); needs to be implemented
    }
}
exports.NSS_Windows = NSS_Windows;
function nss_execute(moduleName) {
    var nss_ssl = new NSS_Windows(moduleName, windows_agent_1.socket_library);
    nss_ssl.execute_hooks();
}
exports.nss_execute = nss_execute;

},{"../ssl_lib/nss":25,"./windows_agent":36}],34:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.boring_execute = exports.OpenSSL_BoringSSL_Windows = void 0;
const openssl_boringssl_1 = require("../ssl_lib/openssl_boringssl");
const windows_agent_1 = require("./windows_agent");
class OpenSSL_BoringSSL_Windows extends openssl_boringssl_1.OpenSSL_BoringSSL {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        let mapping = {};
        mapping[`${moduleName}`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new"];
        mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        super(moduleName, socket_library, mapping);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    /*
    SSL_CTX_set_keylog_callback not exported by default on windows.

    We need to find a way to install the callback function for doing that

    Alternatives?:SSL_export_keying_material, SSL_SESSION_get_master_key
    */
    install_tls_keys_callback_hook() {
        // install hooking for windows
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
    }
}
exports.OpenSSL_BoringSSL_Windows = OpenSSL_BoringSSL_Windows;
function boring_execute(moduleName) {
    var boring_ssl = new OpenSSL_BoringSSL_Windows(moduleName, windows_agent_1.socket_library);
    boring_ssl.execute_hooks();
}
exports.boring_execute = boring_execute;

},{"../ssl_lib/openssl_boringssl":26,"./windows_agent":36}],35:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sspi_execute = exports.SSPI_Windows = void 0;
const shared_functions_1 = require("../shared/shared_functions");
const windows_agent_1 = require("./windows_agent");
const log_1 = require("../util/log");
const ssl_log_1 = require("../ssl_log");
/*
ToDo:
- Write Test Client for ground truth and test everything
- Obtain information from the running process to get the socket information instead of using default values
*/
var keylog = (key, tlsVersion) => {
    (0, log_1.devlog)(`[*] Exporting TLS 1.${tlsVersion} handshake keying material`);
    var message = {};
    message["contentType"] = "keylog";
    message["keylog"] = key;
    send(message);
};
// This library is only existend under Windows therefore there is no Superclass
class SSPI_Windows {
    moduleName;
    socket_library;
    // global variables
    library_method_mapping = {};
    addresses;
    constructor(moduleName, socket_library) {
        this.moduleName = moduleName;
        this.socket_library = socket_library;
        this.library_method_mapping[`*${moduleName}*`] = ["DecryptMessage", "EncryptMessage", "SslHashHandshake", "SslGenerateMasterKey", "SslImportMasterKey", "SslGenerateSessionKeys", "SslExpandTrafficKeys", "SslExpandExporterMasterKey"];
        this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        this.addresses = (0, shared_functions_1.readAddresses)(this.library_method_mapping);
        // @ts-ignore
        if (ssl_log_1.offsets != "{OFFSETS}" && ssl_log_1.offsets.gnutls != null) {
            if (ssl_log_1.offsets.sockets != null) {
                const socketBaseAddress = (0, shared_functions_1.getBaseAddress)(socket_library);
                for (const method of Object.keys(ssl_log_1.offsets.sockets)) {
                    //@ts-ignore
                    this.addresses[`${method}`] = ssl_log_1.offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(ssl_log_1.offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(ssl_log_1.offsets.sockets[`${method}`].address));
                }
            }
            const libraryBaseAddress = (0, shared_functions_1.getBaseAddress)(moduleName);
            if (libraryBaseAddress == null) {
                (0, log_1.log)("Unable to find library base address! Given address values will be interpreted as absolute ones!");
            }
            for (const method of Object.keys(ssl_log_1.offsets.gnutls)) {
                //@ts-ignore
                this.addresses[`${method}`] = ssl_log_1.offsets.gnutls[`${method}`].absolute || libraryBaseAddress == null ? ptr(ssl_log_1.offsets.gnutls[`${method}`].address) : libraryBaseAddress.add(ptr(ssl_log_1.offsets.gnutls[`${method}`].address));
            }
        }
    }
    install_plaintext_read_hook() {
        Interceptor.attach(this.addresses["DecryptMessage"], {
            onEnter: function (args) {
                this.pMessage = args[1];
            },
            onLeave: function () {
                this.cBuffers = this.pMessage.add(4).readULong(); //unsigned long cBuffers (Count of buffers)
                this.pBuffers = this.pMessage.add(8).readPointer(); //PSecBuffer  pBuffers (Pointer to array of secBuffers)
                //https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
                //One SecBuffer got 16 Bytes (unsigned long + unsigned long + pointer (64 Bit))
                //--> Bytes to read: cBuffers + 16 Bytes
                this.secBuffers = []; //Addresses of all secBuffers
                for (let i = 0; i < this.cBuffers; i++) {
                    var secBuffer = this.pBuffers.add(i * 16);
                    this.secBuffers.push(secBuffer);
                }
                for (let i = 0; i < this.secBuffers.length; i++) {
                    var size = this.secBuffers[i].add(0).readULong();
                    var type = this.secBuffers[i].add(4).readULong();
                    var bufferPointer = this.secBuffers[i].add(8).readPointer();
                    if (type == 1) {
                        //TODO: Obtain information from the running process to get the socket information
                        var bytes = bufferPointer.readByteArray(size);
                        var message = {};
                        message["ss_family"] = "AF_INET";
                        message["src_port"] = 444;
                        message["src_addr"] = 222;
                        message["dst_port"] = 443;
                        message["dst_addr"] = 222;
                        message["function"] = "DecryptMessage";
                        message["contentType"] = "datalog";
                        message["ssl_session_id"] = 10;
                        send(message, bytes);
                    }
                }
            }
        });
    }
    install_plaintext_write_hook() {
        Interceptor.attach(this.addresses["EncryptMessage"], {
            onEnter: function (args) {
                this.pMessage = args[2]; //PSecBufferDesc pMessage (https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbufferdesc)
                this.cBuffers = this.pMessage.add(4).readULong(); //unsigned long cBuffers (Count of buffers)
                this.pBuffers = this.pMessage.add(8).readPointer(); //PSecBuffer  pBuffers (Pointer to array of secBuffers)
                //https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
                //One SecBuffer got 16 Bytes (unsigned long + unsigned long + pointer (64 Bit))
                //--> Bytes to read: cBuffers + 16 Bytes
                this.secBuffers = []; //Addresses of all secBuffers
                for (let i = 0; i < this.cBuffers; i++) {
                    var secBuffer = this.pBuffers.add(i * 16);
                    this.secBuffers.push(secBuffer);
                }
                for (let i = 0; i < this.secBuffers.length; i++) {
                    var size = this.secBuffers[i].add(0).readULong();
                    var type = this.secBuffers[i].add(4).readULong();
                    var bufferPointer = this.secBuffers[i].add(8).readPointer();
                    if (type == 1) {
                        //TODO: Obtain information from the running process
                        var bytes = bufferPointer.readByteArray(size);
                        var message = {};
                        message["ss_family"] = "AF_INET";
                        message["src_port"] = 443;
                        message["src_addr"] = 222;
                        message["dst_port"] = 444;
                        message["dst_addr"] = 222;
                        message["function"] = "EncryptMessage";
                        message["contentType"] = "datalog";
                        message["ssl_session_id"] = 10;
                        send(message, bytes);
                    }
                }
            }
        });
    }
    install_tls_keys_hook() {
        /* Most of the following code fragments were copied from
         * https://github.com/ngo/win-frida-scripts/tree/master/lsasslkeylog-easy
        */
        var client_randoms = {};
        var buf2hex = function (buffer) {
            return Array.prototype.map.call(new Uint8Array(buffer), function (x) { return ('00' + x.toString(16)).slice(-2); }).join('');
        };
        /* ----- TLS1.2-specific ----- */
        var parse_h_master_key = function (pMasterKey) {
            var NcryptSslKey_ptr = pMasterKey; // NcryptSslKey
            var ssl5_ptr = NcryptSslKey_ptr.add(0x10).readPointer();
            var master_key = ssl5_ptr.add(28).readByteArray(48);
            return buf2hex(master_key);
        };
        var parse_parameter_list = function (pParameterList, calling_func) {
            /*
                typedef struct _NCryptBufferDesc {
                    ULONG         ulVersion;
                    ULONG         cBuffers;
                    PNCryptBuffer pBuffers;
                } NCryptBufferDesc, *PNCryptBufferDesc;
                typedef struct _NCryptBuffer {
                    ULONG cbBuffer;
                    ULONG BufferType;
                    PVOID pvBuffer;
                } NCryptBuffer, *PNCryptBuffer;
             */
            var buffer_count = pParameterList.add(4).readU32();
            var buffers = pParameterList.add(8).readPointer();
            for (var i = 0; i < buffer_count; i++) {
                var buf = buffers.add(16 * i);
                var buf_size = buf.readU32();
                var buf_type = buf.add(4).readU32();
                var buf_buf = buf.add(8).readPointer().readByteArray(buf_size);
                // For buf_type values see NCRYPTBUFFER_SSL_* constans in ncrypt.h
                if (buf_type == 20) { // NCRYPTBUFFER_SSL_CLIENT_RANDOM
                    (0, log_1.devlog)("Got client random from " + calling_func + "'s pParameterList: " + buf2hex(buf_buf));
                    return buf2hex(buf_buf);
                }
                //console.log("buf_type " + buf_type);
            }
            return null;
        };
        if (this.addresses["SslHashHandshake"] != null)
            Interceptor.attach(this.addresses["SslHashHandshake"], {
                onEnter: function (args) {
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/sslhashhandshake
                    var buf = ptr(args[2]);
                    var len = args[3].toInt32();
                    var mem = buf.readByteArray(len);
                    var msg_type = buf.readU8();
                    var version = buf.add(4).readU16();
                    if (msg_type == 1 && version == 0x0303) {
                        // If we have client random, save it tied to current thread
                        var crandom = buf2hex(buf.add(6).readByteArray(32));
                        (0, log_1.devlog)("[*] Got client random from SslHashHandshake: " + crandom);
                        client_randoms[this.threadId] = crandom;
                    }
                },
                onLeave: function (retval) {
                }
            });
        if (this.addresses["SslGenerateMasterKey"] != null)
            Interceptor.attach(this.addresses["SslGenerateMasterKey"], {
                onEnter: function (args) {
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratemasterkey
                    this.phMasterKey = ptr(args[3]);
                    this.hSslProvider = ptr(args[0]);
                    this.pParameterList = ptr(args[6]);
                    this.client_random = parse_parameter_list(this.pParameterList, 'SslGenerateMasterKey') || client_randoms[this.threadId] || "???";
                },
                onLeave: function (retval) {
                    var master_key = parse_h_master_key(this.phMasterKey.readPointer());
                    (0, log_1.devlog)("[*] Got masterkey from SslGenerateMasterKey");
                    keylog("CLIENT_RANDOM " + this.client_random + " " + master_key, 2 /* TLSVersion.ONE_TWO */);
                }
            });
        if (this.addresses["SslImportMasterKey"] != null)
            Interceptor.attach(this.addresses["SslImportMasterKey"], {
                onEnter: function (args) {
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/sslimportmasterkey
                    this.phMasterKey = ptr(args[2]);
                    this.pParameterList = ptr(args[5]);
                    // Get client random from the pParameterList, and if that fails - from the value saved by SslHashHandshake handler
                    this.client_random = parse_parameter_list(this.pParameterList, 'SslImportMasterKey') || client_randoms[this.threadId] || "???";
                },
                onLeave: function (retval) {
                    var master_key = parse_h_master_key(this.phMasterKey.readPointer());
                    (0, log_1.devlog)("[*] Got masterkey from SslImportMasterKey");
                    keylog("CLIENT_RANDOM " + this.client_random + " " + master_key, 2 /* TLSVersion.ONE_TWO */);
                }
            });
        if (this.addresses["SslGenerateSessionKeys"] != null)
            Interceptor.attach(this.addresses["SslGenerateSessionKeys"], {
                onEnter: function (args) {
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratesessionkeys
                    this.hMasterKey = ptr(args[1]);
                    this.hSslProvider = ptr(args[0]);
                    this.pParameterList = ptr(args[4]);
                    this.client_random = parse_parameter_list(this.pParameterList, 'SslGenerateSessionKeys') || client_randoms[this.threadId] || "???";
                    var master_key = parse_h_master_key(this.hMasterKey);
                    (0, log_1.devlog)("[*] Got masterkey from SslGenerateSessionKeys");
                    keylog("CLIENT_RANDOM " + this.client_random + " " + master_key, 2 /* TLSVersion.ONE_TWO */);
                },
                onLeave: function (retval) {
                }
            });
        /* ----- TLS1.3-specific ----- */
        var stages = {};
        var get_secret_from_BDDD = function (struct_BDDD) {
            var struct_3lss = struct_BDDD.add(0x10).readPointer();
            var struct_RUUU = struct_3lss.add(0x20).readPointer();
            var struct_YKSM = struct_RUUU.add(0x10).readPointer();
            var secret_ptr = struct_YKSM.add(0x18).readPointer();
            var size = struct_YKSM.add(0x10).readU32();
            return secret_ptr.readByteArray(size);
        };
        if (this.addresses["SslExpandTrafficKeys"] != null)
            Interceptor.attach(this.addresses["SslExpandTrafficKeys"], {
                onEnter: function (args) {
                    this.retkey1 = ptr(args[3]);
                    this.retkey2 = ptr(args[4]);
                    this.client_random = client_randoms[this.threadId] || "???";
                    if (stages[this.threadId]) {
                        stages[this.threadId] = null;
                        this.suffix = "TRAFFIC_SECRET_0";
                    }
                    else {
                        stages[this.threadId] = "handshake";
                        this.suffix = "HANDSHAKE_TRAFFIC_SECRET";
                    }
                },
                onLeave: function (retval) {
                    var key1 = get_secret_from_BDDD(this.retkey1.readPointer());
                    var key2 = get_secret_from_BDDD(this.retkey2.readPointer());
                    keylog("CLIENT_" + this.suffix + " " + this.client_random + " " + buf2hex(key1), 3 /* TLSVersion.ONE_THREE */);
                    keylog("SERVER_" + this.suffix + " " + this.client_random + " " + buf2hex(key2), 3 /* TLSVersion.ONE_THREE */);
                }
            });
        if (this.addresses["SslExpandExporterMasterKey"] != null)
            Interceptor.attach(this.addresses["SslExpandExporterMasterKey"], {
                onEnter: function (args) {
                    this.retkey = ptr(args[3]);
                    this.client_random = client_randoms[this.threadId] || "???";
                },
                onLeave: function (retval) {
                    var key = this.retkey.readPointer().add(0x10).readPointer().add(0x20).readPointer().add(0x10).readPointer().add(0x18).readPointer().readByteArray(48);
                    keylog("EXPORTER_SECRET " + this.client_random + " " + buf2hex(key), 3 /* TLSVersion.ONE_THREE */);
                }
            });
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        if (ssl_log_1.experimental) {
            this.install_tls_keys_hook();
        }
    }
}
exports.SSPI_Windows = SSPI_Windows;
function sspi_execute(moduleName) {
    var sspi_ssl = new SSPI_Windows(moduleName, windows_agent_1.socket_library);
    sspi_ssl.execute_hooks();
}
exports.sspi_execute = sspi_execute;

},{"../shared/shared_functions":20,"../ssl_log":28,"../util/log":29,"./windows_agent":36}],36:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.load_windows_hooking_agent = exports.socket_library = void 0;
const shared_structures_1 = require("../shared/shared_structures");
const log_1 = require("../util/log");
const shared_functions_1 = require("../shared/shared_functions");
const sspi_1 = require("./sspi");
const openssl_boringssl_windows_1 = require("./openssl_boringssl_windows");
const gnutls_windows_1 = require("./gnutls_windows");
const mbedTLS_windows_1 = require("./mbedTLS_windows");
const nss_windows_1 = require("./nss_windows");
const wolfssl_windows_1 = require("./wolfssl_windows");
var plattform_name = "windows";
var moduleNames = (0, shared_functions_1.getModuleNames)();
exports.socket_library = "WS2_32.dll";
function hook_Windows_Dynamic_Loader(module_library_mapping) {
    try {
        const resolver = new ApiResolver('module');
        var loadLibraryExW = resolver.enumerateMatches("exports:KERNELBASE.dll!*LoadLibraryExW");
        if (loadLibraryExW.length == 0)
            return console.log("[-] Missing windows dynamic loader!");
        Interceptor.attach(loadLibraryExW[0].address, {
            onLeave(retval) {
                let map = new ModuleMap();
                let moduleName = map.findName(retval);
                if (moduleName === null)
                    return;
                for (let map of module_library_mapping[plattform_name]) {
                    let regex = map[0];
                    let func = map[1];
                    if (regex.test(moduleName)) {
                        (0, log_1.log)(`${moduleName} was loaded & will be hooked on Windows!`);
                        func(moduleName);
                    }
                }
            }
        });
        console.log("[*] Windows dynamic loader hooked.");
    }
    catch (error) {
        (0, log_1.devlog)("Loader error: " + error);
        (0, log_1.log)("No dynamic loader present for hooking.");
    }
}
function hook_Windows_SSL_Libs(module_library_mapping) {
    (0, shared_functions_1.ssl_library_loader)(plattform_name, module_library_mapping, moduleNames, "Windows");
}
function load_windows_hooking_agent() {
    shared_structures_1.module_library_mapping[plattform_name] = [[/^(libssl|LIBSSL)-[0-9]+(_[0-9]+)?\.dll$/, openssl_boringssl_windows_1.boring_execute], [/^.*(wolfssl|WOLFSSL).*\.dll$/, wolfssl_windows_1.wolfssl_execute], [/^.*(libgnutls|LIBGNUTLS)-[0-9]+\.dll$/, gnutls_windows_1.gnutls_execute], [/^(nspr|NSPR)[0-9]*\.dll/, nss_windows_1.nss_execute], [/(sspicli|SSPICLI)\.dll$/, sspi_1.sspi_execute], [/mbedTLS\.dll/, mbedTLS_windows_1.mbedTLS_execute]];
    hook_Windows_SSL_Libs(shared_structures_1.module_library_mapping);
    hook_Windows_Dynamic_Loader(shared_structures_1.module_library_mapping);
}
exports.load_windows_hooking_agent = load_windows_hooking_agent;

},{"../shared/shared_functions":20,"../shared/shared_structures":21,"../util/log":29,"./gnutls_windows":31,"./mbedTLS_windows":32,"./nss_windows":33,"./openssl_boringssl_windows":34,"./sspi":35,"./wolfssl_windows":37}],37:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.wolfssl_execute = exports.WolfSSL_Windows = void 0;
const wolfssl_1 = require("../ssl_lib/wolfssl");
const windows_agent_1 = require("./windows_agent");
const log_1 = require("../util/log");
class WolfSSL_Windows extends wolfssl_1.WolfSSL {
    moduleName;
    socket_library;
    constructor(moduleName, socket_library) {
        let mapping = {};
        mapping[`${moduleName}`] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_KeepArrays"];
        mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        super(moduleName, socket_library, mapping);
        this.moduleName = moduleName;
        this.socket_library = socket_library;
    }
    install_tls_keys_callback_hook() {
        (0, log_1.log)("Key extraction currently not implemented for windows!");
    }
    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        //this.install_tls_keys_callback_hook(); currently not implemented
    }
}
exports.WolfSSL_Windows = WolfSSL_Windows;
function wolfssl_execute(moduleName) {
    var wolf_ssl = new WolfSSL_Windows(moduleName, windows_agent_1.socket_library);
    wolf_ssl.execute_hooks();
}
exports.wolfssl_execute = wolfssl_execute;

},{"../ssl_lib/wolfssl":27,"../util/log":29,"./windows_agent":36}]},{},[28])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCIuLi9hZ2VudC9hbmRyb2lkL2FuZHJvaWRfYWdlbnQudHMiLCIuLi9hZ2VudC9hbmRyb2lkL2FuZHJvaWRfamF2YV90bHNfbGlicy50cyIsIi4uL2FnZW50L2FuZHJvaWQvYm91bmN5Y2FzdGxlLnRzIiwiLi4vYWdlbnQvYW5kcm9pZC9jb25zY3J5cHQudHMiLCIuLi9hZ2VudC9hbmRyb2lkL2dudXRsc19hbmRyb2lkLnRzIiwiLi4vYWdlbnQvYW5kcm9pZC9tYmVkVExTX2FuZHJvaWQudHMiLCIuLi9hZ2VudC9hbmRyb2lkL25zc19hbmRyb2lkLnRzIiwiLi4vYWdlbnQvYW5kcm9pZC9vcGVuc3NsX2JvcmluZ3NzbF9hbmRyb2lkLnRzIiwiLi4vYWdlbnQvYW5kcm9pZC93b2xmc3NsX2FuZHJvaWQudHMiLCIuLi9hZ2VudC9pb3MvaW9zX2FnZW50LnRzIiwiLi4vYWdlbnQvaW9zL29wZW5zc2xfYm9yaW5nc3NsX2lvcy50cyIsIi4uL2FnZW50L2xpbnV4L2dudXRsc19saW51eC50cyIsIi4uL2FnZW50L2xpbnV4L2xpbnV4X2FnZW50LnRzIiwiLi4vYWdlbnQvbGludXgvbWJlZFRMU19saW51eC50cyIsIi4uL2FnZW50L2xpbnV4L25zc19saW51eC50cyIsIi4uL2FnZW50L2xpbnV4L29wZW5zc2xfYm9yaW5nc3NsX2xpbnV4LnRzIiwiLi4vYWdlbnQvbGludXgvd29sZnNzbF9saW51eC50cyIsIi4uL2FnZW50L21hY29zL21hY29zX2FnZW50LnRzIiwiLi4vYWdlbnQvbWFjb3Mvb3BlbnNzbF9ib3Jpbmdzc2xfbWFjb3MudHMiLCIuLi9hZ2VudC9zaGFyZWQvc2hhcmVkX2Z1bmN0aW9ucy50cyIsIi4uL2FnZW50L3NoYXJlZC9zaGFyZWRfc3RydWN0dXJlcy50cyIsIi4uL2FnZW50L3NzbF9saWIvZ251dGxzLnRzIiwiLi4vYWdlbnQvc3NsX2xpYi9qYXZhX3NzbF9saWJzLnRzIiwiLi4vYWdlbnQvc3NsX2xpYi9tYmVkVExTLnRzIiwiLi4vYWdlbnQvc3NsX2xpYi9uc3MudHMiLCIuLi9hZ2VudC9zc2xfbGliL29wZW5zc2xfYm9yaW5nc3NsLnRzIiwiLi4vYWdlbnQvc3NsX2xpYi93b2xmc3NsLnRzIiwiLi4vYWdlbnQvc3NsX2xvZy50cyIsIi4uL2FnZW50L3V0aWwvbG9nLnRzIiwiLi4vYWdlbnQvdXRpbC9wcm9jZXNzX2luZm9zLnRzIiwiLi4vYWdlbnQvd2luZG93cy9nbnV0bHNfd2luZG93cy50cyIsIi4uL2FnZW50L3dpbmRvd3MvbWJlZFRMU193aW5kb3dzLnRzIiwiLi4vYWdlbnQvd2luZG93cy9uc3Nfd2luZG93cy50cyIsIi4uL2FnZW50L3dpbmRvd3Mvb3BlbnNzbF9ib3Jpbmdzc2xfd2luZG93cy50cyIsIi4uL2FnZW50L3dpbmRvd3Mvc3NwaS50cyIsIi4uL2FnZW50L3dpbmRvd3Mvd2luZG93c19hZ2VudC50cyIsIi4uL2FnZW50L3dpbmRvd3Mvd29sZnNzbF93aW5kb3dzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7O0FDQUEsbUVBQXFFO0FBQ3JFLGlFQUFnRjtBQUNoRixxQ0FBMEM7QUFDMUMscURBQWtEO0FBQ2xELHVEQUFvRDtBQUNwRCwrQ0FBNEM7QUFDNUMsdURBQW9EO0FBQ3BELDJFQUE2RDtBQUM3RCxtRUFBc0Q7QUFHdEQsSUFBSSxjQUFjLEdBQUcsT0FBTyxDQUFDO0FBQzdCLElBQUksV0FBVyxHQUFrQixJQUFBLGlDQUFjLEdBQUUsQ0FBQztBQUVyQyxRQUFBLGNBQWMsR0FBRyxNQUFNLENBQUE7QUFFcEMsU0FBUyxrQkFBa0I7SUFDdkIsSUFBQSxvQ0FBWSxHQUFFLENBQUM7QUFDbkIsQ0FBQztBQUVELFNBQVMsMkJBQTJCLENBQUMsc0JBQW1GO0lBQ3BILElBQUk7UUFDSixNQUFNLFdBQVcsR0FBRyxlQUFlLENBQUE7UUFDbkMsTUFBTSxLQUFLLEdBQUcsV0FBVyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsRUFBRSxDQUFD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QVcsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxPQUFPLEVBQUU7WUFDeEUsV0FBVyxFQUFFLFVBQVUsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFdBQVcsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsT0FBTyxFQUFFO1lBQzlFLE1BQU0sRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxXQUFXLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxXQUFXLEVBQUU7WUFDakYsTUFBTSxFQUFFLFVBQVUsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFdBQVcsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUMsV0FBVyxFQUFFO1lBQ3ZHLGNBQWMsRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxXQUFXLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQyxXQUFXLEVBQUU7WUFDbkgsS0FBSyxFQUFFLFVBQVUsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFFBQVEsSUFBSSxTQUFTLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsV0FBVyxFQUFFO1lBRTVFLFVBQVUsRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxXQUFXLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQyxX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
