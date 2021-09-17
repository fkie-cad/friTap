(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const log_1 = require("./log");
const shared_1 = require("./shared");
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
                message["src_addr"] = shared_1.byteArrayToNumber(localAddress);
                message["dst_addr"] = shared_1.byteArrayToNumber(inetAddress);
                message["ss_family"] = "AF_INET";
            }
            else {
                message["src_addr"] = shared_1.byteArrayToString(localAddress);
                message["dst_addr"] = shared_1.byteArrayToString(inetAddress);
                message["ss_family"] = "AF_INET6";
            }
            message["ssl_session_id"] = shared_1.byteArrayToString(this.this$0.value.getConnection().getSession().getId());
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
                message["src_addr"] = shared_1.byteArrayToNumber(inetAddress);
                message["dst_addr"] = shared_1.byteArrayToNumber(localAddress);
                message["ss_family"] = "AF_INET";
            }
            else {
                message["src_addr"] = shared_1.byteArrayToString(inetAddress);
                message["dst_addr"] = shared_1.byteArrayToString(localAddress);
                message["ss_family"] = "AF_INET6";
            }
            message["ssl_session_id"] = shared_1.byteArrayToString(this.this$0.value.getConnection().getSession().getId());
            log_1.log(message["ssl_session_id"]);
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
            var masterSecretObj = shared_1.getAttribute(securityParameters, "masterSecret");
            //The key is in the AbstractTlsSecret, so we need to access the superclass to get the field
            var clazz = Java.use("java.lang.Class");
            var masterSecretRawField = Java.cast(masterSecretObj.getClass(), clazz).getSuperclass().getDeclaredField("data");
            masterSecretRawField.setAccessible(true);
            var masterSecretReflectArray = masterSecretRawField.get(masterSecretObj);
            var message = {};
            message["contentType"] = "keylog";
            message["keylog"] = "CLIENT_RANDOM " + shared_1.byteArrayToString(clientRandom) + " " + shared_1.reflectionByteArrayToString(masterSecretReflectArray);
            send(message);
            return this.notifyHandshakeComplete(x);
        };
    });
}
exports.execute = execute;
},{"./log":4,"./shared":7}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const log_1 = require("./log");
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
                log_1.log("Process is loading ProviderInstallerImpl");
                var providerInstallerImpl = findProviderInstallerFromClassloaders(javaClassLoader, backupImplementation);
                if (providerInstallerImpl === null) {
                    log_1.log("ProviderInstallerImpl could not be found, although it has been loaded");
                }
                else {
                    providerInstallerImpl.insertProvider.implementation = function () {
                        log_1.log("ProviderinstallerImpl redirection/blocking");
                    };
                }
            }
            return retval;
        };
        /*
        //Do the same for second overload of javaClassLoader
        var backupImplementation = javaClassLoader.loadClass.overload("java.lang.String", "boolean").implementation
        //The classloader for ProviderInstallerImpl might not be present on startup, so we hook the loadClass method.
        javaClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = function (className: string, resolve: boolean) {
            if (className.endsWith("ProviderInstallerImpl")) {
                log("Process is loading ProviderInstallerImpl (Method 2)")
                var providerInstallerImpl = findProviderInstallerFromClassloaders(javaClassLoader, backupImplementation)
                if (providerInstallerImpl === null) {
                    log("ProviderInstallerImpl could not be found, although it has been loaded")
                } else {
                    providerInstallerImpl.insertProvider.implementation = function () {
                        log("ProviderinstallerImpl redirection/blocking")

                    }

                }
            }
            return this.loadClass(className, resolve)
        }
        */
        //Part two: Hook Providerinstaller
        try {
            var providerInstaller = Java.use("com.google.android.gms.security.ProviderInstaller");
            providerInstaller.installIfNeeded.implementation = function (context) {
                log_1.log("Providerinstaller redirection/blocking");
            };
            providerInstaller.installIfNeededAsync.implementation = function (context, callback) {
                log_1.log("Providerinstaller redirection/blocking");
                callback.onProviderInstalled();
            };
        }
        catch (error) {
            // As it is not available, do nothing
        }
    });
}
exports.execute = execute;
},{"./log":4}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute(moduleName) {
    var socket_library = "";
    switch (Process.platform) {
        case "linux":
            socket_library = "libc";
            break;
        case "windows":
            socket_library = "WS2_32.dll";
            break;
        case "darwin":
            //TODO:Darwin implementation pending...
            break;
        default:
            log_1.log(`Platform "${Process.platform} currently not supported!`);
    }
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["gnutls_record_recv", "gnutls_record_send", "gnutls_session_set_keylog_function", "gnutls_transport_get_int", "gnutls_session_get_id", "gnutls_init", "gnutls_handshake", "gnutls_session_get_keylog_function", "gnutls_session_get_random"];
    //? Just in case darwin methods are different to linux and windows ones
    if (socket_library === "libc" || socket_library === "WS2_32.dll") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = shared_1.readAddresses(library_method_mapping);
    const gnutls_transport_get_int = new NativeFunction(addresses["gnutls_transport_get_int"], "int", ["pointer"]);
    const gnutls_session_get_id = new NativeFunction(addresses["gnutls_session_get_id"], "int", ["pointer", "pointer", "pointer"]);
    const gnutls_session_set_keylog_function = new NativeFunction(addresses["gnutls_session_set_keylog_function"], "void", ["pointer", "pointer"]);
    const gnutls_session_get_random = new NativeFunction(addresses["gnutls_session_get_random"], "pointer", ["pointer", "pointer", "pointer"]);
    const keylog_callback = new NativeCallback(function (session, label, secret) {
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
        gnutls_session_get_random(session, client_random_ptr, server_random_ptr);
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
    function getSslSessionId(session) {
        var len_pointer = Memory.alloc(4);
        var err = gnutls_session_get_id(session, NULL, len_pointer);
        if (err != 0) {
            return "";
        }
        var len = len_pointer.readU32();
        var p = Memory.alloc(len);
        err = gnutls_session_get_id(session, p, len_pointer);
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
    Interceptor.attach(addresses["gnutls_record_recv"], {
        onEnter: function (args) {
            var message = shared_1.getPortsAndAddresses(gnutls_transport_get_int(args[0]), true, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
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
    Interceptor.attach(addresses["gnutls_record_send"], {
        onEnter: function (args) {
            var message = shared_1.getPortsAndAddresses(gnutls_transport_get_int(args[0]), false, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
            message["function"] = "SSL_write";
            message["contentType"] = "datalog";
            send(message, args[1].readByteArray(parseInt(args[2])));
        },
        onLeave: function (retval) {
        }
    });
    Interceptor.attach(addresses["gnutls_init"], {
        onEnter: function (args) {
            this.session = args[0];
        },
        onLeave: function (retval) {
            gnutls_session_set_keylog_function(this.session.readPointer(), keylog_callback);
        }
    });
}
exports.execute = execute;
},{"./log":4,"./shared":7}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.log = void 0;
function log(str) {
    var message = {};
    message["contentType"] = "console";
    message["console"] = str;
    send(message);
}
exports.log = log;
},{}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = exports.getSSLLibrary = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
/*
SSL_ImportFD === SSL_NEW
*/
//GLOBALS
const AF_INET = 2;
const AF_INET6 = 100;
// Exported for use in openssl_boringssl.ts
function getSSLLibrary() {
    var moduleNames = shared_1.getModuleNames();
    //TODO: CONTINUE
}
exports.getSSLLibrary = getSSLLibrary;
function execute(moduleName) {
    var socket_library = shared_1.getSocketLibrary();
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_SetEnv", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName"];
    library_method_mapping[Process.platform === "linux" ? "*libssl*.so" : "*ssl*.dll"] = ["SSL_ImportFD", "SSL_GetSessionID"];
    //? Just in case darwin methods are different to linux and windows ones
    if (Process.platform === "linux" || Process.platform === "windows") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = shared_1.readAddresses(library_method_mapping);
    const SSL_get_fd = new NativeFunction(addresses["PR_FileDesc2NativeHandle"], "int", ["pointer"]);
    const SET_NSS_ENV = new NativeFunction(addresses["PR_SetEnv"], "pointer", ["pointer"]);
    const SSL_SESSION_get_id = new NativeFunction(addresses["SSL_GetSessionID"], "pointer", ["pointer"]);
    //var SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"])
    const getsockname = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetSockName'), "int", ["pointer", "pointer"]); //? Why libnspr4.so?
    const getpeername = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetPeerName'), "int", ["pointer", "pointer"]); //? Why libnspr4.so?
    //Commented out for testing purposes on Linux
    //const getsockname = new NativeFunction(addresses["PR_GetSockName"], "int", ["pointer", "pointer"]);
    //const getpeername = new NativeFunction(addresses["PR_GetPeerName"], "int", ["pointer", "pointer"]);
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
    function getPortsAndAddressesFromNSS(sockfd, isRead, methodAddresses) {
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
            if (addr.readU16() == AF_INET) {
                message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
                message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32());
                message["ss_family"] = "AF_INET";
            }
            else if (addr.readU16() == AF_INET6) {
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
                //FIXME: Sometimes addr.readU16() will be 0, thus this error will be thrown. Why isnt this the case on linux? Something windows specific?
                throw "Only supporting IPv4/6";
            }
        }
        return message;
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
       * };
       *
       *
       */
    function getSslSessionId(sslSessionIdSECItem) {
        if (sslSessionIdSECItem == null) {
            log_1.log("Session is null");
            return 0;
        }
        var session_id = "";
        /*var a = Memory.dup(sslSessionIdSECItem, 32)
        log(hexdump(a))*/
        //var type_field = sslSessionIdSECItem.readByteArray(1) // enum should be the same size as char => 1 byte
        //session_id = sslSessionIdSECItem.add(1+Process.pointerSize).readPointer().readUtf8String() || "";
        var session_id_ptr = sslSessionIdSECItem.add(8).readPointer();
        var len_tmp = sslSessionIdSECItem.add(16).readU32();
        var len = (len_tmp > 32) ? 32 : len_tmp;
        var session_id = "";
        var b = Memory.dup(sslSessionIdSECItem, 32);
        /*log(hexdump(b))
        log("lenght value")
        log(len.toString());*/
        for (var i = 8; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + session_id_ptr.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
    }
    Interceptor.attach(addresses["PR_Read"], {
        onEnter: function (args) {
            this.fd = ptr(args[0]);
            this.buf = ptr(args[1]);
        },
        onLeave: function (retval) {
            if (retval.toInt32() <= 0) {
                return;
            }
            var addr = Memory.alloc(128);
            var res = getpeername(this.fd, addr); //FIXME: Results in crash! Fix: More Memory: why? Fix: 128 Bytes for addr (libnspr4 needed 8 Bytes for that)
            //!Der getpeername call gibt bei mir -1 zurück. Wenn ich mir die Daten unte in dem else ausgeben lasse, dann sehen die aber top aus!
            console.log(res);
            if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                var message = getPortsAndAddressesFromNSS(this.fd, true, addresses);
                //console.log("Session ID: ", getSslSessionId(this.fd))
                message["ssl_session_id"] = getSslSessionId(this.fd);
                message["function"] = "NSS_read";
                this.message = message;
                this.message["contentType"] = "datalog";
                var data = this.buf.readByteArray((new Uint32Array([retval]))[0]);
                //console.log(this.message)
                //send(this.message, data)
            }
            else {
                var temp = this.buf.readByteArray((new Uint32Array([retval]))[0]);
                console.log(temp);
            }
        }
    });
    Interceptor.attach(addresses["PR_Write"], {
        onEnter: function (args) {
            var addr = Memory.alloc(128);
            getsockname(args[0], addr);
            if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                var message = getPortsAndAddressesFromNSS(args[0], false, addresses);
                message["ssl_session_id"] = getSslSessionId(args[0]);
                message["function"] = "NSS_write";
                message["contentType"] = "datalog";
                send(message, args[1].readByteArray(parseInt(args[2])));
            }
        },
        onLeave: function (retval) {
        }
    });
    Interceptor.attach(addresses["SSL_ImportFD"], {
        onEnter: function (args) {
            var keylog = Memory.allocUtf8String("SSLKEYLOGFILE=keylogfile");
            SET_NSS_ENV(keylog);
        }
    });
}
exports.execute = execute;
},{"./log":4,"./shared":7}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute(moduleName) {
    var socket_library = "";
    switch (Process.platform) {
        case "linux":
            socket_library = "libc";
            break;
        case "windows":
            socket_library = "WS2_32.dll";
            break;
        case "darwin":
            //TODO:Darwin implementation pending...
            break;
        default:
            log_1.log(`Platform "${Process.platform} currently not supported!`);
    }
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback", "SSL_get_SSL_CTX"];
    //? Just in case darwin methods are different to linux and windows ones
    if (socket_library === "libc" || socket_library === "WS2_32.dll") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = shared_1.readAddresses(library_method_mapping);
    const SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
    const SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
    const SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
    const SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
    const keylog_callback = new NativeCallback(function (ctxPtr, linePtr) {
        var message = {};
        message["contentType"] = "keylog";
        message["keylog"] = linePtr.readCString();
        send(message);
    }, "void", ["pointer", "pointer"]);
    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getSslSessionId(ssl) {
        var session = SSL_get_session(ssl);
        if (session.isNull()) {
            log_1.log("Session is null");
            return 0;
        }
        var len_pointer = Memory.alloc(4);
        var p = SSL_SESSION_get_id(session, len_pointer);
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
    Interceptor.attach(addresses["SSL_read"], {
        onEnter: function (args) {
            var message = shared_1.getPortsAndAddresses(SSL_get_fd(args[0]), true, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
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
    Interceptor.attach(addresses["SSL_write"], {
        onEnter: function (args) {
            var message = shared_1.getPortsAndAddresses(SSL_get_fd(args[0]), false, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
            message["function"] = "SSL_write";
            message["contentType"] = "datalog";
            send(message, args[1].readByteArray(parseInt(args[2])));
        },
        onLeave: function (retval) {
        }
    });
    Interceptor.attach(addresses["SSL_new"], {
        onEnter: function (args) {
            SSL_CTX_set_keylog_callback(args[0], keylog_callback);
        }
    });
}
exports.execute = execute;
},{"./log":4,"./shared":7}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAttribute = exports.byteArrayToNumber = exports.reflectionByteArrayToString = exports.byteArrayToString = exports.getPortsAndAddresses = exports.readAddresses = exports.getModuleNames = exports.getSocketLibrary = void 0;
const log_1 = require("./log");
/**
 * This file contains methods which are shared for reading
 * secrets/data from different libraries. These methods are
 * indipendent from the implementation of ssl/tls, but they depend
 * on libc.
 */
//GLOBALS
const AF_INET = 2;
const AF_INET6 = 10;
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
            return "";
            //TODO:Darwin implementation pending...
            break;
        default:
            log_1.log(`Platform "${Process.platform} currently not supported!`);
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
            if (matches.length == 0) {
                throw "Could not find " + library_name + "!" + method;
            }
            else {
                //log("Found " + method + " " + matches[0].address)
            }
            if (matches.length == 0) {
                throw "Could not find " + library_name + "!" + method;
            }
            else if (matches.length != 1) {
                // Sometimes Frida returns duplicates.
                var address = null;
                var s = "";
                var duplicates_only = true;
                for (var k = 0; k < matches.length; k++) {
                    if (s.length != 0) {
                        s += ", ";
                    }
                    s += matches[k].name + "@" + matches[k].address;
                    if (address == null) {
                        address = matches[k].address;
                    }
                    else if (!address.equals(matches[k].address)) {
                        duplicates_only = false;
                    }
                }
                if (!duplicates_only) {
                    throw "More than one match found for " + library_name + "!" + method + ": " +
                        s;
                }
            }
            addresses[method.toString()] = matches[0].address;
        });
    }
    return addresses;
}
exports.readAddresses = readAddresses;
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
            getsockname(sockfd, addr, addrlen);
        }
        else {
            getpeername(sockfd, addr, addrlen);
        }
        if (addr.readU16() == AF_INET) {
            message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
            message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32());
            message["ss_family"] = "AF_INET";
        }
        else if (addr.readU16() == AF_INET6) {
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
},{"./log":4}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const openssl_boringssl_1 = require("./openssl_boringssl");
const wolfssl_1 = require("./wolfssl");
const bouncycastle_1 = require("./bouncycastle");
const conscrypt_1 = require("./conscrypt");
const sspi_1 = require("./sspi");
const nss_1 = require("./nss");
const gnutls_1 = require("./gnutls");
const log_1 = require("./log");
const shared_1 = require("./shared");
// sometimes libraries loaded but don't have function implemented we need to hook
function hasRequiredFunctions(libName, expectedFuncName) {
    var functionList = Process.getModuleByName(libName).enumerateExports().filter(exports => exports.name.toLowerCase().includes(expectedFuncName));
    if (functionList.length == 0) {
        return false;
    }
    else {
        return true;
    }
}
var moduleNames = shared_1.getModuleNames();
var module_library_mapping = {};
module_library_mapping["windows"] = [[/libssl-[0-9]+(_[0-9]+)?\.dll/, openssl_boringssl_1.execute], [/.*wolfssl.*\.dll/, wolfssl_1.execute], [/.*libgnutls-[0-9]+\.dll/, gnutls_1.execute], [/nspr[0-9]*\.dll/, nss_1.execute], [/sspicli\.dll/i, sspi_1.execute]];
module_library_mapping["linux"] = [[/.*libssl\.so/, openssl_boringssl_1.execute], [/.*libgnutls\.so/, gnutls_1.execute], [/.*libwolfssl\.so/, wolfssl_1.execute], [/.*libnspr[0-9]?\.so/, nss_1.execute]];
if (Process.platform === "windows") {
    for (let map of module_library_mapping["windows"]) {
        let regex = map[0];
        let func = map[1];
        for (let module of moduleNames) {
            //console.log(module + "vs" + map[0])
            if (regex.test(module)) {
                log_1.log(`${module} found & will be hooked on Windows!`);
                func(module);
            }
        }
    }
}
if (Process.platform === "linux") {
    for (let map of module_library_mapping["linux"]) {
        let regex = map[0];
        let func = map[1];
        for (let module of moduleNames) {
            if (regex.test(module)) {
                log_1.log(`${module} found & will be hooked on Linux!`);
                func(module);
            }
        }
    }
}
if (Java.available) {
    Java.perform(function () {
        try {
            //If we can load a class of spongycastle, we know its present and we have to hook it
            var testLoad = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect");
            log_1.log("Bouncycastle/Spongycastle detected.");
            bouncycastle_1.execute();
        }
        catch (error) {
            //On error, just do nothing
        }
    });
}
//Hook the dynamic loaders, in case library gets loaded at a later point in time
//! Repeated module loading results in multiple intereceptions. This will cause multiple log entries if module is loaded into the same address space 
try {
    switch (Process.platform) {
        case "windows":
            hookWindowsDynamicLoader();
            break;
        case "linux":
            hookLinuxDynamicLoader();
            break;
        default:
            console.log("Missing dynamic loader hook implementation!");
    }
}
catch (error) {
    console.log("Loader error: ", error);
    log_1.log("No dynamic loader present for hooking.");
}
function hookLinuxDynamicLoader() {
    const regex_libdl = /.*libdl.*\.so/;
    const libdl = moduleNames.find(element => element.match(regex_libdl));
    if (libdl === undefined)
        throw "Linux Dynamic loader not found!";
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
                if (this.moduleName.endsWith("libssl.so")) {
                    log_1.log("OpenSSL/BoringSSL detected.");
                    openssl_boringssl_1.execute("libssl");
                }
                else if (this.moduleName.endsWith("libwolfssl.so")) {
                    log_1.log("WolfSSL detected.");
                    wolfssl_1.execute("libwolfssl");
                }
            }
        }
    });
    console.log(`[*] ${dlopen.indexOf("android") == -1 ? "Linux" : "Android"} dynamic loader hooked.`);
}
function hookWindowsDynamicLoader() {
    const resolver = new ApiResolver('module');
    var loadLibraryExW = resolver.enumerateMatches("exports:KERNELBASE.dll!*LoadLibraryExW");
    if (loadLibraryExW.length == 0)
        return console.log("[!] Missing windows dynamic loader!");
    Interceptor.attach(loadLibraryExW[0].address, {
        onLeave(retval) {
            let map = new ModuleMap();
            let moduleName = map.findName(retval);
            if (moduleName === null)
                return;
            if (moduleName.indexOf("libssl-1_1.dll") != -1) {
                log_1.log("OpenSSL/BoringSSL detected.");
                openssl_boringssl_1.execute("libssl-1_1.dll");
            }
            //TODO:More module comparisons
        }
    });
    console.log("[*] Windows dynamic loader hooked.");
}
if (Java.available) {
    Java.perform(function () {
        //Conscrypt needs early instrumentation as we block the provider installation
        var Security = Java.use("java.security.Security");
        if (Security.getProviders().toString().includes("GmsCore_OpenSSL")) {
            log_1.log("WARNING: PID " + Process.id + " Detected GmsCore_OpenSSL Provider. This can be a bit unstable. If you having issues, rerun with -spawn for early instrumentation. Trying to remove it to fall back on default Provider");
            Security.removeProvider("GmsCore_OpenSSL");
            log_1.log("Removed GmsCore_OpenSSL");
        }
        //As the classloader responsible for loading ProviderInstaller sometimes is not present from the beginning on,
        //we always have to watch the classloader activity
        conscrypt_1.execute();
        //Now do the same for Ssl_guard
        if (Security.getProviders().toString().includes("Ssl_Guard")) {
            log_1.log("Ssl_Guard deteced, removing it to fall back on default Provider");
            Security.removeProvider("Ssl_Guard");
            log_1.log("Removed Ssl_Guard");
        }
        //Same thing for Conscrypt provider which has been manually inserted (not by providerinstaller)
        if (Security.getProviders().toString().includes("Conscrypt version")) {
            log_1.log("Conscrypt detected");
            Security.removeProvider("Conscrypt");
            log_1.log("Removed Conscrypt");
        }
        //Uncomment this line to show all remaining providers
        //log("Remaining: " + Security.getProviders().toString())
        //Hook insertProviderAt/addprovider for dynamic provider blocking
        Security.insertProviderAt.implementation = function (provider, position) {
            if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                log_1.log("Blocking provider registration of " + provider.getName());
                return position;
            }
            else {
                return this.insertProviderAt(provider, position);
            }
        };
        //Same for addProvider
        Security.insertProviderAt.implementation = function (provider) {
            if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                log_1.log("Blocking provider registration of " + provider.getName());
                return 1;
            }
            else {
                return this.addProvider(provider);
            }
        };
    });
}
},{"./bouncycastle":1,"./conscrypt":2,"./gnutls":3,"./log":4,"./nss":5,"./openssl_boringssl":6,"./shared":7,"./sspi":9,"./wolfssl":10}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
/*
SspiCli.dll!DecryptMessage called!
ncrypt.dll!SslDecryptPacket called!
bcrypt.dll!BCryptDecrypt called!
*/
function execute(moduleName) {
    var socket_library = shared_1.getSocketLibrary();
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["DecryptMessage", "EncryptMessage"];
    //? Just in case darwin methods are different to linux and windows ones
    if (Process.platform === "linux" || Process.platform === "windows") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = shared_1.readAddresses(library_method_mapping);
    Interceptor.attach(addresses["DecryptMessage"], {
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
                    console.log(bytes);
                    send(message, bytes);
                }
            }
        }
    });
    Interceptor.attach(addresses["EncryptMessage"], {
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
exports.execute = execute;
},{"./shared":7}],10:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute(moduleName) {
    var socket_library = "";
    switch (Process.platform) {
        case "linux":
            socket_library = "libc";
            break;
        case "windows":
            socket_library = "WS2_32.dll";
            break;
        case "darwin":
            //TODO:Darwin implementation pending...
            break;
        default:
            log_1.log(`Platform "${Process.platform} currently not supported!`);
    }
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_KeepArrays"];
    //? Just in case darwin methods are different to linux and windows ones
    if (socket_library === "libc" || socket_library === "WS2_32.dll") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = shared_1.readAddresses(library_method_mapping);
    const wolfSSL_get_fd = new NativeFunction(addresses["wolfSSL_get_fd"], "int", ["pointer"]);
    const wolfSSL_get_session = new NativeFunction(addresses["wolfSSL_get_session"], "pointer", ["pointer"]);
    //const wolfSSL_SESSION_get_master_key = new NativeFunction(addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"])
    //const wolfSSL_get_client_random = new NativeFunction(addresses["wolfSSL_get_client_random"], "int", ["pointer", "pointer", "uint"])
    const wolfSSL_KeepArrays = new NativeFunction(addresses["wolfSSL_KeepArrays"], "void", ["pointer"]);
    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getSslSessionId(ssl) {
        var session = wolfSSL_get_session(ssl);
        if (session.isNull()) {
            log_1.log("Session is null");
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
    /**
       * Get the masterKey of the current session and return it as a hex string.
       * @param {!NativePointer} wolfSslPtr A pointer to an SSL object.
       * @return {string} A string representing the masterKey of the SSL object's
       *     current session. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    /*function getMasterKey(wolfSslPtr: NativePointer) {
        var session = wolfSSL_get_session(wolfSslPtr)
        var nullPtr = ptr(0)
        var masterKeySize = wolfSSL_SESSION_get_master_key(session, nullPtr, 0) as number
        var buffer = Memory.alloc(masterKeySize)
        wolfSSL_SESSION_get_master_key(session, buffer, masterKeySize)

        var masterKey = ""
        for (var i = 0; i < masterKeySize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.

            masterKey +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return masterKey;
    }
    */
    /**
       * Get the clientRandom of the current session and return it as a hex string.
       * @param {!NativePointer} wolfSslPtr A pointer to an SSL object.
       * @return {string} A string representing the clientRandom of the SSL object's
       *     current session. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    /*function getClientRandom(wolfSslPtr: NativePointer) {
        var nullPtr = ptr(0)
        var clientRandomSize = wolfSSL_get_client_random(wolfSslPtr, nullPtr, 0) as number
        var buffer = Memory.alloc(clientRandomSize)
        //console.log(wolfSSL_get_client_random(wolfSslPtr, buffer, clientRandomSize))

        var clientRandom = ""
        for (var i = 0; i < clientRandomSize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.

            clientRandom +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return clientRandom;
    }
    */
    Interceptor.attach(addresses["wolfSSL_read"], {
        onEnter: function (args) {
            var message = shared_1.getPortsAndAddresses(wolfSSL_get_fd(args[0]), true, addresses);
            message["function"] = "wolfSSL_read";
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
    Interceptor.attach(addresses["wolfSSL_write"], {
        onEnter: function (args) {
            var message = shared_1.getPortsAndAddresses(wolfSSL_get_fd(args[0]), false, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
            message["function"] = "wolfSSL_write";
            message["contentType"] = "datalog";
            send(message, args[1].readByteArray(parseInt(args[2])));
        },
        onLeave: function (retval) {
        }
    });
    Interceptor.attach(addresses["wolfSSL_connect"], {
        onEnter: function (args) {
            this.wolfSslPtr = args[0];
            wolfSSL_KeepArrays(this.wolfSslPtr);
        },
        onLeave: function (retval) {
            //var clientRandom = getClientRandom(this.wolfSslPtr)
            //var masterKey = getMasterKey(this.wolfSslPtr)
            var message = {};
            message["contentType"] = "keylog";
            //message["keylog"] = "CLIENT_RANDOM " + clientRandom + " " + masterKey
            send(message);
        }
    });
}
exports.execute = execute;
},{"./log":4,"./shared":7}]},{},[8])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL0FwcERhdGEvUm9hbWluZy9ucG0vbm9kZV9tb2R1bGVzL2ZyaWRhLWNvbXBpbGUvbm9kZV9tb2R1bGVzL2Jyb3dzZXItcGFjay9fcHJlbHVkZS5qcyIsImFnZW50L2JvdW5jeWNhc3RsZS50cyIsImFnZW50L2NvbnNjcnlwdC50cyIsImFnZW50L2dudXRscy50cyIsImFnZW50L2xvZy50cyIsImFnZW50L25zcy50cyIsImFnZW50L29wZW5zc2xfYm9yaW5nc3NsLnRzIiwiYWdlbnQvc2hhcmVkLnRzIiwiYWdlbnQvc3NsX2xvZy50cyIsImFnZW50L3NzcGkudHMiLCJhZ2VudC93b2xmc3NsLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7O0FDQUEsK0JBQTJCO0FBQzNCLHFDQUEwRztBQUMxRyxTQUFnQixPQUFPO0lBQ25CLElBQUksQ0FBQyxPQUFPLENBQUM7UUFFVCwwRkFBMEY7UUFDMUYsZ0VBQWdFO1FBQ2hFLElBQUksYUFBYSxHQUFHLElBQUksQ0FBQyxHQUFHLENBQUMsa0VBQWtFLENBQUMsQ0FBQTtRQUNoRyxhQUFhLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxJQUFJLEVBQUUsS0FBSyxFQUFFLEtBQUssQ0FBQyxDQUFDLGNBQWMsR0FBRyxVQUFVLEdBQVEsRUFBRSxNQUFXLEVBQUUsR0FBUTtZQUN2RyxJQUFJLE1BQU0sR0FBa0IsRUFBRSxDQUFDO1lBQy9CLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxHQUFHLEVBQUUsRUFBRSxDQUFDLEVBQUU7Z0JBQzFCLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxHQUFHLElBQUksQ0FBQyxDQUFDO2FBQzlCO1lBQ0QsSUFBSSxPQUFPLEdBQTJCLEVBQUUsQ0FBQTtZQUN4QyxPQUFPLENBQUMsYUFBYSxDQUFDLEdBQUcsU0FBUyxDQUFBO1lBQ2xDLE9BQU8sQ0FBQyxVQUFVLENBQUMsR0FBRyxJQUFJLENBQUMs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
