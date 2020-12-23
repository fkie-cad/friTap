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

},{"./log":3,"./shared":6}],2:[function(require,module,exports){
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

},{"./log":3}],3:[function(require,module,exports){
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

},{}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
/*
SSL_ImportFD === SSL_NEW


*/
//GLOBALS
const AF_INET = 2;
const AF_INET6 = 100;
function execute() {
    var library_method_mapping = {};
    library_method_mapping["*libssl*"] = ["SSL_ImportFD", "SSL_GetSessionID"];
    library_method_mapping["*libnspr*"] = ["PR_Write", "PR_Read", "PR_SetEnv", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName"];
    library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    var addresses = shared_1.readAddresses(library_method_mapping);
    var SSL_get_fd = new NativeFunction(addresses["PR_FileDesc2NativeHandle"], "int", ["pointer"]);
    var SET_NSS_ENV = new NativeFunction(addresses["PR_SetEnv"], "pointer", ["pointer"]);
    var SSL_SESSION_get_id = new NativeFunction(addresses["SSL_GetSessionID"], "pointer", ["pointer"]);
    //var SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"])
    var getsockname = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetSockName'), "int", ["pointer", "pointer"]);
    var getpeername = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetPeerName'), "int", ["pointer", "pointer"]);
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
        //var getpeername = new NativeFunction(methodAddresses["PR_GetPeerName"], "int", ["pointer", "pointer"])
        //var getsockname = new NativeFunction(methodAddresses["PR_GetSockName"], "int", ["pointer", "pointer"])
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
            this.fd = args[0];
            this.buf = args[1];
        },
        onLeave: function (retval) {
            //log("write")
            retval |= 0; // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return;
            }
            var addr = Memory.alloc(8);
            getpeername(this.fd, addr);
            if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                var message = getPortsAndAddressesFromNSS(this.fd, true, addresses);
                message["ssl_session_id"] = getSslSessionId(this.fd);
                message["function"] = "NSS_read";
                this.message = message;
                this.message["contentType"] = "datalog";
                send(this.message, this.buf.readByteArray(retval));
            }
        }
    });
    Interceptor.attach(addresses["PR_Write"], {
        onEnter: function (args) {
            //log("write")
            var addr = Memory.alloc(8);
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

},{"./log":3,"./shared":6}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute() {
    var library_method_mapping = {};
    library_method_mapping["*libssl*"] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback", "SSL_get_SSL_CTX"];
    library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    var addresses = shared_1.readAddresses(library_method_mapping);
    var SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
    var SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
    var SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
    var SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
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
            var keylog_callback = new NativeCallback(function (ctxPtr, linePtr) {
                var message = {};
                message["contentType"] = "keylog";
                message["keylog"] = linePtr.readCString();
                send(message);
            }, "void", ["pointer", "pointer"]);
            SSL_CTX_set_keylog_callback(args[0], keylog_callback);
        }
    });
}
exports.execute = execute;

},{"./log":3,"./shared":6}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAttribute = exports.byteArrayToNumber = exports.reflectionByteArrayToString = exports.byteArrayToString = exports.getPortsAndAddresses = exports.readAddresses = void 0;
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
                send("Found " + library_name + "!" + method);
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
    log_1.log("using strange");
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
            log_1.log("writing socket");
            log_1.log(sockfd.toString());
            getsockname(sockfd, addr, addrlen);
        }
        else {
            log_1.log("reading socket");
            log_1.log(sockfd.toString());
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
            log_1.log("addr.readU16() ==");
            log_1.log(addr.readU16().toString());
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

},{"./log":3}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const openssl_boringssl_1 = require("./openssl_boringssl");
const wolfssl_1 = require("./wolfssl");
const bouncycastle_1 = require("./bouncycastle");
const conscrypt_1 = require("./conscrypt");
const nss_1 = require("./nss");
const log_1 = require("./log");
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
var moduleNames = [];
Process.enumerateModules().forEach(item => moduleNames.push(item.name));
for (var mod of moduleNames) {
    if (mod.indexOf("libssl.so") >= 0) {
        if (hasRequiredFunctions(mod, "SSL_read")) {
            log_1.log("OpenSSL/BoringSSL detected.");
            openssl_boringssl_1.execute();
        }
        break;
    }
}
for (var mod of moduleNames) {
    if (mod.indexOf("libwolfssl.so") >= 0) {
        log_1.log("WolfSSL detected.");
        wolfssl_1.execute();
        break;
    }
}
for (var mod of moduleNames) {
    if (mod.indexOf("libnspr") >= 0) {
        log_1.log("NSS SSL detected.");
        nss_1.execute();
        break;
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
//Hook the dynamic loader, in case library gets loaded at a later point in time
//check wether we are on android or linux
try {
    let dl_exports = Process.getModuleByName("libdl.so").enumerateExports();
    var dlopen = "dlopen";
    for (var ex of dl_exports) {
        if (ex.name === "android_dlopen_ext") {
            dlopen = "android_dlopen_ext";
            break;
        }
    }
    Interceptor.attach(Module.getExportByName("libdl.so", dlopen), {
        onEnter: function (args) {
            this.moduleName = args[0].readCString();
        },
        onLeave: function (retval) {
            if (this.moduleName != undefined) {
                if (this.moduleName.endsWith("libssl.so")) {
                    log_1.log("OpenSSL/BoringSSL detected.");
                    openssl_boringssl_1.execute();
                }
                else if (this.moduleName.endsWith("libwolfssl.so")) {
                    log_1.log("WolfSSL detected.");
                    wolfssl_1.execute();
                }
            }
        }
    });
}
catch (error) {
    log_1.log("No dynamic loader present for hooking.");
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

},{"./bouncycastle":1,"./conscrypt":2,"./log":3,"./nss":4,"./openssl_boringssl":5,"./wolfssl":8}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute() {
    var library_method_mapping = {};
    library_method_mapping["*libwolfssl*"] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_SESSION_get_master_key", "wolfSSL_get_client_random", "wolfSSL_KeepArrays"];
    library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    var addresses = shared_1.readAddresses(library_method_mapping);
    var wolfSSL_get_fd = new NativeFunction(addresses["wolfSSL_get_fd"], "int", ["pointer"]);
    var wolfSSL_get_session = new NativeFunction(addresses["wolfSSL_get_session"], "pointer", ["pointer"]);
    var wolfSSL_SESSION_get_master_key = new NativeFunction(addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"]);
    var wolfSSL_get_client_random = new NativeFunction(addresses["wolfSSL_get_client_random"], "int", ["pointer", "pointer", "uint"]);
    var wolfSSL_KeepArrays = new NativeFunction(addresses["wolfSSL_KeepArrays"], "void", ["pointer"]);
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
    function getMasterKey(wolfSslPtr) {
        var session = wolfSSL_get_session(wolfSslPtr);
        var nullPtr = ptr(0);
        var masterKeySize = wolfSSL_SESSION_get_master_key(session, nullPtr, 0);
        var buffer = Memory.alloc(masterKeySize);
        wolfSSL_SESSION_get_master_key(session, buffer, masterKeySize);
        var masterKey = "";
        for (var i = 0; i < masterKeySize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.
            masterKey +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return masterKey;
    }
    /**
       * Get the clientRandom of the current session and return it as a hex string.
       * @param {!NativePointer} wolfSslPtr A pointer to an SSL object.
       * @return {string} A string representing the clientRandom of the SSL object's
       *     current session. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getClientRandom(wolfSslPtr) {
        var nullPtr = ptr(0);
        var clientRandomSize = wolfSSL_get_client_random(wolfSslPtr, nullPtr, 0);
        var buffer = Memory.alloc(clientRandomSize);
        console.log(wolfSSL_get_client_random(wolfSslPtr, buffer, clientRandomSize));
        var clientRandom = "";
        for (var i = 0; i < clientRandomSize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.
            clientRandom +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return clientRandom;
    }
    Interceptor.attach(addresses["wolfSSL_read"], {
        onEnter: function (args) {
            var message = shared_1.getPortsAndAddresses(wolfSSL_get_fd(args[0]), true, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
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
            var clientRandom = getClientRandom(this.wolfSslPtr);
            var masterKey = getMasterKey(this.wolfSslPtr);
            var message = {};
            message["contentType"] = "keylog";
            message["keylog"] = "CLIENT_RANDOM " + clientRandom + " " + masterKey;
            send(message);
        }
    });
}
exports.execute = execute;

},{"./log":3,"./shared":6}]},{},[7])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL21heF9zdHVmZi9mcmlkYS1jb21waWxlL25vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9ib3VuY3ljYXN0bGUudHMiLCJhZ2VudC9jb25zY3J5cHQudHMiLCJhZ2VudC9sb2cudHMiLCJhZ2VudC9uc3MudHMiLCJhZ2VudC9vcGVuc3NsX2JvcmluZ3NzbC50cyIsImFnZW50L3NoYXJlZC50cyIsImFnZW50L3NzbF9sb2cudHMiLCJhZ2VudC93b2xmc3NsLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7O0FDQUEsK0JBQTJCO0FBQzNCLHFDQUEwRztBQUcxRyxTQUFnQixPQUFPO0lBQ25CLElBQUksQ0FBQyxPQUFPLENBQUM7UUFFVCwwRkFBMEY7UUFDMUYsZ0VBQWdFO1FBQ2hFLElBQUksYUFBYSxHQUFHLElBQUksQ0FBQyxHQUFHLENBQUMsa0VBQWtFLENBQUMsQ0FBQTtRQUNoRyxhQUFhLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxJQUFJLEVBQUUsS0FBSyxFQUFFLEtBQUssQ0FBQyxDQUFDLGNBQWMsR0FBRyxVQUFVLEdBQVEsRUFBRSxNQUFXLEVBQUUsR0FBUTtZQUN2RyxJQUFJLE1BQU0sR0FBa0IsRUFBRSxDQUFDO1lBQy9CLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxHQUFHLEVBQUUsRUFBRSxDQUFDLEVBQUU7Z0JBQzFCLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxHQUFHLElBQUksQ0FBQyxDQUFDO2FBQzlCO1lBQ0QsSUFBSSxPQUFPLEdBQTJCLEVBQUUsQ0FBQTtZQUN4QyxPQUFPLENBQUMsYUFBYSxDQUFDLEdBQUcsU0FBUyxDQUFBO1lBQ2xDLE9BQU8sQ0FBQyxVQUFVLENBQUMsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxZQUFZLEVBQUUsQ0FBQTtZQUN0RCxPQUFPLENBQUMsVUFBVSxDQUFDLEdB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QUMsQ0FBQyxDQUFDLEdBQUcsT0FBTyxDQUFDLEdBQUcsS0FBSyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxFQUFFLENBQVcsQ0FBQTtnQkFDdEUsT0FBTyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsR0FBRyxPQUFPLENBQUMsR0FBRyxLQUFLLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLEVBQUUsQ0FBVyxDQUFBO2dCQUN0RSxPQUFPLENBQUMsV0FBVyxDQUFDLEdBQUcsU0FBUyxDQUFBO2FBQ25DO2lCQUFNLElBQUksSUFBSSxDQUFDLE9BQU8sRUFBRSxJQUFJLFFBQVEsRUFBRTtnQkFDbkMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsR0FBRyxPQUFPLENBQUMsR0FBRyxLQUFLLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLEVBQUUsQ0FBVyxDQUFBO2dCQUN0RSxPQUFPLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxHQUFHLEVBQUUsQ0FBQTtnQkFDbEMsSUFBSSxTQUFTLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQTtnQkFDM0IsS0FBSyxJQUFJLE1BQU0sR0FBRyxDQUFDLEVBQUUsTUFBTSxHQUFHLEVBQUUsRUFBRSxNQUFNLElBQUksQ0FBQyxFQUFFO29CQUMzQyxPQUFPLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxJQUFJLENBQUMsR0FBRyxHQUFHLFNBQVMsQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsTUFBTSxFQUFFLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUE7aUJBQ2hIO2dCQUNELElBQUksT0FBTyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsR0FBRyxPQUFPLENBQUMsQ0FB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Q0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLGVBQWUsQ0FBQyxFQUN6QztRQUNJLE9BQU8sRUFBRSxVQUFVLElBQVM7WUFDeEIsSUFBSSxPQUFPLEdBQUcsNkJBQW9CLENBQUMsY0FBYyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBVyxFQUFFLEtBQUssRUFBRSxTQUFTLENBQUMsQ0FBQTtZQUN2RixPQUFPLENBQUMsZ0JBQWdCLENBQUMsR0FBRyxlQUFlLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFDcEQsT0FBTyxDQUFDLFVBQVUsQ0FBQyxHQUFHLGVBQWUsQ0FBQTtZQUNyQyxPQUFPLENBQUMsYUFBYSxDQUFDLEdBQUcsU0FBUyxDQUFBO1lBQ2xDLElBQUksQ0FBQyxPQUFPLEVBQUUsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO1FBQzNELENBQUM7UUFDRCxPQUFPLEVBQUUsVUFBVSxNQUFXO1FBQzlCLENBQUM7S0FDSixDQUFDLENBQUE7SUFHTixXQUFXLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxpQkFBaUIsQ0FBQyxFQUMzQztRQUNJLE9BQU8sRUFBRSxVQUFVLElBQVM7WUFFeEIsSUFBSSxDQUFDLFVBQVUsR0FBRyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFDekIsa0JBQWtCLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFBO1FBQ3ZDLENBQUM7UUFDRCxPQUFPLEVBQUUsVUFBVSxNQUFXO1lBQzFCLElBQUksWUFBWSxHQUFHLGVBQWUsQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUE7WUFDbkQsSUFBSSxTQUFTLEdBQUcsWUFBWSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQTtZQUM3QyxJQUFJLE9BQU8sR0FBMkIsRUFBRSxDQUFBO1lBQ3hDLE9BQU8sQ0FBQyxhQUFhLENBQUMsR0FBRyxRQUFRLENBQUE7WUFDakMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxHQUFHLGdCQUFnQixHQUFHLFlBQVksR0FBRyxHQUFHLEdBQUcsU0FBUyxDQUFBO1lBQ3JFLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQTtRQUVqQixDQUFDO0tBQ0osQ0FBQyxDQUFBO0FBR1YsQ0FBQztBQTlJRCwwQkE4SUMiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
