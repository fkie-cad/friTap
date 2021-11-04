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
},{"./log":4,"./shared":8}],2:[function(require,module,exports){
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
},{"./log":4,"./shared":8}],4:[function(require,module,exports){
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
exports.execute = void 0;
const shared_1 = require("./shared");
var getSocketDescriptor = function (sslcontext) {
    console.log(`Pointersize: ${Process.pointerSize}`);
    var bioOffset = Process.platform == 'windows' ? 48 : 56; //Documentation not valid (8 Bytes less)Process.pointerSize + 4 * 6 +  Process.pointerSize *3
    //For linux it is valid
    var p_bio = sslcontext.add(bioOffset).readPointer();
    var bio_value = p_bio.readS32();
    return bio_value;
};
var getSessionId = function (sslcontext) {
    var offsetSession = Process.pointerSize * 7 + 4 + 4 + 4 + +4 + 4 + 4;
    var sessionPointer = sslcontext.add(offsetSession).readPointer();
    var offsetSessionId = 8 + 4 + 4 + 4;
    var offsetSessionLength = 8 + 4 + 4;
    var idLength = sessionPointer.add(offsetSessionLength).readU32();
    var idData = sessionPointer.add(offsetSessionId);
    var session_id = "";
    for (var byteCounter = 0; byteCounter < idLength; byteCounter++) {
        session_id = `${session_id}${idData.add(byteCounter).readU8().toString(16).toUpperCase()}`;
    }
    return session_id;
};
//TODO: Complete for full parsing
function parse_mbedtls_ssl_context_struct(sslcontext) {
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
        p_bio: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 3 * Process.pointerSize).readPointer(),
        session_in: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 4 * Process.pointerSize).readPointer(),
        session_out: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 5 * Process.pointerSize).readPointer(),
        session: {
            start: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().readPointer(),
            ciphersuite: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8).readS32(),
            compression: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4).readS32(),
            id_len: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4).readU32(),
            id: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4 + 4).readByteArray(sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4).readU32())
        }
        //TODO: Complete parsing here
    };
}
function execute(moduleName) {
    var socket_library = shared_1.getSocketLibrary();
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["mbedtls_ssl_read", "mbedtls_ssl_write"];
    //? Just in case darwin methods are different to linux and windows ones
    if (Process.platform === "linux" || Process.platform === "windows") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = shared_1.readAddresses(library_method_mapping);
    //https://tls.mbed.org/api/ssl_8h.html#aa2c29eeb1deaf5ad9f01a7515006ede5
    Interceptor.attach(addresses["mbedtls_ssl_read"], {
        onEnter: function (args) {
            this.buffer = args[1];
            this.len = args[2];
            this.sslContext = args[0];
            var message = shared_1.getPortsAndAddresses(getSocketDescriptor(args[0]), true, addresses);
            message["ssl_session_id"] = getSessionId(args[0]);
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
    //https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
    Interceptor.attach(addresses["mbedtls_ssl_write"], {
        onEnter: function (args) {
            var buffer = args[1];
            var len = args[2];
            len |= 0; // Cast retval to 32-bit integer.
            if (len <= 0) {
                return;
            }
            var data = buffer.readByteArray(len);
            var message = shared_1.getPortsAndAddresses(getSocketDescriptor(args[0]), false, addresses);
            message["ssl_session_id"] = getSessionId(args[0]);
            message["function"] = "mbedtls_ssl_write";
            message["contentType"] = "datalog";
            send(message, data);
        }
    });
}
exports.execute = execute;
},{"./shared":8}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
//GLOBALS
const AF_INET = 2;
const AF_INET6 = 100;
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
    const SET_NSS_ENV = new NativeFunction(addresses["PR_SetEnv"], "pointer", ["pointer"]);
    const getsockname = new NativeFunction(addresses["PR_GetSockName"], "int", ["pointer", "pointer"]);
    /**
* Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
* "dst_port".
* @param {pointer} sockfd The file descriptor of the socket to inspect as PRFileDesc.
* @param {boolean} isRead If true, the context is an SSL_read call. If
*     false, the context is an SSL_write call.
* @param {{ [key: string]: NativePointer}} methodAddresses Dictionary containing (at least) addresses for getpeername, getsockname, ntohs and ntohl
* @return {{ [key: string]: string | number }} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
*     and "dst_port".
*/
    function getPortsAndAddressesFromNSS(sockfd, isRead, methodAddresses) {
        var getpeername = new NativeFunction(methodAddresses["PR_GetPeerName"], "int", ["pointer", "pointer"]);
        var getsockname = new NativeFunction(methodAddresses["PR_GetSockName"], "int", ["pointer", "pointer"]);
        var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"]);
        var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"]);
        var message = {};
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
       */
    function getSslSessionId(sslSessionIdSECItem) {
        if (sslSessionIdSECItem == null) {
            log_1.log("Session is null");
            return 0;
        }
        var session_id = "";
        var session_id_ptr = sslSessionIdSECItem.add(8).readPointer();
        var len_tmp = sslSessionIdSECItem.add(16).readU32();
        var len = (len_tmp > 32) ? 32 : len_tmp;
        var session_id = "";
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
            if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                var message = getPortsAndAddressesFromNSS(this.fd, true, addresses);
                message["ssl_session_id"] = getSslSessionId(this.fd);
                message["function"] = "NSS_read";
                this.message = message;
                this.message["contentType"] = "datalog";
                var data = this.buf.readByteArray((new Uint32Array([retval]))[0]);
                send(this.message, data);
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
        }
    });
    Interceptor.attach(addresses["SSL_ImportFD"], {
        onEnter: function (args) {
            //TODO: Keylogfile path must be set according to -k parameter
            var keylog = Memory.allocUtf8String("SSLKEYLOGFILE=keylogfile");
            SET_NSS_ENV(keylog);
        }
    });
}
exports.execute = execute;
},{"./log":4,"./shared":8}],7:[function(require,module,exports){
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
},{"./log":4,"./shared":8}],8:[function(require,module,exports){
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
},{"./log":4}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const openssl_boringssl_1 = require("./openssl_boringssl");
const wolfssl_1 = require("./wolfssl");
const bouncycastle_1 = require("./bouncycastle");
const conscrypt_1 = require("./conscrypt");
const sspi_1 = require("./sspi");
const nss_1 = require("./nss");
const gnutls_1 = require("./gnutls");
const mbedTLS_1 = require("./mbedTLS");
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
module_library_mapping["linux"] = [[/.*libssl\.so/, openssl_boringssl_1.execute], [/.*libgnutls\.so/, gnutls_1.execute], [/.*libwolfssl\.so/, wolfssl_1.execute], [/.*libnspr[0-9]?\.so/, nss_1.execute], [/libmbedtls\.so.*/, mbedTLS_1.execute]];
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
},{"./bouncycastle":1,"./conscrypt":2,"./gnutls":3,"./log":4,"./mbedTLS":5,"./nss":6,"./openssl_boringssl":7,"./shared":8,"./sspi":10,"./wolfssl":11}],10:[function(require,module,exports){
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
                    //TODO: Obtain information from the running process       
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
exports.execute = execute;
},{"./shared":8}],11:[function(require,module,exports){
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
}
exports.execute = execute;
},{"./log":4,"./shared":8}]},{},[9])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL0FwcERhdGEvUm9hbWluZy9ucG0vbm9kZV9tb2R1bGVzL2ZyaWRhLWNvbXBpbGUvbm9kZV9tb2R1bGVzL2Jyb3dzZXItcGFjay9fcHJlbHVkZS5qcyIsImFnZW50L2JvdW5jeWNhc3RsZS50cyIsImFnZW50L2NvbnNjcnlwdC50cyIsImFnZW50L2dudXRscy50cyIsImFnZW50L2xvZy50cyIsImFnZW50L21iZWRUTFMudHMiLCJhZ2VudC9uc3MudHMiLCJhZ2VudC9vcGVuc3NsX2JvcmluZ3NzbC50cyIsImFnZW50L3NoYXJlZC50cyIsImFnZW50L3NzbF9sb2cudHMiLCJhZ2VudC9zc3BpLnRzIiwiYWdlbnQvd29sZnNzbC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7OztBQ0FBLCtCQUEyQjtBQUMzQixxQ0FBMEc7QUFDMUcsU0FBZ0IsT0FBTztJQUNuQixJQUFJLENBQUMsT0FBTyxDQUFDO1FBRVQsMEZBQTBGO1FBQzFGLGdFQUFnRTtRQUNoRSxJQUFJLGFBQWEsR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFDLGtFQUFrRSxDQUFDLENBQUE7UUFDaEcsYUFBYSxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsSUFBSSxFQUFFLEtBQUssRUFBRSxLQUFLLENBQUMsQ0FBQyxjQUFjLEdBQUcsVUFBVSxHQUFRLEVBQUUsTUFBVyxFQUFFLEdBQVE7WUFDdkcsSUFBSSxNQUFNLEdBQWtCLEVBQUUsQ0FBQztZQUMvQixLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsR0FBRyxFQUFFLEVBQUUsQ0FBQyxFQUFFO2dCQUMxQixNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsR0FBRyxJQUFJLENBQUMsQ0FBQzthQUM5QjtZQUNELElBQUksT0FBTyxHQUEyQixFQUFFLENBQUE7WUFDeEMsT0FBTyxDQUFDLGFBQWEsQ0FBQyxHQUFHLFNBQVMsQ0FBQTtZQUNsQyxPQUFPLENBQUMsVUFBVSxD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QUFVLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxXQUFXLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUUsQ0FBQyxHQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sRUFBRTtRQUM1RSxNQUFNLEVBQUUsVUFBVSxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsV0FBVyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFFLENBQUMsR0FBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsV0FBVyxFQUFFO1FBQy9FLE1BQU0sRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxXQUFXLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUUsQ0FBQyxHQUFFLENBQUMsR0FBRyxDQUFDLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDLFdBQVcsRUFBRTtRQUNyRyxjQUFjLEVBQUUsVUFBVSxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsV0FBVyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFFLENBQUMsR0FBRSxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRSxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUMsV0FBVyxFQUFFO1FBQ2hILEtBQUssRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxXQUFXLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUUsQ0FBQyxHQUFFLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQyxXQUFXLEVBQUU7UUFDeEcsVUFBVSxFQUFFLFVBQVUsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFdBQVcsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRSxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDLFdBQVcsRUFBRTtRQUM5RyxXQUFXLEVBQUUsVUFBVSxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsV0FBVyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFFLENBQUMsR0FBRSxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUMsV0FBVyxFQUFFO1FBQzlHLE9BQU8sRUFBRTtZQUNMLEtBQUssRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDLFdBQVcsRUFBRTtZQUMvRSxXQUFXLEVBQUUsVUFBVSxDQUFDLEdBQUcsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxFQUFFO1lBQ3hGLFdBQVcsRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxFQUFFO1lBQzFGLE1BQU0sRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUMsQ0FBQyxHQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sRUFBRTtZQUN2RixFQUFFLEVBQUUsVUFBVSxDQUFDLEdBQUcsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFDLENBQUMsR0FBQyxDQUFDLEdBQUMsQ0FBQyxDQUFDLENBQUMsYUFBYSxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsRUFBRSxHQUFHLENBQUMsR0FBRyxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUMs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
