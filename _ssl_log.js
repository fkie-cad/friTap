(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.execute = void 0;

var shared_1 = require("./shared");

function execute() {
  var library_method_mapping = {};
  library_method_mapping["*libssl*"] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback", "SSL_get_SSL_CTX"];
  library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"];
  var addresses = shared_1.readAddresses(library_method_mapping);
  var SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
  var SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
  var SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
  var SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
  var SSL_get_SSL_CTX = new NativeFunction(addresses["SSL_get_SSL_CTX"], "pointer", ["pointer"]);
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
      console.log("Session is null");
      return 0;
    }

    var len_pointer = Memory.alloc(4);
    var p = SSL_SESSION_get_id(session, len_pointer);
    var len = len_pointer.readU32();
    var session_id = "";

    for (var i = 0; i < len; i++) {
      // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
      // it to session_id.
      session_id += ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
    }

    return session_id;
  }

  Interceptor.attach(addresses["SSL_read"], {
    onEnter: function onEnter(args) {
      var message = shared_1.getPortsAndAddresses(SSL_get_fd(args[0]), true, addresses);
      message["ssl_session_id"] = getSslSessionId(args[0]);
      message["function"] = "SSL_read";
      this.message = message;
      this.buf = args[1];
    },
    onLeave: function onLeave(retval) {
      retval |= 0; // Cast retval to 32-bit integer.

      if (retval <= 0) {
        return;
      }

      this.message["contentType"] = "datalog";
      send(this.message, this.buf.readByteArray(retval));
    }
  });
  Interceptor.attach(addresses["SSL_write"], {
    onEnter: function onEnter(args) {
      var message = shared_1.getPortsAndAddresses(SSL_get_fd(args[0]), false, addresses);
      message["ssl_session_id"] = getSslSessionId(args[0]);
      message["function"] = "SSL_write";
      message["contentType"] = "datalog";
      send(message, args[1].readByteArray((0, _parseInt2["default"])(args[2])));
    },
    onLeave: function onLeave(retval) {}
  });
  Interceptor.attach(addresses["SSL_new"], {
    onEnter: function onEnter(args) {
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

},{"./shared":2,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/core-js/parse-int":5,"@babel/runtime-corejs2/helpers/interopRequireDefault":6}],2:[function(require,module,exports){
"use strict";
/**
 * This file contains methods which are shared for reading
 * secrets/data from different libraries. These methods are
 * indipendent from the implementation of ssl/tls, but they depend
 * on libc.
 */

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.getPortsAndAddresses = exports.readAddresses = void 0; //GLOBALS

var AF_INET = 2;
var AF_INET6 = 10;
/**
 * Read the addresses for the given methods from the given modules
 * @param {{[key: string]: Array<String> }} library_method_mapping A string indexed list of arrays, mapping modules to methods
 * @return {{[key: string]: NativePointer }} A string indexed list of NativePointers, which point to the respective methods
 */

function readAddresses(library_method_mapping) {
  var resolver = new ApiResolver("module");
  var addresses = {};

  var _loop = function _loop(library_name) {
    library_method_mapping[library_name].forEach(function (method) {
      var matches = resolver.enumerateMatches("exports:" + library_name + "!" + method);

      if (matches.length == 0) {
        throw "Could not find " + library_name + "!" + method;
      } else {
        send("Found " + library_name + "!" + method);
      }

      if (matches.length == 0) {
        throw "Could not find " + library_name + "!" + method;
      } else if (matches.length != 1) {
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
          } else if (!address.equals(matches[k].address)) {
            duplicates_only = false;
          }
        }

        if (!duplicates_only) {
          throw "More than one match found for " + library_name + "!" + method + ": " + s;
        }
      }

      addresses[method.toString()] = matches[0].address;
    });
  };

  for (var library_name in library_method_mapping) {
    _loop(library_name);
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

    if (src_dst[i] == "src" !== isRead) {
      getsockname(sockfd, addr, addrlen);
    } else {
      getpeername(sockfd, addr, addrlen);
    }

    if (addr.readU16() == AF_INET) {
      message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
      message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32());
      message["ss_family"] = "AF_INET";
    } else if (addr.readU16() == AF_INET6) {
      message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
      message[src_dst[i] + "_addr"] = "";
      var ipv6_addr = addr.add(8);

      for (var offset = 0; offset < 16; offset += 1) {
        message[src_dst[i] + "_addr"] += ("0" + ipv6_addr.add(offset).readU8().toString(16).toUpperCase()).substr(-2);
      }

      message["ss_family"] = "AF_INET6";
    } else {
      throw "Only supporting IPv4/6";
    }
  }

  return message;
}

exports.getPortsAndAddresses = getPortsAndAddresses;

},{"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/interopRequireDefault":6}],3:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var openssl_boringssl_1 = require("./openssl_boringssl");

var moduleNames = [];
Process.enumerateModules().forEach(function (item) {
  return moduleNames.push(item.name);
});

if (moduleNames.indexOf("libssl.so") > -1) {
  console.log("OpenSSL/BoringSSL detected.");
  openssl_boringssl_1.execute();
}

if (moduleNames.indexOf("libwolfssl.so") > -1) {
  console.log("WolfSSL detected, not yet supported.");
}

Interceptor.attach(Module.getExportByName("libdl.so", "android_dlopen_ext"), function (args) {
  var moduleName = args[0].readCString();

  if (moduleName === null || moduleName === void 0 ? void 0 : moduleName.endsWith("libssl.so")) {
    console.log("OpenSSL/BoringSSL detected.");
    openssl_boringssl_1.execute();
  } else if (moduleName === null || moduleName === void 0 ? void 0 : moduleName.endsWith("libwolfssl.so")) {
    console.log("WolfSSL detected, not yet supported.");
  }
});

},{"./openssl_boringssl":1,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/interopRequireDefault":6}],4:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/define-property");
},{"core-js/library/fn/object/define-property":7}],5:[function(require,module,exports){
module.exports = require("core-js/library/fn/parse-int");
},{"core-js/library/fn/parse-int":8}],6:[function(require,module,exports){
function _interopRequireDefault(obj) {
  return obj && obj.__esModule ? obj : {
    "default": obj
  };
}

module.exports = _interopRequireDefault;
},{}],7:[function(require,module,exports){
require('../../modules/es6.object.define-property');
var $Object = require('../../modules/_core').Object;
module.exports = function defineProperty(it, key, desc) {
  return $Object.defineProperty(it, key, desc);
};

},{"../../modules/_core":11,"../../modules/es6.object.define-property":29}],8:[function(require,module,exports){
require('../modules/es6.parse-int');
module.exports = require('../modules/_core').parseInt;

},{"../modules/_core":11,"../modules/es6.parse-int":30}],9:[function(require,module,exports){
module.exports = function (it) {
  if (typeof it != 'function') throw TypeError(it + ' is not a function!');
  return it;
};

},{}],10:[function(require,module,exports){
var isObject = require('./_is-object');
module.exports = function (it) {
  if (!isObject(it)) throw TypeError(it + ' is not an object!');
  return it;
};

},{"./_is-object":22}],11:[function(require,module,exports){
var core = module.exports = { version: '2.6.11' };
if (typeof __e == 'number') __e = core; // eslint-disable-line no-undef

},{}],12:[function(require,module,exports){
// optional / simple context binding
var aFunction = require('./_a-function');
module.exports = function (fn, that, length) {
  aFunction(fn);
  if (that === undefined) return fn;
  switch (length) {
    case 1: return function (a) {
      return fn.call(that, a);
    };
    case 2: return function (a, b) {
      return fn.call(that, a, b);
    };
    case 3: return function (a, b, c) {
      return fn.call(that, a, b, c);
    };
  }
  return function (/* ...args */) {
    return fn.apply(that, arguments);
  };
};

},{"./_a-function":9}],13:[function(require,module,exports){
// 7.2.1 RequireObjectCoercible(argument)
module.exports = function (it) {
  if (it == undefined) throw TypeError("Can't call method on  " + it);
  return it;
};

},{}],14:[function(require,module,exports){
// Thank's IE8 for his funny defineProperty
module.exports = !require('./_fails')(function () {
  return Object.defineProperty({}, 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_fails":17}],15:[function(require,module,exports){
var isObject = require('./_is-object');
var document = require('./_global').document;
// typeof document.createElement is 'object' in old IE
var is = isObject(document) && isObject(document.createElement);
module.exports = function (it) {
  return is ? document.createElement(it) : {};
};

},{"./_global":18,"./_is-object":22}],16:[function(require,module,exports){
var global = require('./_global');
var core = require('./_core');
var ctx = require('./_ctx');
var hide = require('./_hide');
var has = require('./_has');
var PROTOTYPE = 'prototype';

var $export = function (type, name, source) {
  var IS_FORCED = type & $export.F;
  var IS_GLOBAL = type & $export.G;
  var IS_STATIC = type & $export.S;
  var IS_PROTO = type & $export.P;
  var IS_BIND = type & $export.B;
  var IS_WRAP = type & $export.W;
  var exports = IS_GLOBAL ? core : core[name] || (core[name] = {});
  var expProto = exports[PROTOTYPE];
  var target = IS_GLOBAL ? global : IS_STATIC ? global[name] : (global[name] || {})[PROTOTYPE];
  var key, own, out;
  if (IS_GLOBAL) source = name;
  for (key in source) {
    // contains in native
    own = !IS_FORCED && target && target[key] !== undefined;
    if (own && has(exports, key)) continue;
    // export native or passed
    out = own ? target[key] : source[key];
    // prevent global pollution for namespaces
    exports[key] = IS_GLOBAL && typeof target[key] != 'function' ? source[key]
    // bind timers to global for call from export context
    : IS_BIND && own ? ctx(out, global)
    // wrap global constructors for prevent change them in library
    : IS_WRAP && target[key] == out ? (function (C) {
      var F = function (a, b, c) {
        if (this instanceof C) {
          switch (arguments.length) {
            case 0: return new C();
            case 1: return new C(a);
            case 2: return new C(a, b);
          } return new C(a, b, c);
        } return C.apply(this, arguments);
      };
      F[PROTOTYPE] = C[PROTOTYPE];
      return F;
    // make static versions for prototype methods
    })(out) : IS_PROTO && typeof out == 'function' ? ctx(Function.call, out) : out;
    // export proto methods to core.%CONSTRUCTOR%.methods.%NAME%
    if (IS_PROTO) {
      (exports.virtual || (exports.virtual = {}))[key] = out;
      // export proto methods to core.%CONSTRUCTOR%.prototype.%NAME%
      if (type & $export.R && expProto && !expProto[key]) hide(expProto, key, out);
    }
  }
};
// type bitmap
$export.F = 1;   // forced
$export.G = 2;   // global
$export.S = 4;   // static
$export.P = 8;   // proto
$export.B = 16;  // bind
$export.W = 32;  // wrap
$export.U = 64;  // safe
$export.R = 128; // real proto method for `library`
module.exports = $export;

},{"./_core":11,"./_ctx":12,"./_global":18,"./_has":19,"./_hide":20}],17:[function(require,module,exports){
module.exports = function (exec) {
  try {
    return !!exec();
  } catch (e) {
    return true;
  }
};

},{}],18:[function(require,module,exports){
// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
var global = module.exports = typeof window != 'undefined' && window.Math == Math
  ? window : typeof self != 'undefined' && self.Math == Math ? self
  // eslint-disable-next-line no-new-func
  : Function('return this')();
if (typeof __g == 'number') __g = global; // eslint-disable-line no-undef

},{}],19:[function(require,module,exports){
var hasOwnProperty = {}.hasOwnProperty;
module.exports = function (it, key) {
  return hasOwnProperty.call(it, key);
};

},{}],20:[function(require,module,exports){
var dP = require('./_object-dp');
var createDesc = require('./_property-desc');
module.exports = require('./_descriptors') ? function (object, key, value) {
  return dP.f(object, key, createDesc(1, value));
} : function (object, key, value) {
  object[key] = value;
  return object;
};

},{"./_descriptors":14,"./_object-dp":23,"./_property-desc":25}],21:[function(require,module,exports){
module.exports = !require('./_descriptors') && !require('./_fails')(function () {
  return Object.defineProperty(require('./_dom-create')('div'), 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_descriptors":14,"./_dom-create":15,"./_fails":17}],22:[function(require,module,exports){
module.exports = function (it) {
  return typeof it === 'object' ? it !== null : typeof it === 'function';
};

},{}],23:[function(require,module,exports){
var anObject = require('./_an-object');
var IE8_DOM_DEFINE = require('./_ie8-dom-define');
var toPrimitive = require('./_to-primitive');
var dP = Object.defineProperty;

exports.f = require('./_descriptors') ? Object.defineProperty : function defineProperty(O, P, Attributes) {
  anObject(O);
  P = toPrimitive(P, true);
  anObject(Attributes);
  if (IE8_DOM_DEFINE) try {
    return dP(O, P, Attributes);
  } catch (e) { /* empty */ }
  if ('get' in Attributes || 'set' in Attributes) throw TypeError('Accessors not supported!');
  if ('value' in Attributes) O[P] = Attributes.value;
  return O;
};

},{"./_an-object":10,"./_descriptors":14,"./_ie8-dom-define":21,"./_to-primitive":28}],24:[function(require,module,exports){
var $parseInt = require('./_global').parseInt;
var $trim = require('./_string-trim').trim;
var ws = require('./_string-ws');
var hex = /^[-+]?0[xX]/;

module.exports = $parseInt(ws + '08') !== 8 || $parseInt(ws + '0x16') !== 22 ? function parseInt(str, radix) {
  var string = $trim(String(str), 3);
  return $parseInt(string, (radix >>> 0) || (hex.test(string) ? 16 : 10));
} : $parseInt;

},{"./_global":18,"./_string-trim":26,"./_string-ws":27}],25:[function(require,module,exports){
module.exports = function (bitmap, value) {
  return {
    enumerable: !(bitmap & 1),
    configurable: !(bitmap & 2),
    writable: !(bitmap & 4),
    value: value
  };
};

},{}],26:[function(require,module,exports){
var $export = require('./_export');
var defined = require('./_defined');
var fails = require('./_fails');
var spaces = require('./_string-ws');
var space = '[' + spaces + ']';
var non = '\u200b\u0085';
var ltrim = RegExp('^' + space + space + '*');
var rtrim = RegExp(space + space + '*$');

var exporter = function (KEY, exec, ALIAS) {
  var exp = {};
  var FORCE = fails(function () {
    return !!spaces[KEY]() || non[KEY]() != non;
  });
  var fn = exp[KEY] = FORCE ? exec(trim) : spaces[KEY];
  if (ALIAS) exp[ALIAS] = fn;
  $export($export.P + $export.F * FORCE, 'String', exp);
};

// 1 -> String#trimLeft
// 2 -> String#trimRight
// 3 -> String#trim
var trim = exporter.trim = function (string, TYPE) {
  string = String(defined(string));
  if (TYPE & 1) string = string.replace(ltrim, '');
  if (TYPE & 2) string = string.replace(rtrim, '');
  return string;
};

module.exports = exporter;

},{"./_defined":13,"./_export":16,"./_fails":17,"./_string-ws":27}],27:[function(require,module,exports){
module.exports = '\x09\x0A\x0B\x0C\x0D\x20\xA0\u1680\u180E\u2000\u2001\u2002\u2003' +
  '\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u202F\u205F\u3000\u2028\u2029\uFEFF';

},{}],28:[function(require,module,exports){
// 7.1.1 ToPrimitive(input [, PreferredType])
var isObject = require('./_is-object');
// instead of the ES6 spec version, we didn't implement @@toPrimitive case
// and the second argument - flag - preferred type is a string
module.exports = function (it, S) {
  if (!isObject(it)) return it;
  var fn, val;
  if (S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  if (typeof (fn = it.valueOf) == 'function' && !isObject(val = fn.call(it))) return val;
  if (!S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  throw TypeError("Can't convert object to primitive value");
};

},{"./_is-object":22}],29:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.4 / 15.2.3.6 Object.defineProperty(O, P, Attributes)
$export($export.S + $export.F * !require('./_descriptors'), 'Object', { defineProperty: require('./_object-dp').f });

},{"./_descriptors":14,"./_export":16,"./_object-dp":23}],30:[function(require,module,exports){
var $export = require('./_export');
var $parseInt = require('./_parse-int');
// 18.2.5 parseInt(string, radix)
$export($export.G + $export.F * (parseInt != $parseInt), { parseInt: $parseInt });

},{"./_export":16,"./_parse-int":24}]},{},[3])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9vcGVuc3NsX2JvcmluZ3NzbC50cyIsImFnZW50L3NoYXJlZC50cyIsImFnZW50L3NzbF9sb2cudHMiLCJub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL29iamVjdC9kZWZpbmUtcHJvcGVydHkuanMiLCJub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL3BhcnNlLWludC5qcyIsIm5vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2hlbHBlcnMvaW50ZXJvcFJlcXVpcmVEZWZhdWx0LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9vYmplY3QvZGVmaW5lLXByb3BlcnR5LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9wYXJzZS1pbnQuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2EtZnVuY3Rpb24uanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2FuLW9iamVjdC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fY29yZS5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fY3R4LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19kZWZpbmVkLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19kZXNjcmlwdG9ycy5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZG9tLWNyZWF0ZS5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZXhwb3J0LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19mYWlscy5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZ2xvYmFsLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19oYXMuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2hpZGUuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2llOC1kb20tZGVmaW5lLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pcy1vYmplY3QuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX29iamVjdC1kcC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fcGFyc2UtaW50LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19wcm9wZXJ0eS1kZXNjLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19zdHJpbmctdHJpbS5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fc3RyaW5nLXdzLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL190by1wcmltaXRpdmUuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2Lm9iamVjdC5kZWZpbmUtcHJvcGVydHkuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2LnBhcnNlLWludC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7Ozs7Ozs7Ozs7QUNBQSxJQUFBLFFBQUEsR0FBQSxPQUFBLENBQUEsVUFBQSxDQUFBOztBQUVBLFNBQWdCLE9BQWhCLEdBQXVCO0FBQ25CLE1BQUksc0JBQXNCLEdBQXFDLEVBQS9EO0FBQ0EsRUFBQSxzQkFBc0IsQ0FBQyxVQUFELENBQXRCLEdBQXFDLENBQUMsVUFBRCxFQUFhLFdB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O0FDOURBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUkE7QUFDQTtBQUNBO0FBQ0E7O0FDSEE7QUFDQTtBQUNBO0FBQ0E7O0FDSEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDVEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzlCQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDWkE7QUFDQTtBQUNBO0FBQ0E7O0FDSEE7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIn0=
