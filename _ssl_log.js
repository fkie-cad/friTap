(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
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

},{"@babel/runtime-corejs2/core-js/object/define-property":3,"@babel/runtime-corejs2/helpers/interopRequireDefault":5}],2:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var shared_1 = require("./shared");

var modules = Process.enumerateModules();
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

},{"./shared":1,"@babel/runtime-corejs2/core-js/object/define-property":3,"@babel/runtime-corejs2/core-js/parse-int":4,"@babel/runtime-corejs2/helpers/interopRequireDefault":5}],3:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/define-property");
},{"core-js/library/fn/object/define-property":6}],4:[function(require,module,exports){
module.exports = require("core-js/library/fn/parse-int");
},{"core-js/library/fn/parse-int":7}],5:[function(require,module,exports){
function _interopRequireDefault(obj) {
  return obj && obj.__esModule ? obj : {
    "default": obj
  };
}

module.exports = _interopRequireDefault;
},{}],6:[function(require,module,exports){
require('../../modules/es6.object.define-property');
var $Object = require('../../modules/_core').Object;
module.exports = function defineProperty(it, key, desc) {
  return $Object.defineProperty(it, key, desc);
};

},{"../../modules/_core":10,"../../modules/es6.object.define-property":28}],7:[function(require,module,exports){
require('../modules/es6.parse-int');
module.exports = require('../modules/_core').parseInt;

},{"../modules/_core":10,"../modules/es6.parse-int":29}],8:[function(require,module,exports){
module.exports = function (it) {
  if (typeof it != 'function') throw TypeError(it + ' is not a function!');
  return it;
};

},{}],9:[function(require,module,exports){
var isObject = require('./_is-object');
module.exports = function (it) {
  if (!isObject(it)) throw TypeError(it + ' is not an object!');
  return it;
};

},{"./_is-object":21}],10:[function(require,module,exports){
var core = module.exports = { version: '2.6.11' };
if (typeof __e == 'number') __e = core; // eslint-disable-line no-undef

},{}],11:[function(require,module,exports){
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

},{"./_a-function":8}],12:[function(require,module,exports){
// 7.2.1 RequireObjectCoercible(argument)
module.exports = function (it) {
  if (it == undefined) throw TypeError("Can't call method on  " + it);
  return it;
};

},{}],13:[function(require,module,exports){
// Thank's IE8 for his funny defineProperty
module.exports = !require('./_fails')(function () {
  return Object.defineProperty({}, 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_fails":16}],14:[function(require,module,exports){
var isObject = require('./_is-object');
var document = require('./_global').document;
// typeof document.createElement is 'object' in old IE
var is = isObject(document) && isObject(document.createElement);
module.exports = function (it) {
  return is ? document.createElement(it) : {};
};

},{"./_global":17,"./_is-object":21}],15:[function(require,module,exports){
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

},{"./_core":10,"./_ctx":11,"./_global":17,"./_has":18,"./_hide":19}],16:[function(require,module,exports){
module.exports = function (exec) {
  try {
    return !!exec();
  } catch (e) {
    return true;
  }
};

},{}],17:[function(require,module,exports){
// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
var global = module.exports = typeof window != 'undefined' && window.Math == Math
  ? window : typeof self != 'undefined' && self.Math == Math ? self
  // eslint-disable-next-line no-new-func
  : Function('return this')();
if (typeof __g == 'number') __g = global; // eslint-disable-line no-undef

},{}],18:[function(require,module,exports){
var hasOwnProperty = {}.hasOwnProperty;
module.exports = function (it, key) {
  return hasOwnProperty.call(it, key);
};

},{}],19:[function(require,module,exports){
var dP = require('./_object-dp');
var createDesc = require('./_property-desc');
module.exports = require('./_descriptors') ? function (object, key, value) {
  return dP.f(object, key, createDesc(1, value));
} : function (object, key, value) {
  object[key] = value;
  return object;
};

},{"./_descriptors":13,"./_object-dp":22,"./_property-desc":24}],20:[function(require,module,exports){
module.exports = !require('./_descriptors') && !require('./_fails')(function () {
  return Object.defineProperty(require('./_dom-create')('div'), 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_descriptors":13,"./_dom-create":14,"./_fails":16}],21:[function(require,module,exports){
module.exports = function (it) {
  return typeof it === 'object' ? it !== null : typeof it === 'function';
};

},{}],22:[function(require,module,exports){
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

},{"./_an-object":9,"./_descriptors":13,"./_ie8-dom-define":20,"./_to-primitive":27}],23:[function(require,module,exports){
var $parseInt = require('./_global').parseInt;
var $trim = require('./_string-trim').trim;
var ws = require('./_string-ws');
var hex = /^[-+]?0[xX]/;

module.exports = $parseInt(ws + '08') !== 8 || $parseInt(ws + '0x16') !== 22 ? function parseInt(str, radix) {
  var string = $trim(String(str), 3);
  return $parseInt(string, (radix >>> 0) || (hex.test(string) ? 16 : 10));
} : $parseInt;

},{"./_global":17,"./_string-trim":25,"./_string-ws":26}],24:[function(require,module,exports){
module.exports = function (bitmap, value) {
  return {
    enumerable: !(bitmap & 1),
    configurable: !(bitmap & 2),
    writable: !(bitmap & 4),
    value: value
  };
};

},{}],25:[function(require,module,exports){
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

},{"./_defined":12,"./_export":15,"./_fails":16,"./_string-ws":26}],26:[function(require,module,exports){
module.exports = '\x09\x0A\x0B\x0C\x0D\x20\xA0\u1680\u180E\u2000\u2001\u2002\u2003' +
  '\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u202F\u205F\u3000\u2028\u2029\uFEFF';

},{}],27:[function(require,module,exports){
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

},{"./_is-object":21}],28:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.4 / 15.2.3.6 Object.defineProperty(O, P, Attributes)
$export($export.S + $export.F * !require('./_descriptors'), 'Object', { defineProperty: require('./_object-dp').f });

},{"./_descriptors":13,"./_export":15,"./_object-dp":22}],29:[function(require,module,exports){
var $export = require('./_export');
var $parseInt = require('./_parse-int');
// 18.2.5 parseInt(string, radix)
$export($export.G + $export.F * (parseInt != $parseInt), { parseInt: $parseInt });

},{"./_export":15,"./_parse-int":23}]},{},[2])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9zaGFyZWQudHMiLCJhZ2VudC9zc2xfbG9nLnRzIiwibm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvY29yZS1qcy9vYmplY3QvZGVmaW5lLXByb3BlcnR5LmpzIiwibm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvY29yZS1qcy9wYXJzZS1pbnQuanMiLCJub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9oZWxwZXJzL2ludGVyb3BSZXF1aXJlRGVmYXVsdC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vb2JqZWN0L2RlZmluZS1wcm9wZXJ0eS5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vcGFyc2UtaW50LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19hLWZ1bmN0aW9uLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19hbi1vYmplY3QuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2NvcmUuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2N0eC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZGVmaW5lZC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZGVzY3JpcHRvcnMuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2RvbS1jcmVhdGUuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2V4cG9ydC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZmFpbHMuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2dsb2JhbC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faGFzLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19oaWRlLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pZTgtZG9tLWRlZmluZS5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faXMtb2JqZWN0LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtZHAuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3BhcnNlLWludC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fcHJvcGVydHktZGVzYy5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fc3RyaW5nLXRyaW0uanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3N0cmluZy13cy5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fdG8tcHJpbWl0aXZlLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5vYmplY3QuZGVmaW5lLXByb3BlcnR5LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5wYXJzZS1pbnQuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7O0FDQUE7Ozs7Ozs7Ozs7Ozs7OytEQU9BOztBQUNBLElBQU0sT0FBTyxHQUFHLENBQWhCO0FBQ0EsSUFBTSxRQUFRLEdBQUcsRUFBakI7QUFFQTs7Ozs7O0FBS0EsU0FBZ0IsYUFBaEIsQ0FBOEIsc0JBQTlCLEVBQXNGO0FBRWxGLE1BQUksUUFBUSxHQUFHLElBQUksV0FBSixDQUFnQixRQUFoQixDQUFmO0FBQ0EsTUFBSSxTQUFTLEdBQXFD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QTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUkE7QUFDQTtBQUNBO0FBQ0E7O0FDSEE7QUFDQTtBQUNBO0FBQ0E7O0FDSEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDVEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzlCQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDWkE7QUFDQTtBQUNBO0FBQ0E7O0FDSEE7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIn0=
