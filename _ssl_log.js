(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
var AF_INET = 2;
var AF_INET6 = 10;
var modules = Process.enumerateModules();
var library_method_mapping = {};
library_method_mapping["*libssl*"] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id"];
library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"];
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

var SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
var SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
var SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
var getpeername = new NativeFunction(addresses["getpeername"], "int", ["int", "pointer", "pointer"]);
var getsockname = new NativeFunction(addresses["getsockname"], "int", ["int", "pointer", "pointer"]);
var ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"]);
var ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"]);
/**
   * Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
   * "dst_port".
   * @param {int} sockfd The file descriptor of the socket to inspect.
   * @param {boolean} isRead If true, the context is an SSL_read call. If
   *     false, the context is an SSL_write call.
   * @return {dict} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
   *     and "dst_port".
   */

function getPortsAndAddresses(sockfd, isRead) {
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
    var message = getPortsAndAddresses(SSL_get_fd(args[0]), true);
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

    send(this.message, this.buf.readByteArray(retval));
  }
});
Interceptor.attach(addresses["SSL_write"], {
  onEnter: function onEnter(args) {
    var message = getPortsAndAddresses(SSL_get_fd(args[0]), false);
    message["ssl_session_id"] = getSslSessionId(args[0]);
    message["function"] = "SSL_write";
    send(message, args[1].readByteArray((0, _parseInt2["default"])(args[2])));
  },
  onLeave: function onLeave(retval) {}
});

},{"@babel/runtime-corejs2/core-js/object/define-property":2,"@babel/runtime-corejs2/core-js/parse-int":3,"@babel/runtime-corejs2/helpers/interopRequireDefault":4}],2:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/define-property");
},{"core-js/library/fn/object/define-property":5}],3:[function(require,module,exports){
module.exports = require("core-js/library/fn/parse-int");
},{"core-js/library/fn/parse-int":6}],4:[function(require,module,exports){
function _interopRequireDefault(obj) {
  return obj && obj.__esModule ? obj : {
    "default": obj
  };
}

module.exports = _interopRequireDefault;
},{}],5:[function(require,module,exports){
require('../../modules/es6.object.define-property');
var $Object = require('../../modules/_core').Object;
module.exports = function defineProperty(it, key, desc) {
  return $Object.defineProperty(it, key, desc);
};

},{"../../modules/_core":9,"../../modules/es6.object.define-property":27}],6:[function(require,module,exports){
require('../modules/es6.parse-int');
module.exports = require('../modules/_core').parseInt;

},{"../modules/_core":9,"../modules/es6.parse-int":28}],7:[function(require,module,exports){
module.exports = function (it) {
  if (typeof it != 'function') throw TypeError(it + ' is not a function!');
  return it;
};

},{}],8:[function(require,module,exports){
var isObject = require('./_is-object');
module.exports = function (it) {
  if (!isObject(it)) throw TypeError(it + ' is not an object!');
  return it;
};

},{"./_is-object":20}],9:[function(require,module,exports){
var core = module.exports = { version: '2.6.11' };
if (typeof __e == 'number') __e = core; // eslint-disable-line no-undef

},{}],10:[function(require,module,exports){
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

},{"./_a-function":7}],11:[function(require,module,exports){
// 7.2.1 RequireObjectCoercible(argument)
module.exports = function (it) {
  if (it == undefined) throw TypeError("Can't call method on  " + it);
  return it;
};

},{}],12:[function(require,module,exports){
// Thank's IE8 for his funny defineProperty
module.exports = !require('./_fails')(function () {
  return Object.defineProperty({}, 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_fails":15}],13:[function(require,module,exports){
var isObject = require('./_is-object');
var document = require('./_global').document;
// typeof document.createElement is 'object' in old IE
var is = isObject(document) && isObject(document.createElement);
module.exports = function (it) {
  return is ? document.createElement(it) : {};
};

},{"./_global":16,"./_is-object":20}],14:[function(require,module,exports){
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

},{"./_core":9,"./_ctx":10,"./_global":16,"./_has":17,"./_hide":18}],15:[function(require,module,exports){
module.exports = function (exec) {
  try {
    return !!exec();
  } catch (e) {
    return true;
  }
};

},{}],16:[function(require,module,exports){
// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
var global = module.exports = typeof window != 'undefined' && window.Math == Math
  ? window : typeof self != 'undefined' && self.Math == Math ? self
  // eslint-disable-next-line no-new-func
  : Function('return this')();
if (typeof __g == 'number') __g = global; // eslint-disable-line no-undef

},{}],17:[function(require,module,exports){
var hasOwnProperty = {}.hasOwnProperty;
module.exports = function (it, key) {
  return hasOwnProperty.call(it, key);
};

},{}],18:[function(require,module,exports){
var dP = require('./_object-dp');
var createDesc = require('./_property-desc');
module.exports = require('./_descriptors') ? function (object, key, value) {
  return dP.f(object, key, createDesc(1, value));
} : function (object, key, value) {
  object[key] = value;
  return object;
};

},{"./_descriptors":12,"./_object-dp":21,"./_property-desc":23}],19:[function(require,module,exports){
module.exports = !require('./_descriptors') && !require('./_fails')(function () {
  return Object.defineProperty(require('./_dom-create')('div'), 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_descriptors":12,"./_dom-create":13,"./_fails":15}],20:[function(require,module,exports){
module.exports = function (it) {
  return typeof it === 'object' ? it !== null : typeof it === 'function';
};

},{}],21:[function(require,module,exports){
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

},{"./_an-object":8,"./_descriptors":12,"./_ie8-dom-define":19,"./_to-primitive":26}],22:[function(require,module,exports){
var $parseInt = require('./_global').parseInt;
var $trim = require('./_string-trim').trim;
var ws = require('./_string-ws');
var hex = /^[-+]?0[xX]/;

module.exports = $parseInt(ws + '08') !== 8 || $parseInt(ws + '0x16') !== 22 ? function parseInt(str, radix) {
  var string = $trim(String(str), 3);
  return $parseInt(string, (radix >>> 0) || (hex.test(string) ? 16 : 10));
} : $parseInt;

},{"./_global":16,"./_string-trim":24,"./_string-ws":25}],23:[function(require,module,exports){
module.exports = function (bitmap, value) {
  return {
    enumerable: !(bitmap & 1),
    configurable: !(bitmap & 2),
    writable: !(bitmap & 4),
    value: value
  };
};

},{}],24:[function(require,module,exports){
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

},{"./_defined":11,"./_export":14,"./_fails":15,"./_string-ws":25}],25:[function(require,module,exports){
module.exports = '\x09\x0A\x0B\x0C\x0D\x20\xA0\u1680\u180E\u2000\u2001\u2002\u2003' +
  '\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u202F\u205F\u3000\u2028\u2029\uFEFF';

},{}],26:[function(require,module,exports){
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

},{"./_is-object":20}],27:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.4 / 15.2.3.6 Object.defineProperty(O, P, Attributes)
$export($export.S + $export.F * !require('./_descriptors'), 'Object', { defineProperty: require('./_object-dp').f });

},{"./_descriptors":12,"./_export":14,"./_object-dp":21}],28:[function(require,module,exports){
var $export = require('./_export');
var $parseInt = require('./_parse-int');
// 18.2.5 parseInt(string, radix)
$export($export.G + $export.F * (parseInt != $parseInt), { parseInt: $parseInt });

},{"./_export":14,"./_parse-int":22}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9zc2xfbG9nLnRzIiwibm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvY29yZS1qcy9vYmplY3QvZGVmaW5lLXByb3BlcnR5LmpzIiwibm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvY29yZS1qcy9wYXJzZS1pbnQuanMiLCJub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9oZWxwZXJzL2ludGVyb3BSZXF1aXJlRGVmYXVsdC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vb2JqZWN0L2RlZmluZS1wcm9wZXJ0eS5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vcGFyc2UtaW50LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19hLWZ1bmN0aW9uLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19hbi1vYmplY3QuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2NvcmUuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2N0eC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZGVmaW5lZC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZGVzY3JpcHRvcnMuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2RvbS1jcmVhdGUuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2V4cG9ydC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZmFpbHMuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2dsb2JhbC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faGFzLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19oaWRlLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pZTgtZG9tLWRlZmluZS5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faXMtb2JqZWN0LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtZHAuanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3BhcnNlLWludC5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fcHJvcGVydHktZGVzYy5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fc3RyaW5nLXRyaW0uanMiLCJub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3N0cmluZy13cy5qcyIsIm5vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fdG8tcHJpbWl0aXZlLmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5vYmplY3QuZGVmaW5lLXByb3BlcnR5LmpzIiwibm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5wYXJzZS1pbnQuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7Ozs7Ozs7Ozs7OztBQ0VBLElBQU0sT0FBTyxHQUFHLENBQWhCO0FBQ0EsSUFBTSxRQUFRLEdBQUcsRUFBakI7QUFHQSxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsZ0JBQVIsRUFBZDtBQUVBLElBQUksc0JBQXNCLEdBQXFDLEVBQS9EO0FBQ0Esc0JBQXNCLENBQUMsVUFBRCxDQUF0QixHQUFxQyxDQUFDLFVBQUQsRUFBYSxXQUFiLEVBQTBCLFlBQTFCLEVBQXdDLGlCQUF4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Q0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNOQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTEE7QUFDQTtBQUNBOztBQ0ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTs7QUNGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDcEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzlEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1BBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1JBO0FBQ0E7QUFDQTtBQUNBOztBQ0hBO0FBQ0E7QUFDQTtBQUNBOztBQ0hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDaEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNSQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM5QkE7QUFDQTtBQUNBOztBQ0ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1pBO0FBQ0E7QUFDQTtBQUNBOztBQ0hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
