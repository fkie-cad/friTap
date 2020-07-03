(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

var modules = Process.enumerateModules();
var library_name = "*libssl*";
var methods = ["SSL_read", "SSL_write", "SSL_get_session", "SSL_SESSION_get_id"];
var resolver = new ApiResolver("module");
var addresses = {};
methods.forEach(function (method) {
  var matches = resolver.enumerateMatches("exports:" + library_name + "!" + method);

  if (matches.length == 0) {
    throw "Could not find " + library_name + "!" + method;
  } else {
    send("Found " + library_name + "!" + method);
  }

  if (matches.length != 1) {
    throw "More than one match found for " + library_name + "!" + method + ": " + matches.length;
  }

  addresses[method] = matches[0].address;
});
Interceptor.attach(addresses["SSL_read"], {
  onEnter: function onEnter(args) {
    send("Entered SSL_read!");
  }
});
Interceptor.attach(addresses["SSL_read"], {
  onEnter: function onEnter(args) {
    send("Entered SSL_write!");
  }
});

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9zc2xfbG9nLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7QUNBQSxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsZ0JBQVIsRUFBZDtBQUVBLElBQUksWUFBWSxHQUFHLFVBQW5CO0FBQ0EsSUFBSSxPQUFPLEdBQUcsQ0FBQyxVQUFELEVBQWEsV0FBYixFQUEwQixpQkFBMUIsRUFBNkMsb0JBQTdDLENBQWQ7QUFDQSxJQUFJLFFBQVEsR0FBRyxJQUFJLFdBQUosQ0FBZ0IsUUFBaEIsQ0FBZjtBQUNBLElBQUksU0FBUyxHQUFxQyxFQUFsRDtBQUNBLE9BQU8sQ0FBQyxPQUFSLENBQWdCLFVBQVUsTUFBVixFQUFnQjtBQUM1QixNQUFJLE9BQU8sR0FBRyxRQUFRLENBQUMsZ0JBQVQsQ0FBMEIsYUFBYSxZQUFiLEdBQTRCLEdBQTVCLEdBQWtDLE1BQTVELENBQWQ7O0FBQ0EsTUFBSSxPQUFPLENBQUMsTUFBUixJQUFrQixDQUF0QixFQUF5QjtBQUNyQixVQUFNLG9CQUFvQixZQUFwQixHQUFtQyxHQUFuQyxHQUF5QyxNQUEvQztBQUNILEdBRkQsTUFHSztBQUNELElBQUEsSUFBSSxDQUFDLFdBQVcsWUFBWCxHQUEwQixHQUExQixHQUFnQyxNQUFqQyxDQUFKO0FBQ0g7O0FBQ0QsTUFBSSxPQUFPLENBQUMsTUFBUixJQUFrQixDQUF0QixFQUF5QjtBQUNyQixVQUFNLG1DQUFtQyxZQUFuQyxHQUFrRCxHQUFsRCxHQUF3RCxNQUF4RCxHQUFpRSxJQUFqRSxHQUF3RSxPQUFPLENBQUMsTUFBdEY7QUFDSDs7QUFDRCxFQUFBLFNBQVMsQ0FBQyxNQUFELENBQVQsR0FBb0IsT0FBTyxDQUFDLENBQUQsQ0FBUCxDQUFXLE9BQS9CO0FBQ0gsQ0FaRDtBQWNBLFdBQVcsQ0FBQyxNQUFaLENBQW1CLFNBQVMsQ0FBQyxVQUFELENBQTVCLEVBQTBDO0FBQ3RDLEVBQUEsT0FBTyxFQUFFLGlCQUFVLElBQVYsRUFBYztBQUNuQixJQUFBLElBQUksQ0FBQyxtQkFBRCxDQUFKO0FBQ0g7QUFIcUMsQ0FBMUM7QUFPQSxXQUFXLENBQUMsTUFBWixDQUFtQixTQUFTLENBQUMsVUFBRCxDQUE1QixFQUEwQztBQUN0QyxFQUFBLE9BQU8sRUFBRSxpQkFBVSxJQUFWLEVBQWM7QUFDbkIsSUFBQSxJQUFJLENBQUMsb0JBQUQsQ0FBSjtBQUNIO0FBSHFDLENBQTFDIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIifQ==
