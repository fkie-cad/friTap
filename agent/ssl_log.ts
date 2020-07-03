var modules = Process.enumerateModules()

var library_name = "*libssl*"
var methods = ["SSL_read", "SSL_write", "SSL_get_session", "SSL_SESSION_get_id"]
var resolver = new ApiResolver("module")
var addresses: { [key: string]: NativePointer } = {}
methods.forEach(function (method) {
    var matches = resolver.enumerateMatches("exports:" + library_name + "!" + method)
    if (matches.length == 0) {
        throw "Could not find " + library_name + "!" + method;
    }
    else {
        send("Found " + library_name + "!" + method)
    }
    if (matches.length != 1) {
        throw "More than one match found for " + library_name + "!" + method + ": " + matches.length;
    }
    addresses[method] = matches[0].address
})

Interceptor.attach(addresses["SSL_read"], {
    onEnter: function (args) {
        send("Entered SSL_read!")
    }
})


Interceptor.attach(addresses["SSL_read"], {
    onEnter: function (args) {
        send("Entered SSL_write!")
    }
})