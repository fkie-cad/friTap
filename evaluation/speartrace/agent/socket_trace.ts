import { readAddresses, getPortsAndAddresses } from "./shared"

var library_method_mapping: { [key: string]: Array<String> } = {}
library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl", "write", "read"]

var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

Interceptor.attach(addresses["read"], {
    onEnter: function (args) {
        this.socket_fd = args[0].toInt32()
        this.buffer = args[1]
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0 && (Socket.type(this.socket_fd) === 'tcp' || Socket.type(this.socket_fd) === 'udp' || Socket.type(this.socket_fd) === 'tcp6' || Socket.type(this.socket_fd) === 'udp6')) {
            var message = getPortsAndAddresses(this.socket_fd, true, addresses)
            message["function"] = "read"
            message["pid"] = Process.id
            send(message, this.buffer.readByteArray(retval.toInt32()))
        }
    }
})

Interceptor.attach(addresses["write"], {
    onEnter: function (args) {
        this.socket_fd = args[0].toInt32()
        this.buffer = args[1]
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0 && (Socket.type(this.socket_fd) === 'tcp' || Socket.type(this.socket_fd) === 'udp' || Socket.type(this.socket_fd) === 'tcp6' || Socket.type(this.socket_fd) === 'udp6')) {
            var message = getPortsAndAddresses(this.socket_fd, false, addresses)
            message["function"] = "write"
            message["pid"] = Process.id
            /*
            console.log('Write called from:\n' +
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n') + '\n');
            var call_addr = Thread.backtrace(this.context, Backtracer.ACCURATE)[0]
            var modmap = new ModuleMap()
            modmap.update()
            console.log("Module:")
            console.log(modmap.findName(call_addr))
            console.log(modmap.findPath(call_addr))
            */

            send(message, this.buffer.readByteArray(retval.toInt32()))
        }
    }
})