import { log, devlog } from "../util/log.js"
import { get_process_architecture } from "../util/process_infos.js"
import { readAddresses, getPortsAndAddresses } from "../shared/shared_functions.js"


export function execute(moduleName:string) {

    log("Doing a full packet capture\nUse -k in order to get TLS keys.");
    
    var socket_library:string =""
    switch(Process.platform){
        case "linux":
            socket_library = "libc"
            break
        case "windows":
            socket_library = "WS2_32.dll"
            break
        case "darwin":
            socket_library = "libSystem.B.dylib"
            break;
        default:
            log(`Platform "${Process.platform} currently not supported!`)
    }
    
var library_method_mapping: { [key: string]: Array<String> } = {}
const socketFDs = new Map()

if(ObjC.available){
    // currently those libraries gets only detected on iOS if we add an *-sign
    library_method_mapping[`*${socket_library}*`] = ["getpeername*", "getsockname*","socket*", "ntohs*", "ntohl*", "recv*", "recvfrom*", "send*", "sendto*", "read*", "write*"]
}else{
    library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl","socket", "recv", "recvfrom", "send", "sendto", "read", "write"]
}

var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

function has_valid_socket_type(fd : number): boolean{
    var socktype = Socket.type(fd);
    if (socktype === 'tcp' || socktype === 'tcp6' || socktype === 'udp' || socktype === 'udp6'){
        if(socktype === 'udp6' && ObjC.available){
            return false // on iOS this leads always to empty addresses
        }
        return true;
    }
      
    return true;
}

Interceptor.attach(addresses["socket"],
{
    onEnter: function (args: any) {

    },
    onLeave: function (retval: any) {
        this.fd = retval.toInt32();
        if(socketFDs.has(this.fd)){
            return;
        }
        if(has_valid_socket_type(this.fd)){
            var message = getPortsAndAddresses(this.fd as number, false, addresses)
            message["function"] = "Full_read"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["dst_addr"])
            send(message)
        }
    }
});



Interceptor.attach(addresses["connect"],
{
    onEnter: function (args: any) {
        this.fd = args[0].toInt32();
       
       
    },
    onLeave: function (retval: any) {
        if(socketFDs.has(this.fd)){
            return;
        }
        if(has_valid_socket_type(this.fd)){
            var message = getPortsAndAddresses(this.fd as number, false, addresses)
            message["function"] = "Full_read"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["dst_addr"])
            send(message)
        }
    }
});


Interceptor.attach(addresses["read"],
{
    onEnter: function (args: any) {
        this.fd = args[0].toInt32();
    },
    onLeave: function (retval: any) {
        if(socketFDs.has(this.fd)){
            return;
        }
        if(has_valid_socket_type(this.fd)){
            var message = getPortsAndAddresses(this.fd as number, true, addresses)
            message["function"] = "Full_read"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["src_addr"])
            send(message)
        }

    }
})


Interceptor.attach(addresses["recv"],
{
    onEnter: function (args: any) {
        this.fd= args[0].toInt32();
       
    },
    onLeave: function (retval: any) {
        if(socketFDs.has(this.fd)){
            return;
        }
        if(has_valid_socket_type(this.fd)){
            var message = getPortsAndAddresses(this.fd as number, true, addresses)
            message["function"] = "Full_read"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["src_addr"])
            send(message)
        }


        
        
    }
})

Interceptor.attach(addresses["recvfrom"],
{
    onEnter: function (args: any) {
        this.fd = args[0].toInt32();
       
    },
    onLeave: function (retval: any) {
        if(socketFDs.has(this.fd)){
            return;
        }
        if(has_valid_socket_type(this.fd)){
            var message = getPortsAndAddresses(this.fd as number, true, addresses)
            message["function"] = "Full_read"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["src_addr"])
            send(message)
        }
    }
})


Interceptor.attach(addresses["send"],
{
    onEnter: function (args: any) {
        this.fd = args[0].toInt32();
        
       
    },
    onLeave: function (retval: any) {
        if(socketFDs.has(this.fd)){
            return;
        }
        if(has_valid_socket_type(this.fd)){
            var message = getPortsAndAddresses(this.fd as number, false, addresses)
            message["function"] = "Full_write"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["dst_addr"])
            send(message)
        }
    }
})


Interceptor.attach(addresses["sendto"],
{
    onEnter: function (args: any) {
        this.fd = args[0].toInt32();
    },
    onLeave: function (retval: any) {
        if(socketFDs.has(this.fd)){
            return;
        }
        if(has_valid_socket_type(this.fd)){
            var message = getPortsAndAddresses(this.fd as number, false, addresses)
            message["function"] = "Full_write"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["dst_addr"])
            send(message)
        }
    }
})

Interceptor.attach(addresses["write"],
{
    onEnter: function (args: any) {
        this.fd = args[0].toInt32();
    },
    onLeave: function (retval: any) {
        if(socketFDs.has(this.fd)){
            return;
        }
        if(has_valid_socket_type(this.fd)){
            var message = getPortsAndAddresses(this.fd as number, false, addresses)
            message["function"] = "Full_write"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["dst_addr"])
            send(message)
        }
    }
})

if(ObjC.available){
    Interceptor.attach(Module.getExportByName("libsystem_kernel.dylib","write"),
{
    onEnter: function (args: any) {
        var fd = args[0].toInt32();
        if(socketFDs.has(fd)){
            return;
        }
        if(has_valid_socket_type(fd)){
            var message = getPortsAndAddresses(fd as number, false, addresses)
            message["function"] = "Full_write"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["dst_addr"])
            send(message)

        }
       
    },
    onLeave: function (retval: any) {
        
    }
})

Interceptor.attach(Module.getExportByName("libsystem_kernel.dylib","read"),
{
    onEnter: function (args: any) {
        this.fd = args[0].toInt32();

    },
    onLeave: function (retval: any) {
        if(socketFDs.has(this.fd)){
            return;
        }
        if(has_valid_socket_type(this.fd)){
            var message = getPortsAndAddresses(this.fd as number, true, addresses)
            message["function"] = "Full_read"
            message["contentType"] = "netlog"
            socketFDs.set(this.fd, message["src_addr"])
            send(message)
        }
        

    }
})

}



}






// the low level part is under development and currently not exported for usage
var socket_syscall_lookup_table: { [key: string]: string | number } = {
    "Android_arm64" : 198

}

function get_syscall_intruction() : string
{
    var arch = get_process_architecture()
    var syscall_inst = "";
    if(arch === "arm"){
        syscall_inst = "swi";
    }else if(arch === "arm64"){
        syscall_inst = "svc";
    }else if(arch === "ia32"){
        syscall_inst = "int 0x80";
    }else{
        syscall_inst = "syscall"
    }
    return syscall_inst

}



/*

Process
Process.id: property containing the PID as a number

Process.arch: property containing the string ia32, x64, arm or arm64

Process.platform: property containing the string windows, darwin, linux or qnx */


function get_socket_syscall_number(){
    return socket_syscall_lookup_table[get_syscall_intruction()];
}

/*
fuction get_socket_syscall(){
    // ARM64    [198,"socket",0xc6,["int","int","int"]],
}*/