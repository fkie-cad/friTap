import { log } from "./log"
import { byteArrayToString, byteArrayToNumber } from "./shared"
import { inspect } from "util";

export function execute() {
    Java.perform(function () {

        var appDataOutput = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect$AppDataOutput")
        appDataOutput.write.overload('[B', 'int', 'int').implementation = function (buf: any, offset: any, len: any) {
            var result: Array<number> = [];
            for (var i = 0; i < len; ++i) {
                result.push(buf[i]);
            }
            var message: { [key: string]: any } = {}
            message["contentType"] = "datalog"
            message["src_port"] = this.this$0.value.getLocalPort()
            message["dst_port"] = this.this$0.value.getPort()
            var localAddress = this.this$0.value.getLocalAddress().getAddress()
            var inetAddress = this.this$0.value.getInetAddress().getAddress()
            if (localAddress.length == 4) {
                message["src_addr"] = byteArrayToNumber(localAddress)
                message["dst_addr"] = byteArrayToNumber(inetAddress)
                message["ss_family"] = "AF_INET"
            } else {
                message["src_addr"] = byteArrayToString(localAddress)
                message["dst_addr"] = byteArrayToString(inetAddress)
                message["ss_family"] = "AF_INET6"
            }
            message["ssl_session_id"] = ""
            message["function"] = "writeApplicationData"
            send(message, result)
            return this.write(buf, offset, len)
        }

        var appDataInput = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect$AppDataInput")
        appDataInput.read.overload('[B', 'int', 'int').implementation = function (buf: any, offset: any, len: any) {
            var bytesRead = this.read(buf, offset, len)
            var result: Array<number> = [];
            for (var i = 0; i < bytesRead; ++i) {
                result.push(buf[i]);
            }
            var message: { [key: string]: any } = {}
            message["contentType"] = "datalog"
            message["ss_family"] = "AF_INET"
            message["src_port"] = this.this$0.value.getPort()
            message["dst_port"] = this.this$0.value.getLocalPort()
            var localAddress = this.this$0.value.getLocalAddress().getAddress()
            var inetAddress = this.this$0.value.getInetAddress().getAddress()
            if (localAddress.length == 4) {
                message["src_addr"] = byteArrayToNumber(localAddress)
                message["dst_addr"] = byteArrayToNumber(inetAddress)
                message["ss_family"] = "AF_INET"
            } else {
                message["src_addr"] = byteArrayToString(localAddress)
                message["dst_addr"] = byteArrayToString(inetAddress)
                message["ss_family"] = "AF_INET6"
            }
            message["ssl_session_id"] = ""
            message["function"] = "readApplicationData"
            send(message, result)
            return bytesRead
        }


    })

}