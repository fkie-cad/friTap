import { log } from "./log"

export function execute() {
    Java.perform(function () {
        var TlsClientProtocol = Java.use("org.spongycastle.tls.TlsClientProtocol")

        TlsClientProtocol.$init.overload("java.io.InputStream", "java.io.OutputStream").implementation = function (x, y) {
            log("Client intit")
            this.$init.call(this, x, y)

            this.writeApplicationData.implementation = function (buf: any, offset: any, len: any) {
                log("writeApplicationData")
                var result: Array<number> = [];
                for (var i = 0; i < len; ++i) {
                    result.push(buf[i]);
                }
                var message: { [key: string]: any } = {}
                message["contentType"] = "datalog"
                message["ss_family"] = "AF_INET"
                message["src_port"] = 50505
                message["dst_port"] = 443
                message["src_addr"] = 0
                message["dst_addr"] = 130
                message["ssl_session_id"] = ""
                message["function"] = "writeApplicationData"
                send(message, result)
                return this.writeApplicationData.call(this, buf, offset, len)
            }
            this.readApplicationData.implementation = function (buf: any, offset: any, len: any) {
                log("readApplicationData")
                log(String(offset))
                var bytesRead = this.readApplicationData.call(this, buf, offset, len)
                var result: Array<number> = [];
                for (var i = 0; i < bytesRead; ++i) {
                    result.push(buf[i]);
                }
                var message: { [key: string]: any } = {}
                message["contentType"] = "datalog"
                message["ss_family"] = "AF_INET"
                message["src_port"] = 443
                message["dst_port"] = 50505
                message["src_addr"] = 130
                message["dst_addr"] = 0
                message["ssl_session_id"] = ""
                message["function"] = "readApplicationData"
                send(message, result)
                return bytesRead
            }
            return
        }

    })
}