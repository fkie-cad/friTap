import { log } from "../util/log.js"
import { byteArrayToString, byteArrayToNumber, getAttribute, reflectionByteArrayToString } from "../shared/shared_functions.js"
export function execute() {
    Java.perform(function () {

        //Hook the inner class "AppDataOutput/input" of ProvSSLSocketDirect, so we can access the 
        //socket information in its outer class by accessing this.this$0
        var appDataOutput = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect$AppDataOutput")
        appDataOutput.write.overload('[B', 'int', 'int').implementation = function (buf: any, offset: any, len: any) {
            var result: Array<number> = [];
            for (var i = 0; i < len; ++i) {
                result.push(buf[i] & 0xff);
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
            message["ssl_session_id"] = byteArrayToString(this.this$0.value.getConnection().getSession().getId())
            //log(message["ssl_session_id"])
            message["function"] = "writeApplicationData"
            send(message, result)

            return this.write(buf, offset, len)
        }

        var appDataInput = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect$AppDataInput")
        appDataInput.read.overload('[B', 'int', 'int').implementation = function (buf: any, offset: any, len: any) {
            var bytesRead = this.read(buf, offset, len)
            var result: Array<number> = [];
            for (var i = 0; i < bytesRead; ++i) {
                result.push(buf[i] & 0xff);
            }
            var message: { [key: string]: any } = {}
            message["contentType"] = "datalog"
            message["ss_family"] = "AF_INET"
            message["src_port"] = this.this$0.value.getPort()
            message["dst_port"] = this.this$0.value.getLocalPort()
            var localAddress = this.this$0.value.getLocalAddress().getAddress()
            var inetAddress = this.this$0.value.getInetAddress().getAddress()
            if (localAddress.length == 4) {
                message["src_addr"] = byteArrayToNumber(inetAddress)
                message["dst_addr"] = byteArrayToNumber(localAddress)
                message["ss_family"] = "AF_INET"
            } else {
                message["src_addr"] = byteArrayToString(inetAddress)
                message["dst_addr"] = byteArrayToString(localAddress)
                message["ss_family"] = "AF_INET6"
            }
            message["ssl_session_id"] = byteArrayToString(this.this$0.value.getConnection().getSession().getId())
            log(message["ssl_session_id"])
            message["function"] = "readApplicationData"
            send(message, result)

            return bytesRead
        }
        //Hook the handshake to read the client random and the master key
        var ProvSSLSocketDirect = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect")
        ProvSSLSocketDirect.notifyHandshakeComplete.implementation = function (x: any) {

            var protocol = this.protocol.value
            var securityParameters = protocol.securityParameters.value
            var clientRandom = securityParameters.clientRandom.value
            var masterSecretObj = getAttribute(securityParameters, "masterSecret")

            //The key is in the AbstractTlsSecret, so we need to access the superclass to get the field
            var clazz = Java.use("java.lang.Class")
            var masterSecretRawField = Java.cast(masterSecretObj.getClass(), clazz).getSuperclass().getDeclaredField("data")
            masterSecretRawField.setAccessible(true)
            var masterSecretReflectArray = masterSecretRawField.get(masterSecretObj)
            var message: { [key: string]: any } = {}
            message["contentType"] = "keylog"
            message["keylog"] = "CLIENT_RANDOM " + byteArrayToString(clientRandom) + " " + reflectionByteArrayToString(masterSecretReflectArray)
            send(message)
            return this.notifyHandshakeComplete(x)
        }

    })

}