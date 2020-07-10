package com.example.sslplayground

import java.lang.Exception
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class CustomSSLSocketFactory : SSLSocketFactory() {
    private val defaultFactory = SSLSocketFactory.getDefault() as SSLSocketFactory

    override fun getDefaultCipherSuites(): Array<String> {
        throw RuntimeException("Not Implemented!")
    }

    override fun createSocket(p0: Socket?, p1: String?, p2: Int, p3: Boolean): Socket {
        throw RuntimeException("Not Implemented!")
    }

    override fun createSocket(host: String?, port: Int): Socket {
        val socket = defaultFactory.createSocket() as SSLSocket
        socket.enabledCipherSuites = socket.enabledCipherSuites.filter{s -> s.contains("RSA")} as Array<String>
        socket.connect(InetSocketAddress(host, port)) //HIER HAST DU AUFGEHÖRT
        return socket
    }

    override fun createSocket(p0: String?, p1: Int, p2: InetAddress?, p3: Int): Socket {
        throw RuntimeException("Not Implemented!")
    }

    override fun createSocket(p0: InetAddress?, p1: Int): Socket {
        throw RuntimeException("Not Implemented!")
    }

    override fun createSocket(p0: InetAddress?, p1: Int, p2: InetAddress?, p3: Int): Socket {
        throw RuntimeException("Not Implemented!")
    }

    override fun getSupportedCipherSuites(): Array<String> {
        throw RuntimeException("Not Implemented!")
    }
}