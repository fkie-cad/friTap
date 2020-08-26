package com.example.sslplayground

import android.util.Log
import android.widget.Spinner
import android.widget.ToggleButton
import com.wolfssl.WolfSSL
import com.wolfssl.provider.jsse.WolfSSLSocket
import com.wolfssl.provider.jsse.WolfSSLSocketFactory
import java.lang.Exception
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import javax.net.ssl.*


class CustomSSLSocketFactory(private val rsaSwitch : ToggleButton, private val sslLibrarySpinner: Spinner) : SSLSocketFactory() {
    private lateinit var defaultFactory : SSLSocketFactory

    init {
        if(sslLibrarySpinner.selectedItem == "BoringSSL"){
            defaultFactory = SSLContext.getInstance("TLS", "AndroidOpenSSL").apply { init(null, null, null) }.socketFactory
        }else if(sslLibrarySpinner.selectedItem == "WolfSSL"){
            defaultFactory = SSLContext.getInstance("TLS", "wolfJSSE").apply { init(null, null, null) }.socketFactory
        }else if(sslLibrarySpinner.selectedItem == "BouncyCastle"){
            defaultFactory = SSLContext.getInstance("TLS", "SCJSSE").apply { init(null, null, null) }.socketFactory
        }else if(sslLibrarySpinner.selectedItem == "GmsCore_OpenSSL"){
            defaultFactory = getDefault() as SSLSocketFactory
        }
    }

    override fun getDefaultCipherSuites(): Array<String> {
        throw RuntimeException("Not Implemented!")
    }

    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
        s?.run { close() }
        Log.i(this.javaClass.name, "Factory: " + this.defaultFactory.javaClass.name)
        val socket = defaultFactory.createSocket() as SSLSocket

        if(rsaSwitch.isChecked){
            //Have to downgrade TLS to 1.2, as 1.3 disallows RSA
            socket.enabledProtocols = socket.enabledProtocols.filterNot { it.contains("1.3") }.toTypedArray()
            socket.enabledCipherSuites = socket.supportedCipherSuites.filter { it.startsWith("TLS_RSA") }.toTypedArray()
        }else{
            socket.enabledCipherSuites = socket.supportedCipherSuites.filterNot { it.startsWith("TLS_RSA") }.toTypedArray()
        }
        Log.i(this.javaClass.name, "Protocols: " + socket.enabledProtocols.joinToString())
        Log.i(this.javaClass.name, "Cipher Suites: " + socket.enabledCipherSuites.joinToString())

        socket.keepAlive = false
        socket.connect(InetSocketAddress(host, port))
        return socket
    }

    override fun createSocket(host: String?, port: Int): Socket {
        throw RuntimeException("Not Implemented!")
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