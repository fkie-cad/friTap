package com.example.sslplayground

import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.util.Log
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.wolfssl.WolfSSL
import com.wolfssl.provider.jsse.WolfSSLProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.lang.ref.WeakReference
import java.net.URL
import java.security.Security
import javax.net.ssl.HttpsURLConnection

class MainActivity : AppCompatActivity() {

    private val textViewOutput: TextView by lazy { findViewById<TextView>(R.id.Output) }

    private val textViewConnectionInformation: TextView by lazy { findViewById<TextView>(R.id.connectionInformation) }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        textViewConnectionInformation.setHorizontallyScrolling(true)
        textViewConnectionInformation.movementMethod = ScrollingMovementMethod()
        textViewConnectionInformation.text = "Welcome!\n"

        textViewOutput.setHorizontallyScrolling(true)
        textViewOutput.movementMethod = ScrollingMovementMethod()

    }


    fun onHTTPGetWikipediaClick(view: View) {
        SSLConnecter(this).connect("https://wikipedia.org")
    }



    class SSLConnecter(val context : MainActivity) : ViewModel(){

        private val activity : WeakReference<MainActivity> = WeakReference(this.context)

        companion object {
            init {
                System.loadLibrary("wolfssl")
                System.loadLibrary("wolfssljni")
            }
        }

        fun connect(url: String) {
            val ssl = WolfSSL()

            Security.insertProviderAt(WolfSSLProvider(), 1)
            Log.i(this.javaClass.name, Security.getProviders().joinToString())
            viewModelScope.launch(Dispatchers.IO) {
                val act: MainActivity? = activity.get()
                if (act != null) {
                    HttpsURLConnection.setDefaultSSLSocketFactory(CustomSSLSocketFactory(act.findViewById(R.id.keyExchangeSwitch)))
                    val url = URL(url)
                    val httpsUrlConnection = url.openConnection() as HttpsURLConnection

                    if (httpsUrlConnection.responseCode == HttpsURLConnection.HTTP_OK) {
                        httpsUrlConnection.inputStream.bufferedReader().use {
                            act.textViewOutput.append(it.readText())
                            act.textViewConnectionInformation.append("HTTP " + httpsUrlConnection.responseCode.toString() + "\n")
                            act.textViewConnectionInformation.append("Cipher suite: " + httpsUrlConnection.cipherSuite + "\n")
                        }
                    } else {
                        act.textViewConnectionInformation.append("HTTP " + httpsUrlConnection.responseCode.toString())
                    }
                    httpsUrlConnection.disconnect()
                }

            }
        }
    }

    fun onHTTPGetGoogleClick(view: View) {
        SSLConnecter(this).connect("https://www.google.com/")
    }
}
