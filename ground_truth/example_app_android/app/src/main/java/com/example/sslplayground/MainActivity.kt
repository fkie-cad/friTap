package com.example.sslplayground

import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.util.Log
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.android.gms.security.ProviderInstaller
import com.wolfssl.WolfSSL
import com.wolfssl.provider.jsse.WolfSSLProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.spongycastle.jce.provider.BouncyCastleProvider
import org.spongycastle.jsse.provider.BouncyCastleJsseProvider
import java.lang.RuntimeException
import java.lang.ref.WeakReference
import java.net.URL
import java.security.Security
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLHandshakeException

class MainActivity : AppCompatActivity() {

    private val textViewOutput: TextView by lazy { findViewById<TextView>(R.id.Output) }

    private val textViewConnectionInformation: TextView by lazy { findViewById<TextView>(R.id.connectionInformation) }

    private val spinnerSSLLibrary: Spinner by lazy {findViewById<Spinner>(R.id.sslLibrarySpinner)}

    companion object {
        init {
            System.loadLibrary("wolfssl")
            System.loadLibrary("wolfssljni")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        textViewConnectionInformation.setHorizontallyScrolling(true)
        textViewConnectionInformation.movementMethod = ScrollingMovementMethod()
        textViewConnectionInformation.text = "Welcome!\n"

        textViewOutput.setHorizontallyScrolling(true)
        textViewOutput.movementMethod = ScrollingMovementMethod()

        //Initialise spinner for selecting library
        ArrayAdapter.createFromResource(
            this,
            R.array.ssl_library_array,
            android.R.layout.simple_spinner_item
        ).also { adapter ->
            // Specify the layout to use when the list of choices appears
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            // Apply the adapter to the spinner
            spinnerSSLLibrary.adapter = adapter
        }
        Security.addProvider(WolfSSLProvider())
        Security.addProvider(BouncyCastleProvider())
        Security.addProvider(BouncyCastleJsseProvider())
        ProviderInstaller.installIfNeeded(this)
    }


    fun onHTTPGetWikipediaClick(view: View) {
        SSLConnecter(this).connect("https://wikipedia.org")
    }



    class SSLConnecter(val context : MainActivity) : ViewModel(){

        private val activity : WeakReference<MainActivity> = WeakReference(this.context)


        fun connect(url: String) {
            val ssl = WolfSSL()

            viewModelScope.launch(Dispatchers.IO) {
                val act: MainActivity? = activity.get()
                if (act != null) {

                    Log.i(this.javaClass.name, Security.getProviders().joinToString())

                    HttpsURLConnection.setDefaultSSLSocketFactory(CustomSSLSocketFactory(act.findViewById(R.id.keyExchangeSwitch), act.findViewById(R.id.sslLibrarySpinner)))
                    val url = URL(url)
                    val httpsUrlConnection = url.openConnection() as HttpsURLConnection
                    try {
                        if (httpsUrlConnection.responseCode == HttpsURLConnection.HTTP_OK) {
                            httpsUrlConnection.inputStream.bufferedReader().use {
                                act.textViewOutput.append(it.readText())
                                act.textViewConnectionInformation.append("HTTP " + httpsUrlConnection.responseCode.toString() + "\n")
                                act.textViewConnectionInformation.append("Cipher suite: " + httpsUrlConnection.cipherSuite + "\n")
                            }
                        } else {
                            act.textViewConnectionInformation.append("HTTP " + httpsUrlConnection.responseCode.toString())
                        }
                    }catch(e : SSLHandshakeException){
                        act.textViewConnectionInformation.append("Handshake error!\n")
                        Log.e(this.javaClass.name, e.toString())
                        e.printStackTrace()
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
