package com.example.sslplayground

import android.os.AsyncTask
import android.os.Bundle
import android.os.Parcel
import android.os.Parcelable
import android.text.method.ScrollingMovementMethod
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.InputStream
import java.lang.ref.WeakReference
import java.net.URL
import java.net.URLConnection
import javax.net.ssl.HttpsURLConnection


class MainActivity : AppCompatActivity() {

    private val textView: TextView by lazy { findViewById<TextView>(R.id.textView) }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        textView.setHorizontallyScrolling(true)
        textView.movementMethod = ScrollingMovementMethod()
        textView.text = "Welcome!\n"
    }


    fun onTestButtonClick(view: View) {
        SSLConnecter(this).connect("https://wikipedia.org")
    }

    class SSLConnecter(val context : MainActivity) : ViewModel(){

        private val activity : WeakReference<MainActivity> = WeakReference(this.context)


        fun connect(url: String) {
            viewModelScope.launch(Dispatchers.IO) {

                val act: MainActivity? = activity.get()
                if (act != null) {
                    val url = URL(url)
                    val httpsUrlConnection: HttpsURLConnection = url.openConnection() as HttpsURLConnection
                    if(httpsUrlConnection.responseCode == HttpsURLConnection.HTTP_OK){
                        httpsUrlConnection.inputStream.bufferedReader().use {
                        act.textView.append(it.readText())

                        }
                    } else {
                           act.textView.append("HTTP " + httpsUrlConnection.responseCode.toString())
                        }
                    }
                }
            }
        }
    }
