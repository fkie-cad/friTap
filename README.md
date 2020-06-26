# SslInterceptor

The main goal is to port ssl_logger(cf. [1]) to the Android PLattform.
For this purpose we want at first enumerate the most used SSL/TLS-libraries for Android. Next we want to build a frida framework which allows us to intercept the traffic for each used TLS-Implementation on Android.
This frida framework - by now called SSL-Interceptor (a better name has to be find) - should allow us two features at least:
- extracting the encryption keys from the used SSL-Implementation
- dunmp a PCAP wiht the decrypted content





[1] https://github.com/google/ssl_logger 