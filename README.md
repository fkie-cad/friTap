# SSL-Interceptor

The main goal is to port ssl_logger(cf. [1]) to the Android Plattform.
For this purpose we want at first enumerate the most used SSL/TLS-libraries for Android. Next we want to build a frida framework which allows us to intercept the traffic for each used TLS-Implementation on Android.
This frida framework - by now called SSL-Interceptor (a better name has to be find) - should allow us two features at least:
- extracting the encryption keys from the used SSL-Implementation
- dump a PCAP wiht the decrypted content

In order to realize this project we fulfill the following steps:
- Enumerate the most common SSL/TLS-implementations used on Android. It is recommend to develop a test app which can use all the diffrent libraries so that we can later test our framework in a first iteration.
- Identify the "hooking points" of each SSL/TLS-implementation with the following goals:
    - 1. we want to extract at least the used symmetric keys 
    - 2. we want to dump the network communication which is encapsulated inside the SSL/TLS-Socket as PCAP
    - it shouldn't matter if cert pinning is in use or not.
- Enumerate a pool of apps in the "wild" which used SSL/TLS where we evaluate our framework
- Bonus: only deactivating cert pinning for the SSL/TLS-libaries


[1] https://github.com/google/ssl_logger 