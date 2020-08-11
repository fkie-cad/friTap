# Evaluation

| App | TLS Implementation | Tracable? | Comment |
| ------ | ------ | ------ | ------ |
| Flipboard | Boringssl/Openssl | Yes | |
| Paypal | Boringssl/Openssl | Yes | Works fine. For HTTP2 traffic you have to tell wireshark explicitly what it is. |
| Spotify | Boringssl/Openssl | Yes | Is unity based, which leads to the assumption that unity apps in general should work. |
| Raid Shadow Legends | Boringssl/Openssl | Yes | |
| FreeNow | Boringssl/Openssl | Yes | |
| Lierando | Boringssl/Openssl | Partly | Can read initial traffic, but not requests to individual restaurants. Lots of forking going on, also spawns a service. |
| Facebook | Boringssl/Openssl | Partly | Can read SSL traffic, but there is mainly QUIC |
| Whatsapp | Boringssl/Openssl | Partly | Some SSL traffic can be read, but most is happening via NoisePipes on port 5222 |
| Firefox | Boringssl/Openssl | Partly? | Some parts are there but there is definitly something missing. |  
| Chrome | Boringsssl/Openssl | Partly? | Some parts are there but there is definitly something missing. Chrome runs multiple processes that cannot even be catched via spawn-gating. When trying to attach to "com.android.chrome:sandboxed_process0:org.chromium.content.app.SandboxedPro" the process crashes, maybe some kind of anti-debug. Some information here: https://www.zdnet.com/article/google-strengthens-chrome-for-android-with-sandbox/|
| Twitter | Openssl ??? | No | No calls to SSL_read/write, but to many methods from libcrypto. Maybe own implementation?|
