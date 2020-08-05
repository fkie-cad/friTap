# Evaluation

| App | TLS Implementation | Tracable? | Comment |
| ------ | ------ | ------ | ------ |
| Firefox | Boringssl/Openssl | Partly? | Some parts are there but there is definitly something missing. |  
| Flipboard | Boringssl/Openssl | Yes | |
| Facebook | Boringssl/Openssl | Partly | Can read SSL traffic, but there is mainly QUIC |
| Whatsapp | Boringssl/Openssl | Partly | Some SSL traffic can be read, but most is happening via NoisePipes on port 5222 |
| Twitter | Openssl ??? | No | No calls to SSL_read/write, but to many methods from libcrypto. Maybe own implementation? |
| Paypal | Boringssl/Openssl | Yes | Works fine. For HTTP2 traffic you have to tell wireshark explicitly what it is. |
| Spotify | Boringssl/Openssl | Yes | |