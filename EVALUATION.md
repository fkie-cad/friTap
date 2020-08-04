# Evaluation

| App | TLS Implementation | Tracable? | Comment |
| ------ | ------ | ------ | ------ |
| Firefox | Boringssl/Openssl | Partly | Not sure if everything is traced, or some part is still missing |  
| Flipboard | Boringssl/Openssl | Yes | |
| Facebook | Boringssl/Openssl | Partly | Can read SSL traffic, but there is mainly QUIC |
| Whatsapp | Boringssl/Openssl | Partly | Some SSL traffic can be read, but most is happening via NoisePipes on port 5222 |
| Twitter | Openssl ??? | No | No calls to SSL_read/write, but to many methods from libcrypto. Maybe own implementation? |
| Paypal | Boringssl/Openssl | Yes | Key reading works fine. Logging pcap also works, but has issues because of the missing session id problem |