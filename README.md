# friTap

![](/home/daniel/research/projects/fritap/logo.png)



The goal of this project is to help researchers to analyze traffic encapsulated in SSL or TLS. For details have a view into the [slides](./friTap.pdf).

This project was inspired by [SSL_Logger](https://github.com/google/ssl_logger ) and currently supports Android and Linux as well. More platforms will be added in future releases.

## Features planend for future releases

- [ ] fix spawning issue on Linux e.g. with Firefox

- [ ] add further Linux/Android Libraries (have a look at this [Wikipedia entry](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations)):

- Botan
- GnuTLS
- Mbed TLS 
- MatrixSSL
- ...

- [ ] Analysing the decrypted traffci/PCAP on the fly with Wireshark (create a FD which can be observed)
- [ ] add iOS support
- [ ] add Windows support 
- [ ] Google traffic analysis