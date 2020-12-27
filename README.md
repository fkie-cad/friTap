# friTap

![](/home/daniel/research/projects/fritap/logo.png)



The goal of this project is to help researchers to analyze traffic encapsulated in SSL or TLS. For details have a view into the [slides](./friTap.pdf).

This project was inspired by [SSL_Logger](https://github.com/google/ssl_logger ) and currently supports Android and Linux as well. More platforms will be added in future releases.

## Usage

On Linux we can easily attach to a process by entering its name or its PID:

```bash
$ sudo python3 ./friTap.py --pcap mycapture.pcap thunderbird
```



For Android we just have to add the -a parameter to indicate that we are now attaching (or spawning) an Android app:

```bash
$ sudo python3 ./friTap.py -a -pcap mycapture.pcap com.example.app
```

Further ensure that the frida-server is running on the Android device. More examples on using fritap can be found in the [USAGE.md](./USAGE.md).

## Planned features

- [ ] fix spawning issue on Linux e.g. with Firefox

- [ ] add further Linux/Android Libraries (have a look at this [Wikipedia entry](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations)):

- Botan
- GnuTLS
- Mbed TLS 
- MatrixSSL
- ...

- [ ] add iOS support
- [ ] add Windows support 
- [ ] Google traffic analysis

