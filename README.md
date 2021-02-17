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
$ sudo python3 ./friTap.py -a --pcap mycapture.pcap com.example.app
```

Further ensure that the frida-server is running on the Android device. More examples on using fritap can be found in the [USAGE.md](./USAGE.md).

## Dependencies

- [frida](https://frida.re) Version 12.11.18 is the most stable, so if you have issues install this via `pip install frida==12.11.18`
- >= python3.6

## Planned features

- [ ] fix spawning issue on Linux e.g. with Firefox

- [ ] add wine support for Windows

- [ ] add further Linux/Android Libraries (have a look at this [Wikipedia entry](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations)):

- Botan
- Mbed TLS 
- MatrixSSL
- ...

- Working with static linked libraries
- Add feature to prototype TLS-Read/Write/SSLKEY functions

- [ ] add iOS support
- [ ] add Windows support 
- [ ] Google traffic analysis

