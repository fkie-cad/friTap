<p align="center">
    <img src="https://raw.githubusercontent.com/fkie-cad/friTap/main/assets/logo.png" alt="friTap logo" width="50%" height="50%"/>
</p>

# friTap
![version](https://img.shields.io/badge/version-1.0.7-blue) [![PyPi](https://badge.fury.io/py/objection.svg)](https://pypi.org/project/friTap)

The goal of this project is to help researchers to analyze traffic encapsulated in SSL or TLS. For details have a view into the [OSDFCon webinar slides](assets/friTapOSDFConwebinar.pdf) or in [this blog post](https://lolcads.github.io/posts/2022/08/fritap/).


This project was inspired by [SSL_Logger](https://github.com/google/ssl_logger ) and currently supports all major operating systems (Linux, Windows, Android). More platforms and libraries will be added in future releases.

## Installation


Installation is simply a matter of `pip3 install fritap`. This will give you the `friTap` command. You can update an existing `friTap` installation with `pip3 install --upgrade friTap`.

Alternatively just clone the repository and run the `friTap.py` file or download the friTap standlone version from the release page.


## Usage

On Linux/Windows/MacOS we can easily attach to a process by entering its name or its PID:

```bash
$ sudo ./friTap.py --pcap mycapture.pcap thunderbird
```

For mobile applications we just have to add the `-m` parameter to indicate that we are now attaching (or spawning) an Android or iOS app:

```bash
$ ./friTap.py -m --pcap mycapture.pcap com.example.app
```

Further ensure that the frida-server is running on the Android/iOS device. 


Remember when working with the pip installation you have to invoke the `friTap` command with sudo a little bit different. Either as module:
```bash
$ sudo -E python3 -m friTap.friTap --pcap mycapture.pcap thunderbird
```
or directly invoking the script:
```bash
$ which friTap
/home/daniel/.local/bin/friTap

$ sudo -E /home/daniel/.local/bin/friTap
```



More examples on using friTap can be found in the [USAGE.md](./USAGE.md). A detailed introduction using friTap on Android is under [EXAMPLE.md](./EXAMPLE.md) as well.

## Supported SSL/TLS implementations and corresponding logging capabilities

```markdown
| Library                   | Linux         | Windows       | MacOSX   | Android  | iOS          |
|---------------------------|---------------|---------------|----------|----------|--------------|
| OpenSSL                   |     Full      | R/W-Hook only |  TBI     |   Full   | TBI          |
| BoringSSL                 |     Full      | R/W-Hook only |  KeyEo   |   Full   | KeyEo        |
| NSS                       | R/W-Hook only | R/W-Hook only |  TBI     |   TBA    | TBI          |
| GnuTLS                    | R/W-Hook only | R/W-Hook only |  TBI     |   Full   | TBI          |
| WolfSSL                   | R/W-Hook only | R/W-Hook only |  TBI     |   Full   | TBI          |
| MbedTLS                   | R/W-Hook only | R/W-Hook only |  TBI     |   Full   | TBI          |
| Bouncycastle/Spongycastle |     TBA       |    TBA        |  TBA     |   Full   | TBA          |
| Conscrypt                 |     TBA       |    TBA        |  TBA     |   Full   | TBA          |
```
**R/W-Hook only** = Logging data sent and received by process<br>
**KeyEo** = Only the keying material can be extracted<br>
**Full** = Logging data send and received by process + Logging keys used for secure connection<br>
**TBA** = To be answered<br>
**TBI** = To be implemented<br>
**LibNO** = This library is not supported for this plattform<br>

**We verified the Windows implementations only for Windows 10**

## Dependencies

- [frida](https://frida.re)
- `>= python3.6`
- hexdump (`pip3 install hexdump`)
- scapy (`pip3 install scapy`)

## Planned features

- [ ] add the capability to alter the decrypted payload
  - integration with https://github.com/mitmproxy/mitmproxy
  - integration with http://portswigger.net/burp/
- [ ] add wine support
- [ ] add Flutter support
- [ ] add further libraries (have a look at this [Wikipedia entry](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations)):
  - Botan (BSD license, Jack Lloyd)
  - LibreSSL (OpenBSD)
  - Cryptlib (Peter Gutmann)
  - S2n (Amazon)
  - JSSE (Java Secure Socket Extension, Oracle)
  - [MatrixSSL](https://github.com/matrixssl/matrixssl) 
  - ...
- [ ] Working with static linked libraries
- [ ] Add feature to prototype TLS-Read/Write/SSLKEY functions
- [ ] improve iOS/MacOS support (currently under development)
- [x] <strike>provide friTap as PyPI package</strike>

## Contribute

Contributions are always welcome. Just fork it and open a pull request!
More details can be found in the [CONTRIBUTION.md](./CONTRIBUTION.md).
___

## Changelog

See the wiki for [release notes](https://github.com/fkie-cad/friTap/wiki#news).

## Support

If you have any suggestions, or bug reports, please create an issue in the Issue Tracker.

In case you have any questions or other problems, feel free to send an email to:

[daniel.baier@fkie.fraunhofer.de](mailto:daniel.baier@fkie.fraunhofer.de).
