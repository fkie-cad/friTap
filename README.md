<p align="center">
    <img src="https://raw.githubusercontent.com/fkie-cad/friTap/main/assets/logo.png" alt="friTap logo" width="50%" height="50%"/>
</p>

# friTap
![version](https://img.shields.io/badge/version-1.3.2.0-blue) [![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=py&r=r&ts=1683906897&type=6e&v=1.3.2.0&x2=0)](https://badge.fury.io/py/friTap)

friTap is a powerful tool designed to assist researchers in analyzing network traffic encapsulated in SSL/TLS. With its ability to automate key extraction, friTap is especially valuable when dealing with malware analysis or investigating privacy issues in applications. By simplifying the process of decrypting and inspecting encrypted traffic, friTap empowers researchers to uncover critical insights with ease.

Key features include seamless support for automated SSL/TLS key extraction, making it an ideal choice for scenarios requiring rapid and accurate traffic analysis. Whether you’re dissecting malicious network behavior or assessing data privacy compliance, friTap streamlines your workflow.

For more details, explore the [OSDFCon webinar slides](assets/friTapOSDFConwebinar.pdf) or check out our [blog post](https://lolcads.github.io/posts/2022/08/fritap/).


This project was inspired by [SSL_Logger](https://github.com/google/ssl_logger ) and currently supports all major operating systems (Linux, Windows, Android). More platforms and libraries will be added in future releases.

## Key Features

The main features of friTap are:

- TLS key extraction in real time (`-k key.log`)
- Decryption of TLS payload as PCAP in real time (`-p plaintext.pcap`)
- Integration with Python. [Learn more](https://github.com/fkie-cad/friTap/blob/main/INTEGRATION.md)
- Support for custom Frida scripts. [Details](https://github.com/fkie-cad/friTap/blob/main/USAGE.md#Using-friTap-with-a-custom-Frida-scripts)
- Support of most common SSL libraries (OpenSSL, BoringSSL, NSS, GnuTLS, etc.)

## Installation

Installation is simply a matter of `pip3 install fritap`. This will give you the `fritap` command. You can update an existing `fritap` installation with `pip3 install --upgrade fritap`.

## Usage

On Linux/Windows/MacOS we can easily attach to a process by entering its name or its PID:

```bash
$ sudo fritap --pcap mycapture.pcap thunderbird
```

For mobile applications we just have to add the `-m` parameter to indicate that we are now attaching (or spawning) an Android or iOS app:

```bash
$ fritap -m -k keys.log com.example.app
```

Further ensure that the frida-server is running on the Android/iOS device. 


Remember when working with the pip installation you have to invoke the `fritap` command with sudo a little bit different. Either as module:
```bash
$ sudo -E python3 -m friTap.friTap --pcap mycapture.pcap thunderbird
```
or directly invoking the script:
```bash
$ which friTap
/home/daniel/.local/bin/friTap

$ sudo -E /home/daniel/.local/bin/friTap
```

friTap can also be used as a Python library within your project:
```python
from friTap import SSL_Logger
```
For more details on integrating friTap into your Python project, check out the [INTEGRATION.md](./INTEGRATION.md) guide.

friTap allows you to enhance its functionality by providing a custom Frida script during your session. This custom script will be invoked just before friTap applies its own hooks. To do so, use the `-c` parameter ([more](./USAGE.md#Using-friTap-with-a-custom-Frida-scripts)).
More examples on using friTap can be found in the [USAGE.md](./USAGE.md). A detailed introduction using friTap on Android is under [EXAMPLE.md](./EXAMPLE.md) as well.

## Hooking Libraries Without Symbols

In certain scenarios, the library we want to hook offers no symbols or is statically linked with other libraries, making it challenging to directly hook functions. For example Cronet (`libcronet.so`) and Flutter (`libflutter.so`) are often statically linked with **BoringSSL**.

Despite the absence of symbols, we can still use friTap for parsing and hooking.

### Hooking by Byte Patterns

To solve this, we can use friTap with byte patterns to hook the desired functions. You can provide friTap with a JSON file that contains byte patterns for hooking specific functions, based on architecture and platform using the `--patterns <byte-pattern-file.json>` option.
In order to apply the apprioate hooks for the various byte patterns we distinguish between different hooking categories.
These categories include:

  -  Dump-Keys
  -  Install-Key-Log-Callback
  -  KeyLogCallback-Function
  -  SSL_Read
  -  SSL_Write

Each category has a primary and fallback byte pattern, allowing flexibility when the primary pattern fails.
For libraries like BoringSSL, where TLS functionality is often statically linked into other binaries, we developed a tool called [BoringSecretHunter](https://github.com/monkeywave/BoringSecretHunter). This tool automatically identifies the necessary byte patterns to hook BoringSSL by byte-pattern matching. Specifically, BoringSecretHunter focuses on identifying the byte patterns for functions in the Dump-Keys category, allowing you to extract encryption keys during TLS sessions with minimal effort. More about the different hooking categories can be found in [usage of byte-patterns in friTap](./USAGE.md#hooking-by-byte-patterns).

### Hooking by Offsets

Alternatively, you can use the `--offsets <offset-file.json>` option to hook functions using known offsets. friTap allows you to specify user-defined offsets (relative to the base address of the targeting SSL/socket library) or absolute virtual addresses for function resolution. This is done through a JSON file, which is passed using the `--offsets` parameter.

If the `--offsets` parameter is used, friTap will only overwrite the function addresses specified in the JSON file. For functions that are not specified, friTap will attempt to detect the addresses automatically (using symbols).


## Problems

The absence of traffic or incomplete traffic capture in the resulting pcap file (-p <your.pcap>) may stem from various causes. Before submitting a new issue, consider attempting the following solutions:

### Default Socket Information

There might be instances where friTap fails to retrieve socket information. In such scenarios, running friTap with default socket information (`--enable_default_fd`) could resolve the issue. This approach utilizes default socket information (127.0.0.1:1234 to 127.0.0.1:2345) for all traffic when the file descriptor (FD) cannot be used to obtain socket details:

```bash
fritap -m --enable_default_fd -p plaintext.pcap com.example.app
```

### Handling Subprocess Traffic

Traffic originating from a subprocess could be another contributing factor. To capture this traffic, friTap can leverage Frida's spawn gating feature, which intercepts newly spawned processes using the `--enable_spawn_gating` parameter:

```bash
fritap -m -p log.pcap --enable_spawn_gating com.example.app
```

### Library Support exist only for Key Extraction

In cases where the target library solely supports key extraction (cf. the table below), you can utilize the `-k <key.log>` parameter alongside full packet capture:

```bash
fritap -m -p log.pcap --full_capture -k keys.log com.example.app
```

### Seeking Further Assistance

If these approaches do not address your issue, please create a detailed issue report to aid in troubleshooting. To facilitate a more effective diagnosis, include the following information in your report:

- The operating system and its version
- The specific application encountering the issue or a comparable application that exhibits similar problems
- The output from executing friTap with the specified parameters, augmented with friTap's debug output:
```bash
fritap -do -v com.example.app
```


## Supported SSL/TLS implementations and corresponding logging capabilities

```markdown
| Library                   | Linux         | Windows       | MacOSX   | Android  | iOS          |
|---------------------------|---------------|---------------|----------|----------|--------------|
| OpenSSL                   |     Full      | R/W-Hook only |  TBI     |   Full   | TBI          |
| BoringSSL                 |     Full      | R/W-Hook only |  KeyEo   |   Full   | KeyEo        |
| NSS                       |     Full      | R/W-Hook only |  TBI     |   TBA    | TBI          |
| GnuTLS                    | R/W-Hook only | R/W-Hook only |  TBI     |   Full   | TBI          |
| WolfSSL                   | R/W-Hook only | R/W-Hook only |  TBI     |   Full   | TBI          |
| MbedTLS                   | R/W-Hook only | R/W-Hook only |  TBI     |   Full   | TBI          |
| Bouncycastle/Spongycastle |     TBA       |    TBA        |  TBA     |   Full   | TBA          |
| Conscrypt                 |     TBA       |    TBA        |  TBA     |   Full   | TBA          |
| S2n-tls                   |     Full      |    LibNO      |  TBA     |   Full   | LibNO        |
| RusTLS                    |     KeyEo     |    TBI        |  TBI     |   KeyEo  | TBI          |
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
- `>= python3.7`
- click (`python3 -m pip install click`)
- hexdump (`python3 -m pip install hexdump`)
- scapy (`python3 -m pip install scapy`)
- watchdog (`python3 -m pip install watchdog`)
- importlib.resources  (`python3 -m pip install importlib-resources`)
- AndroidFridaManager (`python3 -m pip install AndroidFridaManager`)
- for hooking on Android ensure that the `adb`-command is in your PATH

## Planned features

- [ ] add the capability to alter the decrypted payload
  - integration with https://github.com/mitmproxy/mitmproxy
  - integration with http://portswigger.net/burp/
- [ ] add wine support
- [x] <strike>add Flutter support</strike>
- [ ] add further libraries (have a look at this [Wikipedia entry](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations)):
  - Botan (BSD license, Jack Lloyd)
  - LibreSSL (OpenBSD)
  - Cryptlib (Peter Gutmann)
  - JSSE (Java Secure Socket Extension, Oracle)
  - [MatrixSSL](https://github.com/matrixssl/matrixssl) 
  - ...
- [x] <strike>Working with static linked libraries</strike>
- [x] <strike>Add feature to prototype TLS-Read/Write/SSLKEY functions</strike>
- [ ] improve iOS/MacOS support (currently under development)

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
