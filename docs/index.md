---
layout: default
title: friTap - Decrypting TLS Traffic On The Fly
---

![friTap Logo](https://raw.githubusercontent.com/fkie-cad/friTap/main/assets/logo.png)

```bash
pip install fritap
```

# Welcome to friTap

friTap is a powerful tool designed to assist researchers in analyzing network traffic encapsulated in SSL/TLS. With its ability to automate key extraction, friTap is especially valuable when dealing with malware analysis or investigating privacy issues in applications. By simplifying the process of decrypting and inspecting encrypted traffic, friTap empowers researchers to uncover critical insights with ease.

Key features include seamless support for automated SSL/TLS key extraction, making it an ideal choice for scenarios requiring rapid and accurate traffic analysis. Whether you're dissecting malicious network behavior or assessing data privacy compliance, friTap streamlines your workflow.

For more details, explore the [OSDFCon webinar slides](https://github.com/fkie-cad/friTap/blob/main/assets/friTapOSDFConwebinar.pdf) or check out [our blog post](https://lolcads.github.io/posts/2022/08/fritap/).

Inspired by [SSL_Logger](https://github.com/google/ssl_logger), friTap supports all major platforms, including Linux, Windows, and Android, with plans to expand to additional platforms and libraries in future releases.

## Key Features

The main features of friTap are:

- TLS key extraction in real time
- Decryption of TLS payload as PCAP in real time
- Integration with Python. [Learn more](https://github.com/fkie-cad/friTap/blob/main/INTEGRATION.md)
- Support for custom Frida scripts. [Details](https://github.com/fkie-cad/friTap/blob/main/USAGE.md#Using-friTap-with-a-custom-Frida-scripts)
- Support of most common SSL libraries (OpenSSL, BoringSSL, NSS, GnuTLS, etc.)


## Motivation

More and more malware leverages TLS encryption to hide its communications and to exfiltrate data to its command server, effectively bypassing traditional detection platforms. Therefore, obtaining decrypted network traffic becomes crucial for digital forensics investigations. Current techniques such as SSL pinning may render established analysis approaches like MitM proxies useless. In many cases, the time-consuming process of reverse engineering the application of interest remains the only option to obtain the keys for decrypting the network traffic.


## Concept

friTap is a framework to solve these issues by intercepting the generation of encryption keys used by TLS for the purpose of decrypting the traffic an application sends.

![friTap Workflow](https://raw.githubusercontent.com/fkie-cad/friTap/main/assets/fritap_workflow.png)

Whenever an application decides to create a TLS connection (1) it usually utilizes its appropriate TLS library. This TLS library then creates the TLS socket (TLS handshake (2)). When the TLS handshake is finished the TLS stream is established (3). 

At this point the application uses the TLS write functions from the used TLS library to write its plaintext to the TLS stream where it gets encapsulated. In addition, the application utilizes the TLS read function from the used TLS library to process the decrypted TLS payload.

friTap identifies the TLS library used and creates the appropriate hooks so that all plaintext is saved into a PCAP. Likewise, the plaintext can be output directly on the command line. Besides the possibility of saving the plaintext of TLS payload into a PCAP, friTap also enables the extraction of the TLS encryption keys. 

![friTap inner working](https://raw.githubusercontent.com/fkie-cad/friTap/main/assets/fritap_inner_working.png)

friTap identifies the TLS library used and creates the appropriate hooks (4) so that all plaintext is saved into a PCAP. Likewise, the plaintext can be output directly on the command line. Besides the possibility of saving the plaintext of TLS payload into a PCAP, friTap also enables the extraction of the TLS encryption keys. 

## Working with friTap

 friTap provides two operation modes. One is to get the plaintext from the TLS payload as PCAP and the other is to get the used TLS keys. In order to get the decrypted TLS payload we need the `-p` parameter:
 ```bash
$ fritap –m –p decrypted_TLS.pcap <target_app>

[*] NSS.so found & will be hooked on Android!
[*] Android dynamic loader hooked.
[*] Logging pcap to decrypted_TLS.pcap
 ```


The `-m` parameter indicates that we are analyzing a mobile application in the above example. Here, the implementations of the SSL libraries often differ from those of conventional desktop systems. For extracting the TLS keys from a target application we need the `-k` parameter:
```bash
$ fritap –m –k TLS_keys.log <target_app>

[*] BoringSSL.dylib found & will be hooked on iOS!
[*] iOS dynamic loader hooked.
[*] Logging keylog file to TLS_keys.log
```

As a result friTap writes all TLS keys to the TLS_keys.log file using the NSS Key Log Format.


## Resources
- [GitHub Repository](https://github.com/fkie-cad/friTap)
- [Usage Guide](https://github.com/fkie-cad/friTap/blob/main/USAGE.md)
- [Integration Guide](https://github.com/fkie-cad/friTap/blob/main/INTEGRATION.md)


