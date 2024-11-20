---
layout: default
title: friTap - DECRYPTING TLS TRAFFIC ON THE FLY
---

![friTap Logo](https://raw.githubusercontent.com/fkie-cad/friTap/main/assets/logo.png)

# Welcome to friTap

friTap is a powerful tool designed to assist researchers in analyzing network traffic encapsulated in SSL/TLS. With its ability to automate key extraction, friTap is especially valuable when dealing with malware analysis or investigating privacy issues in applications. By simplifying the process of decrypting and inspecting encrypted traffic, friTap empowers researchers to uncover critical insights with ease.

Key features include seamless support for automated SSL/TLS key extraction, making it an ideal choice for scenarios requiring rapid and accurate traffic analysis. Whether you're dissecting malicious network behavior or assessing data privacy compliance, friTap streamlines your workflow.

For more details, explore the [OSDFCon webinar slides](https://github.com/fkie-cad/friTap/blob/main/assets/friTapOSDFConwebinar.pdf) or check out [our blog post](https://lolcads.github.io/posts/2022/08/fritap/).

Inspired by [SSL_Logger](https://github.com/google/ssl_logger), friTap supports all major platforms, including Linux, Windows, and Android, with plans to expand to additional platforms and libraries in future releases.

## Key Features

The main features of friTap are:

- TLS key extraction in real time
- Decryption of TLS payload as PCAP in real time
- Integration with Python
- Support for custom Frida scripts
- Support of most common SSL libraries (OpenSSL, BoringSSL, NSS, GnuTLS, etc.)


## Motivation

More and more malware leverages TLS encryption to hide its communications and to exfiltrate data to its command server, effectively bypassing traditional detection platforms. Therefore, obtaining decrypted network traffic becomes crucial for digital forensics investigations. Current techniques such as SSL pinning may render established analysis approaches like MitM proxies useless. In many cases, the time-consuming process of reverse engineering the application of interest remains the only option to obtain the keys for decrypting the network traffic.


## Concept

friTap is a framework to solve these issues by intercepting the generation of encryption keys used by TLS for the purpose of decrypting the traffic an application sends.

![friTap Workflow](https://raw.githubusercontent.com/fkie-cad/friTap/main/assets/fritap_workflow.png)

Whenever an application decides to create a TLS connection it usually utilizes its appropriate TLS library. This TLS library then creates the TLS socket (TLS handshake x   ). When the TLS handshake is finished the TLS stream is established. 

At this point the application uses the TLS write functions from the used TLS library to write its plaintext to the TLS stream where it gets encapsulated. In addition, the application utilizes the TLS read function from the used TLS library to process the decrypted TLS payload.

friTap identifies the TLS library used and creates the appropriate hooks so that all plaintext is saved into a PCAP. Likewise, the plaintext can be output directly on the command line. Besides the possibility of saving the plaintext of TLS payload into a PCAP, friTap also enables the extraction of the TLS encryption keys. 



## Resources
- [GitHub Repository](https://github.com/fkie-cad/friTap)
- [Usage Guide](https://github.com/fkie-cad/friTap/blob/main/USAGE.md)
- [Integration Guide](https://github.com/fkie-cad/friTap/blob/main/INTEGRATION.md)


