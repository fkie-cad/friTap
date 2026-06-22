# Example
In this file we will show two ways how you can use friTap (formally know as sslinterceptor) to decrypt and analyse TLS traffic of an application. For general information, look at USAGE.md.

The examples are demonstrated using the app from "Flipboard" [1].

## Setup

### Android
To work with friTap you can either use a real phone connected to the PC with USB-Debugging enabled or use a emulator. The only important thing is
that the phone must be rooted for frida to work. If you use Genymotion, it is rooted per default. For AVD, have a look at [this repository](https://github.com/Frint0/avd-root).

### Frida
To enable frida to communicate with the device it needs to have an instance of frida-server running. Download the latest release for android and your architecture from [here](https://github.com/frida/frida/releases)
and execute the following commands to get it up and running:

```
adb push frida-server /data/local/tmp
adb shell "chmod +x /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

## Extracting a pcap with friTap
The first way is to directly tell friTap to write all traffic to a pcap file. To do this with flipboard, use the following command:

`python3 friTap.py -m flipboard.app --spawn --pcap flipboard.pcap`

In this example, we had Flipboard running on a Genymotion instance:

![Output while logging](/images/flipboard_pcap_1.png)

When finished, you can open the resulting `flipboard.pcap` with wireshark and look at the decrypted traffic: 

![Wireshark view of resulting pcap](/images/flipboard_pcap_2.png)

## Extracting keys and decrypting with wireshark
Wireshark offers a way to automatically decrypt TLS traffic when provided a file containing the neccessary keys [2]. Such a file can be created using the `-keylog` option on friTap:

`python3 friTap.py -m flipboard.app --spawn --keylog flipboard.keylog`

To make use of this, we can simultaniously use friTap to log the keys and tcpdump (via adb) to record the pcap:

![Output while logging](/images/flipboard_keylog_1.png)

When finished, pull the pcap from the device and open it in wireshark. To decrypt the traffic, go to Preferences->Protocols->TLS and add it under "(Pre)-Master-Secret log filename".

## Remarks

The first way is the easiest way and also has the advantage, that your pcap only contains packets from this process. However, the second way is more accurate when it comes to information about lower layers. When you use the first method, the program hooks the "SSL_read/write" functions in the program and then artificially crafts packets. For these packets, header data is set to default values, as we can only access application layer data at this point. So, if you are not only interested about the packets payload but need accurate information about the traffic, choose the second method.

Also keep in mind that, when using the `--pcap` option, **only** decrypted TLS traffic is written to the pcap! This means, if the app also has non-TLS communication like pure HTTP or QUIC, this will not be contained in the pcap.

[1] https://flipboard.com/
[2] https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
