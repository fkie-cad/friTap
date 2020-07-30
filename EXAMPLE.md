# Example
In this file we will show two ways how you can use sslinterceptor to decrypt and analyse TLS traffic of an application. For general information, look at USAGE.md.

The examples are demonstrated using the app from "Flipboard" [1].

## Extracting a pcap with sllinterceptor
The first way is to directly tell sslinterceptor write all traffic to a pcap file. To do this with flipboard, use the following command:

`python sslinterceptor.py flipboard.app -spawn -pcap flipboard.pcap`

In this example, we had Flipboard running on a Genymotion instance:

![Output while logging](/images/flipboard_pcap_1.png)

When finished, you can open the resulting `flipboard.pcap` with wireshark and look at the decrypted traffic: 

![Wireshark view of resulting pcap](/images/flipboard_pcap_2.png)

## Extracting keys and decrypting with wireshark

## Remarks

The first way is the easiest way and also has the advantage, that your pcap only contains packets from this process. However, the second way is more accurate when it comes to information about lower layers. When you use the first method, the program hooks the "SSL_read/write" functions in the program and then artificially crafts packets. For these packets, header data is set to default values, as we can only access application layer data at this point. So, if you are not only interested about the packets payload but need accurate information about the traffic, choose the second method.

Also keep in mind that, when using the `-pcap` option, **only** decrypted TLS traffic is written to the pcap! This means, if the app also has non-TLS communication like pure HTTP or QUIC, this will not be contained in the pcap.

[1] https://flipboard.com/