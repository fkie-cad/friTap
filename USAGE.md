# Usage
General Usage: `ssl_interceptor.py [-pcap <path>] [-verbose] [-spawn] [-keylog <path>]
                          <app name>`
                          
Arguments:
  - `pcap <path>`         Name of PCAP file to write
  - `verbose`             Show verbose output
  - `spawn`               Spawn the app instead of attaching to a running process
  - `keylog <path>`       Log the keys used for tls traffic
  - `enable_spawn_gating` Catch newly spawned processes. ATTENTION: These could be unrelated to the current process!
  - `<app name>`          APP whose SSL calls to log

The target device needs to have frida-server running. Further information about setting up the device can be found [here](https://frida.re/docs/android/).
# Examples
## Spawn an app and show output on screen
`python3 ./sslinterceptor.py com.example.app -spawn -verbose`

The output could look like this:

![Example output](/images/verbose_output.png)

## Attach to a running app and write traffic to pcap
`python3 ./sslinterceptor.py com.example.app -pcap myLogFile.pcap`

Output:

![Log pcap output](/images/pcap_output.png)

Note that the packets in this pcap currently only reflect the content, source and destination of packets. Certain IP/TCP header information may be omitted or set to default values. For a more precise output, log the traffic seperately and decrypt it using the keys logged by the `-keylog` option (see example below). 
Also, when you try to analyse the resulting pcap, it might happen that wireshark mistakes the decrypted traffic for still being encoded because it still runs on port 443 (happens e.g. for HTTP2 traffic, Http1.1 seems to work fine). To circumvent this, just tell wireshark to decode traffic on port 443 as HTTP2 traffic (or  any other).

## Log keys of TLS traffic
`python3 ./sslinterceptor.py com.example.app -spawn -keylog myKeyLogFile.log`

Output:

![Log pcap output](/images/keylog_output.png)

The script logs the keys used for encryption like described [here](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format) in the given file. If you record the traffic from the app (e.g. with tcpdump) you can use this file to decrypt the traffic with wireshark. For more information, look [here](https://wiki.wireshark.org/TLS#Using_the_.28Pre.29-Master-Secret).
