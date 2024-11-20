# Usage

Usage: friTap.py [-m] [-k <path>] [-l] [-p  <path>] [-s] [-v] [--enable_spawn_gating] <executable/app name/pid>

Decrypts and logs an executables or mobile applications SSL/TLS traffic.

Arguments:
  - `-m`, `--mobile` Attach to a process on android or iOS
  - `-k <path>`, `--keylog <path>` Log the keys used for tls traffic
  - `-l`, `--live` Creates a named pipe /tmp/sharkfin which can be read by Wireshark during the capturing process
  - `-p  <path>`, `--pcap <path>` Name of PCAP file to write
  - `-s`, `--spawn` Spawn the executable/app instead of attaching to a running process
  - `-v`, `--verbose` Show verbose output
  - `--enable_spawn_gating` Catch newly spawned processes. ATTENTION: These could be unrelated to the current process!
  - `<executable/app name/pid>` executable/app whose SSL calls to log

The target device needs to have frida-server running when Android or iOS apps are analyzed. Further information about setting up the device can be found [here](https://frida.re/docs/android/).

# Examples
## Spawn an app and show output on screen
`python3 ./fritap.py -m com.example.app --spawn --verbose`

The output could look like this:

![Example output](/images/verbose_output.png)

## Attach to a running app and write traffic to pcap
`python3 ./fritap.py -m com.example.app -p myLogFile.pcap`

Output:

![Log pcap output](/images/pcap_output.png)

Note that the packets in this pcap currently only reflect the content, source and destination of packets. Certain IP/TCP header information may be omitted or set to default values. For a more precise output, log the traffic seperately and decrypt it using the keys logged by the `-keylog` option (see example below). 
Also, when you try to analyse the resulting pcap, it might happen that wireshark mistakes the decrypted traffic for still being encoded because it still runs on port 443 (happens e.g. for HTTP2 traffic, Http1.1 seems to work fine). To circumvent this, just tell wireshark to decode traffic on port 443 as HTTP2 traffic (or  any other).

## Log keys of TLS traffic
`python3 ./fritap.py -m -spawn --keylog myKeyLogFile.log com.example.app`

Output:

![Log pcap output](/images/keylog_output.png)

The script logs the keys used for encryption like described [here](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format) in the given file. If you record the traffic from the app (e.g. with tcpdump) you can use this file to decrypt the traffic with wireshark. For more information, look [here](https://wiki.wireshark.org/TLS#Using_the_.28Pre.29-Master-Secret).

## Live view utilizing named pipes with Wireshark

```bash
$ python3 ./fritap.py -l com.example.app
[*] Created named pipe for Wireshark live view to /tmp/tmp9is_q9_k/fritap_sharkfin
[*] Now open this named pipe with Wireshark in another terminal: sudo wireshark -k -i /tmp/tmp9is_q9_k/fritap_sharkfin
[*] friTap will continue after the named pipe is ready....

```

In another terminal we than open this named pipe with Wireshark:

```bash
$ sudo wireshark -k -i /tmp/tmp9is_q9_k/fritap_sharkfin &
```

Now we can see and analyze all the packets live with Wireshark. As soon as we stop the capturing friTap will exit. For later analysis it is than possible to safe the capture as pcap:

![](./images/live_view.png) 



**Note:** It is not possible to safe the PCAP and having a live capture directly through friTap. If you want to safe the PCAP just use the capability of Wireshark to do so.


## Providing custom offsets/addresses

FriTap allows to specify user-defined offsets (starting from the base address of the ssl/socket library) and to specify absolute virtual addresses of ssl/socket functions for function resolution. For this a JSON file (see offsets_example.json) must be specified using the `--offsets` parameter.  If the parameter is set, then friTap will overwrite only those addresses of those functions that were specified. For all functions for which nothing was specified, friTap will try to detect an address on its own.

The JSON file consists of the following fields:

    - `address`: The offset or absolute address of the specified function, formatted as a hexadecimal string.
    - `absolute`:
        If `true`, the value in the `address` field is interpreted as an absolute address.
        If `false`, the value is treated as an offset from the base address of the SSL/socket library.

If friTap cannot find the base address of the socket/SSL library, or if the `absolute` field is set to `true`, the specified addresses will be interpreted as absolute addresses.

### **Example**:
Suppose friTap detects the base address of the OpenSSL library, but it fails to find exports for the `SSL_read` and `SSL_write` functions. If you know the offsets for these functions and the absolute addresses for certain socket functions, your JSON file could look like this:

```json
{
    "openssl":{
        "SSL_read": {
            "address":"0x15b4",
            "absolute":false
        },
        "SSL_write":{
            "address":"0x144c",
            "absolute": false
        }
    },
    "sockets":{
        "getpeername":{
            "address":"0x572115b4",
            "absolute":true
        },
        "getsockname":{
            "address":"0x5721163",
            "absolute":true
        },
        "ntohs":{
            "address":"0x572116f2",
            "absolute":true         
        },
        "ntohl":{
            "address":"0x572116c2",
            "absolute":true
        }
    }  
}
```
## Hooking by Byte-Patterns

In certain scenarios, the library we want to hook offers no symbols or is statically linked with other libraries, making it challenging to directly hook functions. For example:

    Cronet (libcronet.so) and Flutter (libflutter.so) are often statically linked with BoringSSL.

To solve this, we can use friTap with byte patterns to hook the desired functions. You can provide friTap with a JSON file that contains byte patterns for hooking specific functions, based on architecture and platform.
Hooking Categories

We define different hooking categories for which specific byte patterns are used. These categories include:

    Dump-Keys
    Install-Key-Log-Callback
    KeyLogCallback-Function
    SSL_Read
    SSL_Write

Each category has a primary and fallback byte pattern, allowing flexibility when the primary pattern fails.


### 1. Dump-Keys

This category is responsible for dumping keys directly from the process. The primary and fallback byte patterns in this category are used to hook functions that deal with key management and extraction. friTap provides than the parsing in order to extract the keys:

```json
"Dump-Keys": {
  "primary": "AA BB CC DD EE FF ...", 
  "fallback": "FF EE DD CC BB AA ..."
}
```
    Primary Pattern: Used to hook the function that allows key dumping.
    Fallback Pattern: If the primary pattern fails, the fallback pattern is tried.

Our developed tool [BoringSecretHunter](https://github.com/monkeywave/BoringSecretHunter) can be used to automatically extract these patterns from a target library.

### 2. Install-Key-Log-Callback

This category installs a callback for logging TLS keys. It typically works alongside `KeyLogCallback-Function`. Both must be specified together in the JSON. As the name suggests it is responsbile for installing the keylog callback function:

```json
"Install-Key-Log-Callback": {
  "primary": "11 22 33 44 55 66 ...",
  "fallback": "66 55 44 33 22 11 ..."
}
```
    Primary Pattern: Hook the function responsible for installing the key log callback.
    Fallback Pattern: If the primary pattern fails, this fallback pattern is tried.

### 3. KeyLogCallback-Function

This category hooks the function that is triggered by the installed key log callback. It must be used alongside the Install-Key-Log-Callback category. It is also used for extracting the TLS key material but **no parsing** has to be done:

```json
"KeyLogCallback-Function": {
  "primary": "77 88 99 AA BB CC ...",
  "fallback": "CC BB AA 99 88 77 ..."
}
```
    Primary Pattern: Hook the function where the key log callback processes keys.
    Fallback Pattern: If the primary pattern fails, this fallback pattern is tried.

###  4. SSL_Read

This category hooks the SSL_Read function, which is responsible for reading encrypted SSL/TLS data. It works alongside the SSL_Write category.

```json
"SSL_Read": {
  "primary": "AA 55 FF 00 11 22 ...",
  "fallback": "22 11 00 FF 55 AA ..."
}
```
    Primary Pattern: Hook the SSL_Read function.
    Fallback Pattern: If the primary pattern fails, the fallback pattern is tried.

### 5. SSL_Write

This category hooks the SSL_Write function, which is responsible for writing encrypted SSL/TLS data. It must be used with the SSL_Read category.

```json
"SSL_Write": {
  "primary": "BB CC DD EE FF 00 ...",
  "fallback": "00 FF EE DD CC BB ..."
}
```
    Primary Pattern: Hook the SSL_Write function.
    Fallback Pattern: If the primary pattern fails, the fallback pattern is tried.



## Using friTap with a custom Frida scripts

This guide explains how to use friTap with a custom Frida script to enhance its functionality. Using the `-c` parameter, you can specify a custom script to be executed during the friTap session.  This custom script will be invoked just before friTap applies its own hooks.

---

### Example Command

To invoke friTap with a custom script, use the following command:

```bash
fritap -m -k cronet18.keys -do -c "/path/to/custom.js" -v YouTube
```

### **Explanation of Parameters**
- `-m`: Indicates that the app is running on a mobile device.
- `-k`: Specifies the output file for the SSL key log.
- `-do`: Enables debug output for detailed logging.
- `-c`: Specifies the path to the custom Frida script to be executed.
- `-v`: Enables verbose logging.
- `YouTube`: The name of the app package to be hooked.

---

### Custom Script Example

The following is an example of a custom Frida script (`custom.js`) that iterates over all loaded modules, checks for exports containing `ssl` or `tls`, and sends relevant information to friTap.

```javascript
/*
 * Example code for using custom hooks in friTap. 
 * To ensure friTap prints content, include a "custom" field in your message payload. 
 * The value of this "custom" field will be displayed by friTap.
 */

// Iterate over all loaded modules
Process.enumerateModules().forEach(module => {
    // Enumerate exports for each module
    module.enumerateExports().forEach(exp => {
        // Check if the export name contains "ssl" or "tls"
        if (exp.name.toLowerCase().includes("ssl") || exp.name.toLowerCase().includes("tls")) {
            // Send the result to Python
            send({
                custom: `Found export: ${exp.name} in module: ${module.name} at address: ${exp.address}`
            });
        }
    });
});
```
friTap will print any messages sent with a `custom` field during execution.
You can download the above example code as `custom.js` file using the link below:

**[Download custom.js](./custom.js)**

Place this file in the same directory as your friTap installation or provide the absolute path to the `-c` parameter.


