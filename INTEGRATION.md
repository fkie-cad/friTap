# friTap Integration Guide

This guide explains how to use the `friTap` as a Python library to hook into applications, log SSL/TLS data, and manage its integration with the `AndroidFridaManager`. The only required argument to initialize `friTap` is the app package name to be hooked.

---

## Basic Usage: Hooking an App and Logging SSL/TLS Data

The following example demonstrates how to use `friTap` to hook into an application and log its SSL/TLS traffic.

### **Code Example**

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from friTap import SSL_Logger
import sys

try:
    print("Start logging")
    print("Press Ctrl+C to stop logging")

    # Specify the app package to hook
    app_package = "YouTube"

    # Initialize SSL_Logger with optional arguments
    ssl_log = SSL_Logger(
        app_package,
        verbose=True,            # Enable verbose output
        mobile=True,             # Indicate that the target app is running on a mobile device
        keylog="keylogtest.log", # Path to save SSL key log
        debug_output=True        # Enable debug output
    )

    ssl_log.install_signal_handler() 

    # Start friTap session
    process, script = ssl_log.start_fritap_session()  
    
    # Wait for user input or interrupt which will invoke the internal signal handler
    while ssl_log.running:
        pass
```

---

## Arguments for `SSL_Logger`

| Argument                | Type    | Default      | Description                                                                 |
|-------------------------|---------|--------------|-----------------------------------------------------------------------------|
| `app`                  | `str`   | **Required** | The package name of the app to be hooked.                                  |
| `pcap_name`            | `str`   | `None`       | Name of the PCAP file to save captured traffic.                            |
| `verbose`              | `bool`  | `False`      | Enable verbose output for debugging purposes.                              |
| `spawn`                | `bool`  | `False`      | Spawn the app automatically if not running.                                |
| `keylog`               | `str`   | `None`       | Path to save the SSL/TLS key log file.                                     |
| `enable_spawn_gating`  | `bool`  | `False`      | Enable gating for app spawning.                                            |
| `mobile`               | `bool`  | `False`      | Indicate whether the target app is on a mobile device.                     |
| `live`                 | `bool`  | `False`      | Enable live monitoring of the app's traffic.                               |
| `environment_file`     | `str`   | `None`       | Path to the environment configuration file.                                |
| `debug_mode`           | `bool`  | `False`      | Enable debugging mode for more detailed information.                       |
| `full_capture`         | `bool`  | `False`      | Enable full capture of traffic.                                            |
| `socket_trace`         | `bool`  | `False`      | Enable tracing of socket connections.                                      |
| `host`                 | `bool`  | `False`      | Indicate whether the app is running on a host machine.                     |
| `offsets`              | `str`   | `None`       | Specify custom offsets for hooking.                                        |
| `debug_output`         | `bool`  | `False`      | Enable debug output for detailed logging.                                  |
| `experimental`         | `bool`  | `False`      | Enable experimental features.                                              |
| `anti_root`            | `bool`  | `False`      | Enable anti-root detection mechanisms.                                     |
| `payload_modification` | `bool`  | `False`      | Enable payload modification during traffic capture.                        |
| `enable_default_fd`    | `bool`  | `False`      | Enable default file descriptor handling.                                   |
| `patterns`             | `list`  | `None`       | List of patterns to match during traffic capture.                          |
| `custom_hook_script`   | `str`   | `None`       | Path to a custom Frida hook script to be executed during the session. These hooks are installed prior to the installation of friTap hooks.     |

---

## Advanced Usage: Integrating friTap with Custom Handler

If you'd like to integrate friTap into your project but prefer to manage Frida yourself, friTap offers advanced flexibility. With this approach, you can either:

- Retrieve the friTap script Path: Use `ssl_log.get_fritap_frida_script_path()` to obtain the path to the friTap Frida script. You can then manually load the script into your target process.
- Use the Advanced API: Utilize the `start_fritap_session_instrumentation(own_message_handler, process)` API to integrate friTap while managing Frida yourself.
    - `on_message_handler`: Your custom handler function to process messages between the script and your Python code.
    - `process`: The Frida process object you manage, which can be created by spawning or attaching to the target application.

This API gives you full control over when the friTap script is loaded into the target process. It returns the script object, allowing you to load the script at your preferred time. Below is an example of how to use this API:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from friTap import SSL_Logger
import sys
import frida

#global variable
script = None

# Custom message handler function
def myAwesomeHandler(message, data):
    global script

    # Pass options to friTap hooks (mandatory)
    if message['payload'] == 'experimental':
        script.post({'type':'experimental', 'payload': False})
        return

    if message['payload'] == 'defaultFD':
        script.post({'type':'defaultFD', 'payload': False})
        return

    if message['payload'] == 'pattern_hooking':
        script.post({'type':'pattern_hooking', 'payload': False})
        return

    if message['payload'] == 'offset_hooking':
        script.post({'type':'offset_hooking', 'payload': False})
        return
    
    if message['payload'] == 'anti':
        script.post({'type':'antiroot', 'payload': False})
        return


    print(f"Message from Frida: {message}")
    if data:
        print(f"Data: {data}")



def getFridaProcess(target_app):
    device = frida.get_usb_device()
    process = device.attach(int(target_app) if target_app.isnumeric() else target_app)
    return process, device



try:
    print("Starting friTap logging...")
    print("Press Ctrl+C to stop logging.")

    # Specify the target app package
    app_package = "YouTube"

    # Create or attach a Frida process (replace with your implementation)
    process, device = getFridaProcess(app_package)  # Your code for creating or attaching to a Frida process.

    # Initialize SSL_Logger with optional arguments
    ssl_log = SSL_Logger(
        app_package,
        verbose=True,             # Enable detailed output
        keylog="keylogtest.log" # Path to save the SSL key log
    )
    
    # Hook friTap into the target process without immediately loading the script
    process, script = ssl_log.start_fritap_session_instrumentation(myAwesomeHandler, process)

    # Manually load the friTap script into the target process
    script.load()

    # Wait for the user to interrupt
    sys.stdin.read()

except KeyboardInterrupt:
    # Detach the process when interrupted
    process.detach()
    print("friTap logging stopped.")

```

Key Notes about this approach:

- Script Loading: The `start_fritap_session_instrumentation` API provides the script object but does not automatically load it. This gives you full control over when the friTap hooks are injected.
- Custom Message Handler: Your on_message_handler function allows you to handle Frida messages and data flexibly. When managing the handler yourself, it is mandatory to ensure that certain internal friTap variables are correctly communicated with the Frida script. Failing to do so will halt the installation of the friTap hooks, as they depend on values from the Python environment to determine how certain hooks should be applied. 
- Full Control: This approach is ideal for advanced use cases where you want precise management of Frida processes and script lifecycle.

### Understanding Frida Messages in friTap

In friTap, the `on_fritap_message(self, job, message, data)` handler processes messages sent from the Frida script. These messages contain important information about the operation of friTap. The key fields in the message are:

- **`payload`**: This field contains a structured dictionary with a `contentType` key that determines the type of the message. The specific `contentType` dictates how the remaining fields in the `payload` are interpreted. The structure looks like this `'payload': {'contentType': '<content type>', '<content key>': <content value>}`
- **`data`**: This field contains the decrypted TLS payload when the `contentType` is `datalog`. In other cases, the `data` field is typically unused and the focus remains on the `payload` field.

Here are the different `contentType` values and their meanings:

| **Content Type**     | **Description**                                                                                          | **Access Key**      |
|-----------------------|----------------------------------------------------------------------------------------------------------|---------------------|
| `datalog`            | Contains decrypted TLS payload data and associated socket information. Useful for analyzing TLS traffic. | `datalog`          |
| `console_dev`        | Debug output intended for development and troubleshooting, such as scanning logs or fallback patterns.   | `console_dev`      |
| `console_error`      | Error messages encountered during the operation of friTap.                                               | `console_error`    |
| `console`            | Standard output messages visible to the user when running friTap.                                        | `console`          |
| `keylog`             | Extracted TLS key material from the target application.                                                  | `keylog`           |

**Key Details**:

1. **Decrypted TLS Data**: 
   - When `contentType` is `datalog`, the `data` field contains the decrypted TLS payload (if available), along with associated socket information.

2. **Development Logs**:
   - `console_dev` messages provide insights into debug operations, which are helpful during development or when fixing bugs.

3. **Error Handling**:
   - Error messages (`console_error`) help identify problems within friTap’s execution.

4. **User Output**:
   - `console` messages are meant for the user and reflect key operational statuses.

5. **TLS Key Extraction**:
   - `keylog` messages provide extracted key material for analyzing the cryptographic state of the target application.

By using the `contentType` as the key, you can access specific fields in the `payload` to analyze the messages accordingly.



By using this API, you can seamlessly integrate friTap while maintaining complete control over Frida's operation in your application.

## Advanced Usage: Using friTap as a Job in AndroidFridaManager

friTap can also be used as a job within the `AndroidFridaManager` framework. This allows you to manage friTap sessions as part of a larger job workflow.

### **Code Example**

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from friTap import SSL_Logger
from AndroidFridaManager import JobManager
import sys

try:
    print("Start logging")
    print("Press Ctrl+C to stop logging")

    # Initialize JobManager
    job_manager = JobManager()

    # Specify app package
    app_package = "YouTube"

    # Initialize SSL_Logger with optional arguments
    ssl_log = SSL_Logger(
        app_package,
        verbose=True,             # Enable verbose output
        keylog="keylogjobtest.log", # Path to save SSL key log
        debug_output=True         # Enable debug output
    )
    
    # Get the Frida script path from SSL_Logger
    frida_script_path = ssl_log.get_fritap_frida_script_path()

    # Set up the Frida session in the JobManager
    job_manager.setup_frida_session(
        app_package,
        ssl_log.on_fritap_message,
        should_spawn=False        # Do not spawn the process
    )

    # Start the job with a custom hooking handler
    job_manager.start_job(
        frida_script_path,
        custom_hooking_handler_name=ssl_log.on_fritap_message
    )

    print("[*] Running jobs:", job_manager.running_jobs())

    # Wait for user input to stop
    sys.stdin.read()

except KeyboardInterrupt:
    # Stop all running jobs
    job_manager.stop_jobs()
    print("Jobs stopped.")
```

---

## Key Notes

1. **App Package Name**:
   - The app package name is the only required argument to initialize `SSL_Logger`. All other arguments are optional but provide additional functionality like saving key logs or enabling debug output.

2. **Custom Hooks**:
   - If you want to execute custom Frida scripts, specify the path using the `custom_hook_script` argument in `SSL_Logger`.

3. **Integration with AndroidFridaManager**:
   - Using friTap as part of `AndroidFridaManager` allows you to manage friTap hooks alongside other Frida jobs seamlessly.

---
