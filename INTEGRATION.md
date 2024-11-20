# friTap Integration Guide

This guide explains how to use the `friTap` as a Python library to hook into applications, log SSL/TLS data, and manage its integration with the `AndroidFridaManager`. The only required argument to initialize `friTap` is the app package name to be hooked.

---

## Basic Usage: Hooking an App and Logging SSL/TLS Data

The following example demonstrates how to use `friTap` to hook into an application and log its SSL/TLS traffic.

### **Code Example**

```python
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
        keylog="keylogtest3.log", # Path to save SSL key log
        debug_output=True        # Enable debug output
    )
    
    # Start friTap session
    process = ssl_log.start_fritap_session()  
    
    # Wait for user input to stop
    sys.stdin.read()

except KeyboardInterrupt:
    # Detach process on interruption
    process.detach()
    print("Logging stopped.")
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
| `custom_hook_script`   | `str`   | `None`       | Path to a custom Frida hook script to be executed during the session.      |

---

## Advanced Usage: Using friTap as a Job in AndroidFridaManager

friTap can also be used as a job within the `AndroidFridaManager` framework. This allows you to manage friTap sessions as part of a larger job workflow.

### **Code Example**

```python
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
        keylog="keylogtest3.log", # Path to save SSL key log
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
