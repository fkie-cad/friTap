# Basic Concepts

Understanding the fundamental concepts behind friTap will help you use it more effectively and troubleshoot issues when they arise.

## How friTap Works

### Dynamic Instrumentation

friTap uses [Frida](https://frida.re/), a dynamic instrumentation framework, to:

1. **Attach to running processes** or spawn new ones
2. **Inject JavaScript code** into the target process
3. **Hook SSL/TLS library functions** to intercept data
4. **Extract keys and plaintext** without modifying the application

### The Hooking Process

```mermaid
graph TD
    A[Target Application] --> B[SSL/TLS Library]
    B --> C[Network]
    
    D[friTap] --> E[Frida Agent]
    E --> F[Hook Functions]
    F --> B
    
    G[Extracted Keys] --> H[Key Log File]
    I[Plaintext Traffic] --> J[PCAP File]
    
    F --> G
    F --> I
```

## Core Components

### 1. friTap CLI

The command-line interface that:
- Manages Frida connections
- Handles device communication
- Processes output files
- Provides user feedback

### 2. Frida Agent

JavaScript code that runs inside the target process:
- Detects SSL/TLS libraries
- Hooks key functions
- Extracts data and keys
- Sends results back to CLI

### 3. SSL/TLS Library Handlers

Platform-specific code for different libraries:
- **OpenSSL/BoringSSL**: Most common, full support
- **NSS**: Mozilla's library, widely used
- **GnuTLS**: GNU TLS implementation
- **WolfSSL**: Embedded/IoT focused
- **mbedTLS**: Lightweight implementation

## Key Concepts

### Process Attachment vs Spawning

**Attachment**: Connect to an already running process
```bash
# Attach to running Firefox
fritap firefox
```

**Spawning**: Start a new process under friTap control
```bash
# Spawn new Firefox instance
fritap -f firefox
```

### Mobile vs Desktop Analysis

**Desktop Mode** (default):
- Requires root/admin privileges
- Hooks system libraries
- Works with any application

**Mobile Mode** (`-m` flag):
- Requires rooted/jailbroken device
- Hooks app-specific libraries
- Handles Android/iOS specifics

### Key Extraction vs Traffic Decryption

**Key Extraction** (`-k` flag):
- Captures TLS keys as they're generated
- Smaller file size
- Requires separate network capture
- Compatible with Wireshark

**Traffic Decryption** (`--pcap` flag):
- Captures decrypted plaintext traffic
- Larger file size
- Self-contained analysis
- Ready for immediate analysis

## SSL/TLS Library Detection

friTap automatically detects which libraries are loaded:

### Detection Methods

1. **Library Enumeration**: List loaded modules
2. **Symbol Resolution**: Check for known function names
3. **Pattern Matching**: Use byte patterns for stripped libraries
4. **Heuristic Analysis**: Analyze library behavior

### Library Priority

When multiple libraries are detected:
1. **OpenSSL/BoringSSL**: Highest priority
2. **NSS**: Second priority
3. **GnuTLS**: Third priority
4. **Others**: Based on platform support

## Hooking Strategies

### Symbol-Based Hooking

Default method when symbols are available:
```javascript
// Hook SSL_read function
const SSL_read = Module.getExportByName("libssl.so", "SSL_read");
Interceptor.attach(SSL_read, {
    onEnter: function(args) {
        // Capture arguments
    },
    onLeave: function(retval) {
        // Capture return value and data
    }
});
```

### Pattern-Based Hooking

For stripped libraries without symbols:
```bash
# Use pattern file
fritap --patterns patterns.json target
```

### Offset-Based Hooking

For known memory layouts:
```bash
# Use offset file
fritap --offsets offsets.json target
```

## Data Flow

### Key Extraction Flow

1. **Key Generation**: Application generates TLS keys
2. **Hook Interception**: friTap hooks key callback functions
3. **Key Capture**: Extract master secrets and randoms
4. **Format Conversion**: Convert to NSS Key Log format
5. **File Output**: Save to specified key log file

### Traffic Decryption Flow

1. **Read/Write Hooks**: Intercept SSL_read/SSL_write calls
2. **Plaintext Capture**: Extract plaintext before encryption/after decryption
3. **Socket Information**: Gather connection details (IP, port)
4. **Packet Reconstruction**: Rebuild network packets
5. **PCAP Generation**: Save as standard PCAP file

## Platform Differences

### Linux
- System-wide SSL libraries
- Process attachment requires root
- Full library support

### Windows
- Multiple SSL implementations
- Admin privileges required
- Limited library support

### macOS
- System Integrity Protection (SIP)
- Code signing restrictions
- Limited library support

### Android
- App-specific libraries
- Java and native SSL implementations
- Requires root access

### iOS
- Objective-C SSL implementations
- Jailbreak required
- Limited library support

## Common Architectures

### Client-Server Applications

```
[Client App] --TLS--> [Server]
     |
   friTap
     |
[Keys/Traffic]
```

### Mobile Applications

```
[Mobile App] --TLS--> [API Server]
     |
   friTap
     |
[Keys/Traffic]
```

### Multi-Process Applications

```
[Parent Process] --> [Child Process 1] --TLS--> [Server]
                 --> [Child Process 2] --TLS--> [Server]
        |
      friTap
        |
   [All Traffic]
```

## Security Considerations

### Defensive Measures

Applications may implement:
- **Anti-debugging**: Detect instrumentation
- **SSL Pinning**: Validate certificates
- **Root Detection**: Refuse to run on rooted devices
- **Code Obfuscation**: Hide SSL library usage

### friTap Countermeasures

- **Anti-root bypass**: Disable root detection
- **Spawn gating**: Intercept child processes
- **Pattern matching**: Hook obfuscated libraries
- **Multiple strategies**: Fallback mechanisms

## Performance Considerations

### Memory Usage

- **Agent injection**: ~10-50MB per process
- **Key storage**: Minimal (few KB)
- **Traffic capture**: Proportional to traffic volume

### CPU Overhead

- **Minimal impact**: <5% for most applications
- **Hook efficiency**: Optimized interception
- **Selective hooking**: Only hook necessary functions

### Network Impact

- **No network changes**: friTap doesn't modify network traffic
- **Passive monitoring**: Read-only access to data
- **Real-time processing**: Minimal latency

## Troubleshooting Concepts

### Common Issues

1. **No hooks installed**: Library not detected
2. **No traffic captured**: Wrong socket information
3. **Crashes**: Incompatible hooking strategy
4. **Missing keys**: Key callback not hooked

### Debug Information

```bash
# Enable debug output
fritap -do -v target

# Check library detection
fritap --list-libraries target

# Verify device connection
fritap --list-devices
```

## Advanced Concepts

### Custom Frida Scripts

Extend friTap with custom JavaScript:
```bash
fritap -c custom_script.js target
```

### Multi-Device Analysis

Analyze multiple devices simultaneously:
```bash
# Device 1
fritap -m -D device1 com.example.app

# Device 2
fritap -m -D device2 com.example.app
```

### Live Analysis Integration

Real-time analysis with external tools:
```bash
# Named pipe to Wireshark
fritap -l target

# JSON output to external tool
fritap --json target | analysis_tool
```

## Best Practices

### 1. Start with Simple Cases

Begin with well-known applications:
```bash
fritap -k keys.log curl https://httpbin.org/get
```

### 2. Use Verbose Mode for Learning

```bash
fritap -v target
```

### 3. Understand Your Target

- Know which SSL library is used
- Understand the application architecture
- Consider security measures

### 4. Test Incrementally

1. Test key extraction first
2. Add traffic capture
3. Enable advanced features
4. Optimize performance

### 5. Document Your Findings

Keep track of:
- Working command lines
- Library versions
- Platform specifics
- Custom patterns/offsets

## Next Steps

Now that you understand the basics:

1. **Practice with [Usage Examples](../examples/index.md)**
2. **Learn platform-specific details in [Platform Guides](../platforms/android.md)**
3. **Explore [Advanced Features](../advanced/patterns.md)**
4. **Read about specific [SSL/TLS Libraries](../libraries/index.md)**