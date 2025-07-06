# friTap Development Guide

This guide helps developers quickly set up a development environment for friTap and run the comprehensive testing suite.

## Quick Start

### Prerequisites

- **Python 3.7+** (recommended: 3.9+)
- **Node.js 16+** (for TypeScript agent compilation)
- **Git**

### Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/fkie-cad/friTap.git
cd friTap

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 3. Install development dependencies
pip install -r requirements-dev.txt

# 4. Install Node.js dependencies (for agent compilation)
npm install

# 5. Install friTap in development mode
pip install -e .

# 6. Verify setup
python run_tests.py summary
```

### Alternative: One-Command Setup

```bash
# Run the automated setup script
python setup_dev.py
```

## Testing

### Quick Testing

```bash
# Run all fast tests (recommended for development)
python run_tests.py --fast

# Run specific test categories
python run_tests.py unit           # Unit tests only
python run_tests.py agent          # Agent compilation tests
python run_tests.py integration    # Mock integration tests
```

### Comprehensive Testing

```bash
# Run all applicable tests
python run_tests.py all

# Generate coverage report
python run_tests.py coverage
open tests/coverage_html/index.html
```

### Testing During Development

```bash
# Run tests automatically on file changes
pytest-watch tests/unit/

# Run specific test file
pytest tests/unit/test_ssl_logger.py -v

# Run tests with specific markers
pytest -m "unit and not slow" -v
```

## Code Quality

### Formatting and Linting

```bash
# Format code with Black
black friTap/ tests/

# Lint with flake8
flake8 friTap/ tests/

# Type checking with mypy
mypy friTap/

# Sort imports
isort friTap/ tests/

# Run all quality checks
python run_tests.py lint
```

### Pre-commit Hooks

```bash
# Install pre-commit hooks (recommended)
pre-commit install

# Run pre-commit on all files
pre-commit run --all-files
```

## Agent Development

friTap's core hooking functionality is implemented in **TypeScript** and compiled to JavaScript using **frida-compile** (installed via frida-tools). Understanding this workflow is essential for developing friTap.

### Architecture Overview

friTap consists of two main components:

1. **Python Host** (`friTap/` directory): Handles process attachment, argument parsing, and communication
2. **TypeScript Agent** (`agent/` directory): Performs actual SSL/TLS hooking inside target processes

The TypeScript agent is compiled into two JavaScript files:
- `friTap/_ssl_log.js` - Modern agent (Frida 17+)  
- `friTap/_ssl_log_legacy.js` - Legacy agent (Frida <17)

### TypeScript Agent Structure

```
agent/
├── ssl_log.ts              # Main agent entry point
├── util/                   # Utility functions
│   ├── process_infos.ts    # OS/platform detection
│   ├── log.ts              # Logging functions
│   └── ssl_library_infos.ts # Library inspection
├── shared/                 # Common functionality
│   ├── shared_functions.ts # Cross-platform functions
│   └── pattern_based_hooking.ts # Pattern matching
├── ssl_lib/               # SSL library implementations
│   ├── openssl_boringssl.ts
│   ├── nss.ts
│   ├── gnutls.ts
│   └── ...
└── {platform}/            # Platform-specific implementations
    ├── android/
    ├── ios/
    ├── linux/
    ├── windows/
    └── macos/
```

### TypeScript Agent Compilation

#### Prerequisites

```bash
# Install frida-tools (includes latest frida-compile)
pip install --upgrade frida-tools

# Install Node.js dependencies
npm install

# Verify frida-compile is available
frida-compile --version
```

!!! important "frida-compile Source"
    Always use frida-compile from frida-tools (`pip install frida-tools`) rather than standalone installations. This ensures you have the latest version compatible with current Frida releases.

#### Compilation Commands

```bash
# Primary compilation (recommended)
npm run build

# Platform-specific scripts
./compile_agent.sh     # Linux/macOS  
compile_agent.bat      # Windows

# Watch mode for development
npm run watch

# Test compilation
python run_tests.py agent
```

#### What Compilation Does

1. **Processes TypeScript** files using frida-compile
2. **Bundles modules** into single JavaScript files
3. **Generates two versions**:
   - Modern: `friTap/_ssl_log.js`
   - Legacy: `friTap/_ssl_log_legacy.js`
4. **Injects placeholders** for runtime values (offsets, patterns)

#### Compilation Output

After compilation, you'll see:

```bash
$ npm run build
> friTap@1.3.5.0 build
> frida-compile agent/ssl_log.ts -o friTap/_ssl_log.js

Compiling main agent...
✓ Generated friTap/_ssl_log.js (450KB)
✓ Generated friTap/_ssl_log_legacy.js (420KB)
```

### Agent Development Workflow

#### 1. Development Cycle

```bash
# 1. Edit TypeScript source
vim agent/ssl_lib/new_library.ts

# 2. Compile agent  
npm run build

# 3. Test compilation
python run_tests.py agent

# 4. Test with real application
fritap -k keys.log target_app

# 5. Debug if needed
fritap -d -k keys.log target_app
```

#### 2. Adding New SSL Library Support

```bash
# 1. Create library implementation
touch agent/ssl_lib/mylibrary.ts

# 2. Add platform-specific hooks
touch agent/linux/mylibrary_linux.ts

# 3. Update main agent loader
vim agent/ssl_log.ts

# 4. Compile and test
npm run build
python run_tests.py agent
```

#### 3. Debugging Agent Issues

```bash
# Enable TypeScript source maps (development)
npm run build:debug

# Debug with Chrome DevTools
fritap -d target_app
# Open chrome://inspect in Chrome

# Verbose compilation
npm run build -- --verbose
```

### Important Development Considerations

#### 1. TypeScript Compilation is Required

- **All hooking logic** is in TypeScript
- **Python cannot directly execute** TypeScript files
- **Must recompile** after any agent/ changes
- **Both modern and legacy** versions need compilation

#### 2. Frida-Specific TypeScript

```typescript
// Valid Frida TypeScript
const module = Process.getModuleByName("libssl.so");
const exports = module.enumerateExports();

// Not valid - uses Node.js APIs
import fs from 'fs';  // ❌ Won't work in Frida
```

#### 3. Placeholder System

The compilation process injects placeholders:

```typescript
// In TypeScript source
export let offsets: IOffsets = "{OFFSETS}";

// After compilation + runtime injection
export let offsets: IOffsets = {"ssl_read": {"offset": "0x1234"}};
```

#### 4. Cross-Platform Considerations

```typescript
// OS detection must happen at runtime
if (isiOS()) {
    load_ios_hooking_agent();
} else if (isAndroid()) {
    load_android_hooking_agent();
}
```

### Advanced Agent Development

#### 1. Custom Hook Development

```typescript
// agent/ssl_lib/custom.ts
export class CustomSSLLibrary {
    static install_hooks(): void {
        const module = Process.getModuleByName("libcustom.so");
        
        Interceptor.attach(module.getExportByName("custom_read"), {
            onEnter: function(args) {
                // Hook logic
            },
            onLeave: function(retval) {
                // Return value processing
            }
        });
    }
}
```

#### 2. Pattern-Based Hooking

```typescript
// Use when symbols aren't available
const pattern = "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9";
const matches = Memory.scanSync(module.base, module.size, pattern);

for (const match of matches) {
    Interceptor.attach(match.address, {
        // Hook implementation
    });
}
```

#### 3. Error Handling

```typescript
try {
    const module = Process.getModuleByName("libssl.so");
    // Hook implementation
} catch (error) {
    devlog(`Failed to hook SSL library: ${error}`);
    // Graceful fallback
}
```

## TypeScript API Reference

### Logging Functions

friTap provides three main logging functions for agent development, all imported from `./util/log.js`:

```typescript
import { log, devlog, devlog_error } from "./util/log.js";
```

#### `log(message: string)`

**Purpose**: Standard output logging for important information
**Usage**: User-visible messages, successful operations, key findings
**Output**: Always visible (controlled by Python host)

```typescript
// Examples
log("Running Script on Android");
log("Found SSL_CTX_set_info_callback at 0x19ff01984");
log("Successfully hooked SSL_read function");
log(`Attached to ${moduleName} at ${moduleBase}`);
```

#### `devlog(message: string)`

**Purpose**: Debug logging for development and troubleshooting
**Usage**: Detailed debugging information, trace messages, verbose output
**Output**: Only visible when debug mode is enabled (`-do` or `-d` flags)

```typescript
// Examples
devlog("[OS Detection] AppKit without UIKit -> macOS");
devlog(`[SSL Library] Trying to hook ${functionName}`);
devlog(`Found ${exportCount} exports in ${moduleName}`);
devlog("Pattern matching succeeded for SSL_read");

// Complex debugging
devlog(`[Memory Scan] Searching for pattern: ${pattern}`);
devlog(`[Hook Status] ${functionName}: ${hookSuccess ? 'SUCCESS' : 'FAILED'}`);
```

#### `devlog_error(message: string)`

**Purpose**: Error logging for debugging issues
**Usage**: Non-fatal errors, warning conditions, debugging problems
**Output**: Only visible when debug mode is enabled (`-do` or `-d` flags)

```typescript
// Examples
devlog_error("Failed to enumerate exports - continuing with fallback");
devlog_error(`Module ${moduleName} not found in process`);
devlog_error("Pattern match failed, trying secondary pattern");
devlog_error("SSL function hook failed - library may be stripped");

// Error context
devlog_error(`Hook error for ${functionName}: ${errorMessage}`);
```

### Logging Best Practices

#### 1. Use Appropriate Log Levels

```typescript
// Good practices
log("SSL_read hooked successfully");                    // Important success
devlog("Checking for SSL exports in libcrypto.so");   // Debug trace
devlog_error("Failed to find SSL_write, trying fallback"); // Debug error

// Avoid
devlog("SSL_read hooked successfully");                 // Don't hide success
log("Checking exports in module 47 of 156");          // Too verbose for log()
```

#### 2. Include Context Information

```typescript
// Good - provides context
devlog(`[${libraryName}] Found ${functionCount} SSL functions`);
log(`Hooked ${libraryName} SSL functions: read=${readHooked}, write=${writeHooked}`);

// Better - includes addresses and details
devlog(`[Pattern Match] SSL_read found at ${address} in ${moduleName}`);
log(`SSL library detected: ${libraryName} v${version} at ${baseAddress}`);
```

#### 3. Use Consistent Formatting

```typescript
// Consistent patterns for different types
log(`Successfully ${action}: ${details}`);              // Success messages
devlog(`[${component}] ${action}: ${details}`);         // Debug traces  
devlog_error(`Failed ${action}: ${reason}`);            // Error messages

// Examples
log("Successfully hooked OpenSSL functions: SSL_read, SSL_write");
devlog("[OS Detection] Platform: darwin, Architecture: arm64");
devlog_error("Failed to hook SSL_CTX_new: function not found");
```

#### 4. Debug Categories

Use consistent prefixes for different debugging categories:

```typescript
// OS and platform detection
devlog("[OS Detection] UIKit found -> iOS");
devlog("[Platform] Architecture: arm64, Platform: darwin");

// Library analysis
devlog("[Library] Scanning exports in libssl.so");
devlog("[Pattern] Trying primary pattern for SSL_read");

// Hook status
devlog("[Hook] Installing interceptor for SSL_write");
devlog("[Hook] SSL_read hook successful");

// Memory operations
devlog("[Memory] Scanning 0x1000 bytes at 0x7fff12345000");
devlog("[Memory] Found pattern at offset 0x234");
```

### Advanced Logging Patterns

#### Conditional Logging

```typescript
// Only log in specific conditions
if (Process.arch === "arm64") {
    devlog("[ARM64] Using ARM64-specific SSL patterns");
}

// Log with function success status
const hookResult = installSSLHook(functionAddress);
if (hookResult) {
    log(`SSL function hooked at ${functionAddress}`);
} else {
    devlog_error(`Failed to hook SSL function at ${functionAddress}`);
}
```

#### Performance Logging

```typescript
// Time-sensitive operations
const startTime = Date.now();
const results = scanForPatterns(moduleBase, moduleSize);
const duration = Date.now() - startTime;
devlog(`[Performance] Pattern scan completed in ${duration}ms, found ${results.length} matches`);
```

#### Structured Information

```typescript
// Complex data logging
const moduleInfo = {
    name: module.name,
    base: module.base,
    size: module.size,
    exports: exportCount
};
devlog(`[Module Info] ${JSON.stringify(moduleInfo)}`);

// Hook summary
const hookSummary = `SSL hooks: read=${readSuccess}, write=${writeSuccess}, session=${sessionSuccess}`;
log(hookSummary);
```

### Integration with Python Host

The TypeScript logging functions integrate with the Python host's logging system:

```typescript
// TypeScript agent                     // Python output (with custom formatter)
log("Start logging");                   // [*] Start logging  
devlog("Debug information");            // [!] Debug information (only with -do/-d)
devlog_error("Debug error");            // [!] Debug error (only with -do/-d)
```

#### Python Debug Flags

- **No flags**: Only `log()` messages visible
- **`-do` (debug output)**: All logging functions visible
- **`-d` (full debug)**: All logging functions + Chrome Inspector

```bash
# Standard mode - only log() visible
fritap -k keys.log target

# Debug output - all logging visible  
fritap -do -k keys.log target

# Full debug - all logging + inspector
fritap -d -k keys.log target
```

## Environment Management

### Multiple Python Versions

```bash
# Test with multiple Python versions using tox
tox

# Test with specific Python version
tox -e py39
```

### Platform-Specific Development

```bash
# Linux development
sudo apt-get install build-essential  # For native dependencies

# macOS development
brew install node                      # Node.js via Homebrew

# Windows development
# Use Visual Studio Build Tools for native dependencies
```

## Dependency Management

### Adding New Dependencies

1. **Runtime dependencies**: Add to `requirements.txt`
2. **Development dependencies**: Add to `requirements-dev.txt`
3. **TypeScript dependencies**: Add to `package.json`

```bash
# Update requirements files
pip-compile requirements.in          # Generate requirements.txt
pip-compile requirements-dev.in      # Generate requirements-dev.txt

# Update Node.js dependencies
npm update
```

### Handling Optional Dependencies

Some dependencies are optional based on the environment:

- **scapy**: Required for PCAP functionality (not available on Windows by default)
- **AndroidFridaManager**: Required for advanced Android features
- **watchdog**: Required for file watching features

The codebase gracefully handles missing optional dependencies.

## Testing Framework Details

### Test Categories

1. **Unit Tests** (`tests/unit/`): Fast, isolated component tests
2. **Agent Tests** (`tests/agent/`): TypeScript compilation validation
3. **Integration Tests** (`tests/integration/`): Mock-based workflow tests
4. **Ground Truth Tests**: Real application testing (requires setup)

### Test Environment

```bash
# Check test environment
python run_tests.py summary

# Setup test environment
python run_tests.py setup

# Install missing test dependencies
pip install -r tests/requirements.txt
```

### Writing Tests

See [Testing Framework Guide](tests/README.md) for detailed guidance on:
- Writing unit tests
- Creating mock objects
- Integration testing patterns
- Platform-specific testing

## Common Development Tasks

### Adding SSL Library Support

1. Create TypeScript implementation in `agent/ssl_lib/`
2. Add platform-specific integration in `agent/{platform}/`
3. Update main agent in `agent/ssl_log.ts`
4. Compile agent: `npm run build`
5. Add tests in `tests/unit/` and `tests/integration/`
6. Update documentation

### Debugging friTap

```bash
# Run with debug output
fritap -do -v target_application

# Debug agent compilation
npm run build -- --verbose

# Debug test failures
pytest tests/unit/test_ssl_logger.py::TestSSLLogger::test_specific -v -s
```

### Documentation Updates

```bash
# Serve documentation locally
mkdocs serve

# Build documentation
mkdocs build

# Deploy documentation (maintainers only)
mkdocs gh-deploy
```

## CI/CD Integration

### GitHub Actions

The repository includes GitHub Actions workflows for:
- Multi-platform testing (Linux, Windows, macOS)
- Multiple Python versions (3.8-3.11)
- Agent compilation validation
- Code quality checks

### Local CI Simulation

```bash
# Run tests as they would run in CI
tox

# Test specific environments
tox -e py39-linux
tox -e py310-windows
```

## Troubleshooting

### Common Issues

**Import Errors:**
```bash
# Ensure friTap is installed in development mode
pip install -e .
```

**Agent Compilation Failures:**
```bash
# Check Node.js and npm versions
node --version
npm --version

# Clean and reinstall Node.js dependencies
rm -rf node_modules package-lock.json
npm install
```

**Test Failures:**
```bash
# Run individual test for debugging
pytest tests/unit/test_ssl_logger.py::TestSSLLogger::test_initialization -v -s

# Check test dependencies
pip install -r tests/requirements.txt
```

**Missing Dependencies:**
```bash
# Install all development dependencies
pip install -r requirements-dev.txt

# For optional dependencies, install manually
pip install scapy  # Linux/macOS only
```

### Platform-Specific Issues

**Linux:**
```bash
# Install system dependencies
sudo apt-get install build-essential python3-dev
```

**macOS:**
```bash
# Install Xcode command line tools
xcode-select --install
```

**Windows:**
```bash
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
```

### Getting Help

1. Check [Testing Documentation](tests/README.md)
2. Review [Contributing Guide](docs/development/contributing.md)
3. Search [existing issues](https://github.com/fkie-cad/friTap/issues)
4. Join discussions in [GitHub Discussions](https://github.com/fkie-cad/friTap/discussions)

## Performance Tips

### Development Performance

```bash
# Run only fast tests during development
python run_tests.py --fast

# Use pytest-xdist for parallel testing
pytest -n auto tests/unit/

# Skip slow tests
pytest -m "not slow" tests/
```

### Memory Usage

```bash
# Monitor memory usage during tests
pytest --memray tests/unit/

# Profile specific tests
python -m cProfile -o profile_output.prof -m pytest tests/unit/test_ssl_logger.py
```

## Release Process

### Pre-release Checklist

1. Run comprehensive tests: `python run_tests.py all`
2. Update version in `friTap/about.py`
3. Update CHANGELOG.md
4. Ensure documentation is up to date
5. Run code quality checks: `python run_tests.py lint`

### Building Distribution

```bash
# Build distribution packages
python setup.py sdist bdist_wheel

# Check distribution
twine check dist/*

# Test installation
pip install dist/fritap-*.whl
```

---

**Happy coding! 🚀**

For questions or contributions, please refer to our [Contributing Guide](docs/development/contributing.md) or open an issue on GitHub.