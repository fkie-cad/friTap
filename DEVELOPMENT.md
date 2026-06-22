# friTap Development Guide

This guide helps developers quickly set up a development environment for friTap and run the comprehensive testing suite.

## Quick Start

### Prerequisites

- **Python 3.10+**
- **Node.js 16+** (for frida-compile runtime)
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

# 3. Install frida-tools and Frida module dependencies
pip install frida-tools
frida-pm install frida-objc-bridge frida-java-bridge

# 4. Install friTap in development mode
pip install -e .

# 5. Verify setup
python dev/run_tests.py summary
```

### Alternative: One-Command Setup

```bash
# Run the automated setup script
python dev/setup_dev.py
```

## Testing

### Quick Testing

```bash
# Run all fast tests (recommended for development)
python dev/run_tests.py --fast

# Run specific test categories
python dev/run_tests.py unit           # Unit tests only
python dev/run_tests.py agent          # Agent compilation tests
python dev/run_tests.py integration    # Mock integration tests
```

### Comprehensive Testing

```bash
# Run all applicable tests
python dev/run_tests.py all

# Generate coverage report
python dev/run_tests.py coverage
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
python dev/run_tests.py lint
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

The TypeScript agent is compiled into a single JavaScript file:
- `friTap/fritap_agent.js` — compiled via `frida-compile`

### TypeScript Agent Structure

```
agent/
├── fritap_agent.ts              # Main agent entry point
├── core/                        # Modern hooking infrastructure
│   ├── context.ts               # AgentContext, AgentConfig
│   ├── hook_definition.ts       # HookDefinition type
│   ├── loader.ts                # executeFromDefinition()
│   └── executors/               # Hook installers
├── schemas/                     # Generated TS interfaces
│   └── messages.ts              # From Pydantic models
├── shared/                      # Common functionality
│   ├── shared_functions.ts      # Cross-platform functions
│   ├── hooking_pipeline.ts      # Pipeline with strategies
│   └── registry.ts              # Hook registration
├── tls/                         # TLS library implementations
│   ├── libs/                    # Base library classes
│   ├── definitions/             # Modern hook definitions
│   ├── platforms/               # Platform-specific hooks
│   │   ├── android/
│   │   ├── ios/
│   │   ├── linux/
│   │   ├── macos/
│   │   └── windows/
│   └── decoders/                # Hex/datum readers
├── platforms/                   # Platform dispatchers
│   ├── linux.ts
│   ├── android.ts
│   ├── ios.ts
│   ├── macos.ts
│   └── windows.ts
├── legacy/                      # V1 hooking code
└── util/                        # Utility functions
    ├── process_infos.ts         # OS/platform detection
    ├── log.ts                   # Logging functions
    └── ssl_library_infos.ts     # Library inspection
```

### TypeScript Agent Compilation

#### Prerequisites

```bash
# Install frida-tools (includes latest frida-compile)
pip install --upgrade frida-tools

# Install Frida module dependencies
frida-pm install frida-objc-bridge frida-java-bridge

# Verify frida-compile is available
frida-compile --version
```

!!! important "frida-compile Source"
    Always use frida-compile from frida-tools (`pip install frida-tools`) rather than standalone installations. This ensures you have the latest version compatible with current Frida releases.

#### Compilation Commands

```bash
# Direct compilation (recommended)
frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js

# Platform-specific scripts (install bridges + compile)
./dev/compile_agent.sh     # Linux/macOS
dev\compile_agent.bat      # Windows

# Test compilation
python dev/run_tests.py agent
```

#### What Compilation Does

1. **Processes TypeScript** files using frida-compile
2. **Bundles modules** into a single JavaScript file: `friTap/fritap_agent.js`
3. **Injects placeholders** for runtime values (offsets, patterns)

### Agent Development Workflow

#### 1. Development Cycle

```bash
# 1. Edit TypeScript source
vim agent/tls/libs/new_library.ts

# 2. Compile agent
frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js

# 3. Test compilation
python dev/run_tests.py agent

# 4. Test with real application
fritap -k keys.log target_app

# 5. Debug if needed
fritap -d -k keys.log target_app
```

#### 2. Adding New SSL Library Support

```bash
# 1. Create library implementation
touch agent/tls/libs/mylibrary.ts

# 2. Add platform-specific hooks
touch agent/tls/platforms/linux/mylibrary_linux.ts

# 3. Update main agent loader
vim agent/fritap_agent.ts

# 4. Compile and test
frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js
python dev/run_tests.py agent
```

#### 3. Debugging Agent Issues

```bash
# Debug with Chrome DevTools
fritap -d target_app
# Open chrome://inspect in Chrome
```

### Important Development Considerations

#### 1. TypeScript Compilation is Required

- **All hooking logic** is in TypeScript
- **Python cannot directly execute** TypeScript files
- **Must recompile** after any agent/ changes

#### 2. Frida-Specific TypeScript

```typescript
// Valid Frida TypeScript
const module = Process.getModuleByName("libssl.so");
const exports = module.enumerateExports();

// Not valid - uses Node.js APIs
import fs from 'fs';  // Won't work in Frida
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
// agent/tls/libs/custom.ts
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

friTap provides three logging functions for agent development, imported from `./util/log.js`:

```typescript
import { log, devlog, devlog_error } from "./util/log.js";
```

| Function | Visibility | Purpose |
|----------|-----------|---------|
| `log(msg)` | Always visible | User-facing messages, successful operations |
| `devlog(msg)` | Only with `-do` or `-d` flags | Debug traces, verbose output |
| `devlog_error(msg)` | Only with `-do` or `-d` flags | Non-fatal errors, debug warnings |

```typescript
// Examples
log("Successfully hooked SSL_read function");
devlog("[OS Detection] AppKit without UIKit -> macOS");
devlog_error("Failed to find SSL_write, trying fallback");
```

Use bracketed prefixes for debug categories: `[Hook]`, `[Pattern]`, `[Memory]`, `[OS Detection]`, `[Library]`.

### Python Debug Flags

- **No flags**: Only `log()` messages visible
- **`-do` (debug output)**: All logging functions visible
- **`-d` (full debug)**: All logging functions + Chrome Inspector

```bash
fritap -k keys.log target        # Standard mode
fritap -do -k keys.log target    # Debug output
fritap -d -k keys.log target     # Full debug + inspector
```

## Dependency Management

### Adding New Dependencies

1. **Runtime dependencies**: Add to `requirements.txt` and `setup.py`
2. **Frida bridge modules**: Install via `frida-pm install <module>`

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
python dev/run_tests.py summary

# Setup test environment
python dev/run_tests.py setup

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

1. Create TypeScript implementation in `agent/tls/libs/`
2. Add platform-specific hooks in `agent/tls/platforms/{platform}/`
3. Update main agent in `agent/fritap_agent.ts`
4. Compile agent: `frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js`
5. Add tests in `tests/unit/` and `tests/integration/`
6. Update documentation

### Debugging friTap

```bash
# Run with debug output
fritap -do -v target_application

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
- Python 3.10+
- Agent compilation validation
- Code quality checks

## Troubleshooting

### Common Issues

**Import Errors:**
```bash
# Ensure friTap is installed in development mode
pip install -e .
```

**Agent Compilation Failures:**
```bash
# Reinstall Frida module dependencies
pip install --upgrade frida-tools
frida-pm install frida-objc-bridge frida-java-bridge
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
# Install all dependencies
pip install -r requirements.txt
pip install -e .

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

## Release Process

### Pre-release Checklist

1. Run comprehensive tests: `python dev/run_tests.py all`
2. Update version in `friTap/about.py`
3. Update CHANGELOG.md
4. Ensure documentation is up to date
5. Run code quality checks: `python dev/run_tests.py lint`

### Building Distribution

```bash
# Build distribution packages
python -m build --sdist --wheel

# Check distribution
twine check dist/*

# Test installation
pip install dist/fritap-*.whl
```

---

For questions or contributions, please refer to our [Contributing Guide](docs/development/contributing.md) or open an issue on GitHub.