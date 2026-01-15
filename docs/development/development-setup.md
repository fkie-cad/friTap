# Development Setup

This guide provides comprehensive instructions for setting up a friTap development environment, including both automated and manual setup options.

## Quick Start

### Prerequisites

- **Python 3.7+** (recommended: 3.9+)
- **Node.js 16+** (for TypeScript agent compilation)
- **Git** for version control
- **Docker** (optional, for BoringSecretHunter integration)

### One-Command Setup (Recommended)

The fastest way to get started is using our automated setup script:

```bash
# Clone the repository
git clone https://github.com/fkie-cad/friTap.git
cd friTap

# Run automated setup
python setup_developer_env.py
```

This script automatically handles all setup requirements and verifies the installation.

## Automated Setup Details

The `setup_developer_env.py` script performs the following steps:

### Python Environment Setup
- Validates Python 3.7+ installation
- Installs friTap in development mode (`pip install -e .`)
- Installs all development dependencies from `requirements-dev.txt`

### Node.js Environment Setup
- Verifies Node.js 16+ and npm availability
- Installs TypeScript compilation dependencies (`npm install`)
- Provides platform-specific installation guidance if missing

### frida-compile Installation
- Installs latest frida-tools package (`pip install --upgrade frida-tools`)
- Verifies frida-compile availability and version
- Ensures compatibility with current Frida releases

### Agent Compilation Testing
- Tests TypeScript agent compilation (`npm run build`)
- Verifies generated JavaScript files exist
- Validates compilation process works correctly

### Testing Framework Setup
- Installs pytest and testing dependencies
- Runs basic framework validation
- Sets up coverage reporting tools

### Pre-commit Hooks
- Installs pre-commit framework
- Configures code quality hooks
- Sets up automated formatting and linting

### BoringSecretHunter Environment
- Checks Docker availability
- Creates necessary directories (`binary/`, `results/`)
- Provides Docker setup guidance
- Tests Docker daemon access

## Manual Setup

If you prefer manual setup or need to troubleshoot issues:

### Step 1: Python Environment

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install friTap in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt
```

### Step 2: Node.js Dependencies

```bash
# Install Node.js dependencies for TypeScript compilation
npm install

# Key dependencies include:
# - @types/frida-gum: TypeScript definitions for Frida
# - typescript: TypeScript compiler
# - Other build tools
```

### Step 3: frida-compile Installation

```bash
# Install frida-tools (includes latest frida-compile)
pip install --upgrade frida-tools

# Verify installation
frida-compile --version
```

!!! important "frida-compile Source"
    Always use frida-compile from frida-tools (`pip install frida-tools`) rather than standalone installations. This ensures you have the latest version compatible with current Frida releases.

### Step 4: Verify Setup

```bash
# Test Python installation
python -c "import friTap; print('friTap imported successfully')"

# Test TypeScript compilation
npm run build

# Verify compiled agents exist
ls -la friTap/_ssl_log.js friTap/_ssl_log_legacy.js

# Run test framework check
python run_tests.py summary
```

## Development Dependencies

### Python Development Tools

#### Core Development
```bash
# Essential development tools
pip install pytest pytest-cov black flake8 mypy

# Testing utilities
pip install pytest-mock pytest-timeout pytest-xdist

# Pre-commit hooks
pip install pre-commit
```

#### Documentation Tools
```bash
# Documentation generation
pip install mkdocs mkdocs-material

# API documentation
pip install pdoc3
```

#### Frida and Analysis Tools
```bash
# Frida framework and tools
pip install frida-tools

# Optional analysis dependencies
pip install scapy watchdog
pip install AndroidFridaManager  # For Android development
```

#### Development Utilities
```bash
# Package management and distribution
pip install setuptools wheel twine

# Code quality tools
pip install isort bandit safety
```

### Node.js/TypeScript Dependencies

The `package.json` file includes all necessary TypeScript dependencies:

```json
{
  "devDependencies": {
    "@types/frida-gum": "^17.0.0",
    "typescript": "^4.9.0"
  },
  "scripts": {
    "build": "./compile_agent.sh",
    "watch": "tsc --watch",
    "clean": "rm -f friTap/_ssl_log*.js"
  }
}
```

Install with:
```bash
npm install
```

## TypeScript Agent Development

### Agent Architecture

friTap consists of two main components:

1. **Python Host** (`friTap/` directory): Handles process attachment, argument parsing, and communication
2. **TypeScript Agent** (`agent/` directory): Performs actual SSL/TLS hooking inside target processes

### Agent Structure

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

### Compilation Workflow

#### Development Compilation

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
   - Modern: `friTap/_ssl_log.js` (Frida 17+)
   - Legacy: `friTap/_ssl_log_legacy.js` (Frida <17)
4. **Injects placeholders** for runtime values (offsets, patterns)

#### Compilation Output

```bash
$ npm run build
> friTap@1.3.5.0 build
> frida-compile agent/ssl_log.ts -o friTap/_ssl_log.js

Compiling main agent...
✓ Generated friTap/_ssl_log.js (450KB)
✓ Generated friTap/_ssl_log_legacy.js (420KB)
```

### Agent Development Cycle

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

### TypeScript API Reference

#### Logging Functions

friTap provides three main logging functions for agent development:

```typescript
import { log, devlog, devlog_error } from "./util/log.js";
```

**`log(message: string)`**
- **Purpose**: Standard output for important information
- **Usage**: User-visible messages, successful operations, key findings
- **Output**: Always visible (controlled by Python host)

```typescript
log("Running Script on Android");
log("Found SSL_CTX_set_info_callback at 0x19ff01984");
log(`Attached to ${moduleName} at ${moduleBase}`);
```

**`devlog(message: string)`**
- **Purpose**: Debug logging for development and troubleshooting
- **Usage**: Detailed debugging information, trace messages, verbose output
- **Output**: Only visible when debug mode is enabled (`-do` or `-d` flags)

```typescript
devlog("[OS Detection] AppKit without UIKit -> macOS");
devlog(`[SSL Library] Trying to hook ${functionName}`);
devlog(`Found ${exportCount} exports in ${moduleName}`);
```

**`devlog_error(message: string)`**
- **Purpose**: Error logging for debugging issues
- **Usage**: Non-fatal errors, warning conditions, debugging problems
- **Output**: Only visible when debug mode is enabled (`-do` or `-d` flags)

```typescript
devlog_error("Failed to enumerate exports - continuing with fallback");
devlog_error(`Module ${moduleName} not found in process`);
devlog_error("Pattern match failed, trying secondary pattern");
```

#### Logging Best Practices

```typescript
// Use consistent formatting for different types
log(`Successfully ${action}: ${details}`);              // Success messages
devlog(`[${component}] ${action}: ${details}`);         // Debug traces  
devlog_error(`Failed ${action}: ${reason}`);            // Error messages

// Include context information
devlog(`[${libraryName}] Found ${functionCount} SSL functions`);
log(`Hooked ${libraryName} SSL functions: read=${readHooked}, write=${writeHooked}`);

// Use debug categories with consistent prefixes
devlog("[OS Detection] UIKit found -> iOS");
devlog("[Library] Scanning exports in libssl.so");
devlog("[Hook] Installing interceptor for SSL_write");
devlog("[Memory] Scanning 0x1000 bytes at 0x7fff12345000");
```

## Testing Setup

### Test Environment

```bash
# Check test environment status
python run_tests.py summary

# Install missing test dependencies
pip install -r tests/requirements.txt

# Setup test environment
python run_tests.py setup
```

### Running Tests

```bash
# Run all fast tests (recommended for development)
python run_tests.py --fast

# Run specific test categories
python run_tests.py unit           # Unit tests only
python run_tests.py agent          # Agent compilation tests
python run_tests.py integration    # Mock integration tests

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

## Code Quality Tools

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

# Update hooks to latest versions
pre-commit autoupdate
```

## BoringSecretHunter Integration

### Docker Setup

BoringSecretHunter is used for automatic pattern generation from stripped SSL libraries:

```bash
# Check Docker availability
docker --version

# Create directories for BoringSecretHunter
mkdir -p binary results

# Copy target libraries to analyze
cp libflutter.so binary/
cp libssl.so binary/

# Run BoringSecretHunter with Docker (recommended)
docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  boringsecrethunter

# Generated patterns will be in results/ directory
ls results/
# Output: libflutter.so_patterns.json, libssl.so_patterns.json

# Use generated patterns with friTap
fritap --patterns results/libflutter.so_patterns.json -k keys.log target_app
```

### Why Docker?

The Docker approach provides:
- Pre-configured environment with Ghidra
- Eliminates complex setup requirements
- Ensures consistent results across platforms
- Automatic dependency management

## Platform-Specific Setup

### Linux Development

```bash
# Install system dependencies
sudo apt-get install build-essential python3-dev

# For Frida development
sudo apt-get install pkg-config libffi-dev

# For optional dependencies
sudo apt-get install libpcap-dev  # For scapy
```

### macOS Development

```bash
# Install Xcode command line tools
xcode-select --install

# Install Homebrew dependencies
brew install node python@3.9

# For optional dependencies
brew install libpcap  # For scapy
```

### Windows Development

```powershell
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Install Node.js
# Download from: https://nodejs.org/

# Install Python from Microsoft Store or python.org

# Install Git for Windows
# Download from: https://git-scm.com/download/win
```

## Environment Variables

### Development Configuration

```bash
# Optional: Set custom paths
export FRITAP_DEV_PATH="/path/to/fritap"
export FRITAP_AGENT_PATH="/path/to/agent"

# For testing
export FRITAP_TEST_MODE=1
export FRITAP_DEBUG_LEVEL=2

# For Docker BoringSecretHunter
export BORING_SECRET_HUNTER_DOCKER=1
```

### Python Path Configuration

```bash
# Ensure friTap is in PYTHONPATH for development
export PYTHONPATH="${PYTHONPATH}:/path/to/friTap"

# Or use development installation
pip install -e .
```

## Troubleshooting Common Issues

### Import Errors

```bash
# Ensure friTap is installed in development mode
pip install -e .

# Check Python path
python -c "import sys; print(sys.path)"

# Verify friTap import
python -c "import friTap; print(friTap.__version__)"
```

### Agent Compilation Failures

```bash
# Check Node.js and npm versions
node --version
npm --version

# Clean and reinstall Node.js dependencies
rm -rf node_modules package-lock.json
npm install

# Check TypeScript compiler
npx tsc --version

# Verify frida-compile
frida-compile --version
```

### Test Failures

```bash
# Run individual test for debugging
pytest tests/unit/test_ssl_logger.py::TestSSLLogger::test_initialization -v -s

# Check test dependencies
pip install -r tests/requirements.txt

# Clear test cache
pytest --cache-clear
```

### Permission Issues

```bash
# Linux/macOS: Ensure proper permissions for Frida
sudo chown -R $USER:$USER ~/.local/lib/python*/site-packages/frida*

# Windows: Run as Administrator for system-level operations
```

## Performance Optimization

### Development Performance

```bash
# Run only fast tests during development
python run_tests.py --fast

# Use pytest-xdist for parallel testing
pytest -n auto tests/unit/

# Skip slow tests
pytest -m "not slow" tests/

# Use incremental compilation
npm run watch  # Continuous TypeScript compilation
```

### Memory Usage Monitoring

```bash
# Monitor memory usage during tests
pytest --memray tests/unit/

# Profile specific operations
python -m cProfile -o profile_output.prof -m pytest tests/unit/test_ssl_logger.py

# Analyze profile
python -c "import pstats; pstats.Stats('profile_output.prof').sort_stats('cumulative').print_stats()"
```

## Next Steps

Once your development environment is set up:

1. **Explore the codebase**: Start with `friTap/friTap.py` and `agent/ssl_log.ts`
2. **Run the test suite**: `python run_tests.py --fast`
3. **Try a simple change**: Add a log message and recompile
4. **Read the other guides**: [Coding Standards](coding-standards.md), [Testing Guide](testing.md)
5. **Join the community**: Check [Community Guidelines](community.md)

## Getting Help

If you encounter issues during setup:

1. **Check the troubleshooting section** above
2. **Review error messages** carefully
3. **Search existing issues** on GitHub
4. **Ask for help** in GitHub Discussions
5. **Contact maintainers** for complex setup problems

The development environment setup should be straightforward with the automated script. If you encounter persistent issues, please open an issue with your platform details and error messages.