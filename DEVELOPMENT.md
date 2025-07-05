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

# 4. Install friTap in development mode
pip install -e .

# 5. Install Node.js dependencies (for agent compilation)
npm install

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

### TypeScript Agent Compilation

```bash
# Compile TypeScript agent
npm run build
# or
./compile_agent.sh  # Linux/macOS
compile_agent.bat   # Windows

# Watch for changes during development
npm run watch

# Test compilation
python run_tests.py agent
```

### Agent Development Workflow

1. Edit TypeScript files in `agent/`
2. Compile with `npm run build`
3. Test with `python run_tests.py agent`
4. Validate with a test application

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