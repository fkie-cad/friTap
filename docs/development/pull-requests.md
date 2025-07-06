# Pull Request Process

This guide covers the complete process for submitting, reviewing, and merging pull requests to friTap.

## Overview

friTap uses a structured pull request process to ensure:

- **Code quality**: Consistent, maintainable code
- **Testing coverage**: Comprehensive validation
- **Documentation**: Clear, up-to-date information
- **Compatibility**: Cross-platform stability
- **Security**: Safe, responsible changes

## Before Submitting

### Prerequisites Checklist

Before creating a pull request, ensure you have:

- [ ] **Forked the repository** and created a feature branch
- [ ] **Set up development environment** ([Development Setup](development-setup.md))
- [ ] **Read coding standards** ([Coding Standards](coding-standards.md))
- [ ] **Written/updated tests** ([Testing Guide](testing.md))
- [ ] **Updated documentation** ([Documentation Guide](documentation.md))

### Code Quality Check

Run the full quality check before submitting:

```bash
# Code formatting and linting
black friTap/ tests/
flake8 friTap/ tests/
mypy friTap/

# TypeScript compilation
npm run build

# Run tests
python run_tests.py --fast

# Documentation build
mkdocs build --strict
```

### Pre-commit Hooks

Ensure pre-commit hooks are installed and passing:

```bash
# Install hooks (if not already done)
pre-commit install

# Run hooks on all files
pre-commit run --all-files

# Fix any issues and re-run
pre-commit run --all-files
```

## Creating a Pull Request

### Branch Naming

Use descriptive branch names following these patterns:

```bash
# Feature additions
feature/add-ssl-library-support
feature/android-anti-root-bypass
feature/json-output-format

# Bug fixes
fix/windows-compilation-error
fix/android-device-detection
fix/memory-leak-ssl-logger

# Documentation updates
docs/update-installation-guide
docs/add-troubleshooting-section

# Refactoring
refactor/ssl-library-detection
refactor/test-framework-structure

# Examples
git checkout -b feature/add-gnutls-support
git checkout -b fix/ios-hook-installation
git checkout -b docs/improve-api-reference
```

### Commit Messages

Write clear, descriptive commit messages:

```bash
# Good commit messages
feat: add GnuTLS SSL library support for Linux
fix: resolve Android device detection on API 33+
docs: update installation guide with Docker setup
test: add unit tests for SSL key extraction
refactor: simplify platform detection logic

# Include details in commit body
feat: add pattern-based hooking for stripped libraries

- Implement byte pattern matching for function detection
- Support ARM64, x64, and ARMv7 architectures  
- Add fallback patterns for improved reliability
- Include comprehensive test coverage

Closes #123
```

### Pull Request Template

Use this template for your pull request description:

```markdown
## Description

Brief description of the changes and their purpose.

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (code improvement without functionality changes)
- [ ] Test improvement

## Changes Made

- List specific changes made
- Include technical details
- Mention any new dependencies
- Note any configuration changes

## Testing

- [ ] Tests pass locally (`python run_tests.py`)
- [ ] New tests added for new functionality
- [ ] Manual testing performed on:
  - [ ] Linux
  - [ ] Windows  
  - [ ] macOS
  - [ ] Android
  - [ ] iOS (if applicable)

## Breaking Changes

List any breaking changes and migration instructions.

## Documentation

- [ ] Documentation updated for new features
- [ ] API documentation updated
- [ ] Examples updated/added
- [ ] Changelog updated

## Screenshots/Output

Include relevant screenshots or command output demonstrating the changes.

## Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings introduced
- [ ] All CI checks passing

## Related Issues

Closes #123
Fixes #456
Related to #789
```

### Example Pull Request

Here's an example of a well-structured pull request:

```markdown
## Add BoringSSL Pattern-Based Hooking Support

This PR adds support for BoringSSL detection and hooking using byte patterns, 
enabling friTap to work with statically-linked BoringSSL in applications like 
Flutter and Chrome.

## Type of Change

- [x] New feature (non-breaking change that adds functionality)

## Changes Made

- **Agent Changes**:
  - Added `agent/ssl_lib/boringssl_patterns.ts` with pattern-based detection
  - Implemented ARM64, x64, and ARMv7 pattern matching
  - Added fallback patterns for different BoringSSL versions
  
- **Platform Integration**:
  - Updated Linux, Android, and Windows platform handlers
  - Added pattern file loading and validation
  
- **Testing**:
  - Added unit tests for pattern matching logic
  - Created integration tests with mock BoringSSL modules
  - Added ground truth tests with Flutter applications

- **Documentation**:
  - Updated pattern-based hooking guide
  - Added BoringSSL-specific examples
  - Created troubleshooting section

## Testing

- [x] Tests pass locally (`python run_tests.py`)
- [x] New tests added for pattern matching functionality
- [x] Manual testing performed on:
  - [x] Linux (Ubuntu 20.04, Flutter app)
  - [x] Android (API 28, 30, 33 with Chrome and Flutter apps)
  - [x] Windows (Windows 10, Chrome browser)
  - [ ] macOS (pending access to test environment)
  - [ ] iOS (requires jailbroken device)

## Example Usage

```bash
# Generate patterns with BoringSecretHunter
mkdir -p binary results  
cp libflutter.so binary/
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter

# Use patterns with friTap
fritap --patterns results/libflutter.so_patterns.json -k keys.log com.flutter.app
```

## Performance Impact

Pattern matching adds ~50ms startup time but enables analysis of previously 
unsupported applications. Memory usage increase is minimal (~2MB).

## Documentation

- [x] Updated [Pattern-Based Hooking Guide](../advanced/patterns.md)
- [x] Added BoringSSL examples to [Libraries Documentation](../libraries/boringssl.md)
- [x] Updated CLI help text and man page
- [x] Added troubleshooting section

## Related Issues

Closes #234 (BoringSSL support request)
Closes #567 (Flutter application analysis)
Related to #123 (Pattern-based hooking framework)
```

## Review Process

### Automated Checks

Every pull request triggers automated checks:

```yaml
# GitHub Actions workflow
✅ Python Tests (3.8, 3.9, 3.10, 3.11)
✅ TypeScript Compilation
✅ Code Quality (Black, flake8, mypy)
✅ Documentation Build
✅ Cross-Platform Testing
✅ Security Scan
```

### Review Criteria

Reviewers will evaluate:

1. **Functionality**: Does the code work as intended?
2. **Quality**: Follows coding standards and best practices?
3. **Testing**: Adequate test coverage and quality?
4. **Documentation**: Clear, accurate, and complete?
5. **Compatibility**: Works across supported platforms?
6. **Performance**: No significant performance regressions?
7. **Security**: No security vulnerabilities introduced?

### Review Stages

#### 1. Automated Review
- CI/CD pipeline checks
- Code quality analysis
- Security scanning
- Documentation building

#### 2. Maintainer Review
- Code architecture and design
- Implementation approach
- Test coverage and quality
- Documentation completeness

#### 3. Community Review
- User experience considerations
- Platform-specific testing
- Edge case identification
- Feature usability

### Addressing Feedback

When reviewers provide feedback:

#### 1. **Understand the feedback**
- Read carefully and ask for clarification if needed
- Consider the reviewer's perspective and experience
- Look at the bigger picture, not just the specific comment

#### 2. **Make requested changes**
```bash
# Create commits addressing feedback
git checkout feature/your-branch
# Make changes
git add .
git commit -m "fix: address review feedback - improve error handling"
git push origin feature/your-branch
```

#### 3. **Respond to comments**
```markdown
# Good responses to review feedback

## Reviewer Comment:
"This function is quite complex. Could we break it into smaller functions?"

## Your Response:
"Good point! I've refactored the function into three smaller functions:
- `validateInput()` - handles parameter validation
- `processData()` - core processing logic  
- `formatOutput()` - result formatting

This improves readability and makes testing easier. See commit abc123."

## Reviewer Comment:
"Should we add error handling for the case where the SSL library isn't found?"

## Your Response:
"Absolutely. I've added a try-catch block that gracefully handles missing libraries and logs a helpful error message. The function now returns `false` instead of throwing an exception. Updated in commit def456."
```

#### 4. **Request re-review**
```markdown
@reviewer Thanks for the feedback! I've addressed all the points:

1. ✅ Refactored complex function into smaller units
2. ✅ Added comprehensive error handling  
3. ✅ Updated tests to cover new error cases
4. ✅ Improved documentation with examples

Could you please take another look when you have a chance?
```

## Advanced Review Topics

### Security Reviews

For security-sensitive changes:

#### 1. **Input Validation**
```python
# Ensure all user inputs are validated
def process_target(target: str) -> bool:
    # Validate target parameter
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string")
    
    # Prevent command injection
    if any(char in target for char in [';', '&', '|', '`']):
        raise ValueError("Target contains invalid characters")
    
    return True
```

#### 2. **Privilege Handling**
```python
# Drop privileges when possible
def drop_privileges():
    if os.geteuid() == 0:  # Running as root
        # Drop to less privileged user
        os.setuid(os.getuid())
```

#### 3. **Data Sanitization**
```python
# Sanitize sensitive data in logs
def log_connection_info(info: Dict[str, Any]) -> None:
    # Remove sensitive information before logging
    safe_info = {k: v for k, v in info.items() if k not in ['password', 'token']}
    logger.info(f"Connection info: {safe_info}")
```

### Performance Reviews

For performance-critical changes:

#### 1. **Benchmarking**
```python
# Include performance benchmarks in PR
import time
import psutil

def benchmark_ssl_extraction():
    start_time = time.time()
    start_memory = psutil.Process().memory_info().rss
    
    # Run SSL extraction
    results = extract_ssl_keys("test_app")
    
    end_time = time.time()
    end_memory = psutil.Process().memory_info().rss
    
    print(f"Duration: {end_time - start_time:.2f}s")
    print(f"Memory usage: {(end_memory - start_memory) / 1024 / 1024:.1f}MB")
    print(f"Keys extracted: {len(results['keys'])}")
```

#### 2. **Resource Usage**
```bash
# Monitor resource usage during testing
./benchmark.sh before_change.txt
# Apply changes
./benchmark.sh after_change.txt
diff before_change.txt after_change.txt
```

### Architecture Reviews

For significant architectural changes:

#### 1. **Design Document**
Include a design document for major changes:

```markdown
## Design Document: Multi-Library SSL Hooking

### Problem Statement
Current implementation can only hook one SSL library at a time, limiting 
analysis of applications using multiple libraries.

### Proposed Solution
Implement a multi-library hook manager that can simultaneously handle 
multiple SSL implementations.

### Architecture Changes
1. **Hook Manager**: Central coordinator for all SSL hooks
2. **Library Registry**: Track discovered SSL libraries
3. **Data Merger**: Combine data from multiple sources

### Implementation Plan
1. Phase 1: Refactor existing hooks to use manager
2. Phase 2: Implement multi-library detection
3. Phase 3: Add data correlation logic

### Testing Strategy
- Unit tests for each component
- Integration tests with multi-library apps
- Performance testing to ensure no regression
```

#### 2. **Migration Strategy**
```markdown
## Migration Strategy

### Backward Compatibility
- Existing APIs remain unchanged
- Old configuration files still supported
- Gradual deprecation of legacy features

### Migration Path
1. Update to new version
2. Test existing workflows
3. Migrate to new APIs when ready
4. Remove deprecated features in next major version
```

## Merge Process

### Requirements for Merge

Before a PR can be merged:

- [ ] **All CI checks passing**
- [ ] **At least one maintainer approval**
- [ ] **All conversations resolved**
- [ ] **Up-to-date with main branch**
- [ ] **Documentation updated**
- [ ] **Tests passing**

### Merge Options

#### 1. **Merge Commit** (Default)
```bash
# Creates merge commit preserving branch history
git merge --no-ff feature/your-branch
```
Use for: Feature branches with multiple meaningful commits

#### 2. **Squash and Merge**
```bash
# Squashes all commits into one
git merge --squash feature/your-branch
```
Use for: Small features or bug fixes with messy commit history

#### 3. **Rebase and Merge**
```bash
# Replays commits on main without merge commit
git rebase main feature/your-branch
git merge --ff-only feature/your-branch
```
Use for: Clean, linear history preference

### Post-Merge Actions

After your PR is merged:

1. **Clean up**:
```bash
# Delete feature branch
git branch -d feature/your-branch
git push origin --delete feature/your-branch
```

2. **Update your fork**:
```bash
git checkout main
git pull upstream main
git push origin main
```

3. **Monitor**:
- Watch for any issues in CI/CD
- Respond to user feedback quickly
- Monitor performance impact

## Troubleshooting

### Common PR Issues

#### CI Failures

**Test Failures**:
```bash
# Run tests locally to debug
python run_tests.py --verbose
pytest tests/unit/test_failing.py -v -s

# Check test environment
python run_tests.py summary
```

**Code Quality Issues**:
```bash
# Fix formatting
black friTap/ tests/
isort friTap/ tests/

# Fix linting issues
flake8 friTap/ tests/ --show-source

# Fix type issues
mypy friTap/ --show-error-codes
```

**Documentation Build Failures**:
```bash
# Test documentation build
mkdocs build --strict --verbose

# Check for broken links
python scripts/check_links.py
```

#### Merge Conflicts

```bash
# Update your branch with latest main
git checkout main
git pull upstream main
git checkout feature/your-branch
git rebase main

# Resolve conflicts
git add resolved_file.py
git rebase --continue

# Force push to update PR
git push --force-with-lease origin feature/your-branch
```

#### Review Delays

If your PR isn't getting reviewed:

1. **Check requirements**: Ensure all checks are passing
2. **Ping maintainers**: Politely ask for review in comments
3. **Community help**: Ask in GitHub Discussions
4. **Self-review**: Double-check your changes
5. **Split PR**: Consider breaking into smaller chunks

### Getting Help

If you need help with the PR process:

1. **Documentation**: Review this guide and [Contributing](contributing.md)
2. **Examples**: Look at recently merged PRs
3. **Community**: Ask questions in GitHub Discussions
4. **Maintainers**: Tag maintainers for guidance
5. **IRC/Discord**: Join community chat (if available)

## Best Practices

### 1. **Keep PRs Focused**
- One feature or fix per PR
- Avoid mixing features with refactoring
- Split large changes into multiple PRs

### 2. **Write Good Descriptions**
- Explain the "why" not just the "what"
- Include context and background
- Show examples of usage
- Explain any tradeoffs made

### 3. **Test Thoroughly**
- Test happy path and edge cases
- Test on multiple platforms
- Include both automated and manual testing
- Document testing approach

### 4. **Communicate Clearly**
- Respond promptly to feedback
- Ask questions when unclear
- Explain your reasoning
- Be open to suggestions

### 5. **Learn from Reviews**
- Take feedback as learning opportunity
- Ask for clarification on best practices
- Apply lessons to future contributions
- Share knowledge with others

## Next Steps

After your first successful PR:

1. **Look for more issues**: Check the [issue tracker](https://github.com/fkie-cad/friTap/issues)
2. **Help others**: Review other contributors' PRs
3. **Improve documentation**: Find areas that could be clearer
4. **Share experience**: Help newcomers in discussions
5. **Suggest improvements**: Propose enhancements to the process

For more information:
- **[Contributing Guide](contributing.md)**: Overview of contribution process
- **[Development Setup](development-setup.md)**: Environment configuration
- **[Testing Guide](testing.md)**: Comprehensive testing strategies
- **[Community Guidelines](community.md)**: Communication and collaboration