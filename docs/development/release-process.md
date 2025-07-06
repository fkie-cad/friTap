# Release Process

This guide covers the release process for friTap maintainers.

## Version Numbering

friTap follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes, incompatible API changes
- **MINOR** (X.Y.0): New features, backward-compatible functionality
- **PATCH** (X.Y.Z): Bug fixes, backward-compatible fixes

## Release Types

### Regular Releases
- **Feature releases**: Every 3-4 months
- **Bug fix releases**: As needed
- **Security releases**: Immediate for critical issues

### Pre-releases
- **Alpha**: Early development versions (X.Y.Z-alpha.N)
- **Beta**: Feature-complete, testing phase (X.Y.Z-beta.N)
- **Release Candidate**: Final testing (X.Y.Z-rc.N)

## Release Checklist

### Pre-Release (1-2 weeks before)

- [ ] **Feature freeze**: No new features, only bug fixes
- [ ] **Update dependencies**: Ensure all dependencies are current
- [ ] **Run comprehensive tests**: All platforms and test suites
- [ ] **Update documentation**: Ensure all docs reflect new features
- [ ] **Review security**: Check for any security implications

### Release Preparation

- [ ] **Update version numbers**:
  ```python
  # friTap/about.py
  __version__ = "X.Y.Z"
  ```

- [ ] **Update CHANGELOG.md**:
  ```markdown
  ## [X.Y.Z] - YYYY-MM-DD
  
  ### Added
  - New features and capabilities
  
  ### Changed  
  - Modifications to existing features
  
  ### Deprecated
  - Features marked for removal
  
  ### Removed
  - Deleted features
  
  ### Fixed
  - Bug fixes and corrections
  
  ### Security
  - Security improvements
  ```

- [ ] **Update documentation version references**
- [ ] **Create release branch**: `release/vX.Y.Z`
- [ ] **Final testing on release branch**

### Release Execution

- [ ] **Tag the release**:
  ```bash
  git tag -a vX.Y.Z -m "Release vX.Y.Z"
  git push origin vX.Y.Z
  ```

- [ ] **Build distribution packages**:
  ```bash
  python setup.py sdist bdist_wheel
  twine check dist/*
  ```

- [ ] **Upload to PyPI**:
  ```bash
  twine upload dist/*
  ```

- [ ] **Create GitHub release**:
  - Use tag vX.Y.Z
  - Include changelog content
  - Attach distribution files

- [ ] **Update documentation site**:
  ```bash
  mkdocs gh-deploy
  ```

### Post-Release

- [ ] **Merge release branch to main**
- [ ] **Update development version**: Set to next version + "-dev"
- [ ] **Announce release**:
  - GitHub Discussions
  - Social media (if applicable)
  - Email notifications

- [ ] **Monitor for issues**: Watch for bug reports
- [ ] **Plan next release**: Update roadmap and milestones

## Hotfix Process

For critical bugs requiring immediate release:

1. **Create hotfix branch** from latest release tag
2. **Apply minimal fix** - only essential changes
3. **Test thoroughly** on affected platforms
4. **Update version** (increment patch number)
5. **Follow standard release process** with expedited timeline
6. **Backport to main** if needed

## Release Notes Template

```markdown
# friTap vX.Y.Z Release

## Overview

Brief description of the release focus and major improvements.

## 🚀 New Features

- **Feature name**: Description of new capability
- **Enhancement**: Improvement to existing functionality

## 🐛 Bug Fixes

- **Issue description**: Fix applied
- **Platform fix**: Platform-specific correction

## 📚 Documentation

- Updated installation guide
- New examples and tutorials
- Improved troubleshooting

## 🔧 Technical Changes

- Dependency updates
- Performance improvements
- Code refactoring

## 📦 Installation

```bash
pip install --upgrade fritap
```

## 🔗 Links

- [Full Changelog](https://github.com/fkie-cad/friTap/blob/main/CHANGELOG.md)
- [Documentation](https://fkie-cad.github.io/friTap)
- [GitHub Releases](https://github.com/fkie-cad/friTap/releases)

## 🙏 Contributors

Thanks to all contributors for this release:
- @contributor1
- @contributor2

## 📋 Next Steps

Preview of next release focus and timeline.
```

## Communication

### Release Announcements

**GitHub Release**: Primary announcement with full details
**GitHub Discussions**: Community notification and discussion
**Documentation**: Updated with new version information
**PyPI**: Automatic via package upload

### Breaking Changes

For releases with breaking changes:

1. **Advance notice**: Announce in previous release
2. **Migration guide**: Provide clear upgrade instructions
3. **Deprecation warnings**: Include in code where possible
4. **Extended support**: Maintain compatibility period when feasible

## Rollback Procedure

If critical issues are discovered post-release:

1. **Assess impact**: Determine severity and affected users
2. **Quick fix**: If possible, prepare hotfix release
3. **PyPI removal**: Remove problematic version if necessary
4. **Communication**: Notify users via all channels
5. **Post-mortem**: Analyze what went wrong and improve process

## Automation

Future improvements to consider:

- **Automated testing**: Comprehensive CI/CD pipeline
- **Release scripts**: Automate version updates and tagging
- **Distribution**: Automatic PyPI uploads via CI
- **Notifications**: Automated release announcements

## Maintainer Notes

- **Access required**: PyPI maintainer permissions, GitHub admin
- **Security**: Use 2FA for all release-related accounts
- **Backup**: Keep local copies of release artifacts
- **Documentation**: Keep this process updated as procedures evolve

---

For questions about the release process, contact the project maintainers.