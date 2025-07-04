# friTap Documentation

This directory contains the comprehensive documentation for friTap, built with [MkDocs](https://www.mkdocs.org/) and [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/).

## Documentation Structure

```
docs/
├── index.md                 # Homepage
├── getting-started/         # Installation and basic usage
│   ├── installation.md
│   ├── quick-start.md
│   └── concepts.md
├── examples/               # Comprehensive usage examples
│   ├── index.md
│   ├── desktop.md
│   ├── android.md
│   ├── ios.md
│   ├── browsers.md
│   ├── malware.md
│   └── live-analysis.md
├── platforms/              # Platform-specific guides
│   ├── android.md
│   ├── ios.md
│   ├── linux.md
│   ├── windows.md
│   └── macos.md
├── advanced/               # Advanced features
│   ├── patterns.md
│   ├── offsets.md
│   ├── spawn-gating.md
│   ├── custom-scripts.md
│   └── anti-detection.md
├── libraries/              # SSL/TLS library specific guides
│   ├── index.md
│   ├── openssl.md
│   ├── nss.md
│   ├── gnutls.md
│   ├── wolfssl.md
│   └── others.md
├── api/                    # API reference
│   ├── python.md
│   ├── cli.md
│   └── configuration.md
├── troubleshooting/        # Issue resolution
│   ├── common-issues.md
│   ├── debugging.md
│   ├── performance.md
│   └── faq.md
└── development/            # Developer resources
    ├── contributing.md
    ├── architecture.md
    ├── building.md
    └── testing.md
```

## Building Documentation Locally

### Prerequisites

Install the required dependencies:

```bash
pip install -r docs/requirements.txt
```

Or install individually:

```bash
pip install mkdocs-material mkdocstrings[python] mkdocs-mermaid2-plugin
```

### Local Development

Start the development server:

```bash
mkdocs serve
```

The documentation will be available at `http://localhost:8000` with live-reload enabled.

### Build Static Site

Generate the static documentation:

```bash
mkdocs build
```

The built site will be in the `site/` directory.

## Deployment

Documentation is automatically built and deployed via GitHub Actions when changes are pushed to the `main` branch. The workflow is defined in `.github/workflows/docs.yml`.

### Manual Deployment

To deploy manually to GitHub Pages:

```bash
mkdocs gh-deploy
```

## Writing Documentation

### Style Guide

- Use clear, concise language
- Include practical examples with commands
- Add code syntax highlighting
- Use admonitions for important information
- Cross-reference related sections

### Code Examples

Use language-specific syntax highlighting:

````markdown
```bash
fritap -k keys.log firefox
```

```python
from friTap import SSL_Logger
logger = SSL_Logger()
```
````

### Admonitions

Use admonitions for important information:

```markdown
!!! warning "Security Notice"
    Always analyze malware in isolated environments.

!!! tip "Pro Tip"
    Use verbose mode for debugging: `fritap -v target`

!!! note "Platform Support"
    This feature is only available on Android.
```

### Cross-References

Link to other documentation sections:

```markdown
See the [Installation Guide](getting-started/installation.md) for setup instructions.

For mobile analysis, check [Android Examples](examples/android.md).
```

## Configuration

The documentation is configured in `mkdocs.yml` with:

- **Theme**: Material Design with dark/light mode toggle
- **Plugins**: Search, API documentation generation, git info
- **Extensions**: Code highlighting, tabs, admonitions, emoji
- **Navigation**: Hierarchical structure with sections

## Contributing

To contribute to the documentation:

1. **Edit markdown files** in the `docs/` directory
2. **Test locally** with `mkdocs serve`
3. **Submit pull request** with changes
4. **Review deployment** after merge

### Adding New Pages

1. Create markdown file in appropriate directory
2. Add to navigation in `mkdocs.yml`
3. Update index pages with links
4. Cross-reference from related pages

### Images and Assets

Place images in `docs/assets/` and reference as:

```markdown
![Description](assets/image.png)
```

## Maintenance

### Regular Tasks

- **Update examples** with new friTap features
- **Review links** for accuracy
- **Update version numbers** in installation guides
- **Add new troubleshooting cases** from user feedback

### Quality Checks

The CI pipeline includes:

- **Build verification**: Ensures documentation builds successfully
- **Link checking**: Validates internal and external links
- **Spelling**: Checks for common typos (future enhancement)

## Contact

For documentation-related questions:

- **GitHub Issues**: Report documentation bugs or suggest improvements
- **Pull Requests**: Contribute directly to documentation
- **Email**: daniel.baier@fkie.fraunhofer.de