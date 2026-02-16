# Contributing to Amadioha Cyber Defense

Thank you for your interest in contributing! Here are guidelines to help you get started.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/AmadiohaCyberDefense.git
   cd AmadiohaCyberDefense
   ```

3. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   ```

4. **Install dependencies** (including dev dependencies):
   ```bash
   pip install -r requirements.txt
   ```

## Development Workflow

### Making Changes

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** with clear, descriptive commits:
   ```bash
   git commit -m "Add [feature]: Brief description of changes"
   ```

3. **Test your changes** locally:
   ```bash
   # Test CLI commands
   python -m amadioha scan --target 127.0.0.1
   python -m amadioha analyze --log-file sample_auth.log
   python -m amadioha intel --ip 198.51.100.22
   
   # Test web dashboard
   python -m amadioha.web
   # Open http://localhost:5000 in browser
   ```

### Submitting Changes

1. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub with:
   - Clear title describing the feature/fix
   - Description of what changed and why
   - Reference any related issues

## Code Standards

- Follow Python PEP 8 style guidelines
- Add docstrings to all functions
- Keep functions focused and maintainable
- Add error handling for user inputs

## Areas for Contribution

- **Real API Integration**: Integrate AbuseIPDB, VirusTotal, or other threat APIs
- **Database Support**: Add PostgreSQL/SQLite backend for result persistence
- **Enhanced Scanning**: Add UDP scanning, service detection, version detection
- **Authentication**: Add user authentication to web dashboard
- **Testing**: Add unit tests and integration tests
- **Documentation**: Improve guides, add tutorials, translate to other languages
- **Bug Fixes**: Report and fix issues found in the toolkit

## Questions?

- Open an issue on GitHub for bug reports and feature requests
- Include steps to reproduce bugs and environment details
- Ping maintainers in issues for guidance

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
