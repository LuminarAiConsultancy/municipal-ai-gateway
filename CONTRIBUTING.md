# Contributing

The Canadian Municipal AI Gateway is an open source project built for Canadian municipalities. Contributions are welcome.

## Reporting bugs

Use [GitHub Issues](https://github.com/LuminarAiConsultancy/municipal-ai-gateway/issues) with the bug report template. Include:

- What happened
- What you expected to happen
- Steps to reproduce
- Gateway version, server OS, and Docker version
- Relevant logs (redact any sensitive information)

## Suggesting features

Use [GitHub Issues](https://github.com/LuminarAiConsultancy/municipal-ai-gateway/issues) with the feature request template. Describe what problem the feature solves for municipalities.

## Contributing code

1. Fork the repository
2. Create a branch from `main`
3. Make your changes
4. Ensure all tests pass (see below)
5. Open a pull request with a clear description of what changed and why

### Code standards

- Python code follows PEP 8
- All new code requires tests
- All new configuration uses environment variables with sensible defaults
- No hardcoded secrets, passwords, or API keys anywhere in the code
- All dependencies pinned to exact versions in `requirements.txt`

### Running tests locally

```bash
cd tests
pip install -r requirements.txt
cd ..
python -m pytest tests/ -v
```

### Review process

The maintainer reviews pull requests within 7 business days. Feedback will be provided directly on the pull request.

## Security vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for reporting instructions.
