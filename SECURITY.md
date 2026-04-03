# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | Yes       |
| 1.0.x   | No        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **joy@luminaryx.ca** with the subject line:

```
SECURITY: municipal-ai-gateway
```

### What to include in your report

- Description of the issue
- Steps to reproduce
- Potential impact
- Any suggested fix

### Response commitment

- We will acknowledge your report within **2 business days**
- We will provide a fix timeline within **7 business days**

### Scope

**In scope:**

- The gateway codebase (Python, Docker configuration, JavaScript)
- Authentication flows (admin login, JWT, TOTP, LDAP)
- PII scrubbing logic
- Audit trail integrity
- Docker Compose service configuration

**Out of scope:**

- The municipality's own network configuration (firewalls, VPN, DNS)
- Third-party AI provider APIs (OpenAI, Anthropic, Google)
- The municipality's Active Directory or LDAP server configuration
- Browser extensions or client-side tools used by staff
