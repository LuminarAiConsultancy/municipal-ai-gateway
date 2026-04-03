# Privacy

## What data the gateway processes

The Canadian Municipal AI Gateway acts as a proxy between your organization's staff and external AI providers. It processes:

- AI prompts and responses passing through it
- API key identifiers (hashed, not plaintext)
- IP addresses of staff making requests
- Token counts (input and output)
- PII detection events

## What the gateway stores

The gateway stores **request metadata** in PostgreSQL:

- Timestamp
- API key ID (not the key itself)
- AI provider and model name
- Token count (input and output)
- PII detected (yes/no and count)
- PII types found (e.g. CA_SIN, EMAIL_ADDRESS)
- Response status code
- Request duration

**The gateway does NOT store the content of prompts or responses.** Only metadata about the request is retained.

## What PII scrubbing does

The gateway detects and redacts Canadian personal information patterns from requests before they reach the AI provider:

- Social Insurance Numbers (SIN) — validated with Luhn checksum
- BC Personal Health Numbers (PHN)
- Alberta Personal Health Numbers (ULI)
- Ontario Health Insurance Plan numbers (OHIP)
- Quebec Health Insurance numbers (RAMQ)
- Canadian postal codes
- Canadian phone numbers
- Email addresses
- Person names
- Street addresses

Detections are logged as events only. The original unredacted content is never stored anywhere by the gateway.

## Data retention

Retention is configurable via the `LOG_RETENTION_DAYS` environment variable. Default is 365 days. After the retention period, log entries are automatically deleted.

## Data residency

All data remains on the municipality's own server. Nothing is sent to LUMINARYX or any third party except the AI provider APIs the municipality has configured (OpenAI, Anthropic, Google).

The gateway does not phone home. It does not collect telemetry. It does not send usage data anywhere.

## Relevant Canadian legislation

Municipalities deploying this gateway operate under various Canadian privacy laws:

- **PIPEDA** — Personal Information Protection and Electronic Documents Act (federal)
- **BC FIPPA** — Freedom of Information and Protection of Privacy Act
- **Alberta FOIPP** — Freedom of Information and Protection of Privacy Act
- **Ontario MFIPPA** — Municipal Freedom of Information and Protection of Privacy Act
- **Quebec Law 25** — An Act to modernize legislative provisions as regards the protection of personal information

Municipalities are responsible for their own compliance obligations under applicable legislation. This software provides tooling to support compliance (PII scrubbing, audit trails, access controls) but does not constitute legal advice.

## Contact

For privacy questions: **joy@luminaryx.ca**
