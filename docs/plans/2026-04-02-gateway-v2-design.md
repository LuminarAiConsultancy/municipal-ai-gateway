# Municipal AI Gateway v2 — Design Document

**Date:** 2026-04-02
**Status:** Approved

## Overview

Six features added to the existing gateway: rate limiting, cost tracking,
model allowlisting, dashboard key management, unit tests, and production
deployment documentation.

**Architecture approach:** Everything in main.py + two new modules
(costs.py, policies.py). No middleware separation or policy engine
abstraction — keep it simple.

## 1. Rate Limiting (gateway/policies.py)

**New DB table: `department_policies`**

| Column | Type | Default |
|--------|------|---------|
| id | Integer PK | auto |
| department | String(128), unique | — |
| requests_per_minute_per_key | Integer | 60 |
| requests_per_minute_department | Integer | 200 |
| allowed_models | Text (JSON array) | null |
| monthly_cost_limit_cents | Integer | null |
| created_at | DateTime | now |
| updated_at | DateTime | now |

**In-memory rate tracking** using `{key_id: deque(timestamps)}` and
`{department: deque(timestamps)}`. On each request:

1. Check key count in last 60s against `requests_per_minute_per_key`
2. Check department count against `requests_per_minute_department`
3. Return 429 with `Retry-After` header if exceeded

No Redis. Counters reset on restart. Default limits (60/key, 200/dept)
apply when no policy row exists.

**Admin endpoints:**
- `POST /admin/policies` — create/update department policy
- `GET /admin/policies` — list all policies
- `GET /admin/policies/{department}` — get one

## 2. Cost Tracking (gateway/costs.py)

**Token extraction** — `extract_usage(provider, response_json)`:
- OpenAI: `response["usage"]["prompt_tokens"]` + `completion_tokens`
- Anthropic: `response["usage"]["input_tokens"]` + `output_tokens`
- Google: `response["usageMetadata"]["promptTokenCount"]` + `candidatesTokenCount`
- Fallback: `estimate_tokens(text)` using `word_count * 1.3`

**Pricing table** — `MODEL_PRICING` dict:
- gpt-4o: $0.250 input / $1.000 output per 1K tokens
- gpt-4o-mini: $0.015 / $0.060
- claude-sonnet: $0.300 / $1.500
- claude-haiku: $0.080 / $0.400
- gemini-2.0-flash: $0.010 / $0.040

**New columns on RequestLog:**
- `model` String(64)
- `input_tokens` Integer
- `output_tokens` Integer
- `estimated_cost_cents` Integer

**Budget enforcement:** If `monthly_cost_limit_cents` is set on the
department policy, sum the department's costs for the current month.
Return 429 if over limit.

## 3. Model Allowlisting (in proxy route)

After authentication, before scrubbing:

1. Extract model from `request_body.get("model")`
2. Look up department policy
3. If `allowed_models` is non-empty, check model is in list
4. Return 403 with clear error if not allowed
5. No policy or empty list = allow all

## 4. Dashboard Key Management (dashboard/index.html)

New "Staff Keys" panel with table:
- Columns: ID, Key Prefix, Department, Description, Created, Last Used, Status, Actions
- Deactivate button with confirm() dialog
- Refresh button
- Existing "Create Key" quick action refreshes the table on success

## 5. Tests (tests/)

Already written and passing. 16 scrubber tests, 8 auth tests,
8 chain tests, 1 integration test. Forward-looking test files for
costs.py (7 tests) and policies.py (7 tests) auto-skip until
modules exist.

## 6. Production Hardening (docs only)

- `docs/DEPLOYMENT.md` — TLS, secrets, firewall, backups, log rotation
- `.env.production.example` — hardened env template
