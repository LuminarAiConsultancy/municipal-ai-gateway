"""Token extraction and cost estimation for the Municipal AI Gateway.

Parses usage data from provider responses (OpenAI, Anthropic, Google)
and estimates costs based on a per-model pricing table. Falls back to
word-count estimation when the provider doesn't return token counts.
"""

from __future__ import annotations

import math


# ── Pricing table (USD per 1 000 tokens) ─────────────────────────────────────

MODEL_PRICING: dict[str, dict[str, float]] = {
    # OpenAI
    "gpt-4o": {"input": 0.250, "output": 1.000},
    "gpt-4o-mini": {"input": 0.015, "output": 0.060},
    "gpt-4.1": {"input": 0.200, "output": 0.800},
    "gpt-4.1-mini": {"input": 0.040, "output": 0.160},
    "gpt-4.1-nano": {"input": 0.010, "output": 0.040},
    "o3-mini": {"input": 0.110, "output": 0.440},
    # Anthropic
    "claude-sonnet-4-20250514": {"input": 0.300, "output": 1.500},
    "claude-haiku-4-5-20251001": {"input": 0.080, "output": 0.400},
    "claude-opus-4-6": {"input": 1.500, "output": 7.500},
    # Google
    "gemini-2.0-flash": {"input": 0.010, "output": 0.040},
    "gemini-2.5-pro": {"input": 0.125, "output": 0.500},
}


# ── Token extraction ─────────────────────────────────────────────────────────


def extract_usage(provider: str, response_json: dict) -> dict[str, int]:
    """Extract input/output token counts from a provider's response JSON.

    Returns ``{"input_tokens": int, "output_tokens": int}``.
    Falls back to zero if the response doesn't include usage data.
    """
    if provider == "openai":
        usage = response_json.get("usage")
        if usage:
            return {
                "input_tokens": usage.get("prompt_tokens", 0),
                "output_tokens": usage.get("completion_tokens", 0),
            }

    elif provider == "anthropic":
        usage = response_json.get("usage")
        if usage:
            return {
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
            }

    elif provider == "google":
        meta = response_json.get("usageMetadata")
        if meta:
            return {
                "input_tokens": meta.get("promptTokenCount", 0),
                "output_tokens": meta.get("candidatesTokenCount", 0),
            }

    return {"input_tokens": 0, "output_tokens": 0}


# ── Fallback token estimation ────────────────────────────────────────────────


def estimate_tokens(text: str) -> int:
    """Estimate token count from text using word_count * 1.3.

    This is a rough approximation used only when the provider doesn't
    return actual usage data.
    """
    if not text:
        return 0
    word_count = len(text.split())
    return round(word_count * 1.3)


# ── Cost estimation ──────────────────────────────────────────────────────────


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in cents for a request given a model and token counts.

    Returns 0.0 if the model is not in the pricing table.
    """
    pricing = MODEL_PRICING.get(model)
    if not pricing:
        return 0.0

    input_cost = (input_tokens / 1000) * pricing["input"] * 100  # cents
    output_cost = (output_tokens / 1000) * pricing["output"] * 100
    return round(input_cost + output_cost, 2)
