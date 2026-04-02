"""Tests for token extraction and cost estimation (gateway/costs.py).

NOTE: gateway/costs.py does not exist yet. These tests will be SKIPPED
automatically until the module is implemented. They serve as a spec for
the expected API.

Assumed API:
  costs.extract_usage(provider: str, response_json: dict)
      -> dict {"input_tokens": int, "output_tokens": int}
      Falls back to estimation if the response lacks usage fields.

  costs.estimate_tokens(text: str) -> int
      Fallback token estimation: word_count * 1.3 (rounded).

  costs.estimate_cost(model: str, input_tokens: int, output_tokens: int)
      -> float  (cost in cents)

  costs.MODEL_PRICING: dict[str, dict]
      e.g. {"gpt-4o": {"input": 0.250, "output": 1.000}}  (per 1K tokens)
"""

import pytest

costs = pytest.importorskip("costs", reason="gateway/costs.py not yet implemented")


class TestExtractUsage:
    def test_openai_usage(self):
        """Parse prompt_tokens and completion_tokens from OpenAI response."""
        response = {
            "usage": {"prompt_tokens": 150, "completion_tokens": 80},
        }
        usage = costs.extract_usage("openai", response)
        assert usage["input_tokens"] == 150
        assert usage["output_tokens"] == 80

    def test_anthropic_usage(self):
        """Parse input_tokens and output_tokens from Anthropic response."""
        response = {
            "usage": {"input_tokens": 200, "output_tokens": 120},
        }
        usage = costs.extract_usage("anthropic", response)
        assert usage["input_tokens"] == 200
        assert usage["output_tokens"] == 120

    def test_google_usage(self):
        """Parse promptTokenCount and candidatesTokenCount from Google response."""
        response = {
            "usageMetadata": {
                "promptTokenCount": 300,
                "candidatesTokenCount": 150,
            },
        }
        usage = costs.extract_usage("google", response)
        assert usage["input_tokens"] == 300
        assert usage["output_tokens"] == 150


class TestFallbackEstimation:
    def test_word_count_estimation(self):
        """Fallback estimation uses word_count * 1.3 (not len/4)."""
        text = "The quick brown fox jumps over the lazy dog"  # 9 words
        tokens = costs.estimate_tokens(text)
        expected = round(9 * 1.3)  # 12
        assert tokens == expected

    def test_empty_string(self):
        """Empty string estimates to 0 tokens."""
        assert costs.estimate_tokens("") == 0


class TestEstimateCost:
    def test_known_model_cost(self):
        """estimate_cost returns correct cents for a known model."""
        cents = costs.estimate_cost("gpt-4o", 1000, 500)
        assert isinstance(cents, (int, float))
        assert cents > 0
        # gpt-4o pricing: $0.250 / 1K input, $1.000 / 1K output
        # 1000 input → 25¢, 500 output → 50¢ → total ~75¢
        expected = (1000 / 1000) * 0.250 * 100 + (500 / 1000) * 1.000 * 100
        assert abs(cents - expected) < 1

    def test_pricing_table_exists(self):
        """MODEL_PRICING dict contains at least gpt-4o."""
        assert "gpt-4o" in costs.MODEL_PRICING
        assert "input" in costs.MODEL_PRICING["gpt-4o"]
        assert "output" in costs.MODEL_PRICING["gpt-4o"]
