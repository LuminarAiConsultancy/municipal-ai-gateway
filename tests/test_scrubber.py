"""Tests for the PII scrubbing engine (gateway/scrubber.py).

Each test verifies that a specific PII type is detected and replaced with
the correct placeholder, and that surrounding text is preserved.
"""


class TestSinDetection:
    def test_valid_sin_detected(self, scrubber):
        """Valid Canadian SIN (passes Luhn checksum) is scrubbed."""
        result = scrubber.scrub("My SIN is 046 454 286")
        assert "046 454 286" not in result.text
        assert "[SIN REMOVED]" in result.text
        assert result.pii_found

    def test_invalid_sin_not_flagged(self, scrubber):
        """SIN that fails Luhn checksum (123-456-789) is NOT flagged as CA_SIN."""
        result = scrubber.scrub("SIN 123-456-789")
        sin_detections = [d for d in result.detections if d.entity_type == "CA_SIN"]
        assert len(sin_detections) == 0


class TestHealthNumbers:
    def test_bc_phn(self, scrubber):
        """BC Personal Health Number (10 digits starting with 9) is scrubbed."""
        result = scrubber.scrub("BC personal health number: 9876543210")
        assert "9876543210" not in result.text
        assert "[BC PHN REMOVED]" in result.text

    def test_alberta_phn(self, scrubber):
        """Alberta ULI / PHN (9 digits with context keyword) is scrubbed."""
        result = scrubber.scrub("Alberta health ULI: 123456789")
        assert "123456789" not in result.text
        assert result.pii_found

    def test_ohip(self, scrubber):
        """Ontario OHIP number (10 digits with context keyword) is scrubbed."""
        result = scrubber.scrub("Ontario OHIP number: 1234567890")
        assert "1234567890" not in result.text
        assert result.pii_found

    def test_ramq(self, scrubber):
        """Quebec RAMQ number (4 letters + 8 digits) is scrubbed."""
        result = scrubber.scrub("RAMQ carte soleil: SMIT75010312")
        assert "SMIT75010312" not in result.text
        assert result.pii_found


class TestContactInfo:
    def test_postal_code(self, scrubber):
        """Canadian postal code is scrubbed."""
        result = scrubber.scrub("Postal code: V0A 1H0")
        assert "V0A 1H0" not in result.text
        assert "[POSTAL CODE REMOVED]" in result.text

    def test_phone_number(self, scrubber):
        """Canadian phone number is scrubbed."""
        result = scrubber.scrub("Phone: 250-344-0000")
        assert "250-344-0000" not in result.text
        assert "[PHONE REMOVED]" in result.text

    def test_email(self, scrubber):
        """Email address is scrubbed."""
        result = scrubber.scrub("Email me at jane.doe@example.ca")
        assert "jane.doe@example.ca" not in result.text
        assert "[EMAIL REMOVED]" in result.text

    def test_street_address(self, scrubber):
        """Canadian street address (number + street + city + province) is scrubbed."""
        result = scrubber.scrub("I live at 456 Oak Street Vancouver BC")
        assert "456 Oak Street" not in result.text
        assert result.pii_found


class TestMunicipalIdentifiers:
    def test_pid(self, scrubber):
        """BC Parcel Identifier (PID) is scrubbed when context is present."""
        result = scrubber.scrub("The parcel PID is 006-714-316")
        assert "006-714-316" not in result.text
        assert result.pii_found

    def test_folio(self, scrubber):
        """Municipal folio / assessment roll number is scrubbed."""
        result = scrubber.scrub("Property tax folio: 1234-567-890")
        assert "1234-567-890" not in result.text
        assert result.pii_found


class TestNameDetection:
    def test_person_name(self, scrubber):
        """Clearly fictional person name is detected via Presidio NLP."""
        result = scrubber.scrub(
            "Please contact Margaret Thompson about this matter"
        )
        assert result.pii_found
        name_detections = [d for d in result.detections if d.entity_type == "PERSON"]
        assert len(name_detections) >= 1


class TestEdgeCases:
    def test_clean_text_unchanged(self, scrubber):
        """Text with no PII passes through unchanged."""
        text = "The weather in Canada is cold today."
        result = scrubber.scrub(text)
        assert result.text == text
        assert not result.pii_found
        assert len(result.detections) == 0

    def test_multiple_pii_types_all_caught(self, scrubber):
        """Multiple PII types in one string are all detected and replaced."""
        text = "SIN 046 454 286, email test@example.ca, postal code V6B 1A1"
        result = scrubber.scrub(text)
        types_found = {d.entity_type for d in result.detections}
        assert "CA_SIN" in types_found
        assert "EMAIL_ADDRESS" in types_found
        assert "CA_POSTAL_CODE" in types_found
        # All PII text should be gone from the output.
        assert "046 454 286" not in result.text
        assert "test@example.ca" not in result.text
        assert "V6B 1A1" not in result.text

    def test_adjacent_pii_both_caught(self, scrubber):
        """Name adjacent to phone number — both caught without offset errors."""
        text = "Call Margaret Thompson at phone 250-344-0000 for details"
        result = scrubber.scrub(text)
        types_found = {d.entity_type for d in result.detections}
        # Phone should always be caught.
        assert "CA_PHONE_NUMBER" in types_found
        assert "250-344-0000" not in result.text
        # Name should be caught by NLP.
        assert "PERSON" in types_found
        assert "Margaret Thompson" not in result.text
        # Surrounding text should be intact.
        assert "Call" in result.text
        assert "for details" in result.text
