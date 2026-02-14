"""Tests for the regex-based PII detection engine."""

import pytest
from src.detection.regex_detector import RegexDetector, luhn_check, ssn_check, pan_check, aadhaar_check


class TestChecksumValidators:
    """Test checksum validation functions."""

    def test_luhn_valid_visa(self):
        assert luhn_check("4532015112830366") is True

    def test_luhn_valid_mastercard(self):
        assert luhn_check("5425233430109903") is True

    def test_luhn_invalid(self):
        assert luhn_check("1234567890123456") is False

    def test_luhn_short(self):
        assert luhn_check("123") is False

    def test_ssn_valid(self):
        assert ssn_check("123-45-6789") is True
        assert ssn_check("123456789") is True

    def test_ssn_invalid_area(self):
        assert ssn_check("000-12-3456") is False
        assert ssn_check("666-12-3456") is False
        assert ssn_check("900-12-3456") is False

    def test_ssn_invalid_group(self):
        assert ssn_check("123-00-6789") is False
        assert ssn_check("123-45-0000") is False

    def test_pan_valid(self):
        assert pan_check("ABCPD1234E") is True
        assert pan_check("ZZZHK5678L") is True

    def test_pan_invalid(self):
        assert pan_check("12345ABCDE") is False
        assert pan_check("ABCDE") is False

    def test_aadhaar_valid(self):
        assert aadhaar_check("234567890123") is True

    def test_aadhaar_invalid_start(self):
        assert aadhaar_check("012345678901") is False
        assert aadhaar_check("112345678901") is False


class TestRegexDetector:
    """Test the regex-based PII detector."""

    def setup_method(self):
        self.detector = RegexDetector()

    def test_detect_email(self):
        results = self.detector.detect("Contact us at john.doe@example.com for details.")
        emails = [r for r in results if r["entity_type"] == "email"]
        assert len(emails) >= 1
        assert emails[0]["value"] == "john.doe@example.com"

    def test_detect_phone_us(self):
        results = self.detector.detect("Call me at (555) 123-4567 today.")
        phones = [r for r in results if r["entity_type"] == "phone"]
        assert len(phones) >= 1

    def test_detect_ssn(self):
        text = "SSN: 123-45-6789 is on file for tax purposes."
        results = self.detector.detect(text)
        ssns = [r for r in results if r["entity_type"] == "ssn"]
        assert len(ssns) >= 1
        assert ssns[0]["sensitivity"] == "critical"

    def test_detect_credit_card_visa(self):
        text = "Payment card: 4532-0151-1283-0366"
        results = self.detector.detect(text)
        cards = [r for r in results if r["entity_type"] == "credit_card"]
        assert len(cards) >= 1
        assert cards[0]["sensitivity"] == "critical"

    def test_detect_pan_card(self):
        text = "PAN: ABCPD1234E for income tax filing."
        results = self.detector.detect(text)
        pans = [r for r in results if r["entity_type"] == "pan_card"]
        assert len(pans) >= 1
        assert pans[0]["sensitivity"] == "critical"

    def test_detect_api_key(self):
        text = 'api_key = "sk-proj-abcdefghij1234567890"'
        results = self.detector.detect(text)
        keys = [r for r in results if r["entity_type"] == "api_key"]
        assert len(keys) >= 1
        assert keys[0]["sensitivity"] == "critical"

    def test_detect_password(self):
        text = 'password = "MySuperSecret123!"'
        results = self.detector.detect(text)
        passwords = [r for r in results if r["entity_type"] == "password"]
        assert len(passwords) >= 1

    def test_detect_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAL..."
        results = self.detector.detect(text)
        keys = [r for r in results if r["entity_type"] == "private_key"]
        assert len(keys) >= 1

    def test_detect_jwt(self):
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        results = self.detector.detect(text)
        tokens = [r for r in results if r["entity_type"] == "token"]
        assert len(tokens) >= 1

    def test_detect_ipv4(self):
        text = "Server running at 192.168.1.100 on port 8080"
        results = self.detector.detect(text)
        ips = [r for r in results if r["entity_type"] == "ip_address"]
        assert len(ips) >= 1

    def test_detect_address(self):
        text = "Ship to 123 Main Street, Springfield"
        results = self.detector.detect(text)
        addresses = [r for r in results if r["entity_type"] == "address"]
        assert len(addresses) >= 1

    def test_no_false_positive_on_clean_text(self):
        text = "The weather is nice today. Let's go for a walk in the park."
        results = self.detector.detect(text)
        # Should be very few or no critical findings
        critical = [r for r in results if r["sensitivity"] == "critical"]
        assert len(critical) == 0

    def test_context_keyword_boost(self):
        text_with_context = "Email contact: user@test.com"
        text_without_context = "user@test.com"
        results_with = self.detector.detect(text_with_context)
        results_without = self.detector.detect(text_without_context)
        
        emails_with = [r for r in results_with if r["entity_type"] == "email"]
        emails_without = [r for r in results_without if r["entity_type"] == "email"]
        
        if emails_with and emails_without:
            assert emails_with[0]["confidence"] >= emails_without[0]["confidence"]

    def test_multiple_pii_types(self):
        text = """
        Name: John Doe
        Email: john@example.com
        SSN: 123-45-6789
        Card: 4532-0151-1283-0366
        """
        results = self.detector.detect(text)
        types_found = set(r["entity_type"] for r in results)
        assert "email" in types_found
        assert "ssn" in types_found or "credit_card" in types_found

    def test_detection_returns_context_snippet(self):
        text = "The SSN number 123-45-6789 was found in the database."
        results = self.detector.detect(text)
        for r in results:
            assert "context_snippet" in r
            assert len(r["context_snippet"]) > 0

    def test_detection_returns_positions(self):
        text = "Email: test@example.com"
        results = self.detector.detect(text)
        emails = [r for r in results if r["entity_type"] == "email"]
        if emails:
            assert emails[0]["char_start"] >= 0
            assert emails[0]["char_end"] > emails[0]["char_start"]
