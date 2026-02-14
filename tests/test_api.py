"""Tests for FastAPI endpoint schemas."""

import pytest


def test_scan_text_schema():
    """Validate ScanTextRequest schema."""
    from src.api.schemas import ScanTextRequest

    req = ScanTextRequest(text="user@test.com", source_type="text")
    assert req.text == "user@test.com"
    assert req.source_type == "text"


def test_scan_text_schema_defaults():
    from src.api.schemas import ScanTextRequest

    req = ScanTextRequest(text="hello")
    assert req.source_type == "text"
    assert req.min_confidence == 0.65


def test_mask_text_schema():
    from src.api.schemas import MaskTextRequest

    req = MaskTextRequest(text="SSN: 123-45-6789", strategy="partial")
    assert req.strategy == "partial"


def test_scan_response_schema():
    from src.api.schemas import ScanResponse, PIIFinding

    finding = PIIFinding(
        entity_type="email",
        confidence=0.95,
        value_masked="u***@test.com",
        context_snippet="contact at u***@test.com",
        detection_method="regex",
        risk_score=0.42,
        risk_tier="medium",
        sensitivity="medium",
        compliance_violations=[],
        explanation={"summary": "An email was found"},
    )
    response = ScanResponse(
        scan_id="abc-123",
        findings=[finding],
        compliance_summary={},
        detection_time_ms=50.0,
    )
    assert len(response.findings) == 1
    assert response.findings[0].entity_type == "email"


def test_generate_report_request_schema():
    from src.api.schemas import GenerateReportRequest

    req = GenerateReportRequest(scan_id="abc-123", format="pdf")
    assert req.format == "pdf"


def test_mask_response_schema():
    from src.api.schemas import MaskResponse

    resp = MaskResponse(
        masked_text="SSN: ***-**-6789",
        total_masks=1,
    )
    assert resp.total_masks == 1
