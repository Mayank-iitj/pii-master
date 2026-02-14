"""Pydantic schemas for API request/response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ─── Request Models ───────────────────────────────────────────────────────────


class ScanTextRequest(BaseModel):
    """Request to scan raw text for PII."""
    text: str = Field(..., min_length=1, max_length=1_000_000, description="Text to scan")
    source_type: str = Field(default="text", description="Source type: text, log, api, email")
    source_name: str = Field(default="direct_input", description="Source identifier")
    context: dict[str, Any] = Field(default_factory=dict, description="Additional context")
    enable_ner: bool = Field(default=True, description="Enable NER model detection")
    enable_regex: bool = Field(default=True, description="Enable regex detection")
    min_confidence: float = Field(default=0.65, ge=0.0, le=1.0)


class ScanBatchRequest(BaseModel):
    """Request to scan multiple text items."""
    items: list[ScanTextRequest] = Field(..., min_length=1, max_length=100)


class MaskTextRequest(BaseModel):
    """Request to mask PII in text."""
    text: str = Field(..., min_length=1)
    strategy: str = Field(default="partial", description="Masking strategy")
    custom_strategies: dict[str, str] = Field(default_factory=dict)
    source_type: str = Field(default="text")


class GenerateReportRequest(BaseModel):
    """Request to generate a compliance report."""
    scan_id: str | None = Field(default=None, description="Scan job ID")
    scan_result: dict[str, Any] | None = Field(default=None, description="Direct scan result")
    report_type: str = Field(default="full", description="Report type: full, gdpr, hipaa")
    format: str = Field(default="json", description="Output format: json, csv, pdf")
    title: str = Field(default="PII Shield Compliance Report")


class FeedbackRequest(BaseModel):
    """Request to submit feedback on a finding (false positive loop)."""
    finding_id: str
    is_false_positive: bool
    notes: str = ""


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: str
    password: str = Field(..., min_length=8)
    role: str = Field(default="analyst")


class LoginRequest(BaseModel):
    username: str
    password: str


# ─── Response Models ──────────────────────────────────────────────────────────


class PIIFinding(BaseModel):
    """A single PII detection finding."""
    entity_type: str
    entity_name: str | None = None
    value_masked: str | None = None
    sensitivity: str
    confidence: float
    risk_score: float = 0.0
    risk_tier: str = "medium"
    detection_method: str
    context_snippet: str | None = None
    char_start: int | None = None
    char_end: int | None = None
    regulations_impacted: list[str] = []
    compliance_violations: list[dict[str, Any]] = []
    explanation: dict[str, Any] | None = None


class ScanSummary(BaseModel):
    """Summary statistics for a scan."""
    total_findings: int = 0
    entity_counts: dict[str, int] = {}
    severity_distribution: dict[str, int] = {}
    detection_methods: dict[str, int] = {}
    critical_count: int = 0
    high_count: int = 0
    frameworks_impacted: list[str] = []


class ScanResponse(BaseModel):
    """Full scan response."""
    scan_id: str | None = None
    findings: list[PIIFinding] = []
    summary: ScanSummary = ScanSummary()
    detection_time_ms: float = 0.0
    source: dict[str, Any] = {}
    compliance_summary: dict[str, Any] = {}


class MaskResponse(BaseModel):
    """Masked text response."""
    masked_text: str
    masks_applied: list[dict[str, Any]] = []
    original_length: int = 0
    masked_length: int = 0
    total_masks: int = 0
    redaction_preview: str = ""


class ReportResponse(BaseModel):
    """Report generation response."""
    format: str
    path: str = ""
    size_bytes: int = 0
    report: dict[str, Any] | None = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "1.0.0"
    uptime_seconds: float = 0.0
    engines: dict[str, bool] = {}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ErrorResponse(BaseModel):
    error: str
    detail: str = ""
    status_code: int = 500
