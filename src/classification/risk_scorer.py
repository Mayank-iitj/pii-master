"""PII Classification & Risk Scoring Engine.

Each detected PII entity is classified by type, assigned a sensitivity level,
and given a composite risk score based on multiple contextual factors.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class Sensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def numeric(self) -> float:
        return {"low": 0.2, "medium": 0.4, "high": 0.7, "critical": 1.0}[self.value]


# ─── Sensitivity Taxonomy ─────────────────────────────────────────────────────

SENSITIVITY_MAP: dict[str, Sensitivity] = {
    # Critical
    "credit_card": Sensitivity.CRITICAL,
    "ssn": Sensitivity.CRITICAL,
    "aadhaar": Sensitivity.CRITICAL,
    "pan_card": Sensitivity.CRITICAL,
    "passport": Sensitivity.CRITICAL,
    "bank_account": Sensitivity.CRITICAL,
    "health_record": Sensitivity.CRITICAL,
    "diagnosis": Sensitivity.CRITICAL,
    "api_key": Sensitivity.CRITICAL,
    "password": Sensitivity.CRITICAL,
    "private_key": Sensitivity.CRITICAL,
    "token": Sensitivity.CRITICAL,
    "insurance_id": Sensitivity.CRITICAL,
    # High
    "dob": Sensitivity.HIGH,
    "address": Sensitivity.HIGH,
    "phone": Sensitivity.HIGH,
    "drivers_license": Sensitivity.HIGH,
    "medication": Sensitivity.HIGH,
    "biometric": Sensitivity.HIGH,
    # Medium
    "email": Sensitivity.MEDIUM,
    "name": Sensitivity.MEDIUM,
    "ip_address": Sensitivity.MEDIUM,
    "numeric_id": Sensitivity.MEDIUM,
    # Low
    "organization": Sensitivity.LOW,
    "zip_code": Sensitivity.LOW,
    "demographic": Sensitivity.LOW,
    "job_title": Sensitivity.LOW,
    "misc": Sensitivity.LOW,
}


@dataclass
class RiskContext:
    """Contextual factors that influence risk scoring."""
    exposure_context: str = "internal"          # internal, external, public, log, api_response
    data_location: str = "application"          # application, database, log, api, file, email
    encryption_status: str = "unknown"          # encrypted, unencrypted, unknown
    access_level: str = "restricted"            # public, internal, restricted, confidential
    data_subject_count: int = 1                 # Number of affected data subjects
    is_in_production: bool = False
    geographic_region: str = "unknown"           # EU, US, IN, etc.


# ─── Risk Scoring Weights ─────────────────────────────────────────────────────

DEFAULT_WEIGHTS = {
    "sensitivity": 0.35,
    "exposure_context": 0.25,
    "data_location": 0.15,
    "encryption_status": 0.15,
    "access_level": 0.10,
}

EXPOSURE_SCORES: dict[str, float] = {
    "public": 1.0,
    "external": 0.8,
    "api_response": 0.7,
    "log": 0.6,
    "internal": 0.3,
    "encrypted_storage": 0.1,
}

LOCATION_SCORES: dict[str, float] = {
    "api": 0.8,
    "log": 0.7,
    "email": 0.7,
    "file": 0.5,
    "application": 0.4,
    "database": 0.3,
}

ENCRYPTION_SCORES: dict[str, float] = {
    "unencrypted": 1.0,
    "unknown": 0.7,
    "partially_encrypted": 0.4,
    "encrypted": 0.1,
}

ACCESS_SCORES: dict[str, float] = {
    "public": 1.0,
    "internal": 0.6,
    "restricted": 0.3,
    "confidential": 0.1,
}


class RiskScorer:
    """
    Computes composite risk scores for PII findings.
    
    Risk = weighted combination of:
    - Inherent sensitivity of the PII type
    - Exposure context (where it was found)
    - Data location (system layer)
    - Encryption status
    - Access control level
    """

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = weights or DEFAULT_WEIGHTS

    def score(
        self,
        entity_type: str,
        confidence: float,
        context: RiskContext | None = None,
    ) -> dict[str, Any]:
        """Calculate risk score for a single PII finding."""
        ctx = context or RiskContext()

        # Factor 1: Inherent sensitivity
        sensitivity = SENSITIVITY_MAP.get(entity_type, Sensitivity.MEDIUM)
        sensitivity_score = sensitivity.numeric

        # Factor 2: Exposure context
        exposure_score = EXPOSURE_SCORES.get(ctx.exposure_context, 0.5)

        # Factor 3: Data location
        location_score = LOCATION_SCORES.get(ctx.data_location, 0.5)

        # Factor 4: Encryption status
        encryption_score = ENCRYPTION_SCORES.get(ctx.encryption_status, 0.7)

        # Factor 5: Access level
        access_score = ACCESS_SCORES.get(ctx.access_level, 0.5)

        # Weighted composite
        raw_score = (
            self.weights["sensitivity"] * sensitivity_score
            + self.weights["exposure_context"] * exposure_score
            + self.weights["data_location"] * location_score
            + self.weights["encryption_status"] * encryption_score
            + self.weights["access_level"] * access_score
        )

        # Modifiers
        if ctx.is_in_production:
            raw_score *= 1.2  # Production penalty

        if ctx.data_subject_count > 100:
            raw_score *= 1.1  # Scale penalty

        # Normalize to 0-1
        final_score = min(raw_score, 1.0)

        # Determine risk tier
        risk_tier = self._score_to_tier(final_score)

        return {
            "risk_score": round(final_score, 4),
            "risk_tier": risk_tier,
            "sensitivity": sensitivity.value,
            "factors": {
                "sensitivity_score": round(sensitivity_score, 4),
                "exposure_score": round(exposure_score, 4),
                "location_score": round(location_score, 4),
                "encryption_score": round(encryption_score, 4),
                "access_score": round(access_score, 4),
            },
            "confidence": confidence,
            "context": {
                "exposure": ctx.exposure_context,
                "location": ctx.data_location,
                "encryption": ctx.encryption_status,
                "access_level": ctx.access_level,
                "production": ctx.is_in_production,
                "subject_count": ctx.data_subject_count,
            },
        }

    def _score_to_tier(self, score: float) -> str:
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.35:
            return "medium"
        return "low"

    def classify_finding(
        self,
        finding: dict[str, Any],
        context: RiskContext | None = None,
    ) -> dict[str, Any]:
        """Enrich a detection finding with risk classification."""
        entity_type = finding.get("entity_type", "unknown")
        confidence = finding.get("confidence", 0.5)

        risk_info = self.score(entity_type, confidence, context)
        finding["risk_score"] = risk_info["risk_score"]
        finding["risk_tier"] = risk_info["risk_tier"]
        finding["sensitivity"] = risk_info["sensitivity"]
        finding["risk_factors"] = risk_info["factors"]

        return finding

    def classify_findings(
        self,
        findings: list[dict[str, Any]],
        context: RiskContext | None = None,
    ) -> list[dict[str, Any]]:
        """Classify and score a batch of findings."""
        return [self.classify_finding(f, context) for f in findings]
