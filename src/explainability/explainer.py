"""Explainability module — generates human-readable explanations for PII detections."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ─── Explanation Templates ────────────────────────────────────────────────────

METHOD_EXPLANATIONS = {
    "regex": "pattern matching",
    "ner": "named entity recognition (NER) model",
    "hybrid": "combined regex pattern matching and NER model agreement",
}

ENTITY_DESCRIPTIONS = {
    "credit_card": "credit/debit card number",
    "ssn": "US Social Security Number",
    "aadhaar": "Indian Aadhaar identification number",
    "pan_card": "Indian PAN (Permanent Account Number) card",
    "passport": "passport number",
    "drivers_license": "driver's license number",
    "email": "email address",
    "phone": "phone number",
    "name": "personal name",
    "address": "physical/mailing address",
    "dob": "date of birth",
    "bank_account": "bank account or routing number",
    "health_record": "protected health information (PHI)",
    "diagnosis": "medical diagnosis code",
    "insurance_id": "health insurance identifier",
    "medication": "medication information",
    "api_key": "API key or access token",
    "password": "password or secret credential",
    "private_key": "cryptographic private key",
    "token": "authentication token (JWT/Bearer)",
    "ip_address": "IP address",
    "zip_code": "postal/ZIP code",
    "organization": "organization name",
}

SENSITIVITY_REASONS = {
    "critical": "This is classified as CRITICAL sensitivity because exposure could lead to identity theft, financial fraud, or severe regulatory penalties.",
    "high": "This is classified as HIGH sensitivity because it contains personally identifiable information that could cause significant harm if exposed.",
    "medium": "This is classified as MEDIUM sensitivity because this data could be used to identify or contact an individual.",
    "low": "This is classified as LOW sensitivity because this data alone poses minimal risk.",
}


class ExplainabilityEngine:
    """
    Generates human-readable, auditable explanations for every PII detection.
    
    Each explanation includes:
    - What was detected and why
    - Detection method and confidence
    - Context analysis
    - Risk justification
    - Compliance clauses violated
    - Recommended remediation
    """

    def explain(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Generate a comprehensive explanation for a single PII finding."""
        entity_type = finding.get("entity_type", "unknown")
        detection_method = finding.get("detection_method", "unknown")
        confidence = finding.get("confidence", 0.0)
        sensitivity = finding.get("sensitivity", "medium")
        context_snippet = finding.get("context_snippet", "")
        context_keywords = finding.get("context_keywords_found", [])
        risk_score = finding.get("risk_score", 0.0)
        violations = finding.get("compliance_violations", [])

        # Build explanation components
        what_detected = self._explain_detection(entity_type, detection_method, confidence)
        why_classified = self._explain_classification(entity_type, sensitivity, context_keywords)
        risk_explanation = self._explain_risk(entity_type, risk_score, finding)
        compliance_explanation = self._explain_compliance(violations)
        remediation = self._explain_remediation(finding)
        context_analysis = self._analyze_context(context_snippet, entity_type)

        # Human-readable summary
        summary = self._build_summary(
            entity_type, detection_method, confidence,
            sensitivity, context_keywords, violations
        )

        explanation = {
            "summary": summary,
            "detection": what_detected,
            "classification": why_classified,
            "risk_analysis": risk_explanation,
            "compliance": compliance_explanation,
            "remediation": remediation,
            "context_analysis": context_analysis,
            "confidence_breakdown": {
                "base_confidence": round(confidence, 4),
                "method": detection_method,
                "context_boost": bool(context_keywords),
                "keywords_found": context_keywords,
            },
            "text_spans": {
                "start": finding.get("char_start"),
                "end": finding.get("char_end"),
                "highlighted_text": finding.get("value", ""),
            },
        }

        # Attach to finding
        finding["explanation"] = explanation
        return finding

    def explain_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generate explanations for a batch of findings."""
        return [self.explain(f) for f in findings]

    def _explain_detection(self, entity_type: str, method: str, confidence: float) -> str:
        entity_desc = ENTITY_DESCRIPTIONS.get(entity_type, entity_type)
        method_desc = METHOD_EXPLANATIONS.get(method, method)

        explanation = f"Detected a {entity_desc} using {method_desc} with {confidence:.1%} confidence."

        if method == "regex" and entity_type in ("credit_card", "ssn", "aadhaar", "pan_card"):
            explanation += f" The detection was validated using checksum verification (e.g., Luhn algorithm for cards, format validation for {entity_type})."
        elif method == "ner":
            explanation += " The NER model identified this entity based on contextual language patterns in the surrounding text."
        elif method == "hybrid":
            explanation += " Both regex pattern matching and NER model independently identified this entity, increasing confidence."

        return explanation

    def _explain_classification(self, entity_type: str, sensitivity: str, keywords: list[str]) -> str:
        entity_desc = ENTITY_DESCRIPTIONS.get(entity_type, entity_type)
        sensitivity_reason = SENSITIVITY_REASONS.get(sensitivity, "")

        explanation = f"This {entity_desc} is classified as '{sensitivity}' sensitivity. {sensitivity_reason}"

        if keywords:
            explanation += f" Contextual keywords [{', '.join(keywords)}] in the surrounding text reinforce this classification."

        return explanation

    def _explain_risk(self, entity_type: str, risk_score: float, finding: dict[str, Any]) -> str:
        risk_tier = finding.get("risk_tier", "medium")
        factors = finding.get("risk_factors", {})

        explanation = f"Risk score: {risk_score:.2f}/1.00 (tier: {risk_tier})."

        if factors:
            top_factor = max(factors.items(), key=lambda x: x[1])
            explanation += f" The primary risk driver is '{top_factor[0]}' (score: {top_factor[1]:.2f})."

        source_type = finding.get("source_type", "")
        if source_type == "log":
            explanation += " PII found in application logs poses elevated risk as logs are often less protected and widely accessible."
        elif source_type == "api":
            explanation += " PII in API payloads risks exposure during network transmission."

        return explanation

    def _explain_compliance(self, violations: list[dict[str, Any]]) -> str:
        if not violations:
            return "No specific compliance violations detected for this finding."

        frameworks = set(v["framework"] for v in violations)
        explanation = f"This finding impacts {len(frameworks)} compliance framework(s): {', '.join(sorted(frameworks))}."

        for v in violations[:5]:  # Limit to top 5 for readability
            explanation += f"\n  - [{v['framework']} {v['rule_id']}] {v['description']}: {v.get('rule_text', '')}"

        return explanation

    def _explain_remediation(self, finding: dict[str, Any]) -> str:
        entity_type = finding.get("entity_type", "unknown")
        source_type = finding.get("source_type", "text")

        remediations = {
            "credit_card": [
                "Immediately mask or tokenize the credit card number",
                "Implement PCI-DSS compliant card data handling",
                "Use payment processor tokenization to avoid storing raw PAN",
            ],
            "ssn": [
                "Remove SSN from this location",
                "Apply irreversible hashing if lookup is needed",
                "Implement field-level encryption for storage",
            ],
            "api_key": [
                "URGENT: Rotate this API key immediately",
                "Remove from source code and use environment variables or secret managers",
                "Implement secret scanning in CI/CD pipeline",
            ],
            "password": [
                "URGENT: Change this password immediately",
                "Never store passwords in plaintext — use bcrypt/argon2 hashing",
                f"Remove password from {source_type}",
            ],
            "private_key": [
                "CRITICAL: Assume this key is compromised — rotate immediately",
                "Use hardware security modules (HSM) or vault services",
                "Never store private keys in application code or logs",
            ],
            "health_record": [
                "Ensure PHI is stored in HIPAA-compliant systems only",
                "Apply minimum necessary standard",
                "Implement audit logging for all PHI access",
            ],
        }

        steps = remediations.get(entity_type, [
            f"Review and remediate {entity_type} exposure",
            "Apply data minimization principles",
            "Consider masking or pseudonymization",
        ])

        return "Recommended actions:\n" + "\n".join(f"  {i+1}. {step}" for i, step in enumerate(steps))

    def _analyze_context(self, context: str, entity_type: str) -> str:
        if not context:
            return "No surrounding context available for analysis."

        analysis = "Context analysis: "
        context_lower = context.lower()

        # Detect context indicators
        if any(w in context_lower for w in ["log", "debug", "error", "warn", "info"]):
            analysis += "Found in logging context — sensitive data should not appear in logs. "
        if any(w in context_lower for w in ["response", "payload", "body", "json"]):
            analysis += "Found in API response/payload context — ensure proper data masking. "
        if any(w in context_lower for w in ["config", "env", ".env", "settings"]):
            analysis += "Found in configuration context — use secret management instead. "
        if any(w in context_lower for w in ["test", "mock", "sample", "example", "demo"]):
            analysis += "Appears to be in test/sample data — still flag for security. "
        if any(w in context_lower for w in ["user", "customer", "patient", "member"]):
            analysis += "Associated with user/customer data — subject to privacy regulations. "

        if analysis == "Context analysis: ":
            analysis += "Standard text context detected."

        return analysis

    def _build_summary(
        self,
        entity_type: str,
        method: str,
        confidence: float,
        sensitivity: str,
        keywords: list[str],
        violations: list[dict[str, Any]],
    ) -> str:
        """Build a one-line human-readable summary."""
        entity_desc = ENTITY_DESCRIPTIONS.get(entity_type, entity_type)
        method_desc = METHOD_EXPLANATIONS.get(method, method)
        fw_list = sorted(set(v["framework"] for v in violations)) if violations else []

        parts = [f"Detected {entity_desc} using {method_desc}"]

        if keywords:
            parts.append(f"with contextual tokens like '{keywords[0]}'")

        if entity_type in ("credit_card", "pan_card", "aadhaar", "ssn"):
            parts.append("and checksum validation")

        parts.append(f"({confidence:.0%} confidence, {sensitivity} sensitivity)")

        if fw_list:
            parts.append(f"— impacting {', '.join(fw_list)}")

        return " ".join(parts) + "."
