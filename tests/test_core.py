"""Tests for classification, compliance, explainability, masking, and pipeline."""

import pytest
from src.classification.risk_scorer import RiskScorer, RiskContext, Sensitivity, SENSITIVITY_MAP
from src.compliance.policy_engine import CompliancePolicyEngine
from src.explainability.explainer import ExplainabilityEngine
from src.masking.masker import mask_text, generate_redaction_preview
from src.pipeline import ScanPipeline


# ─── Risk Scoring Tests ──────────────────────────────────────────────────────

class TestRiskScorer:

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_critical_pii_scores_high(self):
        result = self.scorer.score("credit_card", 0.95)
        assert result["risk_score"] > 0.5
        assert result["sensitivity"] == "critical"

    def test_low_sensitivity_scores_low(self):
        result = self.scorer.score("zip_code", 0.8)
        assert result["risk_score"] < 0.5

    def test_public_exposure_increases_risk(self):
        ctx = RiskContext(exposure_context="public", encryption_status="unencrypted")
        result = self.scorer.score("email", 0.9, ctx)
        assert result["risk_score"] > 0.5

    def test_encrypted_reduces_risk(self):
        ctx_encrypted = RiskContext(encryption_status="encrypted")
        ctx_unencrypted = RiskContext(encryption_status="unencrypted")
        score_enc = self.scorer.score("ssn", 0.9, ctx_encrypted)
        score_unenc = self.scorer.score("ssn", 0.9, ctx_unencrypted)
        assert score_enc["risk_score"] < score_unenc["risk_score"]

    def test_production_penalty(self):
        ctx_dev = RiskContext(is_in_production=False)
        ctx_prod = RiskContext(is_in_production=True)
        score_dev = self.scorer.score("email", 0.9, ctx_dev)
        score_prod = self.scorer.score("email", 0.9, ctx_prod)
        assert score_prod["risk_score"] >= score_dev["risk_score"]

    def test_risk_tier_mapping(self):
        result = self.scorer.score("private_key", 0.99, RiskContext(
            exposure_context="public",
            encryption_status="unencrypted",
            access_level="public",
        ))
        assert result["risk_tier"] in ("critical", "high")

    def test_classify_finding(self):
        finding = {"entity_type": "ssn", "confidence": 0.95}
        enriched = self.scorer.classify_finding(finding)
        assert "risk_score" in enriched
        assert "risk_tier" in enriched
        assert "sensitivity" in enriched

    def test_classify_findings_batch(self):
        findings = [
            {"entity_type": "email", "confidence": 0.9},
            {"entity_type": "credit_card", "confidence": 0.95},
        ]
        enriched = self.scorer.classify_findings(findings)
        assert len(enriched) == 2
        assert all("risk_score" in f for f in enriched)

    def test_sensitivity_map_completeness(self):
        expected_types = ["credit_card", "ssn", "email", "phone", "name", "api_key"]
        for t in expected_types:
            assert t in SENSITIVITY_MAP


# ─── Compliance Tests ─────────────────────────────────────────────────────────

class TestComplianceEngine:

    def setup_method(self):
        self.engine = CompliancePolicyEngine()

    def test_policies_loaded(self):
        assert len(self.engine.frameworks) > 0
        assert len(self.engine.rules) > 0

    def test_gdpr_loaded(self):
        assert "GDPR" in self.engine.frameworks

    def test_hipaa_loaded(self):
        assert "HIPAA" in self.engine.frameworks

    def test_pci_loaded(self):
        assert "PCI-DSS" in self.engine.frameworks

    def test_evaluate_credit_card_finding(self):
        finding = {
            "entity_type": "credit_card",
            "sensitivity": "critical",
            "source_type": "log",
            "confidence": 0.95,
        }
        violations = self.engine.evaluate(finding)
        assert len(violations) > 0
        frameworks = set(v.framework for v in violations)
        assert "PCI-DSS" in frameworks

    def test_evaluate_health_record(self):
        finding = {
            "entity_type": "health_record",
            "sensitivity": "critical",
            "source_type": "text",
            "confidence": 0.9,
        }
        violations = self.engine.evaluate(finding)
        frameworks = set(v.framework for v in violations)
        assert "HIPAA" in frameworks

    def test_evaluate_ssn_finding(self):
        finding = {
            "entity_type": "ssn",
            "sensitivity": "critical",
            "source_type": "api",
            "confidence": 0.92,
        }
        violations = self.engine.evaluate(finding)
        assert len(violations) > 0

    def test_evaluate_findings_batch(self):
        findings = [
            {"entity_type": "email", "sensitivity": "medium", "source_type": "text", "confidence": 0.9},
            {"entity_type": "credit_card", "sensitivity": "critical", "source_type": "log", "confidence": 0.95},
        ]
        enriched = self.engine.evaluate_findings(findings)
        assert all("compliance_violations" in f for f in enriched)
        assert all("regulations_impacted" in f for f in enriched)

    def test_framework_summary(self):
        summary = self.engine.get_framework_summary()
        assert len(summary) > 0
        for fw_name, fw_info in summary.items():
            assert "total_rules" in fw_info
            assert "severity_distribution" in fw_info


# ─── Explainability Tests ────────────────────────────────────────────────────

class TestExplainabilityEngine:

    def setup_method(self):
        self.engine = ExplainabilityEngine()

    def test_explain_basic_finding(self):
        finding = {
            "entity_type": "email",
            "detection_method": "regex",
            "confidence": 0.85,
            "sensitivity": "medium",
            "context_snippet": "Contact us at user@test.com",
            "context_keywords_found": ["email", "contact"],
            "risk_score": 0.45,
            "risk_tier": "medium",
            "compliance_violations": [],
        }
        result = self.engine.explain(finding)
        assert "explanation" in result
        exp = result["explanation"]
        assert "summary" in exp
        assert "detection" in exp
        assert "classification" in exp
        assert "remediation" in exp
        assert len(exp["summary"]) > 0

    def test_explain_with_violations(self):
        finding = {
            "entity_type": "credit_card",
            "detection_method": "hybrid",
            "confidence": 0.96,
            "sensitivity": "critical",
            "context_snippet": "Card: 4532-xxxx-xxxx-0366",
            "context_keywords_found": ["card", "payment"],
            "risk_score": 0.92,
            "risk_tier": "critical",
            "compliance_violations": [
                {"framework": "PCI-DSS", "rule_id": "PCI-3.4", "description": "Render PAN unreadable", "rule_text": "PAN must be encrypted"},
                {"framework": "GDPR", "rule_id": "GDPR-32.1.a", "description": "Encryption", "rule_text": "Encrypt personal data"},
            ],
        }
        result = self.engine.explain(finding)
        exp = result["explanation"]
        assert "PCI-DSS" in exp["compliance"]
        assert "GDPR" in exp["compliance"]

    def test_explain_findings_batch(self):
        findings = [
            {"entity_type": "ssn", "detection_method": "regex", "confidence": 0.92,
             "sensitivity": "critical", "risk_score": 0.85, "risk_tier": "critical",
             "compliance_violations": [], "context_snippet": "", "context_keywords_found": []},
        ]
        results = self.engine.explain_findings(findings)
        assert len(results) == 1
        assert "explanation" in results[0]


# ─── Masking Tests ────────────────────────────────────────────────────────────

class TestMasking:

    def test_mask_text_partial(self):
        text = "Email: user@example.com, Call: (555) 123-4567"
        findings = [
            {"entity_type": "email", "value": "user@example.com", "char_start": 7, "char_end": 23},
            {"entity_type": "phone", "value": "(555) 123-4567", "char_start": 31, "char_end": 45},
        ]
        result = mask_text(text, findings, strategy="partial")
        assert result["total_masks"] == 2
        assert "user@example.com" not in result["masked_text"]

    def test_mask_text_full(self):
        text = "API key: sk-abcdef1234567890"
        findings = [{"entity_type": "api_key", "value": "sk-abcdef1234567890", "char_start": 9, "char_end": 28}]
        result = mask_text(text, findings, strategy="full")
        assert "sk-abcdef" not in result["masked_text"]

    def test_mask_text_redact(self):
        text = "SSN: 123-45-6789"
        findings = [{"entity_type": "ssn", "value": "123-45-6789", "char_start": 5, "char_end": 16}]
        result = mask_text(text, findings, strategy="redact")
        assert "REDACTED" in result["masked_text"]

    def test_redaction_preview(self):
        text = "Call John at 555-1234"
        findings = [
            {"entity_type": "name", "char_start": 5, "char_end": 9},
            {"entity_type": "phone", "char_start": 13, "char_end": 21},
        ]
        preview = generate_redaction_preview(text, findings)
        assert "«NAME»" in preview
        assert "«PHONE»" in preview

    def test_mask_with_no_findings(self):
        text = "This is clean text."
        result = mask_text(text, [], strategy="partial")
        assert result["masked_text"] == text
        assert result["total_masks"] == 0


# ─── Pipeline Integration Tests ──────────────────────────────────────────────

class TestPipeline:

    def setup_method(self):
        self.pipeline = ScanPipeline(enable_ner=False, enable_regex=True)

    def test_scan_basic_text(self):
        result = self.pipeline.scan("Email: test@example.com")
        assert "findings" in result
        assert "summary" in result
        assert "detection_time_ms" in result

    def test_scan_multiple_pii(self):
        text = """
        Patient: John Smith
        Email: john@hospital.com
        SSN: 123-45-6789
        Card: 4532-0151-1283-0366
        PAN: ABCPD1234E
        """
        result = self.pipeline.scan(text, source_type="file", source_name="patient_record.txt")
        findings = result["findings"]
        assert len(findings) > 0
        
        # Check that findings have all expected fields
        for f in findings:
            assert "entity_type" in f
            assert "confidence" in f
            assert "risk_score" in f
            assert "sensitivity" in f
            assert "value_masked" in f
            assert "explanation" in f

    def test_scan_clean_text(self):
        result = self.pipeline.scan("The weather is nice today.")
        assert result["summary"]["critical_count"] == 0

    def test_scan_compliance_mapping(self):
        result = self.pipeline.scan("SSN: 123-45-6789", source_type="log")
        findings = result["findings"]
        ssn_findings = [f for f in findings if f["entity_type"] == "ssn"]
        if ssn_findings:
            assert len(ssn_findings[0].get("compliance_violations", [])) > 0

    def test_scan_returns_masked_values(self):
        result = self.pipeline.scan("Email: secret@company.com")
        for f in result["findings"]:
            assert "value" not in f  # Raw value should be removed
            if f.get("value_masked"):
                assert "secret@company.com" != f["value_masked"]

    def test_scan_returns_framework_summary(self):
        result = self.pipeline.scan("Test card: 4532-0151-1283-0366")
        assert "compliance_summary" in result
