"""Full scan pipeline orchestrator — ties together all engines."""

from __future__ import annotations

import logging
import time
from typing import Any

from .classification.risk_scorer import RiskContext, RiskScorer
from .compliance.policy_engine import CompliancePolicyEngine
from .core.security import mask_value
from .detection.engine import PIIDetectionEngine
from .explainability.explainer import ExplainabilityEngine

logger = logging.getLogger(__name__)


class ScanPipeline:
    """
    Orchestrates the full PII scan pipeline:
    
    1. Detection (regex + NER)
    2. Classification & Risk Scoring
    3. Compliance Evaluation
    4. Explainability Generation
    5. Result Aggregation
    """

    def __init__(
        self,
        enable_ner: bool = True,
        enable_regex: bool = True,
        min_confidence: float = 0.65,
    ) -> None:
        self.detection_engine = PIIDetectionEngine(
            enable_ner=enable_ner,
            enable_regex=enable_regex,
            min_confidence=min_confidence,
        )
        self.risk_scorer = RiskScorer()
        self.compliance_engine = CompliancePolicyEngine()
        self.explainability_engine = ExplainabilityEngine()

    def scan(
        self,
        text: str,
        source_type: str = "text",
        source_name: str = "direct_input",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute the full scan pipeline.
        
        Args:
            text: Input text to scan
            source_type: Type of source (text, file, api, log, database, email)
            source_name: Name/identifier of the source
            context: Additional context (encryption, access_level, etc.)
        
        Returns:
            Complete scan result with findings, compliance, explanations
        """
        start_time = time.perf_counter()
        ctx = context or {}

        # Step 1: Detect PII
        detection_result = self.detection_engine.detect(
            text=text,
            source_type=source_type,
            source_name=source_name,
        )
        findings = detection_result["findings"]
        logger.info(f"Detection complete: {len(findings)} findings")

        # Step 2: Classify & score risks
        risk_context = RiskContext(
            exposure_context=ctx.get("exposure_context", self._infer_exposure(source_type)),
            data_location=ctx.get("data_location", source_type),
            encryption_status=ctx.get("encryption_status", "unknown"),
            access_level=ctx.get("access_level", "internal"),
            is_in_production=ctx.get("is_production", False),
        )
        findings = self.risk_scorer.classify_findings(findings, risk_context)
        logger.info("Risk classification complete")

        # Step 3: Evaluate compliance
        compliance_context = {
            "encryption_status": risk_context.encryption_status,
            "access_level": risk_context.access_level,
        }
        findings = self.compliance_engine.evaluate_findings(findings, compliance_context)
        logger.info("Compliance evaluation complete")

        # Step 4: Generate explanations
        findings = self.explainability_engine.explain_findings(findings)
        logger.info("Explanations generated")

        # Step 5: Mask sensitive values in findings
        for finding in findings:
            entity_type = finding.get("entity_type", "")
            raw_value = finding.get("value", "")
            finding["value_masked"] = mask_value(raw_value, entity_type)
            # Remove raw value from output for security
            finding.pop("value", None)

        # Build final result
        total_time = (time.perf_counter() - start_time) * 1000
        detection_result["findings"] = findings
        detection_result["summary"] = self._rebuild_summary(findings)
        detection_result["detection_time_ms"] = round(total_time, 2)
        detection_result["compliance_summary"] = self.compliance_engine.get_framework_summary()

        return detection_result

    def _infer_exposure(self, source_type: str) -> str:
        """Infer exposure context from source type."""
        mapping = {
            "log": "log",
            "api": "api_response",
            "email": "external",
            "file": "internal",
            "database": "internal",
            "text": "internal",
        }
        return mapping.get(source_type, "internal")

    def _rebuild_summary(self, findings: list[dict]) -> dict[str, Any]:
        """Rebuild summary after full pipeline enrichment."""
        entity_counts: dict[str, int] = {}
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        method_counts: dict[str, int] = {}
        frameworks_impacted: set[str] = set()

        for f in findings:
            et = f.get("entity_type", "unknown")
            entity_counts[et] = entity_counts.get(et, 0) + 1

            sev = f.get("sensitivity", "medium")
            if sev in severity_counts:
                severity_counts[sev] += 1

            method = f.get("detection_method", "unknown")
            method_counts[method] = method_counts.get(method, 0) + 1

            for fw in f.get("regulations_impacted", []):
                frameworks_impacted.add(fw)

        return {
            "total_findings": len(findings),
            "entity_counts": entity_counts,
            "severity_distribution": severity_counts,
            "detection_methods": method_counts,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "frameworks_impacted": sorted(frameworks_impacted),
        }
