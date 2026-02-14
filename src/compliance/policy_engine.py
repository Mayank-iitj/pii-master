"""Compliance Policy Engine — maps PII findings to regulatory frameworks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..core import CONFIG_DIR

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """A single compliance rule."""
    rule_id: str
    framework: str
    description: str
    pii_types: list[str]
    rule_text: str
    severity: str
    checks: list[str] = field(default_factory=list)

    def applies_to(self, entity_type: str) -> bool:
        """Check if this rule applies to a given PII type."""
        return "*" in self.pii_types or entity_type in self.pii_types


@dataclass
class ComplianceViolationResult:
    """A detected compliance violation."""
    rule_id: str
    framework: str
    description: str
    severity: str
    entity_type: str
    remediation: str
    rule_text: str


class CompliancePolicyEngine:
    """
    Loads compliance policies from YAML and evaluates PII findings
    against GDPR, HIPAA, PCI-DSS, SOC-2, and ISO-27001 rules.
    """

    def __init__(self, policy_dir: str | Path | None = None) -> None:
        self.policy_dir = Path(policy_dir) if policy_dir else CONFIG_DIR / "policies"
        self.frameworks: dict[str, dict[str, Any]] = {}
        self.rules: list[PolicyRule] = []
        self._load_policies()

    def _load_policies(self) -> None:
        """Load all YAML policy files."""
        if not self.policy_dir.exists():
            logger.warning(f"Policy directory not found: {self.policy_dir}")
            return

        for yaml_file in self.policy_dir.glob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    policy = yaml.safe_load(f)
                if not policy:
                    continue

                framework = policy.get("framework", yaml_file.stem.upper())
                self.frameworks[framework] = policy
                self._extract_rules(framework, policy)
                logger.info(f"Loaded policy: {framework} ({len(self.rules)} total rules)")
            except Exception as e:
                logger.error(f"Failed to load policy {yaml_file}: {e}")

    def _extract_rules(self, framework: str, policy: dict[str, Any]) -> None:
        """Extract individual rules from a policy document."""
        # Handle different policy structures
        sources = []

        # GDPR-style: articles -> requirements
        if "articles" in policy:
            for article_data in policy["articles"].values():
                if isinstance(article_data, dict) and "requirements" in article_data:
                    sources.extend(article_data["requirements"])

        # HIPAA-style: rules -> requirements
        if "rules" in policy:
            for rule_section in policy["rules"].values():
                if isinstance(rule_section, dict) and "requirements" in rule_section:
                    sources.extend(rule_section["requirements"])

        # PCI-DSS-style: requirements -> rules
        if "requirements" in policy and isinstance(policy["requirements"], dict):
            for req_section in policy["requirements"].values():
                if isinstance(req_section, dict) and "rules" in req_section:
                    sources.extend(req_section["rules"])

        # SOC-2-style: trust_service_criteria -> requirements
        if "trust_service_criteria" in policy:
            for criteria in policy["trust_service_criteria"].values():
                if isinstance(criteria, dict) and "requirements" in criteria:
                    sources.extend(criteria["requirements"])

        # ISO-27001-style: controls -> requirements
        if "controls" in policy:
            for control in policy["controls"].values():
                if isinstance(control, dict) and "requirements" in control:
                    sources.extend(control["requirements"])

        for rule_data in sources:
            if not isinstance(rule_data, dict):
                continue
            rule = PolicyRule(
                rule_id=rule_data.get("id", "UNKNOWN"),
                framework=framework,
                description=rule_data.get("description", ""),
                pii_types=rule_data.get("pii_types", ["*"]),
                rule_text=rule_data.get("rule", ""),
                severity=rule_data.get("severity", "medium"),
                checks=rule_data.get("checks", []),
            )
            self.rules.append(rule)

    def evaluate(
        self,
        finding: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[ComplianceViolationResult]:
        """Evaluate a single PII finding against all active compliance rules."""
        entity_type = finding.get("entity_type", "unknown")
        violations: list[ComplianceViolationResult] = []
        ctx = context or {}

        for rule in self.rules:
            if not rule.applies_to(entity_type):
                continue

            # Check if this constitutes a violation based on context
            is_violation = self._check_violation(rule, finding, ctx)
            if is_violation:
                remediation = self._generate_remediation(rule, finding)
                violations.append(
                    ComplianceViolationResult(
                        rule_id=rule.rule_id,
                        framework=rule.framework,
                        description=rule.description,
                        severity=rule.severity,
                        entity_type=entity_type,
                        remediation=remediation,
                        rule_text=rule.rule_text,
                    )
                )

        return violations

    def evaluate_findings(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluate multiple findings and attach compliance violations."""
        for finding in findings:
            violations = self.evaluate(finding, context)
            finding["compliance_violations"] = [
                {
                    "rule_id": v.rule_id,
                    "framework": v.framework,
                    "description": v.description,
                    "severity": v.severity,
                    "remediation": v.remediation,
                    "rule_text": v.rule_text,
                }
                for v in violations
            ]
            finding["regulations_impacted"] = list(
                set(v.framework for v in violations)
            )
        return findings

    def _check_violation(
        self, rule: PolicyRule, finding: dict[str, Any], context: dict[str, Any]
    ) -> bool:
        """Determine if a finding violates a specific rule."""
        # If PII is detected in a location where it shouldn't be, it's a violation
        source_type = finding.get("source_type", "")
        entity_type = finding.get("entity_type", "")

        # Check data location rules
        data_rules = self.frameworks.get(rule.framework, {}).get("data_rules", {})

        # Check logging violations
        logging_rules = data_rules.get("logging", {})
        prohibited_in_logs = logging_rules.get("prohibited_fields", [])
        if source_type in ("log", "logs") and entity_type in prohibited_in_logs:
            return True

        # Check storage violations
        storage_rules = data_rules.get("storage", {})
        prohibited_storage = storage_rules.get("prohibited_fields", [])
        if entity_type in prohibited_storage:
            return True

        # Check encryption requirements
        if rule.checks:
            encryption_status = context.get("encryption_status", "unknown")
            if "encryption_at_rest" in rule.checks and encryption_status != "encrypted":
                return True
            if "encryption_in_transit" in rule.checks and encryption_status != "encrypted":
                return True

        # Check access control
        access_level = context.get("access_level", "unknown")
        if access_level == "public" and finding.get("sensitivity") in ("high", "critical"):
            return True

        # Default: any PII detection in an uncontrolled context is a potential violation
        sensitivity = finding.get("sensitivity", "medium")
        if sensitivity in ("critical", "high"):
            return True

        return False

    def _generate_remediation(
        self, rule: PolicyRule, finding: dict[str, Any]
    ) -> str:
        """Generate remediation suggestion for a violation."""
        entity_type = finding.get("entity_type", "unknown")
        source_type = finding.get("source_type", "text")

        remediations = {
            "credit_card": f"Mask or tokenize credit card data. Ensure PCI-DSS compliance by removing full PAN from {source_type}.",
            "ssn": f"Remove SSN from {source_type}. Apply field-level encryption or tokenization.",
            "aadhaar": f"Mask Aadhaar number in {source_type}. Apply data minimization per regulations.",
            "pan_card": f"Redact PAN card from {source_type}. Ensure proper encryption at rest.",
            "health_record": f"Remove PHI from {source_type}. Ensure HIPAA-compliant storage and access controls.",
            "diagnosis": f"Remove diagnosis codes from {source_type}. Apply HIPAA safeguards.",
            "api_key": f"Rotate exposed API key immediately. Remove from {source_type} and use secret management.",
            "password": f"Rotate compromised password. Remove from {source_type}. Use hashed storage.",
            "email": f"Consider masking email in {source_type} unless business-justified.",
            "phone": f"Consider masking phone number in {source_type}.",
            "name": f"Review necessity of storing name in {source_type}. Apply pseudonymization if possible.",
            "address": f"Evaluate data minimization for address in {source_type}.",
            "passport": f"Remove passport number from {source_type}. Apply encryption and access controls.",
            "bank_account": f"Mask bank account details in {source_type}. Apply encryption.",
            "private_key": f"CRITICAL: Rotate private key immediately. Remove from {source_type}.",
            "token": f"Revoke and rotate exposed token. Remove from {source_type}.",
        }

        base = remediations.get(
            entity_type,
            f"Review and remediate {entity_type} exposure in {source_type}."
        )

        return f"{base} [{rule.framework} {rule.rule_id}: {rule.description}]"

    def get_framework_summary(self) -> dict[str, Any]:
        """Get summary of loaded compliance frameworks."""
        summary = {}
        for fw_name, fw_data in self.frameworks.items():
            rules_for_fw = [r for r in self.rules if r.framework == fw_name]
            summary[fw_name] = {
                "description": fw_data.get("description", ""),
                "version": fw_data.get("version", ""),
                "total_rules": len(rules_for_fw),
                "severity_distribution": {
                    "critical": sum(1 for r in rules_for_fw if r.severity == "critical"),
                    "high": sum(1 for r in rules_for_fw if r.severity == "high"),
                    "medium": sum(1 for r in rules_for_fw if r.severity == "medium"),
                    "low": sum(1 for r in rules_for_fw if r.severity == "low"),
                },
            }
        return summary
