"""Compliance Report Generator — PDF, JSON, CSV output."""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates compliance reports in PDF, JSON, and CSV formats.
    
    Report types:
    - Full scan report with all findings
    - GDPR compliance report
    - Audit summary
    - Violation timeline
    - Risk heatmap data
    """

    def __init__(self, output_dir: str = "./reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        scan_result: dict[str, Any],
        report_type: str = "full",
        format: str = "json",
        title: str = "PII Shield Compliance Report",
    ) -> dict[str, Any]:
        """Generate a compliance report."""
        report_data = self._build_report_data(scan_result, report_type, title)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"pii_report_{report_type}_{timestamp}"

        if format == "json":
            return self._generate_json(report_data, filename)
        elif format == "csv":
            return self._generate_csv(report_data, filename)
        elif format == "pdf":
            return self._generate_pdf(report_data, filename, title)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _build_report_data(
        self, scan_result: dict[str, Any], report_type: str, title: str
    ) -> dict[str, Any]:
        """Build structured report data."""
        findings = scan_result.get("findings", [])
        summary = scan_result.get("summary", {})
        source = scan_result.get("source", {})

        report = {
            "report_metadata": {
                "title": title,
                "type": report_type,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "PII Shield v1.0.0",
                "source": source,
            },
            "executive_summary": {
                "total_findings": summary.get("total_findings", 0),
                "critical_findings": summary.get("critical_count", 0),
                "high_findings": summary.get("high_count", 0),
                "severity_distribution": summary.get("severity_distribution", {}),
                "entity_types_found": summary.get("entity_counts", {}),
                "detection_methods_used": summary.get("detection_methods", {}),
                "detection_time_ms": scan_result.get("detection_time_ms", 0),
            },
            "risk_assessment": self._build_risk_assessment(findings),
            "compliance_status": self._build_compliance_status(findings),
            "findings_detail": self._build_findings_detail(findings),
            "violation_timeline": self._build_violation_timeline(findings),
            "remediation_plan": self._build_remediation_plan(findings),
        }

        if report_type == "gdpr":
            report["gdpr_specific"] = self._build_gdpr_section(findings)
        elif report_type == "hipaa":
            report["hipaa_specific"] = self._build_hipaa_section(findings)

        return report

    def _build_risk_assessment(self, findings: list[dict]) -> dict[str, Any]:
        """Build risk assessment section."""
        if not findings:
            return {"overall_risk": "low", "risk_score": 0.0, "heatmap": {}}

        scores = [f.get("risk_score", 0) for f in findings]
        avg_risk = sum(scores) / len(scores) if scores else 0

        # Build entity-type risk heatmap
        heatmap: dict[str, dict[str, Any]] = {}
        for f in findings:
            et = f.get("entity_type", "unknown")
            if et not in heatmap:
                heatmap[et] = {"count": 0, "avg_risk": 0, "max_risk": 0, "risks": []}
            heatmap[et]["count"] += 1
            heatmap[et]["risks"].append(f.get("risk_score", 0))

        for et, data in heatmap.items():
            risks = data.pop("risks")
            data["avg_risk"] = round(sum(risks) / len(risks), 4) if risks else 0
            data["max_risk"] = round(max(risks), 4) if risks else 0

        overall_risk = "critical" if avg_risk >= 0.8 else "high" if avg_risk >= 0.6 else "medium" if avg_risk >= 0.35 else "low"

        return {
            "overall_risk": overall_risk,
            "average_risk_score": round(avg_risk, 4),
            "max_risk_score": round(max(scores, default=0), 4),
            "heatmap": heatmap,
        }

    def _build_compliance_status(self, findings: list[dict]) -> dict[str, Any]:
        """Build compliance status by framework."""
        framework_status: dict[str, dict[str, Any]] = {}

        for f in findings:
            violations = f.get("compliance_violations", [])
            for v in violations:
                fw = v.get("framework", "UNKNOWN")
                if fw not in framework_status:
                    framework_status[fw] = {
                        "total_violations": 0,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "rules_violated": set(),
                    }
                framework_status[fw]["total_violations"] += 1
                severity = v.get("severity", "medium")
                if severity in framework_status[fw]:
                    framework_status[fw][severity] += 1
                framework_status[fw]["rules_violated"].add(v.get("rule_id", ""))

        # Convert sets to lists for JSON serialization
        for fw_data in framework_status.values():
            fw_data["rules_violated"] = sorted(fw_data["rules_violated"])
            fw_data["compliance_score"] = max(
                0, 100 - (fw_data["critical"] * 25 + fw_data["high"] * 15 + fw_data["medium"] * 5 + fw_data["low"] * 2)
            )

        return framework_status

    def _build_findings_detail(self, findings: list[dict]) -> list[dict[str, Any]]:
        """Build detailed findings for report."""
        details: list[dict[str, Any]] = []
        for f in findings:
            detail = {
                "entity_type": f.get("entity_type"),
                "entity_name": f.get("entity_name"),
                "sensitivity": f.get("sensitivity"),
                "confidence": f.get("confidence"),
                "risk_score": f.get("risk_score"),
                "risk_tier": f.get("risk_tier"),
                "detection_method": f.get("detection_method"),
                "regulations_impacted": f.get("regulations_impacted", []),
                "location": {
                    "char_start": f.get("char_start"),
                    "char_end": f.get("char_end"),
                    "context": f.get("context_snippet", "")[:200],
                },
            }
            # Add explanation summary if available
            explanation = f.get("explanation", {})
            if isinstance(explanation, dict):
                detail["explanation_summary"] = explanation.get("summary", "")

            details.append(detail)

        return sorted(details, key=lambda d: d.get("risk_score", 0), reverse=True)

    def _build_violation_timeline(self, findings: list[dict]) -> list[dict[str, Any]]:
        """Build violation timeline (ordered by position in source)."""
        timeline: list[dict[str, Any]] = []
        for f in findings:
            for v in f.get("compliance_violations", []):
                timeline.append({
                    "position": f.get("char_start", 0),
                    "entity_type": f.get("entity_type"),
                    "framework": v.get("framework"),
                    "rule_id": v.get("rule_id"),
                    "severity": v.get("severity"),
                    "description": v.get("description"),
                })
        return sorted(timeline, key=lambda t: t.get("position", 0))

    def _build_remediation_plan(self, findings: list[dict]) -> list[dict[str, Any]]:
        """Build prioritized remediation plan."""
        plan: list[dict[str, Any]] = []
        seen: set[str] = set()

        # Sort by risk score descending
        sorted_findings = sorted(findings, key=lambda f: f.get("risk_score", 0), reverse=True)

        for f in sorted_findings:
            et = f.get("entity_type", "unknown")
            if et in seen:
                continue
            seen.add(et)

            explanation = f.get("explanation", {})
            remediation = explanation.get("remediation", "") if isinstance(explanation, dict) else ""

            plan.append({
                "priority": len(plan) + 1,
                "entity_type": et,
                "risk_score": f.get("risk_score", 0),
                "sensitivity": f.get("sensitivity"),
                "remediation": remediation,
                "affected_count": sum(1 for ff in findings if ff.get("entity_type") == et),
            })

        return plan

    def _build_gdpr_section(self, findings: list[dict]) -> dict[str, Any]:
        return {
            "data_processing_assessment": {
                "pii_categories_found": sorted(set(f.get("entity_type", "") for f in findings)),
                "total_pii_instances": len(findings),
                "requires_dpia": any(f.get("sensitivity") == "critical" for f in findings),
                "cross_border_risk": False,
            },
            "article_violations": self._get_framework_violations(findings, "GDPR"),
        }

    def _build_hipaa_section(self, findings: list[dict]) -> dict[str, Any]:
        phi_types = {"health_record", "diagnosis", "medication", "insurance_id"}
        phi_findings = [f for f in findings if f.get("entity_type") in phi_types]
        return {
            "phi_assessment": {
                "phi_instances_found": len(phi_findings),
                "phi_types": sorted(set(f.get("entity_type", "") for f in phi_findings)),
                "breach_notification_required": len(phi_findings) > 0,
            },
            "rule_violations": self._get_framework_violations(findings, "HIPAA"),
        }

    def _get_framework_violations(self, findings: list[dict], framework: str) -> list[dict]:
        violations: list[dict] = []
        for f in findings:
            for v in f.get("compliance_violations", []):
                if v.get("framework") == framework:
                    violations.append(v)
        return violations

    # ─── Output Formatters ────────────────────────────────────────────────────

    def _generate_json(self, report_data: dict, filename: str) -> dict[str, Any]:
        filepath = self.output_dir / f"{filename}.json"
        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        return {
            "format": "json",
            "path": str(filepath),
            "size_bytes": filepath.stat().st_size,
            "report": report_data,
        }

    def _generate_csv(self, report_data: dict, filename: str) -> dict[str, Any]:
        filepath = self.output_dir / f"{filename}.csv"
        findings = report_data.get("findings_detail", [])

        with open(filepath, "w", newline="") as f:
            if findings:
                writer = csv.DictWriter(f, fieldnames=[
                    "entity_type", "entity_name", "sensitivity", "confidence",
                    "risk_score", "risk_tier", "detection_method", "regulations_impacted",
                    "explanation_summary",
                ])
                writer.writeheader()
                for finding in findings:
                    row = {k: finding.get(k, "") for k in writer.fieldnames}
                    if isinstance(row.get("regulations_impacted"), list):
                        row["regulations_impacted"] = "; ".join(row["regulations_impacted"])
                    writer.writerow(row)

        return {
            "format": "csv",
            "path": str(filepath),
            "size_bytes": filepath.stat().st_size,
            "rows": len(findings),
        }

    def _generate_pdf(self, report_data: dict, filename: str, title: str) -> dict[str, Any]:
        filepath = self.output_dir / f"{filename}.pdf"

        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
            )

            doc = SimpleDocTemplate(str(filepath), pagesize=A4)
            styles = getSampleStyleSheet()
            elements = []

            # Title
            title_style = ParagraphStyle("CustomTitle", parent=styles["Title"], fontSize=18, spaceAfter=20)
            elements.append(Paragraph(title, title_style))
            elements.append(Spacer(1, 12))

            # Executive Summary
            exec_summary = report_data.get("executive_summary", {})
            elements.append(Paragraph("Executive Summary", styles["Heading2"]))
            summary_data = [
                ["Metric", "Value"],
                ["Total Findings", str(exec_summary.get("total_findings", 0))],
                ["Critical Findings", str(exec_summary.get("critical_findings", 0))],
                ["High Findings", str(exec_summary.get("high_findings", 0))],
                ["Detection Time", f"{exec_summary.get('detection_time_ms', 0):.0f}ms"],
            ]
            table = Table(summary_data, colWidths=[3 * inch, 3 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a73e8")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 20))

            # Findings Table
            findings = report_data.get("findings_detail", [])
            if findings:
                elements.append(Paragraph("Detailed Findings", styles["Heading2"]))
                finding_data = [["Type", "Sensitivity", "Confidence", "Risk", "Method"]]
                for f in findings[:50]:  # Limit for PDF
                    finding_data.append([
                        str(f.get("entity_type", "")),
                        str(f.get("sensitivity", "")),
                        f"{f.get('confidence', 0):.1%}",
                        f"{f.get('risk_score', 0):.2f}",
                        str(f.get("detection_method", "")),
                    ])

                ftable = Table(finding_data, colWidths=[1.5 * inch, 1.2 * inch, 1 * inch, 0.8 * inch, 1 * inch])
                ftable.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dc3545")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff3f3")]),
                ]))
                elements.append(ftable)
                elements.append(Spacer(1, 20))

            # Compliance Status
            compliance = report_data.get("compliance_status", {})
            if compliance:
                elements.append(Paragraph("Compliance Status", styles["Heading2"]))
                comp_data = [["Framework", "Violations", "Critical", "High", "Score"]]
                for fw, data in compliance.items():
                    comp_data.append([
                        fw,
                        str(data.get("total_violations", 0)),
                        str(data.get("critical", 0)),
                        str(data.get("high", 0)),
                        f"{data.get('compliance_score', 0)}%",
                    ])
                ctable = Table(comp_data, colWidths=[1.5 * inch, 1 * inch, 1 * inch, 1 * inch, 1 * inch])
                ctable.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#28a745")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(ctable)

            # Footer
            elements.append(Spacer(1, 30))
            footer_text = f"Generated by PII Shield v1.0 | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
            elements.append(Paragraph(footer_text, ParagraphStyle("Footer", fontSize=8, textColor=colors.grey)))

            doc.build(elements)

            return {
                "format": "pdf",
                "path": str(filepath),
                "size_bytes": filepath.stat().st_size,
            }

        except ImportError:
            logger.warning("ReportLab not installed. Falling back to JSON format.")
            return self._generate_json(report_data, filename)
