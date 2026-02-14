"""Hybrid PII Detection Engine — combines regex, NER, and context analysis."""

from __future__ import annotations

import logging
import time
from typing import Any

from ..core import get_app_config
from .ner_detector import NERDetector
from .regex_detector import RegexDetector

logger = logging.getLogger(__name__)


class PIIDetectionEngine:
    """
    Production-grade hybrid PII detection engine.
    
    Combines:
    1. Regex patterns with checksum validation (high precision for structured PII)
    2. Transformer NER models (for unstructured name/address/org detection)
    3. Contextual analysis (keyword proximity, data location awareness)
    
    The engine deduplicates, merges overlapping detections, and produces
    unified results with confidence scores and explanations.
    """

    def __init__(
        self,
        enable_ner: bool = True,
        enable_regex: bool = True,
        ner_model: str = "dslim/bert-base-NER",
        use_gpu: bool = False,
        min_confidence: float = 0.60,
    ) -> None:
        config = get_app_config()

        self.enable_ner = enable_ner and config.get("detection.enable_ner", True)
        self.enable_regex = enable_regex and config.get("detection.enable_regex", True)
        self.min_confidence = min_confidence or config.get("detection.min_confidence", 0.60)

        self.regex_detector = RegexDetector() if self.enable_regex else None
        self.ner_detector = (
            NERDetector(
                model_name=ner_model,
                use_gpu=use_gpu,
                batch_size=config.get("detection.ner_batch_size", 32),
                max_length=config.get("detection.max_chunk_length", 512),
            )
            if self.enable_ner
            else None
        )

    def detect(
        self,
        text: str,
        source_type: str = "text",
        source_name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Run full PII detection pipeline on input text.
        
        Returns:
            {
                "findings": [...],
                "summary": {...},
                "detection_time_ms": float,
                "source": {...}
            }
        """
        start_time = time.perf_counter()
        all_detections: list[dict[str, Any]] = []

        # Phase 1: Regex detection
        if self.regex_detector:
            regex_results = self.regex_detector.detect(text)
            all_detections.extend(regex_results)
            logger.info(f"Regex detector found {len(regex_results)} matches")

        # Phase 2: NER detection
        if self.ner_detector:
            ner_results = self.ner_detector.detect(text)
            all_detections.extend(ner_results)
            logger.info(f"NER detector found {len(ner_results)} matches")

        # Phase 3: Merge & deduplicate
        merged = self._merge_detections(all_detections)

        # Phase 4: Filter by confidence
        filtered = [d for d in merged if d["confidence"] >= self.min_confidence]

        # Phase 5: Enrich with source context
        for detection in filtered:
            detection["source_type"] = source_type
            detection["source_name"] = source_name
            if metadata:
                detection["metadata"] = metadata

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Build summary
        summary = self._build_summary(filtered)

        return {
            "findings": filtered,
            "summary": summary,
            "detection_time_ms": round(elapsed_ms, 2),
            "source": {
                "type": source_type,
                "name": source_name,
                "text_length": len(text),
                "engines_used": self._engines_used(),
            },
        }

    def _merge_detections(self, detections: list[dict]) -> list[dict]:
        """Merge overlapping detections, preferring higher confidence."""
        if not detections:
            return []

        # Sort by start position
        sorted_dets = sorted(detections, key=lambda d: (d.get("char_start", 0), -d.get("confidence", 0)))
        merged: list[dict] = []

        for det in sorted_dets:
            start = det.get("char_start", 0)
            end = det.get("char_end", 0)

            # Check for overlap with existing merged detections
            overlap_found = False
            for existing in merged:
                ex_start = existing.get("char_start", 0)
                ex_end = existing.get("char_end", 0)

                if start < ex_end and end > ex_start:
                    # Overlapping span — keep the one with higher confidence
                    # or merge them if they're complementary
                    if det["confidence"] > existing["confidence"]:
                        # If methods differ, boost confidence via ensemble
                        if det.get("detection_method") != existing.get("detection_method"):
                            det["confidence"] = min(
                                det["confidence"] + 0.05, 0.99
                            )
                            det["detection_method"] = "hybrid"
                            det["ensemble_methods"] = [
                                existing.get("detection_method", "unknown"),
                                det.get("detection_method", "unknown"),
                            ]
                        existing.update(det)
                    elif det.get("detection_method") != existing.get("detection_method"):
                        # Both detectors agree — boost confidence
                        existing["confidence"] = min(
                            existing["confidence"] + 0.05, 0.99
                        )
                        existing["detection_method"] = "hybrid"
                    overlap_found = True
                    break

            if not overlap_found:
                merged.append(det.copy())

        return merged

    def _build_summary(self, findings: list[dict]) -> dict[str, Any]:
        """Build detection summary statistics."""
        entity_counts: dict[str, int] = {}
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        method_counts: dict[str, int] = {}

        for f in findings:
            et = f.get("entity_type", "unknown")
            entity_counts[et] = entity_counts.get(et, 0) + 1

            sev = f.get("sensitivity", "medium")
            if sev in severity_counts:
                severity_counts[sev] += 1

            method = f.get("detection_method", "unknown")
            method_counts[method] = method_counts.get(method, 0) + 1

        return {
            "total_findings": len(findings),
            "entity_counts": entity_counts,
            "severity_distribution": severity_counts,
            "detection_methods": method_counts,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
        }

    def _engines_used(self) -> list[str]:
        engines = []
        if self.enable_regex:
            engines.append("regex")
        if self.enable_ner:
            engines.append("ner")
        return engines
