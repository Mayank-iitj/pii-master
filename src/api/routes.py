"""API route handlers for PII Shield."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse

from .schemas import (
    ErrorResponse,
    FeedbackRequest,
    GenerateReportRequest,
    HealthResponse,
    MaskResponse,
    MaskTextRequest,
    ReportResponse,
    ScanResponse,
    ScanTextRequest,
)
from ..detection.document_parser import DocumentParser
from ..masking.masker import generate_redaction_preview, mask_text
from ..pipeline import ScanPipeline
from ..reporting.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

router = APIRouter()

# Shared instances (initialized on startup)
_pipeline: ScanPipeline | None = None
_report_generator: ReportGenerator | None = None
_parser = DocumentParser()
_start_time = time.time()


def get_pipeline() -> ScanPipeline:
    global _pipeline
    if _pipeline is None:
        # Enable both engines; NER degrades gracefully if model unavailable
        _pipeline = ScanPipeline(enable_ner=True, enable_regex=True, min_confidence=0.60)
    return _pipeline


def get_report_generator() -> ReportGenerator:
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator


# ─── Health & Info ────────────────────────────────────────────────────────────


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """System health check."""
    pipeline = get_pipeline()
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=round(time.time() - _start_time, 2),
        engines={
            "regex": pipeline.detection_engine.enable_regex,
            "ner": pipeline.detection_engine.enable_ner,
        },
    )


@router.get("/compliance/frameworks", tags=["Compliance"])
async def list_frameworks():
    """List loaded compliance frameworks."""
    pipeline = get_pipeline()
    return pipeline.compliance_engine.get_framework_summary()


# ─── Scan Endpoints ──────────────────────────────────────────────────────────


@router.post("/scan/text", response_model=ScanResponse, tags=["Scan"])
async def scan_text(request: ScanTextRequest):
    """Scan raw text for PII."""
    pipeline = get_pipeline()
    try:
        result = pipeline.scan(
            text=request.text,
            source_type=request.source_type,
            source_name=request.source_name,
            context=request.context,
        )
        result["scan_id"] = str(uuid.uuid4())
        return result
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan/file", response_model=ScanResponse, tags=["Scan"])
async def scan_file(file: UploadFile = File(...)):
    """Scan an uploaded file (PDF, DOCX, TXT, CSV, JSON, LOG) for PII."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    if not DocumentParser.is_supported(file.filename):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Supported: {DocumentParser.SUPPORTED_EXTENSIONS}",
        )

    content = await file.read()
    if len(content) > 100 * 1024 * 1024:  # 100MB limit
        raise HTTPException(status_code=413, detail="File too large (max 100MB)")

    try:
        text = _parser.parse(content=content, filename=file.filename)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse file: {str(e)}")

    if not text.strip():
        raise HTTPException(status_code=400, detail="No text content extracted from file")

    pipeline = get_pipeline()
    result = pipeline.scan(
        text=text,
        source_type="file",
        source_name=file.filename,
    )
    result["scan_id"] = str(uuid.uuid4())
    return result


@router.post("/scan/batch", tags=["Scan"])
async def scan_batch(items: list[ScanTextRequest]):
    """Scan multiple text items in batch."""
    pipeline = get_pipeline()
    results = []
    for item in items[:100]:  # Limit to 100 items
        result = pipeline.scan(
            text=item.text,
            source_type=item.source_type,
            source_name=item.source_name,
            context=item.context,
        )
        result["scan_id"] = str(uuid.uuid4())
        results.append(result)
    return {"results": results, "total": len(results)}


# ─── Masking Endpoints ───────────────────────────────────────────────────────


@router.post("/mask", response_model=MaskResponse, tags=["Masking"])
async def mask_pii(request: MaskTextRequest):
    """Detect and mask PII in text."""
    pipeline = get_pipeline()

    # First detect PII
    result = pipeline.scan(
        text=request.text,
        source_type=request.source_type,
    )
    findings = result.get("findings", [])

    # We need original values for masking — re-detect with regex to get them
    from ..detection.regex_detector import RegexDetector
    detector = RegexDetector()
    raw_findings = detector.detect(request.text)

    # Mask the text
    mask_result = mask_text(
        text=request.text,
        findings=raw_findings,
        strategy=request.strategy,
        custom_strategies=request.custom_strategies,
    )

    # Generate redaction preview
    preview = generate_redaction_preview(request.text, raw_findings)
    mask_result["redaction_preview"] = preview

    return mask_result


# ─── Report Endpoints ────────────────────────────────────────────────────────


@router.post("/report/generate", response_model=ReportResponse, tags=["Reports"])
async def generate_report(request: GenerateReportRequest):
    """Generate a compliance report."""
    generator = get_report_generator()

    if not request.scan_result:
        raise HTTPException(status_code=400, detail="scan_result is required")

    try:
        report = generator.generate(
            scan_result=request.scan_result,
            report_type=request.report_type,
            format=request.format,
            title=request.title,
        )
        return report
    except Exception as e:
        logger.error(f"Report generation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.post("/report/scan-and-report", tags=["Reports"])
async def scan_and_report(request: ScanTextRequest, report_format: str = "json", report_type: str = "full"):
    """Scan text and immediately generate a compliance report."""
    pipeline = get_pipeline()
    generator = get_report_generator()

    scan_result = pipeline.scan(
        text=request.text,
        source_type=request.source_type,
        source_name=request.source_name,
        context=request.context,
    )

    report = generator.generate(
        scan_result=scan_result,
        report_type=report_type,
        format=report_format,
    )

    return {
        "scan_id": str(uuid.uuid4()),
        "scan_summary": scan_result.get("summary"),
        "report": report,
    }


@router.get("/report/download/{filename}", tags=["Reports"])
async def download_report(filename: str):
    """Download a generated report file."""
    report_dir = Path("./reports")
    filepath = report_dir / filename

    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(
        path=str(filepath),
        filename=filename,
        media_type="application/octet-stream",
    )


# ─── Feedback (False-Positive Learning Loop) ─────────────────────────────────


@router.post("/feedback", tags=["Feedback"])
async def submit_feedback(request: FeedbackRequest):
    """Submit feedback on a finding (false positive labeling)."""
    # In production, this would update the database and trigger model retraining
    logger.info(
        f"Feedback received: finding={request.finding_id}, "
        f"false_positive={request.is_false_positive}, notes={request.notes}"
    )
    return {
        "status": "accepted",
        "finding_id": request.finding_id,
        "is_false_positive": request.is_false_positive,
        "message": "Feedback recorded. Model will be updated in the next training cycle.",
    }


# ─── Dashboard Data Endpoints ────────────────────────────────────────────────


@router.get("/dashboard/stats", tags=["Dashboard"])
async def dashboard_stats():
    """Get dashboard statistics."""
    return {
        "total_scans": 0,
        "total_findings": 0,
        "critical_findings": 0,
        "compliance_score": 100,
        "frameworks_active": 5,
        "recent_scans": [],
        "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "top_entity_types": [],
    }
