"""Data Masking & Auto-Remediation Engine."""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from typing import Any

from ..core.security import mask_value

logger = logging.getLogger(__name__)


class MaskingStrategy:
    """Available masking strategies."""

    FULL = "full"           # Replace entirely with ***
    PARTIAL = "partial"     # Show first/last chars
    HASH = "hash"           # SHA-256 hash
    TOKENIZE = "tokenize"   # Random token
    REDACT = "redact"       # [REDACTED]
    ENCRYPT = "encrypt"     # Fernet encryption (requires key)


# Token vault for reversible tokenization
_token_vault: dict[str, str] = {}


def mask_text(
    text: str,
    findings: list[dict[str, Any]],
    strategy: str = "partial",
    custom_strategies: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Mask PII in text based on detection findings.
    
    Args:
        text: Original text
        findings: List of PII findings from detection engine
        strategy: Default masking strategy
        custom_strategies: Entity-type specific strategies
    
    Returns:
        {
            "masked_text": str,
            "masks_applied": [...],
            "original_length": int,
            "masked_length": int
        }
    """
    strategies = custom_strategies or {}
    masks_applied: list[dict[str, Any]] = []

    # Sort findings by position (reverse order for safe replacement)
    sorted_findings = sorted(
        findings,
        key=lambda f: f.get("char_start", 0),
        reverse=True,
    )

    masked = text
    for finding in sorted_findings:
        start = finding.get("char_start")
        end = finding.get("char_end")
        entity_type = finding.get("entity_type", "unknown")
        original_value = finding.get("value", "")

        if start is None or end is None:
            continue

        # Determine strategy for this entity type
        entity_strategy = strategies.get(entity_type, strategy)

        # Apply masking
        replacement = _apply_mask(original_value, entity_type, entity_strategy)
        masked = masked[:start] + replacement + masked[end:]

        masks_applied.append({
            "entity_type": entity_type,
            "original_start": start,
            "original_end": end,
            "strategy": entity_strategy,
            "replacement_length": len(replacement),
        })

    return {
        "masked_text": masked,
        "masks_applied": list(reversed(masks_applied)),  # Return in original order
        "original_length": len(text),
        "masked_length": len(masked),
        "total_masks": len(masks_applied),
    }


def _apply_mask(value: str, entity_type: str, strategy: str) -> str:
    """Apply a specific masking strategy to a value."""
    if strategy == MaskingStrategy.FULL:
        return "***"

    elif strategy == MaskingStrategy.PARTIAL:
        return mask_value(value, entity_type)

    elif strategy == MaskingStrategy.HASH:
        hashed = hashlib.sha256(value.encode()).hexdigest()[:16]
        return f"[HASH:{hashed}]"

    elif strategy == MaskingStrategy.TOKENIZE:
        token = f"TOK_{secrets.token_hex(8)}"
        _token_vault[token] = value  # Store for potential reversal
        return token

    elif strategy == MaskingStrategy.REDACT:
        return f"[REDACTED-{entity_type.upper()}]"

    elif strategy == MaskingStrategy.ENCRYPT:
        # Simplified — in production use Fernet
        return f"[ENC:{hashlib.sha256(value.encode()).hexdigest()[:20]}]"

    return mask_value(value, entity_type)


def generate_redaction_preview(
    text: str,
    findings: list[dict[str, Any]],
) -> str:
    """Generate a human-readable redaction preview with highlights."""
    sorted_findings = sorted(findings, key=lambda f: f.get("char_start", 0))
    preview_parts: list[str] = []
    last_end = 0

    for finding in sorted_findings:
        start = finding.get("char_start", 0)
        end = finding.get("char_end", 0)
        entity_type = finding.get("entity_type", "unknown")

        if start > last_end:
            preview_parts.append(text[last_end:start])

        preview_parts.append(f"«{entity_type.upper()}»")
        last_end = end

    if last_end < len(text):
        preview_parts.append(text[last_end:])

    return "".join(preview_parts)


def detokenize(token: str) -> str | None:
    """Reverse a tokenization (if token exists in vault)."""
    return _token_vault.get(token)
