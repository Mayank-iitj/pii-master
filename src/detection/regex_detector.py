"""Regex-based PII detection patterns with checksum validation and contextual filtering.

This module provides high-precision regex patterns for structured PII detection.
Each pattern can optionally require nearby context keywords to fire, dramatically
reducing false positives on ambiguous patterns (ZIP codes, ICD-10 codes, etc.).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class PIIPattern:
    """A compiled PII detection pattern."""
    name: str
    entity_type: str
    pattern: re.Pattern
    sensitivity: str  # low, medium, high, critical
    validator: Callable[[str], bool] | None = None
    description: str = ""
    context_keywords: list[str] = field(default_factory=list)
    requires_context: bool = False          # Must match >=1 context keyword to fire
    context_window: int = 120               # Char window to search for keywords
    base_confidence: float = 0.75           # Default confidence when no validator
    validated_confidence: float = 0.95      # Confidence when validator passes
    group_index: int = 0                    # Which capture group holds the match (0 = full)
    soft_validator: bool = False            # When True, failed validation lowers confidence instead of skipping


# ─── Checksum Validators ──────────────────────────────────────────────────────


def luhn_check(number: str) -> bool:
    """Luhn algorithm for credit card validation."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def aadhaar_check(number: str) -> bool:
    """Validate Aadhaar number (12 digits, not starting with 0 or 1)."""
    clean = re.sub(r"\D", "", number)
    if len(clean) != 12:
        return False
    if clean[0] in ("0", "1"):
        return False
    return True


def pan_check(pan: str) -> bool:
    """Validate Indian PAN card format: AAAAA9999A."""
    clean = pan.strip().upper()
    if len(clean) != 10:
        return False
    return bool(re.match(r'^[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]$', clean))


def ssn_check(ssn: str) -> bool:
    """Validate US SSN format."""
    clean = re.sub(r"\D", "", ssn)
    if len(clean) != 9:
        return False
    area = int(clean[:3])
    if area == 0 or area == 666 or area >= 900:
        return False
    if clean[3:5] == "00" or clean[5:] == "0000":
        return False
    return True


def validate_email(email: str) -> bool:
    """Basic email validation."""
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


def _is_valid_name(name: str) -> bool:
    """Validate that a regex-captured name looks like a real person name."""
    parts = name.strip().split()
    if len(parts) < 2:
        return False
    for p in parts:
        cleaned = p.rstrip(".,;:")
        if len(cleaned) < 2:
            return False
        if not cleaned[0].isupper():
            return False
    reject = {
        "main street", "medical center", "best regards", "patient details",
        "payment information", "api configuration", "credit card", "pan card",
    }
    if name.strip().lower() in reject:
        return False
    return True


# ─── Pattern Registry ─────────────────────────────────────────────────────────


def build_patterns() -> list[PIIPattern]:
    """Build all PII detection patterns."""
    return [
        # ════════════════════════════════════════════════════════════════════
        # PERSONAL IDENTIFIERS
        # ════════════════════════════════════════════════════════════════════

        # ── Names ──
        PIIPattern(
            name="Person Name (labeled)",
            entity_type="name",
            pattern=re.compile(
                r'(?:(?:Name|Patient|Customer|Client|User|Applicant|Employee|Dear|Attn)\s*:?\s*)'
                r'(?:(?:Dr|Mr|Mrs|Ms|Miss|Prof|Rev)\.?\s+)?'
                r'([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,3})',
            ),
            sensitivity="medium",
            validator=_is_valid_name,
            description="Person name preceded by a label",
            context_keywords=["name", "patient", "customer", "client", "user", "dear",
                              "applicant", "employee", "contact", "person", "attn"],
            base_confidence=0.88,
            validated_confidence=0.95,
            group_index=1,
        ),
        PIIPattern(
            name="Person Name (titled)",
            entity_type="name",
            pattern=re.compile(
                r'\b(?:Dr|Mr|Mrs|Ms|Miss|Prof|Rev)\.?\s+'
                r'([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,3})\b',
            ),
            sensitivity="medium",
            validator=_is_valid_name,
            description="Person name with title prefix",
            context_keywords=["doctor", "appointment", "patient", "contact", "staff",
                              "physician", "name"],
            base_confidence=0.90,
            validated_confidence=0.96,
            group_index=1,
        ),

        # ── Email ──
        PIIPattern(
            name="Email Address",
            entity_type="email",
            pattern=re.compile(
                r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            ),
            sensitivity="medium",
            validator=validate_email,
            description="Email address pattern",
            context_keywords=["email", "e-mail", "mail", "contact", "address", "send"],
            base_confidence=0.90,
            validated_confidence=0.97,
        ),

        # ── Phone Numbers ──
        PIIPattern(
            name="Phone Number (US)",
            entity_type="phone",
            pattern=re.compile(
                r'(?<!\d)(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)'
            ),
            sensitivity="medium",
            description="US phone number",
            context_keywords=["phone", "tel", "call", "mobile", "cell", "contact",
                              "fax", "number", "dial"],
            base_confidence=0.82,
        ),
        PIIPattern(
            name="Phone Number (International)",
            entity_type="phone",
            pattern=re.compile(
                r'(?<!\d)\+[1-9]\d{1,2}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}(?!\d)'
            ),
            sensitivity="medium",
            description="International phone number with country code",
            context_keywords=["phone", "tel", "mobile", "contact", "number"],
            base_confidence=0.85,
        ),

        # ── Dates ──
        PIIPattern(
            name="Date of Birth (numeric)",
            entity_type="dob",
            pattern=re.compile(
                r'\b(?:(?:0[1-9]|1[0-2])[/\-.](?:0[1-9]|[12]\d|3[01])[/\-.](?:19|20)\d{2}|'
                r'(?:19|20)\d{2}[/\-.](?:0[1-9]|1[0-2])[/\-.](?:0[1-9]|[12]\d|3[01]))\b'
            ),
            sensitivity="high",
            description="Date in common numeric formats (MM/DD/YYYY or YYYY-MM-DD)",
            context_keywords=["dob", "birth", "born", "birthday", "date of birth",
                              "date", "issued", "expires", "expiry"],
            base_confidence=0.80,
        ),
        PIIPattern(
            name="Date (written)",
            entity_type="dob",
            pattern=re.compile(
                r'\b(?:January|February|March|April|May|June|July|August|September|'
                r'October|November|December)\s+\d{1,2},?\s+\d{4}\b',
                re.IGNORECASE,
            ),
            sensitivity="high",
            description="Date in written format (Month DD, YYYY)",
            context_keywords=["dob", "birth", "born", "birthday", "appointment",
                              "date", "confirmed", "scheduled", "expires"],
            requires_context=True,
            base_confidence=0.78,
        ),

        # ── Addresses ──
        PIIPattern(
            name="US Street Address",
            entity_type="address",
            pattern=re.compile(
                r'\b\d{1,5}\s+(?:[A-Z][a-zA-Z]*\s*){1,4}'
                r'(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Road|Rd|'
                r'Way|Court|Ct|Place|Pl|Circle|Cir|Terrace|Ter)\b\.?',
                re.IGNORECASE,
            ),
            sensitivity="high",
            description="US street address",
            context_keywords=["address", "street", "residence", "home", "location",
                              "mailing", "shipping", "billing", "lives"],
            base_confidence=0.85,
        ),
        PIIPattern(
            name="ZIP Code (US)",
            entity_type="zip_code",
            pattern=re.compile(r'\b\d{5}(?:-\d{4})?\b'),
            sensitivity="low",
            description="US ZIP code",
            context_keywords=[
                "zip", "postal", "code", "address", "city", "state",
                "mailing", "shipping", "billing",
                "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL",
                "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA",
                "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE",
                "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK",
                "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT",
                "VA", "WA", "WV", "WI", "WY", "DC",
            ],
            requires_context=True,
            context_window=150,
            base_confidence=0.72,
        ),

        # ════════════════════════════════════════════════════════════════════
        # GOVERNMENT IDs
        # ════════════════════════════════════════════════════════════════════

        PIIPattern(
            name="SSN (US)",
            entity_type="ssn",
            pattern=re.compile(
                r'(?<!\d)(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}(?!\d)'
            ),
            sensitivity="critical",
            validator=ssn_check,
            description="US Social Security Number",
            context_keywords=["ssn", "social security", "social sec", "tax id",
                              "taxpayer", "social"],
            requires_context=True,
            base_confidence=0.78,
            validated_confidence=0.97,
        ),
        PIIPattern(
            name="Passport Number",
            entity_type="passport",
            pattern=re.compile(
                r'\b[A-Z][0-9]{7,8}\b'
            ),
            sensitivity="critical",
            description="Passport number (letter followed by 7-8 digits)",
            context_keywords=["passport", "travel document", "immigration",
                              "travel", "visa", "consulate", "embassy"],
            requires_context=True,
            base_confidence=0.80,
            validated_confidence=0.93,
        ),
        PIIPattern(
            name="US Driver License",
            entity_type="drivers_license",
            pattern=re.compile(
                r'\b[A-Z]\d{7,14}\b'
            ),
            sensitivity="high",
            description="US driver's license number",
            context_keywords=["driver", "license", "licence", "dl", "driving",
                              "motor vehicle", "dmv"],
            requires_context=True,
            base_confidence=0.75,
        ),

        # ════════════════════════════════════════════════════════════════════
        # FINANCIAL
        # ════════════════════════════════════════════════════════════════════

        PIIPattern(
            name="Credit Card (Visa)",
            entity_type="credit_card",
            pattern=re.compile(
                r'(?<!\d)4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)'
            ),
            sensitivity="critical",
            validator=luhn_check,
            soft_validator=True,
            description="Visa credit card number",
            context_keywords=["visa", "card", "credit", "payment", "cc", "debit"],
            base_confidence=0.82,
            validated_confidence=0.98,
        ),
        PIIPattern(
            name="Credit Card (Mastercard)",
            entity_type="credit_card",
            pattern=re.compile(
                r'(?<!\d)5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)'
            ),
            sensitivity="critical",
            validator=luhn_check,
            soft_validator=True,
            description="Mastercard credit card number",
            context_keywords=["mastercard", "card", "credit", "payment", "cc", "debit"],
            base_confidence=0.82,
            validated_confidence=0.98,
        ),
        PIIPattern(
            name="Credit Card (Amex)",
            entity_type="credit_card",
            pattern=re.compile(
                r'(?<!\d)3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}(?!\d)'
            ),
            sensitivity="critical",
            validator=luhn_check,
            soft_validator=True,
            description="American Express credit card number",
            context_keywords=["amex", "american express", "card", "credit", "payment"],
            base_confidence=0.82,
            validated_confidence=0.98,
        ),
        PIIPattern(
            name="Credit Card (Discover)",
            entity_type="credit_card",
            pattern=re.compile(
                r'(?<!\d)6(?:011|5\d{2})\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)'
            ),
            sensitivity="critical",
            validator=luhn_check,
            soft_validator=True,
            description="Discover credit card number",
            context_keywords=["discover", "card", "credit", "payment"],
            base_confidence=0.82,
            validated_confidence=0.98,
        ),

        # ── Indian IDs ──
        PIIPattern(
            name="Aadhaar Number",
            entity_type="aadhaar",
            pattern=re.compile(
                r'(?<!\d)[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}(?!\d)'
            ),
            sensitivity="critical",
            validator=aadhaar_check,
            description="Indian Aadhaar number (12 digits)",
            context_keywords=["aadhaar", "aadhar", "uid", "unique id", "identity",
                              "identification", "uidai"],
            requires_context=True,
            base_confidence=0.78,
            validated_confidence=0.96,
        ),
        PIIPattern(
            name="PAN Card",
            entity_type="pan_card",
            pattern=re.compile(
                r'\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b'
            ),
            sensitivity="critical",
            validator=pan_check,
            description="Indian PAN card number",
            context_keywords=["pan", "permanent account", "tax", "income tax"],
            base_confidence=0.85,
            validated_confidence=0.98,
        ),

        # ── Banking ──
        PIIPattern(
            name="IBAN",
            entity_type="bank_account",
            pattern=re.compile(
                r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})?\b'
            ),
            sensitivity="critical",
            description="International Bank Account Number",
            context_keywords=["iban", "bank", "account", "transfer", "wire", "swift"],
            base_confidence=0.88,
        ),
        PIIPattern(
            name="Bank Account (US Routing)",
            entity_type="bank_account",
            pattern=re.compile(
                r'(?<!\d)\d{9}(?!\d)'
            ),
            sensitivity="high",
            description="US bank routing number",
            context_keywords=["routing", "aba", "bank", "account", "checking",
                              "savings", "wire", "transfer"],
            requires_context=True,
            context_window=100,
            base_confidence=0.70,
        ),

        # ════════════════════════════════════════════════════════════════════
        # HEALTH / MEDICAL
        # ════════════════════════════════════════════════════════════════════

        PIIPattern(
            name="Medical Record Number",
            entity_type="health_record",
            pattern=re.compile(
                r'\b(?:MRN|MR#|Med\.?\s*Rec)\s*:?\s*[A-Z0-9]{6,12}\b',
                re.IGNORECASE,
            ),
            sensitivity="critical",
            description="Medical record number",
            context_keywords=["medical", "record", "mrn", "patient", "health",
                              "hospital", "clinic"],
            base_confidence=0.90,
        ),
        PIIPattern(
            name="ICD-10 Code",
            entity_type="diagnosis",
            pattern=re.compile(
                r'\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b'
            ),
            sensitivity="critical",
            description="ICD-10 diagnosis code",
            context_keywords=["diagnosis", "icd", "condition", "medical", "disease",
                              "disorder", "code", "clinical", "dx", "icd-10",
                              "pneumonia", "diabetes", "hypertension"],
            requires_context=True,
            context_window=150,
            base_confidence=0.82,
        ),
        PIIPattern(
            name="Health Insurance ID",
            entity_type="insurance_id",
            pattern=re.compile(
                r'\b(?:insurance|policy|member|group|subscriber)\s*'
                r'(?:#|no\.?|num\.?|number|id|ID)?\s*:?\s*'
                r'([A-Z0-9]{6,15})\b',
                re.IGNORECASE,
            ),
            sensitivity="high",
            description="Health insurance identifier",
            context_keywords=["insurance", "policy", "member", "group", "coverage",
                              "subscriber", "plan", "benefit"],
            base_confidence=0.85,
            group_index=1,
        ),

        # ════════════════════════════════════════════════════════════════════
        # CREDENTIALS & SECRETS
        # ════════════════════════════════════════════════════════════════════

        PIIPattern(
            name="API Key (assignment)",
            entity_type="api_key",
            pattern=re.compile(
                r'(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|'
                r'secret[_-]?key|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*'
                r'["\']?([a-zA-Z0-9_\-]{20,})["\']?',
                re.IGNORECASE,
            ),
            sensitivity="critical",
            description="API key or token in assignment",
            context_keywords=["api", "key", "token", "secret", "auth", "bearer",
                              "authorization", "credential"],
            base_confidence=0.92,
            validated_confidence=0.98,
            group_index=1,
        ),
        PIIPattern(
            name="API Key (service prefix)",
            entity_type="api_key",
            pattern=re.compile(
                r'\b(?:sk-(?:proj-|live-|test-)?[a-zA-Z0-9_-]{20,}|'
                r'pk_(?:live|test)_[a-zA-Z0-9]{20,}|'
                r'ghp_[a-zA-Z0-9]{36,}|'
                r'gho_[a-zA-Z0-9]{36,}|'
                r'glpat-[a-zA-Z0-9_-]{20,}|'
                r'xox[bpas]-[a-zA-Z0-9-]{10,})\b'
            ),
            sensitivity="critical",
            description="Service-specific API key with known prefix",
            context_keywords=["api", "key", "token", "secret", "openai", "stripe",
                              "github", "slack"],
            base_confidence=0.96,
        ),
        PIIPattern(
            name="AWS Access Key",
            entity_type="api_key",
            pattern=re.compile(
                r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'
            ),
            sensitivity="critical",
            description="AWS access key ID",
            context_keywords=["aws", "access", "key", "iam", "credential", "amazon"],
            base_confidence=0.96,
        ),
        PIIPattern(
            name="Generic Secret/Password",
            entity_type="password",
            pattern=re.compile(
                r'(?:password|passwd|pwd|secret|credential)\s*[:=]\s*'
                r'["\']?([^\s"\']{8,})["\']?',
                re.IGNORECASE,
            ),
            sensitivity="critical",
            description="Password or secret in configuration",
            context_keywords=["password", "secret", "credential", "passwd", "pwd",
                              "login", "auth"],
            base_confidence=0.93,
            group_index=1,
        ),
        PIIPattern(
            name="Private Key Block",
            entity_type="private_key",
            pattern=re.compile(
                r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'
            ),
            sensitivity="critical",
            description="Private key block header",
            context_keywords=["key", "private", "certificate", "ssl", "tls", "pem"],
            base_confidence=0.99,
        ),
        PIIPattern(
            name="JWT Token",
            entity_type="token",
            pattern=re.compile(
                r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b'
            ),
            sensitivity="critical",
            description="JSON Web Token",
            context_keywords=["jwt", "token", "bearer", "authorization", "auth"],
            base_confidence=0.96,
        ),
        PIIPattern(
            name="Connection String",
            entity_type="password",
            pattern=re.compile(
                r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://'
                r'[^\s"\'<>]{10,}',
                re.IGNORECASE,
            ),
            sensitivity="critical",
            description="Database or service connection string with credentials",
            context_keywords=["database", "connection", "db", "dsn", "uri", "url"],
            base_confidence=0.94,
        ),

        # ════════════════════════════════════════════════════════════════════
        # NETWORK
        # ════════════════════════════════════════════════════════════════════

        PIIPattern(
            name="IPv4 Address",
            entity_type="ip_address",
            pattern=re.compile(
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
            ),
            sensitivity="medium",
            description="IPv4 address",
            context_keywords=["ip", "address", "server", "host", "network", "client",
                              "remote", "source"],
            requires_context=True,
            base_confidence=0.78,
        ),
        PIIPattern(
            name="IPv6 Address",
            entity_type="ip_address",
            pattern=re.compile(
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
            ),
            sensitivity="medium",
            description="IPv6 address",
            context_keywords=["ip", "address", "server", "host", "network", "ipv6"],
            requires_context=True,
            base_confidence=0.80,
        ),
    ]


class RegexDetector:
    """PII detector using regex patterns with checksum validation and context filtering."""

    def __init__(self, custom_patterns: list[PIIPattern] | None = None) -> None:
        self.patterns = build_patterns()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def detect(self, text: str) -> list[dict]:
        """Detect PII in text using all registered patterns."""
        results: list[dict] = []
        text_lower = text.lower()
        seen_spans: dict[tuple[int, int], int] = {}  # span -> index in results

        for pii_pattern in self.patterns:
            for match in pii_pattern.pattern.finditer(text):
                # Determine matched text: full match or specific capture group
                if (pii_pattern.group_index > 0
                        and match.lastindex
                        and match.lastindex >= pii_pattern.group_index):
                    matched_text = match.group(pii_pattern.group_index)
                    span_start = match.start(pii_pattern.group_index)
                    span_end = match.end(pii_pattern.group_index)
                else:
                    matched_text = match.group(0)
                    span_start = match.start()
                    span_end = match.end()

                span = (span_start, span_end)

                # ── Context keyword check ──
                ctx_start = max(0, span[0] - pii_pattern.context_window)
                ctx_end = min(len(text), span[1] + pii_pattern.context_window)
                context_window_text = text_lower[ctx_start:ctx_end]

                keywords_found = [
                    kw for kw in pii_pattern.context_keywords
                    if kw.lower() in context_window_text
                ]

                # Skip if context is required but none found
                if pii_pattern.requires_context and not keywords_found:
                    continue

                # ── Overlap check — prefer longer/higher-confidence matches ──
                overlap_idx = None
                skip = False
                for existing_span, idx in list(seen_spans.items()):
                    if (existing_span[0] <= span[0] < existing_span[1]
                            or span[0] <= existing_span[0] < span[1]):
                        existing_len = existing_span[1] - existing_span[0]
                        new_len = span[1] - span[0]
                        if new_len > existing_len:
                            overlap_idx = idx
                            break
                        else:
                            skip = True
                            break
                if skip:
                    continue

                # ── Validation ──
                confidence = pii_pattern.base_confidence
                if pii_pattern.validator:
                    if pii_pattern.validator(matched_text):
                        confidence = pii_pattern.validated_confidence
                    elif pii_pattern.soft_validator:
                        # Validator failed but soft — keep with lower confidence
                        confidence = pii_pattern.base_confidence * 0.90
                    else:
                        continue  # Hard validator: skip

                # ── Context boosting ──
                if keywords_found:
                    boost = min(0.05 * len(keywords_found), 0.12)
                    confidence = min(confidence + boost, 0.99)

                # ── Extract display context snippet ──
                snippet_start = max(0, span[0] - 50)
                snippet_end = min(len(text), span[1] + 50)
                context_snippet = text[snippet_start:snippet_end]

                result = {
                    "entity_type": pii_pattern.entity_type,
                    "entity_name": pii_pattern.name,
                    "value": matched_text,
                    "char_start": span[0],
                    "char_end": span[1],
                    "confidence": round(confidence, 4),
                    "sensitivity": pii_pattern.sensitivity,
                    "detection_method": "regex",
                    "context_snippet": context_snippet,
                    "context_keywords_found": keywords_found,
                    "pattern_description": pii_pattern.description,
                }

                # Replace overlapping shorter match, or append
                if overlap_idx is not None:
                    old_span = (results[overlap_idx]["char_start"],
                                results[overlap_idx]["char_end"])
                    del seen_spans[old_span]
                    results[overlap_idx] = result
                    seen_spans[span] = overlap_idx
                else:
                    seen_spans[span] = len(results)
                    results.append(result)

        return results
