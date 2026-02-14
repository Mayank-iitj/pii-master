"""NER-based PII detection using transformer models."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# NER entity type mapping to our PII taxonomy
NER_ENTITY_MAP: dict[str, str] = {
    "PERSON": "name",
    "PER": "name",
    "B-PER": "name",
    "I-PER": "name",
    "ORG": "organization",
    "B-ORG": "organization",
    "I-ORG": "organization",
    "LOC": "address",
    "B-LOC": "address",
    "I-LOC": "address",
    "GPE": "address",
    "DATE": "dob",
    "CARDINAL": "numeric_id",
    "FAC": "address",
    "NORP": "demographic",
    "MISC": "misc",
    "B-MISC": "misc",
    "I-MISC": "misc",
}

# Sensitivity mapping for NER-detected entities
NER_SENSITIVITY: dict[str, str] = {
    "name": "medium",
    "organization": "low",
    "address": "high",
    "dob": "high",
    "numeric_id": "medium",
    "demographic": "medium",
    "misc": "low",
}


class NERDetector:
    """NER-based PII detector using transformer models (HuggingFace pipeline)."""

    def __init__(
        self,
        model_name: str = "dslim/bert-base-NER",
        use_gpu: bool = False,
        batch_size: int = 32,
        max_length: int = 512,
    ) -> None:
        self.model_name = model_name
        self.use_gpu = use_gpu
        self.batch_size = batch_size
        self.max_length = max_length
        self._pipeline: Any = None
        self._loaded = False

    def _load_model(self) -> None:
        """Lazy-load the NER pipeline."""
        if self._loaded:
            return

        try:
            from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

            device = 0 if self.use_gpu else -1

            logger.info(f"Loading NER model: {self.model_name}")
            self._pipeline = pipeline(
                "ner",
                model=self.model_name,
                tokenizer=self.model_name,
                aggregation_strategy="simple",
                device=device,
            )
            self._loaded = True
            logger.info("NER model loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load NER model: {e}. NER detection disabled.")
            self._loaded = False

    def _chunk_text(self, text: str) -> list[tuple[str, int]]:
        """Split text into overlapping chunks for processing."""
        chunks: list[tuple[str, int]] = []
        words = text.split()

        if len(words) <= self.max_length:
            return [(text, 0)]

        # Chunk by approximate word boundaries
        chunk_size = self.max_length
        overlap = 50
        start = 0

        while start < len(words):
            end = min(start + chunk_size, len(words))
            chunk_text = " ".join(words[start:end])

            # Calculate character offset
            char_offset = len(" ".join(words[:start])) + (1 if start > 0 else 0)
            chunks.append((chunk_text, char_offset))

            if end >= len(words):
                break
            start = end - overlap

        return chunks

    def detect(self, text: str) -> list[dict]:
        """Detect PII entities using NER model."""
        self._load_model()
        if not self._loaded or self._pipeline is None:
            return []

        results: list[dict] = []
        chunks = self._chunk_text(text)

        for chunk_text, char_offset in chunks:
            try:
                entities = self._pipeline(chunk_text)
            except Exception as e:
                logger.error(f"NER inference error: {e}")
                continue

            for entity in entities:
                raw_label = entity.get("entity_group", entity.get("entity", ""))
                score = float(entity.get("score", 0.0))

                # Map NER label to our PII type
                pii_type = NER_ENTITY_MAP.get(raw_label)
                if pii_type is None:
                    continue

                # Skip low-confidence detections
                if score < 0.65:
                    continue

                word = entity.get("word", "").strip()
                if not word or len(word) < 2:
                    continue

                start = entity.get("start", 0) + char_offset
                end = entity.get("end", 0) + char_offset

                # Extract context
                ctx_start = max(0, start - 50)
                ctx_end = min(len(text), end + 50)
                context = text[ctx_start:ctx_end]

                sensitivity = NER_SENSITIVITY.get(pii_type, "medium")

                results.append({
                    "entity_type": pii_type,
                    "entity_name": f"NER-{raw_label}",
                    "value": word,
                    "char_start": start,
                    "char_end": end,
                    "confidence": round(score, 4),
                    "sensitivity": sensitivity,
                    "detection_method": "ner",
                    "context_snippet": context,
                    "ner_label": raw_label,
                    "model": self.model_name,
                })

        return self._deduplicate(results)

    def _deduplicate(self, results: list[dict]) -> list[dict]:
        """Remove duplicate detections from overlapping chunks."""
        seen: set[tuple[int, int, str]] = set()
        unique: list[dict] = []

        for r in results:
            key = (r["char_start"], r["char_end"], r["entity_type"])
            if key not in seen:
                seen.add(key)
                unique.append(r)

        return unique

    @property
    def is_available(self) -> bool:
        """Check if the NER model is loaded and available."""
        if not self._loaded:
            self._load_model()
        return self._loaded
