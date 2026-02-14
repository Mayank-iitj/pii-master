# PII Shield – Enterprise PII Detection & Compliance Platform

**Production-ready AI system that automatically detects, classifies, explains, and reports sensitive data (PII) leaks across text, logs, documents, APIs, and databases, while mapping findings to GDPR, HIPAA, PCI-DSS, SOC-2, and ISO-27001 compliance requirements.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PII Shield Platform                              │
│                                                                         │
│  ┌──────────┐   ┌──────────────┐   ┌────────────┐   ┌───────────────┐  │
│  │  React    │──▶│  FastAPI      │──▶│  Detection  │──▶│ Regex Engine  │  │
│  │ Dashboard │   │  Backend     │   │  Engine     │   │ (25+ patterns)│  │
│  └──────────┘   └──────┬───────┘   └──────┬─────┘   └───────────────┘  │
│                        │                   │                            │
│                        │                   ▼          ┌───────────────┐  │
│                        │            ┌────────────┐   │ NER (BERT)    │  │
│                        │            │  Hybrid     │◀──│ Transformer   │  │
│                        │            │  Merger     │   └───────────────┘  │
│                        │            └──────┬─────┘                      │
│                        │                   │                            │
│  ┌──────────┐         │                   ▼                            │
│  │ Report   │◀────────┤            ┌────────────┐   ┌───────────────┐  │
│  │Generator │         │            │Risk Scorer  │──▶│ Compliance    │  │
│  │(PDF/CSV) │         │            │(Composite)  │   │ Policy Engine │  │
│  └──────────┘         │            └──────┬─────┘   └───────┬───────┘  │
│                        │                   │                 │          │
│  ┌──────────┐         │                   ▼                 ▼          │
│  │ Alert    │◀────────┤            ┌────────────┐   ┌───────────────┐  │
│  │ Manager  │         │            │Explainability│  │ Masking       │  │
│  │(Slack/   │         │            │  Engine     │   │ (6 strategies)│  │
│  │ Email)   │         │            └────────────┘   └───────────────┘  │
│  └──────────┘         │                                                │
│                        │            ┌────────────────────────────────┐  │
│                        └───────────▶│  PostgreSQL / Redis / Kafka   │  │
│                                     └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Features

| Category | Capability |
|---|---|
| **Detection** | 25+ regex patterns with checksum validation (Luhn, Verhoeff, mod-11), transformer NER (BERT), hybrid deduplication |
| **Documents** | PDF, DOCX, TXT, LOG, CSV, JSON, XML with charset auto-detection |
| **Classification** | Weighted composite risk scoring (sensitivity, exposure, encryption, access, location) with 4 risk tiers |
| **Compliance** | Declarative YAML policies for GDPR, HIPAA, PCI-DSS, SOC-2, ISO-27001 with rule-level mapping |
| **Explainability** | Human-readable, multi-section explanations per finding (detection, classification, risk, compliance, remediation) |
| **Masking** | 6 strategies – full, partial, hash, tokenize, redact, encrypt – with reversible token vault |
| **Alerting** | Multi-channel (Slack, Email, Webhook) with severity filtering and cooldown deduplication |
| **Reporting** | PDF with styled tables & heatmap, JSON, CSV; framework-specific sections (GDPR Article references, HIPAA safeguards) |
| **API** | RESTful FastAPI with async support, batch scanning, file upload, JWT auth, audit logging |
| **Frontend** | React 18 dashboard with dark theme, severity charts, compliance scores, interactive masking |
| **Infrastructure** | Docker Compose with PostgreSQL, Redis, Kafka; health checks; non-root containers |

## PII Types Detected

| Category | Types |
|---|---|
| **Identity** | Name, SSN, Passport, Date of Birth, PAN (India), Aadhaar |
| **Financial** | Credit Card (Visa/MC/Amex/Discover with Luhn), IBAN, Bank Account, Routing Number |
| **Contact** | Email, Phone, Address, ZIP Code |
| **Digital** | IP Address (v4/v6), MAC Address, JWT Token |
| **Secrets** | API Key, Password in URL/Config, Private Key (RSA/EC/PGP), AWS Key |
| **Medical** | Health Record, Medical ID, NPI |

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend)
- Docker & Docker Compose (for full stack)

### Option 1 – Docker Compose (Recommended)

```bash
# Clone and configure
cp .env.example .env
# Edit .env with your settings

# Start all services
docker compose up -d

# With Kafka for streaming (optional)
docker compose --profile streaming up -d
```

Services will be available at:
- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/docs

### Option 2 – Local Development

```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Download NER model (optional – regex-only mode works without it)
python -c "from transformers import pipeline; pipeline('ner', model='dslim/bert-base-NER')"

# Start the API server
uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000
```

For the frontend:

```bash
cd frontend
npm install
npm run dev
```

## API Usage

### Scan Text

```bash
curl -X POST http://localhost:8000/api/v1/scan/text \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Contact sarah@example.com, SSN: 219-09-9999, Card: 4539148803436467",
    "source_type": "text",
    "min_confidence": 0.6
  }'
```

**Response:**
```json
{
  "scan_id": "a1b2c3d4-...",
  "total_findings": 3,
  "findings": [
    {
      "entity_type": "email",
      "confidence": 0.95,
      "value_masked": "s****@example.com",
      "risk_score": 0.42,
      "risk_tier": "medium",
      "sensitivity": "medium",
      "compliance_violations": [
        {"framework": "GDPR", "rule_id": "GDPR-32.1.a", "severity": "high"}
      ],
      "explanation": {
        "summary": "An email address was detected with high confidence...",
        "detection": { ... },
        "remediation": ["Encrypt personal data at rest", "Implement access controls"]
      }
    }
  ],
  "compliance_summary": {
    "GDPR": {"violations": 3, "severity_breakdown": {"high": 2, "medium": 1}},
    "PCI-DSS": {"violations": 1, "severity_breakdown": {"critical": 1}}
  }
}
```

### Scan File

```bash
curl -X POST http://localhost:8000/api/v1/scan/file \
  -F "file=@patient_records.pdf" \
  -F "min_confidence=0.7"
```

### Mask Text

```bash
curl -X POST http://localhost:8000/api/v1/mask \
  -H "Content-Type: application/json" \
  -d '{
    "text": "SSN: 219-09-9999",
    "strategy": "partial"
  }'
```

### Generate Report

```bash
curl -X POST http://localhost:8000/api/v1/report/scan-and-report \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Email: user@test.com, Card: 4532015112830366",
    "report_format": "pdf",
    "include_sections": ["executive_summary", "findings_detail", "compliance_status"]
  }'
```

### Other Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/compliance/frameworks` | List loaded compliance frameworks |
| POST | `/api/v1/scan/batch` | Batch scan multiple texts |
| POST | `/api/v1/feedback` | Submit detection feedback |
| GET | `/api/v1/dashboard/stats` | Dashboard statistics |
| GET | `/api/v1/report/download/{file}` | Download generated report |

## Configuration

### Environment Variables (`.env`)

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./pii_shield.db` | Database connection string |
| `NER_MODEL_NAME` | `dslim/bert-base-NER` | HuggingFace NER model |
| `ENABLE_NER` | `true` | Enable transformer NER (set `false` for regex-only) |
| `NER_CONFIDENCE_THRESHOLD` | `0.7` | Minimum NER confidence |
| `REGEX_CONFIDENCE_THRESHOLD` | `0.6` | Minimum regex confidence |
| `ENABLE_KAFKA` | `false` | Enable Kafka streaming |
| `SLACK_WEBHOOK_URL` | | Slack alert webhook |
| `SMTP_HOST` | | Email alert SMTP server |
| `ENCRYPTION_KEY` | | Fernet key for encrypt masking strategy |
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed CORS origins |

### Compliance Policies

Policies are defined as YAML in `config/policies/`. Each policy specifies:

```yaml
# config/policies/gdpr.yaml
framework: GDPR
version: "2016/679"
articles:
  - id: "Article 5"
    title: "Principles relating to processing"
    rules:
      - id: "GDPR-5.1.f"
        description: "Integrity and confidentiality"
        severity: high
        applies_to: ["*"]
        conditions:
          sensitivity_min: medium
```

To add a new compliance framework, create a new YAML file in `config/policies/` following the existing structure. The policy engine auto-loads all `.yaml` files on startup.

### Risk Scoring Weights

Configured in `config/settings.yaml`:

```yaml
risk_scoring:
  weights:
    sensitivity: 0.35    # How sensitive is the PII type
    exposure: 0.25       # Where was it found (public/internal/private)
    location: 0.15       # Source type context
    encryption: 0.15     # Was it encrypted
    access: 0.10         # Access control level
```

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run all tests
pytest tests/ -v

# Run specific test modules
pytest tests/test_detection.py -v          # Regex & checksum tests
pytest tests/test_core.py -v               # Risk, compliance, masking, pipeline tests
pytest tests/test_api.py -v                # API schema tests

# With coverage
pytest tests/ --cov=src --cov-report=html
```

## Project Structure

```
pii-shield/
├── config/
│   ├── settings.yaml              # Application configuration
│   └── policies/                  # Compliance policy definitions
│       ├── gdpr.yaml
│       ├── hipaa.yaml
│       ├── pci_dss.yaml
│       ├── soc2.yaml
│       └── iso27001.yaml
├── src/
│   ├── core/
│   │   ├── __init__.py            # Settings & config loaders
│   │   ├── database.py            # SQLAlchemy models & async sessions
│   │   └── security.py            # JWT, hashing, API key generation
│   ├── detection/
│   │   ├── regex_detector.py      # 25+ patterns with validators
│   │   ├── ner_detector.py        # Transformer NER (BERT)
│   │   ├── document_parser.py     # PDF/DOCX/TXT parser
│   │   └── engine.py              # Hybrid detection orchestrator
│   ├── classification/
│   │   └── risk_scorer.py         # Composite risk scoring
│   ├── compliance/
│   │   └── policy_engine.py       # YAML policy loader & evaluator
│   ├── explainability/
│   │   └── explainer.py           # Human-readable explanations
│   ├── alerting/
│   │   └── alert_manager.py       # Slack, Email, Webhook alerts
│   ├── reporting/
│   │   └── report_generator.py    # PDF, JSON, CSV reports
│   ├── masking/
│   │   └── masker.py              # 6 masking strategies
│   ├── api/
│   │   ├── app.py                 # FastAPI app factory
│   │   ├── routes.py              # API endpoints
│   │   ├── schemas.py             # Pydantic models
│   │   └── middleware.py          # Logging, audit, security headers
│   └── pipeline.py                # Full scan orchestration pipeline
├── frontend/
│   ├── src/
│   │   ├── App.jsx                # Dashboard with 4 views
│   │   ├── api.js                 # API client
│   │   ├── index.css              # Dark theme styles
│   │   └── main.jsx               # React entry point
│   ├── Dockerfile                 # Node build + nginx
│   └── package.json
├── tests/
│   ├── test_detection.py          # Regex & checksum validator tests
│   ├── test_core.py               # Risk, compliance, explainability, masking, pipeline tests
│   ├── test_api.py                # API schema tests
│   └── demo_data.py               # Synthetic PII samples for testing
├── Dockerfile                     # Python backend container
├── docker-compose.yml             # Full stack orchestration
├── requirements.txt               # Python dependencies
├── pyproject.toml                 # Build & tool configuration
├── .env.example                   # Environment variable template
└── .gitignore
```

## Design Decisions & Trade-offs

| Decision | Rationale |
|---|---|
| **Hybrid detection (regex + NER)** | Regex provides deterministic, fast detection with checksum validation; NER catches context-dependent entities (names, addresses). Hybrid merging boosts confidence when both agree. |
| **YAML-based compliance policies** | Declarative format allows non-developers to author/modify compliance rules without code changes. Auto-loaded on startup. |
| **Weighted composite risk scoring** | Single risk score combining 5 factors is more actionable than separate scores. Weights are configurable per deployment. |
| **SQLite fallback** | Enables zero-config local development while PostgreSQL is used in production. Same async ORM layer. |
| **Regex-only mode** | Transformer models require GPU/memory. Setting `ENABLE_NER=false` allows deployment on minimal hardware with sub-second scan times. |
| **Reversible tokenization** | The `tokenize` masking strategy maintains a vault for de-tokenization, supporting workflows that need PII restoration (e.g., authorized review). |
| **Multi-format reports** | PDF for management/audit, JSON for system integration, CSV for data analysis. All from the same scan result. |
| **Non-root Docker containers** | Security best practice. Backend runs as `appuser` (UID 1000). |
| **Cooldown deduplication for alerts** | Prevents alert fatigue during batch scans by suppressing duplicate alerts within a configurable window. |

## Limitations

- **NER model size**: `dslim/bert-base-NER` is ~400MB. First scan triggers model download. Use `ENABLE_NER=false` to skip.
- **Language support**: Regex patterns are English-centric. NER supports multilingual with model swap (e.g., `xlm-roberta`).
- **No streaming scan**: Current implementation buffers full documents. Kafka integration provides event streaming but not chunked document scanning.
- **Database scans**: Schema introspection is planned but not yet implemented. Current version scans exported text/files.
- **No fine-tuning pipeline**: NER uses pre-trained models. Custom entity training requires external tooling.

## License

MIT
