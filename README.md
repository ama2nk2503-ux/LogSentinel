# LogSentinel — SIH26156

> **Universal Cybersecurity Data Preparation and Threat Intelligence Layer**
>
> Transforms heterogeneous raw logs into normalized, privacy-safe, enriched, correlated and SIEM-ready security intelligence.

**RAW LOGS IN. SECURITY INTELLIGENCE OUT.**

---

## Live Demo

```
Login:  admin / changeme
URL:    http://127.0.0.1:5173
```

Click **DEMO MODE** to watch four attack scenarios flow through the entire pipeline with live narration.

---

## Quick Start

### Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Python | 3.12+ (tested on 3.14) | `python --version` |
| Node.js | 20+ | `node --version` |
| npm | 10+ | `npm --version` |

### Setup

```bash
# Clone
git clone https://github.com/ama2nk2503-ux/logsentinel.git
cd logsentinel

# Backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt       # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # Linux/Mac

# Frontend
cd frontend
npm install
cd ..
```

### Run

```bash
# Terminal 1 — Backend (http://127.0.0.1:8000)
.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000 --app-dir backend

# Terminal 2 — Frontend (http://127.0.0.1:5173)
cd frontend && npm run dev
```

Open **http://127.0.0.1:5173**, login with `admin` / `changeme`.

---

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │              React Frontend                   │
                    │  Upload · Dashboard · Explorer · Threats     │
                    │  Graph · Intel · Privacy · Export · Demo     │
                    └──────────────────┬───────────────────────────┘
                                       │ REST API
                    ┌──────────────────┴───────────────────────────┐
                    │            FastAPI Backend (Python)           │
                    │                                               │
                    │  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
                    │  │ Parsers │→ │Detection │→ │  Privacy   │  │
                    │  │  (9)    │  │ Engine   │  │  Gate      │  │
                    │  └────┬────┘  └────┬─────┘  └─────┬──────┘  │
                    │       │            │               │         │
                    │  ┌────┴────────────┴───────────────┴──────┐  │
                    │  │         SQLite (WAL mode)               │  │
                    │  └────────────────────────────────────────┘  │
                    └──────────────────────────────────────────────┘
```

---

## Pipeline

Every log file goes through these 17 stages deterministically — no AI in the loop:

```
 1. INGESTION         Upload / paste / sample / stream → job (UUID)
 2. VALIDATION        Extension whitelist (.log .txt .json .csv .xml), 200 MB cap
 3. CHUNKED READ      5k-line batches from disk, flat memory profile
 4. FORMAT DETECTION  Heuristic scoring per format → confidence %
 5. PARSER DISPATCH   Registry → syslog | apache | windows | firewall | json | csv | xml | generic
 6. NORMALIZATION     UniversalEvent schema + field-mapping provenance
 7. PERSISTENCE       Batched inserts to SQLite (WAL mode)
 8. IOC EXTRACTION    IPv4/IPv6/domains/URLs/MD5/SHA1/SHA256 + suspicious patterns
 9. PII DETECTION     Email / phone / name / API key / password / token / session
10. RULE ENGINE       YAML-driven, windowed stateful evaluation
11. CORRELATION       Entity + time clustering → attack chains with evidence
12. CLASSIFICATION    BENIGN / SUSPICIOUS / MALICIOUS × 13 categories
13. MITRE ATT&CK      Rule → technique/tactic mapping + kill-chain per attacker
14. RISK SCORING      0–100 additive weighted factors, every point explained
15. PRIVACY GATE      SINGLE output choke: API / export / PDF / graph / search
16. THREAT INTEL      Indicator aggregation + human-readable reports
17. EXPORT            JSON · CSV · CEF · LEEF · STIX 2.1 · Syslog · PDF
```

---

## Features

### Core Pipeline

| Feature | Details |
|---------|---------|
| **Universal Parsing** | 9 format parsers behind a registry with auto-detection and real confidence scores |
| **IOC Extraction** | IPv4/IPv6/domains/URLs/MD5/SHA1/SHA256 + encoded PowerShell, SQLi, traversal — deterministic validation only |
| **YAML Threat Rules** | External rules in `rules/*.yaml` — brute force, port scan, credential abuse, web attacks, malware |
| **Correlation Engine** | Entity + time clustering; identity-linked chains (e.g. failed logins → success → suspicious command) |
| **Risk Scoring** | 0–100 additive capped factors; every score ships its reason breakdown |
| **Classification** | BENIGN / SUSPICIOUS / MALICIOUS across 13 event categories |

### Judge-Facing Features

| Feature | Details |
|---------|---------|
| **ATT&CK Kill-Chain** | Every detection mapped to MITRE ATT&CK techniques; animated 14-tactic progression per attacker |
| **Live Attack Graph** | Cytoscape.js entity graph with severity-colored edges, risk-sized nodes, drill-down panel |
| **Cinematic Demo Mode** | One-click run of 4 attack scenarios through real pipeline milestones with live narration |
| **Ask-the-Data** | Natural-language query → intent chips + filtered results. Deterministic parser, zero AI |
| **PDF Threat Report** | Branded multi-page report: exec summary, findings, evidence, charts (reportlab) |

### Privacy & Security

| Feature | Details |
|---------|---------|
| **Privacy Policy Engine** | Editable UI policy — REDACT / TYPE / MASK / HASH / KEEP applied at a single choke point |
| **Benchmark Suite** | Precision/recall/F1 for IOC & PII, redaction effectiveness, latency/RAM/CPU — computed live |
| **JWT Authentication** | Login-protected routes with bcrypt password hashing |

---

## Project Structure

```
logsentinel/
├── backend/                    # Python FastAPI application
│   ├── main.py                 # App entry, auth middleware, route registration
│   ├── api/                    # REST API route handlers
│   │   ├── routes_auth.py      #   POST /auth/login, GET /auth/me
│   │   ├── routes_upload.py    #   POST /upload (file, paste, sample)
│   │   ├── routes_dashboard.py #   GET /dashboard (stats, timeline, severity)
│   │   ├── routes_events.py    #   GET /events (paginated, filterable)
│   │   ├── routes_threats.py   #   GET /threats (incidents + kill-chain)
│   │   ├── routes_graph.py     #   GET /graph (nodes + edges)
│   │   ├── routes_intel.py     #   GET /intel (IOCs + reports)
│   │   ├── routes_privacy.py   #   GET/PUT /policy, POST /policy/preview
│   │   ├── routes_export.py    #   GET /export/{job}?format= (6 formats)
│   │   ├── routes_benchmark.py #   POST /benchmark/run, GET /benchmark/results
│   │   ├── routes_query.py     #   POST /query (Ask-the-Data)
│   │   ├── routes_samples.py   #   GET /samples (bundled demo scenarios)
│   │   └── routes_stream.py    #   POST /stream/start (live simulation)
│   ├── core/                   # Business logic
│   │   ├── config.py           #   Settings (env-based)
│   │   ├── storage.py          #   SQLite schema + connection (WAL mode)
│   │   ├── auth.py             #   bcrypt hashing, JWT create/decode
│   │   ├── pipeline.py         #   17-stage processing pipeline
│   │   ├── benchmark.py        #   Live benchmark harness
│   │   ├── jobs.py             #   Job lifecycle management
│   │   └── ingest.py           #   File upload + chunked reading
│   ├── parsers/                # Format parsers
│   │   ├── detector.py         #   Format auto-detection (confidence scoring)
│   │   ├── registry.py         #   Parser registry + dispatch
│   │   ├── syslog_parser.py    #   Syslog (RFC3164 / RFC5424)
│   │   ├── apache_parser.py    #   Apache / Nginx access logs
│   │   ├── firewall_parser.py  #   Key=value firewall logs
│   │   ├── windows_parser.py   #   Windows XML event logs
│   │   ├── structured_parser.py#   JSON / CSV structured data
│   │   └── generic_parser.py   #   Fallback parser
│   ├── detection/              # Detection engine
│   │   ├── engine.py           #   YAML rule evaluation (windowed, stateful)
│   │   ├── correlator.py       #   Entity + time clustering
│   │   ├── classifier.py       #   BENIGN / SUSPICIOUS / MALICIOUS
│   │   ├── attack.py           #   MITRE ATT&CK mapping + kill-chain
│   │   ├── risk.py             #   0–100 risk scoring with reasons
│   │   └── intent.py           #   Ask-the-Data deterministic parser
│   ├── ioc/                    # IOC extraction
│   │   ├── extractor.py        #   Regex + pattern extraction
│   │   └── validator.py        #   IPv4/IPv6/domain/URL/hash validation
│   ├── privacy/                # Privacy engine
│   │   ├── pii_detector.py     #   PII pattern detection
│   │   ├── policy_engine.py    #   Policy evaluation (REDACT/TYPE/MASK/HASH/KEEP)
│   │   └── redactor.py         #   Value redaction + hash mode
│   ├── normalization/          # Event normalization
│   │   ├── normalizer.py       #   Field mapping + UniversalEvent schema
│   │   └── schema.py           #   Event data model
│   ├── intelligence/           # Threat intel
│   │   └── aggregator.py       #   IOC aggregation + report generation
│   ├── exporters/              # SIEM export formats
│   │   ├── exporters.py        #   JSON / CSV / CEF / LEEF / STIX 2.1 / Syslog
│   │   ├── validator.py        #   Pre-download structural validation
│   │   └── pdf_report.py       #   Branded PDF report (reportlab)
│   └── streaming/              # Live simulation
│       └── simulator.py        #   Real-time log stream generator
│
├── frontend/                   # React 18 + Vite 6 + Tailwind v4
│   ├── src/
│   │   ├── main.jsx            #   App bootstrap (Router + Query + Auth)
│   │   ├── App.jsx             #   Route definitions (lazy-loaded)
│   │   ├── index.css           #   Theme: dark palette + CSS custom properties
│   │   ├── lib/
│   │   │   ├── api.js          #   Fetch wrapper (Bearer header + 401 redirect)
│   │   │   ├── AuthContext.jsx  #  JWT auth state (login/logout)
│   │   │   ├── QueryProvider.jsx#  TanStack Query client
│   │   │   └── useQueryParam.js#  URL state persistence hook
│   │   ├── components/
│   │   │   ├── Layout.jsx      #   Sidebar nav + responsive hamburger
│   │   │   ├── JobPicker.jsx   #   Shared dataset selector (cached)
│   │   │   ├── Skeleton.jsx    #   Loading placeholder
│   │   │   └── ProtectedRoute.jsx # Route guard
│   │   └── pages/
│   │       ├── Login.jsx       #   JWT authentication
│   │       ├── Upload.jsx      #   File upload / paste / sample loader
│   │       ├── Dashboard.jsx   #   Stats cards + timeline + severity donut
│   │       ├── Explorer.jsx    #   Paginated event log (search + filters)
│   │       ├── Threats.jsx     #   Threat incidents + ATT&CK kill-chain
│   │       ├── Graph.jsx       #   Cytoscape.js entity attack graph
│   │       ├── Intel.jsx       #   IOC feed + intelligence reports
│   │       ├── Privacy.jsx     #   Editable privacy policy UI
│   │       ├── ExportPage.jsx  #   SIEM export (6 formats + PDF)
│   │       ├── Benchmark.jsx   #   Live benchmark results
│   │       └── Demo.jsx        #   Cinematic 4-scenario demo
│   ├── vite.config.js          #   Dev server + API proxy
│   └── package.json
│
├── rules/                      # External YAML rules (hot-reloadable)
│   ├── authentication.yaml     #   Brute force, credential abuse
│   ├── network.yaml            #   Port scan, host scan
│   ├── web_attacks.yaml        #   SQLi, XSS, path traversal
│   ├── malware.yaml            #   Suspicious processes, encoded commands
│   ├── privacy_policy.yaml     #   Default REDACT policy
│   └── attack_mapping.json     #   rule_id → MITRE ATT&CK technique mapping
│
├── samples/                    # Bundled demo scenarios
│   ├── scenario1_ssh_bruteforce.log
│   ├── scenario2_port_scan.log
│   ├── scenario3_web_attack.log
│   ├── scenario4_windows_auth.xml
│   └── labeled/                #   Ground-truth for benchmark
│       ├── ioc_labels.json
│       └── pii_labels.json
│
├── specs/                      # Design documents
│   ├── design.md               #   Technical design (17 pipeline stages)
│   └── wow_features.spec.md    #   Feature specs with EARS requirements
│
├── tests/                      # 103 unit + integration tests
│   ├── conftest.py             #   Shared fixtures
│   ├── test_parsers.py         #   16 parser tests
│   ├── test_ioc.py             #   16 IOC extraction tests
│   ├── test_export.py          #   10 export format tests
│   ├── test_privacy.py         #   11 privacy/redaction tests
│   ├── test_normalization.py   #   9 normalization tests
│   ├── test_detection.py       #   7 rule engine tests
│   ├── test_detector.py        #   8 format detection tests
│   ├── test_correlation.py     #   9 correlation tests
│   ├── test_intent.py          #   6 Ask-the-Data tests
│   ├── test_intel.py           #   4 intelligence tests
│   ├── test_attack.py          #   3 ATT&CK mapping tests
│   ├── test_benchmark.py       #   2 benchmark harness tests
│   ├── test_pdf.py             #   2 PDF report tests
│   └── scripts/                #   Phase gate scripts (P1–P15)
│
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Test configuration
└── README.md                   # This file
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.14, FastAPI, Pydantic v2, Uvicorn |
| **Database** | SQLite (WAL mode), parameterized SQL only |
| **Frontend** | React 18, Vite 6, Tailwind CSS v4 |
| **Charts** | Recharts |
| **Graph** | Cytoscape.js (bundled locally, no CDN) |
| **PDF** | reportlab |
| **Auth** | JWT (PyJWT) + bcrypt |
| **Data Fetching** | TanStack Query v5 (auto-caching, polling) |
| **Routing** | React Router v6 (lazy-loaded pages) |
| **Testing** | pytest + httpx |

---

## API Reference

All endpoints require JWT auth (via `Authorization: Bearer <token>`) except `/api/auth/login`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Login → `{ access_token, username }` |
| `GET` | `/api/auth/me` | Current user info |
| `POST` | `/api/auth/register` | Create new user |
| `POST` | `/api/upload` | Upload file / paste / sample |
| `GET` | `/api/jobs` | List all jobs |
| `GET` | `/api/jobs/{id}` | Job detail + stats |
| `GET` | `/api/dashboard` | Aggregated stats + timeline |
| `GET` | `/api/events` | Paginated events (filter by severity, threat, search) |
| `GET` | `/api/events/{id}` | Single event detail |
| `GET` | `/api/threats` | Threat incidents + kill-chain |
| `GET` | `/api/graph` | Entity graph (nodes + edges) |
| `GET` | `/api/intel` | IOC feed + reports |
| `GET` | `/api/policy` | Current privacy policy |
| `PUT` | `/api/policy` | Update privacy policy |
| `POST` | `/api/policy/preview` | Preview redaction |
| `GET` | `/api/export/{job}` | Export (format: json/csv/cef/leef/stix/syslog) |
| `GET` | `/api/report/{job}` | PDF threat report |
| `POST` | `/api/query` | Ask-the-Data natural language query |
| `POST` | `/api/benchmark/run` | Run benchmark suite |
| `GET` | `/api/benchmark/results` | Latest benchmark results |
| `GET` | `/api/samples` | List bundled demo scenarios |
| `POST` | `/api/stream/start` | Start live log stream |

---

## Testing

```bash
# Run all 103 tests
.venv\Scripts\python -m pytest           # Windows
source .venv/bin/activate && pytest      # Linux/Mac

# Run specific module
.venv\Scripts\python -m pytest tests/test_ioc.py -v

# With coverage
.venv\Scripts\python -m pytest --tb=short
```

---

## Benchmark Results

All metrics computed live from labeled fixtures in `samples/labeled/` — nothing is hardcoded.

| Metric | Value |
|--------|-------|
| Format Detection | 100% accuracy |
| Full Parse Rate | 100% |
| IOC Precision | 100% |
| IOC Recall | 70% |
| IOC F1 | 82.4% |
| PII Precision | 88.9% |
| PII Recall | 88.9% |
| PII F1 | 88.9% |
| Redaction Effectiveness | 100% |
| Throughput | ~7,000 lines/sec |
| Peak RSS | ~32 MB |

---

## Security

- Server binds `127.0.0.1` only; CORS locked to dev origin
- Upload whitelist: `.log .txt .json .csv .xml`; size cap 200 MB
- UUID storage names (no user-controlled paths on disk)
- Parameterized SQL everywhere — no string interpolation
- Uploaded content is **parsed, never executed**
- React JSX auto-escapes; CEF/LEEF output escaped; STIX validated pre-download
- All export surfaces route through the privacy policy choke point

---

## License

SIH26156 — Smart India Hackathon 2026
