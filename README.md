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
                    │  Upload · Dashboard · Explorer · Threats      │
                    │  Graph · Intel · Alerts · Live · Compliance   │
                    │  Assets · Privacy · Export · Benchmark · Demo │
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

Every log file goes through these 17 stages deterministically — every step
explainable. One seeded, fully-offline ML signal (IsolationForest, no network)
is trained per job and fed back into incident escalation with a reason line:

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

**ML ANOMALY SCORING** (`backend/ml/`, scikit-learn, seeded `random_state=42`,
single-threaded, offline): fits an IsolationForest per job over a deterministic
16-dimension event vector, writes `anomaly_score` (0–1) + `anomalous` flags to
every event, and escalates any correlated detection whose evidence contains an
anomalous event by `+2..+30` risk with an auditable reason (e.g.
`+20 ML anomaly signal (1/7 evidence events anomalous, peak score 0.97)`).
Surfaced as the Explorer **ANOMALY** column (★ = flagged) and the Dashboard
**ML ANOMALIES** card; inspect via `GET /api/ml/{job_id}`.

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

### Operational Capabilities (M1–M3)

| Milestone | Feature | Details |
|-----------|---------|---------|
| **M1** | Live SOC Ops | Alerting engine (YAML rules, dedup, SMTP/webhook notify, ack/resolve/FP lifecycle), incident triage (NEW→RESOLVED + analyst + notes), MITRE investigation timeline, real-time EVENT WALL (1.5s polling) |
| **M2** | Intel / Geo / Compliance / Assets | Offline GeoIP enrichment, bundled reputation feed (7 indicators), NIST SP 800-53 / CIS v8 / ISO 27001 audits with Markdown reports, asset inventory + per-asset alert rules |
| **M3** | In-loop ML anomaly scoring | Seeded offline IsolationForest per job → `anomaly_score` + `anomalous` flags, evidence-driven incident risk bump with reason, Explorer ANOMALY column (★), Dashboard ML card, `GET /api/ml/{job_id}` |

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
│   │   ├── routes_detections.py#   GET /detections
│   │   ├── routes_threats.py   #   GET /threats (incidents, kill-chain, triage)
│   │   ├── routes_alerts.py    #   GET/POST /alerts, /alert-rules, notify/ack/resolve
│   │   ├── routes_graph.py     #   GET /graph (nodes + edges)
│   │   ├── routes_intel.py     #   GET /intel, /intel/reputation/{value}
│   │   ├── routes_geo.py       #   GET /geo/lookup, /geo/job/{id}
│   │   ├── routes_audit.py     #   Compliance audits + Markdown reports
│   │   ├── routes_assets.py    #   GET /assets (asset inventory)
│   │   ├── routes_ml.py        #   GET /api/ml/{job_id} (model + anomalies)
│   │   ├── routes_privacy.py   #   GET/PUT /policy, POST /policy/preview
│   │   ├── routes_export.py    #   GET /export/{job}?format= (6 formats)
│   │   ├── routes_ioc.py       #   IOC watchlist
│   │   ├── routes_jobs.py      #   GET /jobs, /jobs/{id}
│   │   ├── routes_benchmark.py #   POST /benchmark/run, GET /benchmark/results
│   │   ├── routes_query.py     #   POST /query (Ask-the-Data)
│   │   ├── routes_samples.py   #   GET /samples (bundled demo scenarios)
│   │   └── routes_stream.py    #   POST /stream/start|stop, GET /stream/recent
│   ├── core/                   # Business logic
│   │   ├── config.py           #   Settings (env-based)
│   │   ├── storage.py          #   SQLite schema + migrations + connection (WAL mode)
│   │   ├── auth.py             #   bcrypt hashing, JWT create/decode
│   │   ├── pipeline.py         #   17-stage processing pipeline
│   │   ├── alerts.py           #   Alerting engine (incident + IOC classes)
│   │   ├── triage.py           #   Incident triage workflow
│   │   ├── timeline.py         #   MITRE investigation timeline
│   │   ├── geoip.py            #   Offline IP → geo lookup (rules/geoip/ranges.csv)
│   │   ├── intel.py            #   Bundled reputation feed + verdicts
│   │   ├── compliance.py       #   Framework audits (NIST/CIS/ISO)
│   │   ├── assets.py           #   Asset inventory derivation
│   │   ├── benchmark.py        #   Live benchmark harness
│   │   ├── jobs.py             #   Job lifecycle management
│   │   └── ingest.py           #   File upload + chunked reading
│   ├── ml/                     # In-loop ML anomaly scorer (M3)
│   │   ├── features.py         #   Deterministic 16-dim feature vector
│   │   └── model.py            #   IsolationForest fit / score / bump, per-job persist
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
│   │       ├── Dashboard.jsx   #   Stats cards (incl. ML anomalies) + timeline + donut
│   │       ├── Explorer.jsx    #   Paginated event log (search + filters + ANOMALY col)
│   │       ├── Threats.jsx     #   Threat incidents + triage + ATT&CK kill-chain
│   │       ├── Alerts.jsx      #   Alert queue + ack/resolve/FP + rule management
│   │       ├── Live.jsx        #   Real-time EVENT WALL
│   │       ├── Graph.jsx       #   Cytoscape.js entity attack graph
│   │       ├── Intel.jsx       #   Tabs: INDICATORS / REFERENCE FEED / REPUTATION / GEO
│   │       ├── Compliance.jsx  #   Framework audits + Markdown report download
│   │       ├── Assets.jsx      #   Asset inventory by criticality/risk
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
│   ├── alert_rules.yaml        #   SOC alerting rules (M1)
│   ├── compliance.yaml         #   NIST/CIS/ISO framework controls (M2)
│   ├── intel_reference.yaml    #   Bundled reputation feed (M2)
│   ├── privacy_policy.yaml     #   Default REDACT policy
│   ├── geoip/ranges.csv        #   Offline IP → geo subnet table (M2)
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
├── tests/                      # 149 unit + integration tests
│   ├── conftest.py             #   Shared fixtures
│   ├── test_parsers.py         #   Format parsers
│   ├── test_ioc.py             #   IOC extraction
│   ├── test_export.py          #   Export formats
│   ├── test_privacy.py         #   Privacy/redaction
│   ├── test_normalization.py   #   Normalization
│   ├── test_detection.py       #   Rule engine
│   ├── test_detector.py        #   Format detection
│   ├── test_correlation.py     #   Correlation
│   ├── test_intent.py          #   Ask-the-Data
│   ├── test_intel.py           #   Intelligence aggregation
│   ├── test_attack.py          #   ATT&CK mapping
│   ├── test_benchmark.py       #   Benchmark harness
│   ├── test_pdf.py             #   PDF report
│   ├── test_alerts.py          #   Alerting engine (M1)
│   ├── test_triage.py          #   Triage workflow (M1)
│   ├── test_timeline.py        #   Investigation timeline (M1)
│   ├── test_geoip.py           #   GeoIP enrichment (M2)
│   ├── test_intel_m2.py        #   Reputation feed + reload (M2)
│   ├── test_compliance.py      #   Compliance audits (M2)
│   ├── test_assets.py          #   Asset inventory (M2)
│   ├── test_ml.py              #   ML anomaly scoring (M3)
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
| **ML** | scikit-learn (IsolationForest — seeded, offline, per-job) |
| **Testing** | pytest + httpx, Playwright (axe accessibility) |

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
| `GET` | `/api/threats/triage/summary` | Triage state distribution (M1) |
| `GET` | `/api/incidents/{id}/timeline` | MITRE investigation timeline (M1) |
| `GET` | `/api/alerts` | Open/acked/resolved alerts (M1) |
| `GET/POST` | `/api/alert-rules` | SOC alert-rule management (M1) |
| `POST` | `/api/alerts/{id}/notify` | SMTP/webhook notification (M1) |
| `GET` | `/api/graph` | Entity graph (nodes + edges) |
| `GET` | `/api/intel` | IOC feed + reports |
| `GET/POST` | `/api/intel/reference`, `/reload` | Bundled reputation feed (M2) |
| `GET` | `/api/intel/reputation/{value}` | Offline malicious/suspicious/unknown verdict (M2) |
| `GET` | `/api/geo/lookup?ip=` | Offline IP → geo lookup (M2) |
| `GET` | `/api/geo/job/{id}[/banner]` | Per-event geo + top regions (M2) |
| `GET` | `/api/audit/report/{job}/{framework}` | Compliance Markdown report (M2) |
| `GET` | `/api/assets` | Asset inventory (M2) |
| `GET` | `/api/ml/{job_id}` | ML model meta + top anomalies (M3) |
| `GET` | `/api/events/{id}` | Single event detail |
| `GET` | `/api/policy` | Current privacy policy |
| `PUT` | `/api/policy` | Update privacy policy |
| `POST` | `/api/policy/preview` | Preview redaction |
| `GET` | `/api/export/{job}` | Export (format: json/csv/cef/leef/stix/syslog) |
| `GET` | `/api/report/{job}` | PDF threat report |
| `POST` | `/api/query` | Ask-the-Data natural language query |
| `POST` | `/api/benchmark/run` | Run benchmark suite |
| `GET` | `/api/benchmark/results` | Latest benchmark results |
| `GET` | `/api/samples` | List bundled demo scenarios |
| `POST` | `/api/stream/start\|/stop` | Start/stop live log stream (M1) |
| `GET` | `/api/stream/recent` | Fresh events for the EVENT WALL (M1) |

---

## Testing

```bash
# Backend: 149 unit + integration tests
.venv\Scripts\python -m pytest           # Windows
source .venv/bin/activate && pytest      # Linux/Mac

# Run a specific module
.venv\Scripts\python -m pytest tests/test_ml.py -v

# Frontend: 31 audit e2e (axe on all 14 pages + functional flows)
cd frontend
npx playwright test
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
