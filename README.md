# LogSentinel — SIH26156

> **A Universal Cybersecurity Data Preparation and Threat Intelligence Layer that transforms
> heterogeneous raw logs into normalized, privacy-safe, enriched, correlated and SIEM-ready
> security intelligence.**

**RAW LOGS IN. SECURITY INTELLIGENCE OUT.**

---

## Quick Start

```bash
# Backend (Python 3.12+ / tested on 3.14)
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt   # Windows
cd backend && ..\.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000

# Frontend (Node 20+)
cd frontend
npm install
npm run dev            # http://127.0.0.1:5173
```

Then: open `http://127.0.0.1:5173` → **★ DEMO MODE** → watch four attack scenarios flow
through the entire pipeline with live narration.

## Pipeline

```
Ingestion → Validation → Chunked streaming → Format Detection (confidence %)
→ Parser Registry (syslog/apache/nginx/windows/firewall/ids/proxy/json/csv/xml/generic)
→ Universal Normalization (+field-mapping provenance) → SQLite persistence
→ IOC Extraction & Validation → PII Detection → YAML Rule Engine → Correlation
→ Classification (BENIGN/SUSPICIOUS/MALICIOUS) → ATT&CK Enrichment + Kill-Chain
→ Transparent Risk Scoring (0-100, every point explained)
→ Privacy Policy Gate (REDACT/TYPE/MASK/HASH/KEEP) → Threat Intelligence
→ SIEM Export: JSON · CSV · CEF · LEEF · STIX 2.1 · Syslog · PDF Report
```

## Feature Highlights

| Area | What it does |
|---|---|
| Universal parsing | 9 format parsers behind a registry; auto-detection with real confidence scores |
| IOC extraction | IPv4/IPv6/domains/URLs/MD5/SHA1/SHA256 + suspicious patterns (encoded PowerShell, SQLi, traversal…) — deterministic validation only |
| Threat rules | External YAML (`rules/*.yaml`) — brute force, port/host scan, credential abuse, web attacks, malware-like activity; hot-reloadable |
| Correlation | Entity+time clustering; identity-linked chains ("failed logins → success → suspicious command" = Possible Account Compromise) |
| Risk scoring | Additive capped factors; every score ships its reason breakdown |
| MITRE ATT&CK | Every rule mapped to techniques; animated 14-tactic kill-chain per attacker |
| Attack graph | Cytoscape entity graph, severity-colored edges, evidence drill-down |
| Privacy engine | Editable policy (UI), applied at ONE output choke point — API/export/report/graph/search all filtered; hash mode preserves correlation |
| Ask-the-Data | Natural-language query → intent chips + filtered results. Deterministic parser, zero AI |
| Demo Mode | One-click cinematic run of all scenarios over real pipeline milestones |
| Benchmark | Precision/recall/F1 for IOC & PII extraction, redaction effectiveness, latency/RAM/CPU — computed live against labeled fixtures, never hardcoded |

## Security Posture (prototype scope)

- Server binds `127.0.0.1`; CORS locked to the dev origin. Single-user prototype — multi-user auth is out of scope and documented as such.
- Upload whitelist (`.log/.txt/.json/.csv/.xml`), size cap (200 MB), UUID storage names.
- Parameterized SQL everywhere; React JSX escaping only; CEF/LEEF escaping; STIX structural validation pre-download.
- Uploaded content is **parsed, never executed**.

## Tests

```bash
.venv\Scripts\python -m pytest          # 100+ unit/integration tests
```

## Layout

```
backend/    FastAPI app: api/ parsers/ normalization/ ioc/ detection/
            privacy/ intelligence/ exporters/ streaming/ core/
frontend/   React+Vite+Tailwind: pages for Upload/Demo/Dashboard/Explorer/
            Threats/Graph/Intel/Privacy/Export/Benchmark
rules/      YAML threat rules + privacy policy + attack_mapping.json
samples/    Demo scenarios + labeled ground-truth fixtures
specs/      design.md + wow_features.spec.md
tests/      pytest suite + gate scripts
```
