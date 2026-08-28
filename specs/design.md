# LogSentinel — Technical Design (SIH26156)

> A Universal Cybersecurity Data Preparation and Threat Intelligence Layer that
> transforms heterogeneous raw logs into normalized, privacy-safe, enriched,
> correlated and SIEM-ready security intelligence.

## 1. Scope

Deterministic core pipeline (no LLM in the loop; one seeded, offline ML signal —
IsolationForest anomaly scoring, deterministic + explainable) + benchmark
dashboard + real-time stream simulation. All offline-capable, no network calls.
Single-user prototype — server binds `127.0.0.1`, default login admin/changeme.

## 2. Stack

| Layer    | Choice |
|----------|--------|
| Backend  | Python 3.14, FastAPI, Pydantic v2, Uvicorn |
| Storage  | SQLite (WAL mode), parameterized queries only |
| Rules    | External YAML (`rules/*.yaml`) — outside application code |
| Frontend | React 18 + Vite + Tailwind CSS v4 + Recharts (+ cytoscape.js bundled locally at P12) |
| PDF      | reportlab (fallback fpdf2 if cp314 wheel unavailable) |
| Tests    | pytest + httpx |

## 3. Pipeline Stages (S01–S17)

```
S01 Ingestion        upload / paste / multi-file / sample / stream -> job(UUID)
S02 Validation       extension whitelist (.log .txt .json .csv .xml),
                     size cap 200MB, UUID storage names (no user paths)
S03 Chunked read     5k-line batches from disk; flat memory profile
S04 Format detection heuristic scoring per format -> confidence %
S05 Parser dispatch  registry -> syslog|apache|nginx|windows|firewall|
                     json|csv|xml|generic(AI-stub fallback)
S06 Normalization    UniversalEvent schema + field-mapping provenance
S07 Persistence      batched inserts to SQLite
S08 IOC extraction   IPv4/IPv6/domain/URL/ports/MD5/SHA1/SHA256/filenames/
                     suspicious patterns + deterministic validation+confidence
S09 PII detection    email/phone/name/api-key/password/token/session/account#
S10 Rule engine      YAML-driven, windowed stateful evaluation over SQLite
S11 Correlation      entity+time attack chains with evidence lists
S12 Classification   BENIGN/SUSPICIOUS/MALICIOUS x 13 categories
S13 ATT&CK enrich    rule_id -> technique/tactic mapping (static JSON);
                     kill-chain progression per attacker entity   [Wow-A]
S14 Risk scoring     0-100 additive weighted factors, capped, each factor
                     recorded as an explicit reason string
S15 Privacy policy   applied at the SINGLE serialization choke point:
                     every API response/export/PDF/graph/search payload
                     passes through privacy.apply_policy()
S16 Threat intel     indicator aggregation + human-readable reports
S17 Output           JSON/CSV/CEF/LEEF/STIX2.1/syslog exporters (validated),
                     PDF report [Wow-E], dashboard/explorer/graph [Wow-B],
                     ask-the-data search [Wow-D], demo mode [Wow-C]
```

## 4. Data Model (SQLite)

```sql
jobs(id PK, filename, size_bytes, source_type, status, progress, stage,
     detected_format, format_confidence, stats_json, error, created_at, updated_at)
raw_lines(job_id, line_no, raw)            -- original text kept for Raw-vs-Normalized view
events(id PK, job_id, line_no, ts, event_type, source, src_ip, dst_ip, src_port,
       dst_port, protocol, username, hostname, action, status, severity, message,
       threat_type, risk_score, iocs_json, pii_json, mappings_json, attack_json)
detections(id PK, job_id, rule_id, rule_name, severity, category, entity,
           entity_type, evidence_json, techniques_json, reasons_json, risk_score, created_at)
correlations(id PK, job_id, title, category, classification, severity, entity,
             risk_score, reasons_json, evidence_event_ids_json, timeline_json,
             techniques_json, killchain_json, created_at)
indicators(id PK, value, type, threat_type, severity, confidence,
           first_seen, last_seen, related_events)  UNIQUE(value,type)
```

Indexes: `events(job_id)`, `events(src_ip)`, `events(ts)`.

### Redaction timing decision
Raw text is retained locally (`raw_lines`, `events.message`) so the Raw-vs-
Normalized view works and detection runs on true values. **Nothing leaves the
process without passing `privacy.apply_policy()`** — API responses, exports,
PDFs, graph payloads, search results all route through one choke point.
Exports therefore never contain un-redacted PII regardless of stored state.

## 5. API Surface (all under `/api`, JSON)

```
GET  /health
POST /upload            multipart multi-file -> {job_ids}
POST /paste             {text, name}          -> {job_id}
GET  /jobs              list jobs
GET  /jobs/{id}         status incl. stage milestones + stats
GET  /events?job_id&severity&threat&q&from&to&page&page_size
GET  /events/{id}       full event incl. mapping provenance + raw line
GET  /dashboard/{job_id}  card stats + chart datasets
GET  /threats/{job_id}  correlations + kill-chains + timelines
GET  /indicators/{job_id}
GET  /policy            PUT /policy           privacy policy YAML get/set
POST /export            {job_id, format, filters} -> file download
POST /stream/start      POST /stream/stop     simulated live feed control
GET  /graph/{job_id}    nodes/edges for cytoscape                    [Wow-B]
POST /query             {text} -> {chips, results}                   [Wow-D]
POST /report/{job_id}   -> PDF download                              [Wow-E]
POST /benchmark/run     GET /benchmark/results                       metrics
```

Job stage milestones: `uploaded → detected → parsed → normalized →
ioc_extracted → correlated → classified → redacted → exported` (drives Demo Mode).

## 6. Detection & Scoring Design

Rules are YAML documents consumed by a generic engine:

```json
{"rule_id":"BRUTE_FORCE_001","name":"Repeated Failed Login","severity":"HIGH",
 "threshold":5,"window":"5m","group_by":["src_ip"],"match":{"event_type":"auth_failure"}}
```

Engine groups events by `group_by` keys inside sliding window, emits detections
with per-event evidence. Correlator chains detections sharing entities
(e.g. brute-force then success then suspicious command => account compromise).
Classifier maps rule category -> threat class. Risk scorer sums weighted factors
with caps; every contribution becomes a reason line ("+30 repeated auth failures").
ATT&CK tactics order = official Enterprise tactic sequence (14 stages); missing
mapping renders `UNMAPPED` — never invented.

## 7. Security Requirements Mapping (checklist)

| Requirement | Implementation |
|---|---|
| File validation | whitelist ext, size cap, empty-file reject, sanitized UUID names |
| Safe parsing | regex-based only; no eval/exec/import of content; never execute log content |
| SQLi | sqlite3 `?` parameters exclusively |
| XSS | React JSX escaping; no dangerouslySetInnerHTML anywhere |
| CORS | locked to http://localhost:5173 / 127.0.0.1:5173 |
| Binding | uvicorn host 127.0.0.1 only |
| Secrets | none required (AI stubbed); env-var pattern documented for future |
| Output safety | CEF `\|` `=` newline escaping; STIX structural validation pre-download |
| Debug logs | no PII/secrets logged |

## 8. Performance

Streaming chunk reader (5k lines/batch), batched inserts, windowed SQL for rules
(no full in-memory sets), lazy graph builder capped at demo scale, Recharts on
aggregates only. Target: low-end laptop usable throughout; benchmark page proves
latency/RAM/CPU claims with psutil measurements — zero hardcoded results.

## 9. Build Phases

P0 foundations → P1 ingestion → P2 parsers → P3 normalization → P4 IOC →
P5 rules → P6 correlation/scoring → P7 privacy → P8 intel → P9 exporters →
P10 stream → P11 core UI → P12 Wow-A/B → P13 Wow-C/D/E → P14 benchmark →
P15 hardening/rehearsal. Gate per phase; see wow_features.spec.md for W1–W7.
