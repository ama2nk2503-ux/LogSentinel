LogSentinel is a COMPLETE, WORKING submission for SIH26156 ("Universal Log Pre-processing
Framework", NTRO, Blockchain & Cybersecurity) — not a prototype or a plan. Per
LOG_SENTINEL_WALKTHROUGH.txt (attached), it already has: a working 17-stage deterministic
pipeline (ingest → format detection → parse → normalize → IOC extract → PII detect → rules →
correlate → classify → MITRE map → risk score → privacy gate → threat intel → export), a
trained offline IsolationForest anomaly scorer wired into detection, geoIP enrichment,
4-framework compliance auditing (NIST/CIS/ISO/CIS Benchmarks), asset inventory, alerting +
triage + investigation timeline, a live streaming simulator, a deterministic NL query parser
("Ask-the-Data"), CEF/LEEF/STIX2.1/Syslog/PDF export, and 14 working frontend pages. It passes
149 backend tests and 31 Playwright e2e tests (axe-scanned) today, running locally via the
commands in section 9 of the walkthrough.

Treat everything below as INCREMENTAL, ADDITIVE work on top of that stable system —
comparable to opening focused PRs, not a rebuild. Hard constraints for every item:
- Run the existing test suite before touching anything, and again after each item, to
  confirm nothing regresses. If an item would require changing an existing pipeline stage's
  behavior (not just extending it), stop and tell me instead of guessing.
- Don't restructure the 17-stage pipeline, the DB schema, or existing page layouts beyond
  what's explicitly asked. Add new tables/columns/routes/pages; don't rewrite working ones.
- Every new backend feature gets tests in the same pytest style already used; every new page
  gets a Playwright test in the same style already used (including axe accessibility scan).
- Everything stays offline: no new network calls, no new cloud dependency, no new required
  API key. If a feature is optional and needs something not already in the stack (e.g. a
  local LLM), it must be off by default and the app must work identically with it absent.

WHY these specific items: a competing team's submission for the same PS uses Neo4j +
BAAI/bge-m3 embeddings + GraphRAG + an LLM (gpt-oss-120b) to generate its answers, and covers
a wide named-vendor format list (ESXi/NSX/vCenter, Cisco ASA, Fortinet, Palo Alto, Check
Point, AWS CloudTrail, Okta, CrowdStrike), plus exports to ECS/OCSF with per-field coverage
docs and a deterministic dedup event ID. LogSentinel's structural advantage is that every
finding traces to a rule, a threshold, or a documented schema field — never to an LLM's
unverified read of retrieved text. The items below close the competitor's visible feature
gaps without giving up that advantage. Do not add anything that makes a detection, count, or
claim depend on an LLM's output being correct — an LLM may only narrate a conclusion the
deterministic engine already reached, evidence shown directly underneath, clearly labeled
"AI-generated summary — verify against evidence below."

Implement, in this order, each as a self-contained change with its own tests:

1. UNIVERSAL EVENT SCHEMA DOCS PAGE
   New page: for every existing UniversalEvent field, show type, a mapped ECS field name, a
   mapped OCSF field name (start with OCSF Authentication 3002 / Network Activity 4001 /
   Application Lifecycle 1008), coverage % for the current job, one-line mapping description.
   Pure read/derived from existing normalized data — no schema change required.

2. ECS JSON + OCSF JSON EXPORT FORMATS
   Add alongside the existing JSON/CSV/CEF/LEEF/STIX2.1/Syslog exporters in exporters/,
   same streaming pattern as the current exporters — new files, existing exporters untouched.

3. DETERMINISTIC IDEMPOTENT EVENT ID (schema-additive, not a rewrite)
   Add a new derived id scheme: hash of (timestamp|hostname|process|raw_text), constant
   marker when no timestamp is parseable, plus a new timestamp_source field ("event" vs
   "ingest"). Ship as an additive migration (new column, like the existing anomaly_score/
   anomalous columns were added) with a backfill script — do not touch existing event ids
   or break existing tests that reference them.

4. PARSER LAB (new page, isolated from Upload)
   New page: paste/type text, parsed live (debounced) against the EXISTING parser registry
   and detector.py confidence scoring, nothing written to the DB. Show per-line matched
   parser (or "unknown — generic fallback"), raw-vs-normalized, and summary tiles (records,
   % by name vs fallback, distinct formats, throughput). Read-only reuse of existing parsing
   code path; no changes to the real upload/paste ingestion flow.

5. NEW NAMED PARSERS (additive to the registry, existing parsers untouched)
   Add parsers/detectors for Cisco ASA syslog, Fortinet key=value, Palo Alto PAN-OS,
   Check Point, AWS CloudTrail JSON, Okta system log JSON, CrowdStrike Falcon JSON, DNS
   query logs, and one OT/industrial key=value sensor log. Each gets its own detector +
   normalizer + at least one new IOC/rule tie-in + a test file, registered alongside the
   existing syslog/apache/windows/firewall parsers without modifying them.

6. UNSUPERVISED TEMPLATE MINING FALLBACK (new stage, sits before the existing generic fallback)
   When format-detection confidence is below the existing threshold, run an offline Drain-
   style template miner (implemented locally, no network/model download) before falling
   back to generic. Persist learned templates per job. Tag provenance as parsed_by:
   "learned_template" alongside the existing "named_parser"/"generic_fallback" values.

7. RULE-VS-ML COMPARISON VIEW (pure UI, no new backend logic)
   New panel using data the pipeline already produces (detections + ml.bump() output):
   counts for rules-only, ML-only, both-agreed incidents.

8. CHAIN-OF-CUSTODY HASH CHAIN (new table, additive)
   New alerts-table-style migration adding a batch-hash-chain table per job; a "Verify
   Integrity" endpoint/button that recomputes and confirms it. Doesn't touch ingestion logic
   beyond appending a hash after each existing batch insert.

9. MODES PAGE (documentation/UX surface, not new infrastructure)
   New page presenting "Demo (bundled samples)" / "Production (offline, air-gapped)" /
   "Custom upload" as explicit cards, making the existing zero-network-calls guarantee an
   inspectable claim in the UI instead of only a README note. This should require no backend
   changes — the offline guarantee already exists; this page just surfaces it.

10. OPTIONAL "AI SUMMARY" NARRATION (off by default, isolated module)
    Only if a local LLM is already available in the environment — no new dependency, no
    network call, no required API key. Toggle that narrates an already-computed risk-score
    breakdown or compliance finding in plain English, with the exact evidence shown
    unedited directly beneath. App must run and pass all tests identically with this off.

After each item: run the full existing test suite (149 backend + 31 e2e), report pass/fail,
then move to the next item. At the end, update LOG_SENTINEL_WALKTHROUGH.txt to document the
additions in the same style as milestones 1-3, and add one short paragraph to the pitch deck
notes contrasting "deterministic, evidence-traceable findings" against a retrieval/LLM-based
alternative — that contrast is the actual differentiation angle for judges, not a footnote. 