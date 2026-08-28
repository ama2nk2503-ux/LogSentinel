# Spec: LogSentinel Judge-Facing Feature Pack (`wow_features.spec.md`)

Five deterministic (zero-LLM), offline-capable features, plus one seeded,
offline ML signal (IsolationForest anomaly scoring — deterministic, no network).
All values sourced from actual processed data; every surface passes the
privacy policy choke point.

## Features

| # | Feature | Summary |
|---|---------|---------|
| A | ATT&CK Kill-Chain View | Detections mapped to MITRE ATT&CK techniques; animated tactic progression per attacker |
| B | Live Attack Graph | Cytoscape.js entity graph, severity-colored edges, node drill-down |
| C | Cinematic Demo Mode | Auto-plays 4 scenarios through real pipeline milestones with narration overlay |
| D | Ask-the-Data Search Bar | Deterministic intent parser -> chips + filtered results (no LLM) |
| E | PDF Threat Report | Branded multi-page reportlab report with charts and evidence |

## Functional Requirements (EARS)

### A. ATT&CK Kill-Chain View
- The system shall ship static mapping `rules/attack_mapping.json` (`rule_id -> [{technique,name,tactic}]`) covering every built-in rule.
- When a detection fires, the engine shall attach mapped technique IDs+tactic.
- When an entity accumulates >=1 detection, the backend shall compute its kill-chain progression as ordered distinct tactics with evidence event IDs.
- When Threats page renders, UI shall show animated progression bars across the 14 ATT&CK Enterprise tactics.
- When a stage is clicked, UI shall list justifying evidence (timestamps, rule IDs, excerpts).
- Where a fired rule lacks a mapping, UI shall render `UNMAPPED` — never invent technique.

### B. Live Attack Graph
- When a job completes, backend shall build `{nodes:[ip|user|host], edges:[interactions]}` with severity weights, risk-sized nodes.
- When Attack Graph opens, UI shall render via locally-bundled cytoscape.js.
- When a node is clicked, side panel shall show events/detections/kill-chain stage/IOCs.
- Where entity has zero detections, system shall dim/cluster it with toggle to include benign.

### C. Cinematic Demo Mode
- Backend shall expose per-job stage milestones (`uploaded..exported`) in job status.
- When Demo Mode starts, frontend shall sequentially process 4 bundled scenarios, advancing narration only on real milestone events showing actual numbers.
- When scenarios finish, summary board totals shall exactly equal Dashboard cards.

### D. Ask-the-Data Search Bar
- When a query is submitted, backend shall parse intents (severity/threat-type/time-window/IP-entity/IOC-type/PII-status) deterministically via keyword/regex.
- API shall return parsed chips AND matching rows from processed data only.
- Where zero intents match, system shall fall back to normalized-message full-text search labeled "fallback text match".

### E. PDF Threat Report
- When report export requested, generator shall produce branded multi-page PDF: exec summary, findings table (threat/source/target/severity/confidence/ATT&CK refs), evidence appendix, risk breakdowns, embedded reportlab-graphics charts.
- All figures shall be read from DB at generation time; file validated (opens, >=4 pages) before serving.

## Non-Functional
- Offline-first: cytoscape bundled into Vite build; no CDN/external APIs.
- Perf: graph interactive <=2s @10k nodes; search p95 <500ms @100k events; PDF <5s typical.
- Determinism: identical input -> identical outputs across A–E.
- Security: all five surfaces route `privacy.apply_policy()`; parameterized SQL; license-clean deps only.

## Acceptance Criteria
1. Given brute-force sample processed, When Kill-Chain view opens, Then `185.23.45.67` shows Credential Access achieved (T1110 badge) advancing to Execution after correlated suspicious command; clicking Credential Access lists 3 failed + 1 successful SSH events with timestamps.
2. Given same dataset, When Attack Graph opens, Then attacker->admin edge severity-red labeled `BRUTE_FORCE_001`; attacker node click shows evidence panel.
3. Given fresh state, When Cinematic Demo runs, Then all 4 scenarios complete with live milestone narration and final summary == dashboard cards.
4. Given HIGH auth attacks within last hour, When `"show me all high-risk authentication attacks from the last hour"` submitted, Then chips `[severity=HIGH][type≈auth][window=last 1h]` render and results exactly equal equivalent Explorer filter.
5. Given any correlation, When Download Report clicked, Then valid multi-page PDF arrives <5s with counts matching dashboard.

## Error Handling
| Case | Behavior |
|---|---|
| Scenario fails mid-demo | Overlay Resume/Retry; continue at failed scenario |
| Unparseable query | Fallback text search + explicit notice chip |
| Rule lacks ATT&CK mapping | `UNMAPPED` badge + server warning log |
| Graph >50k entities | Auto-cluster low-degree benign nodes + toast |
| PDF generation error | 500 JSON error; partial file discarded, never served |
| Job deleted while viewed | stale-data banner + reprocess link |

## Implementation Phases
W1 mapping+enrichment+killchain API · W2 Threats UI bars · W3 graph endpoint+cytoscape page ·
W4 intent parser+chips · W5 demo orchestrator+milestones · W6 reportlab exporter ·
W7 tests + rehearsal (folded into P15).
