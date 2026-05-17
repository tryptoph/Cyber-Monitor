# Implementation vs Specification Analysis

> Last updated: 2026-05-17.
> Source of truth: current `index.html`, `js/*.js`, `SPEC.md`, and `issues.md`.
> This document describes the current vanilla-JS implementation. It does not imply that the project has migrated to the larger Next.js/React architecture described as a possible target in older planning notes.

## Architecture Alignment

| SPEC / Target Area | Current Implementation | Status |
|--------------------|------------------------|--------|
| Browser app stack | Vanilla JavaScript IIFE modules loaded from `index.html` | ✅ Current implementation |
| Framework target from earlier planning | No Next.js, React, Zustand, or TypeScript | ❌ Not implemented |
| State management | Internal shallow-frozen snapshots exposed through a read-only `window.cyberData` getter | ⚠️ Partial |
| Map stack | Leaflet.js 2D map with CartoDB dark tiles | ✅ Implemented |
| 3D globe / deck.gl / MapLibre target | Not present; map remains Leaflet-only | ❌ Not implemented |
| Styling | Single global `css/style.css` with CSS variables and terminal theme | ✅ Implemented |
| Build/deploy model | Static GitHub Pages style app, no build step | ✅ Implemented |

## Feature Implementation Status

### 1. CVE Tracking System

| SPEC Feature | Current Implementation | Status |
|--------------|------------------------|--------|
| NVD API 2.0 | Live NVD integration via `fetchCVEsFromNVD()` | ✅ Implemented |
| cvelistV5 | Included in multi-source CVE collection | ✅ Implemented |
| GitHub Advisory | Included in multi-source CVE collection | ✅ Implemented |
| CVE.org | Included in multi-source CVE collection | ✅ Implemented |
| CISA KEV | Live KEV catalog lookup via `fetchKEV()` | ✅ Implemented |
| EPSS | CVE enrichment via `enrichWithEPSS()` | ✅ Implemented |
| CVSS severity filter | Severity dropdown filters CVE results | ✅ Implemented |
| Date range filters | Time range selector controls CVE queries | ✅ Implemented |
| Vendor/product CPE display | NVD CPE values and GitHub package identifiers are displayed in the affected-products field | ✅ Implemented |
| CVE detail modal | Detail modal renders selected vulnerability data | ✅ Implemented |
| Trend charts | No charting or trend visualization view | ❌ Not implemented |

### 2. Malware & Ransomware Monitor

| SPEC Feature | Current Implementation | Status |
|--------------|------------------------|--------|
| ransomware.live | Live ransomware victim source | ✅ Implemented |
| URLhaus | Malware URL feed source | ✅ Implemented |
| ThreatFox | IOC/malware intelligence source | ✅ Implemented |
| InQuest Labs | Malware intelligence source | ✅ Implemented |
| Have I Been Pwned | Breach feed source | ✅ Implemented |
| All-sources merge | Combined source path via `fetchAllMalwareSources()` | ✅ Implemented |
| Source selector | Malware source dropdown filters source-specific data | ✅ Implemented |
| Time range selector | Malware time range filter controls displayed records | ✅ Implemented |
| Group profile pages | No dedicated ransomware group profile pages | ❌ Not implemented |
| Revenue/employees/status enrichment | No live enrichment for victim revenue, employee count, or incident status | ❌ Not implemented |

### 3. APT Intelligence

| SPEC Feature | Current Implementation | Status |
|--------------|------------------------|--------|
| MISP Galaxy | Live MISP Galaxy actor ingestion via `fetchMISPGalaxy()` | ✅ Implemented |
| Curated static ATT&CK-style actors | Static actor data supplements live sources | ✅ Implemented |
| APT RSS activity | RSS-backed activity collection via `fetchAPTNews()` | ✅ Implemented |
| Source selector | APT source dropdown filters actor/activity source | ✅ Implemented |
| Time range selector | APT time range filter controls displayed activity | ✅ Implemented |
| Country flags/aliases/sectors | Actor metadata includes country flags, aliases, and sectors | ✅ Implemented |
| Attack flow lines | Actor/victim geography can render map flow lines | ✅ Implemented |
| MITRE ATT&CK STIX live integration | No live ATT&CK STIX ingestion | ❌ Not implemented |
| Technique heatmap / ATT&CK Navigator | No technique heatmap or Navigator export/view | ❌ Not implemented |

### 4. Security News Aggregation

| SPEC Feature | Current Implementation | Status |
|--------------|------------------------|--------|
| RSS aggregation | Multiple RSS feeds are fetched and normalized | ✅ Implemented |
| HackerNews Algolia | HackerNews search/source integration is present | ✅ Implemented |
| Proxy fallback chain | RSS fetching uses proxy fallbacks for browser CORS limits | ✅ Implemented |
| Source selector | News source dropdown filters source-specific data | ✅ Implemented |
| Time range selector | News time range filter controls displayed records | ✅ Implemented |
| Deduplication | News items are deduplicated during normalization/merge | ✅ Implemented |
| Entity extraction / CVE linking | No robust entity extraction or automatic cross-panel CVE/APT linking | ❌ Not implemented |
| Read/unread tracking | No persistent read/unread state | ❌ Not implemented |

### 5. Threat Map

| SPEC Feature | Current Implementation | Status |
|--------------|------------------------|--------|
| 2D map | Leaflet.js map renders the threat geography view | ✅ Implemented |
| Custom markers | Custom marker styling distinguishes data types | ✅ Implemented |
| Rich popups | Popups show contextual threat details | ✅ Implemented |
| APT labels | APT actors can be labeled on the map | ✅ Implemented |
| Attack flow lines | Flow lines visualize selected attack paths | ✅ Implemented |
| Heatmap toggle | Circle-cluster style overlay exists, but it is not a true weighted heatmap | ⚠️ Partial |
| 3D globe | No globe mode | ❌ Not implemented |
| Country detail hover panel | No dedicated country hover detail panel | ❌ Not implemented |

### 6. AI-Powered Briefs

| SPEC Feature | Current Implementation | Status |
|--------------|------------------------|--------|
| Ollama | No local Ollama integration | ❌ Not implemented |
| Groq | No Groq fallback integration | ❌ Not implemented |
| Transformers.js | No in-browser Transformers.js summarization | ❌ Not implemented |
| Daily threat brief | No generated daily brief workflow | ❌ Not implemented |
| AI summaries | No AI-generated summaries | ❌ Not implemented |

## Issue Tracker Status

`issues.md` is the current operational issue tracker. It tracks 73 issues: 72 solved, 1 partial, 0 open. The remaining partial item is CORS proxy trust.

## Current Known Risks

| Risk | Status | Notes |
|------|--------|-------|
| CORS proxy trust | ⚠️ Partial | Browser-only RSS/proxy fetching cannot fully verify upstream/proxy integrity without a trusted backend; most displayed text fields are escaped, but this remains a browser-only/proxy trust risk and should not be treated as a complete integrity or XSS guarantee. |
| Public API rate limits | ✅ Mitigated | Bounded concurrency via `mapWithConcurrency()` reduces burst pressure, but public APIs can still throttle or fail. |
| Browser-only architecture | Intentional tradeoff | Static hosting is simpler, but CORS, caching, API auth, and data validation control are weaker than with a backend. |
| Test coverage | ⚠️ Partial | pytest smoke test skips if Playwright is absent; direct script execution requires Playwright; unit tests for mapping/filter helpers are absent. |

## Recommendations

### High Priority

1. Add small trusted backend/proxy if data integrity, API auth, or reliable CORS behavior matters.
2. Add unit tests for `api.js` mapping functions, source filters, search filtering, cache snapshot trimming.
3. Keep `issues.md` as operational issue tracker and update this doc only for implementation-vs-spec drift.

### Medium Priority

1. Decide whether project remains static vanilla JS or migrates to Next.js/TypeScript architecture.
2. Add entity extraction for news articles so CVEs/APT names can link across panels.
3. Add real charting/trend views if analyst reporting is a product goal.

### Low Priority

1. Add 3D globe only if clear analyst use case.
2. Add read/unread tracking if dashboard becomes daily workflow tool.
3. Split large source files if future changes make `api.js` or `app.js` harder to maintain.
