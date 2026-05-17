# Implementation vs Spec Documentation Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace stale claims in `IMPLEMENTATION_VS_SPEC.md` with an accurate current-state comparison against `SPEC.md` and the actual browser app code.

**Architecture:** This is a documentation-only change. The source of truth is current code in `index.html`, `js/api.js`, `js/app.js`, `js/map.js`, `js/ui.js`, `js/utils.js`, plus `issues.md` for resolved-risk status. The refreshed document should separate intentional architecture mismatches from implemented features, partial features, and true gaps.

**Tech Stack:** Markdown documentation, vanilla JavaScript app, Leaflet map, browser localStorage cache, Playwright smoke test metadata.

---

## File Structure

- Modify: `IMPLEMENTATION_VS_SPEC.md`
- Read-only verification: `SPEC.md`
- Read-only verification: `issues.md`
- Read-only verification: `README.md`
- Read-only verification: `index.html`
- Read-only verification: `js/api.js`
- Read-only verification: `js/app.js`
- Read-only verification: `js/map.js`
- Read-only verification: `test_app.py`

---

### Task 1: Establish Current Implementation Facts

**Files:**
- Read: `index.html`
- Read: `js/api.js`
- Read: `js/app.js`
- Read: `js/map.js`
- Read: `issues.md`

- [ ] **Step 1: Verify implemented data source selectors**

Run:

```bash
rg -n "cve-source-filter|malware-source-filter|news-source-filter|apt-source-filter|cve-time-filter|malware-time-filter|news-time-filter|apt-time-filter" index.html
```

Expected: output includes all four source selectors and all four time range selectors.

- [ ] **Step 2: Verify current API implementation**

Run:

```bash
rg -n "fetchCVEsFromNVD|fetchKEV|enrichWithEPSS|fetchAllMalwareSources|fetchMISPGalaxy|fetchNewsBySource|fetchAPTBySource|mapWithConcurrency|loadAllData" js/api.js
```

Expected: output confirms live NVD, KEV, EPSS, malware source merge, MISP Galaxy, source-specific news/APT fetchers, bounded concurrency, and main loader exist.

- [ ] **Step 3: Verify current app behavior implementation**

Run:

```bash
rg -n "Object.defineProperty\\(window, 'cyberData'|beginPanelRequest|isPanelRequestStale|refreshCVEPanel|refreshNewsPanel|refetchCVESource|toggleHeatmap|initSearch|initKeyboardShortcuts" js/app.js js/map.js
```

Expected: output confirms read-only global data snapshot, stale request guards, live panel refreshes, heatmap toggle, search, and keyboard shortcuts exist.

- [ ] **Step 4: Record exact fact summary for the rewrite**

Use this summary in the document:

```markdown
- Architecture is intentionally vanilla HTML/CSS/JS, not Next.js/React/TypeScript.
- State is still browser-global for test/UI read access, but `window.cyberData` is exposed as a read-only getter backed by internal immutable snapshots.
- CVE sources implemented: CVEProject/cvelistV5, GitHub Advisory, NVD API 2.0, CVE.org, FIRST EPSS enrichment, CISA KEV enrichment.
- Malware/threat sources implemented: ransomware.live recent victims, URLhaus, ThreatFox, InQuest Labs, HIBP, plus curated fallback.
- APT sources implemented: MISP Galaxy, curated static ATT&CK-style dataset, Mandiant RSS, CrowdStrike RSS, Securelist RSS.
- News sources implemented: HackerNews Algolia plus RSS feeds for The Hacker News, Krebs, BleepingComputer, SANS ISC, SecurityWeek, Dark Reading, Malwarebytes, Threatpost, Schneier, Wired Security.
- Map implementation is Leaflet 2D only; 3D globe, deck.gl, and MapLibre are not implemented.
- Heatmap toggle exists as marker-cluster circle overlay, not a true weighted heatmap library.
- AI-powered briefs, entity extraction, read/unread tracking, trend charts, ATT&CK Navigator, and 3D globe remain unimplemented.
- Open issue status in `issues.md`: 73 tracked, 72 solved, 1 partial, 0 open; the partial item is CORS proxy trust.
```

---

### Task 2: Replace the Stale Feature Tables

**Files:**
- Modify: `IMPLEMENTATION_VS_SPEC.md`

- [ ] **Step 1: Replace the document title and status note**

Replace the first heading and add this header:

```markdown
# Implementation vs Specification Analysis

> Last updated: 2026-05-17.
> Source of truth: current `index.html`, `js/*.js`, `SPEC.md`, and `issues.md`.
> This document describes the current vanilla-JS implementation. It does not imply that the project has migrated to the larger Next.js/React architecture described as a possible target in older planning notes.
```

- [ ] **Step 2: Replace the Architecture Mismatch section**

Use this exact table:

```markdown
## Architecture Alignment

| SPEC / Target Area | Current Implementation | Status |
|--------------------|------------------------|--------|
| Browser app stack | Vanilla JavaScript IIFE modules loaded from `index.html` | ✅ Current implementation |
| Framework target from earlier planning | No Next.js, React, Zustand, or TypeScript | ❌ Not implemented |
| State management | Internal immutable snapshots exposed through read-only `window.cyberData` getter | ⚠️ Partial |
| Map stack | Leaflet.js 2D map with CartoDB dark tiles | ✅ Implemented |
| 3D globe / deck.gl / MapLibre target | Not present; map remains Leaflet-only | ❌ Not implemented |
| Styling | Single global `css/style.css` with CSS variables and terminal theme | ✅ Implemented |
| Build/deploy model | Static GitHub Pages style app, no build step | ✅ Implemented |
```

- [ ] **Step 3: Replace CVE Tracking System table**

Use this exact table:

```markdown
### 1. CVE Tracking System

| Feature | Current Status | Evidence / Notes |
|---------|----------------|------------------|
| NVD API 2.0 integration | ✅ Implemented | `fetchCVEsFromNVD()` queries `services.nvd.nist.gov/rest/json/cves/2.0` with date/severity filters |
| cvelistV5 integration | ✅ Implemented | GitHub commits + raw CVE JSON fetch path |
| GitHub Advisory integration | ✅ Implemented | `api.github.com/advisories` source path |
| CVE.org integration | ✅ Implemented | `cveawg.mitre.org/api/cve/{id}` source path |
| CISA KEV enrichment | ✅ Implemented | `fetchKEV()`, `isInKEV()`, `getKEVDetails()` |
| EPSS enrichment | ✅ Implemented | `enrichWithEPSS()` batches against `api.first.org/data/v1/epss` |
| CVSS severity filter | ✅ Implemented | `#cve-severity-filter` and `currentSeverityFilter` |
| Date range filters | ✅ Implemented | `#cve-time-filter` supports `24h`, `1w`, `1m` |
| Vendor/Product CPE display | ✅ Implemented for NVD/GitHub-derived data | Modal shows CPE list when provided |
| CVE detail modal | ✅ Implemented | Shows severity, EPSS, KEV, description, vector, CPE, references |
| Trend charts | ❌ Not implemented | No charting library or chart panel |
```

- [ ] **Step 4: Replace Malware/Ransomware table**

Use this exact table:

```markdown
### 2. Malware & Ransomware Monitor

| Feature | Current Status | Evidence / Notes |
|---------|----------------|------------------|
| ransomware.live victims | ✅ Implemented | `fetchLiveRansomware()` with proxy fallbacks |
| URLhaus malicious URLs | ✅ Implemented | `fetchURLhaus()` |
| ThreatFox recent IOCs | ✅ Implemented | `fetchThreatFox()` |
| InQuest Labs IOC DB | ✅ Implemented | `fetchInQuestIOCs()` |
| HIBP breaches | ✅ Implemented | `fetchHIBPBreaches()` |
| All-sources merge | ✅ Implemented | `fetchAllMalwareSources()` with bounded concurrency |
| Source selector | ✅ Implemented | `#malware-source-filter` |
| Time range selector | ✅ Implemented | `#malware-time-filter` |
| Ransomware group profile pages | ❌ Not implemented | Cards open detail modal only |
| Revenue/employees/status enrichment | ❌ Not implemented | Not present in normalized data model |
```

- [ ] **Step 5: Replace APT Intelligence table**

Use this exact table:

```markdown
### 3. APT Intelligence

| Feature | Current Status | Evidence / Notes |
|---------|----------------|------------------|
| MISP Galaxy threat actors | ✅ Implemented | `fetchMISPGalaxy()` loads `threat-actor.json` |
| Curated static ATT&CK-style actors | ✅ Implemented | `getMockAPT()` fallback/static source |
| APT RSS activity | ✅ Implemented | Mandiant, CrowdStrike, Securelist via `fetchAPTNews()` |
| Source selector | ✅ Implemented | `#apt-source-filter` |
| Time range selector | ✅ Implemented for RSS plus scaled static slice | `fetchAllAPTSources()` filters dated RSS and scales MISP count |
| Country flags / aliases / sectors | ✅ Implemented | Rendered in cards and map popups when data exists |
| Attack flow lines | ✅ Implemented | `MapManager.addAttackLine()` |
| MITRE ATT&CK STIX live integration | ❌ Not implemented | No STIX bundle parser/source |
| Technique heatmap / ATT&CK Navigator | ❌ Not implemented | No ATT&CK matrix UI |
```

- [ ] **Step 6: Replace News and Threat Map tables**

Use these exact tables:

```markdown
### 4. Security News Aggregation

| Feature | Current Status | Evidence / Notes |
|---------|----------------|------------------|
| RSS feed aggregation | ✅ Implemented | 10 RSS feeds in `RSS_FEEDS` |
| HackerNews Algolia fallback/source | ✅ Implemented | `fetchHackerNews()` |
| Proxy fallback chain | ✅ Implemented | rss2json → allorigins → corsproxy |
| Source selector | ✅ Implemented | `#news-source-filter` |
| Time range selector | ✅ Implemented | `#news-time-filter` |
| Deduplication | ✅ Implemented | Normalized URL dedupe in `fetchAllNews()` |
| Entity extraction / CVE linking | ❌ Not implemented | No entity extraction pipeline |
| Read/unread tracking | ❌ Not implemented | No persisted article read state |

### 5. Threat Map

| Feature | Current Status | Evidence / Notes |
|---------|----------------|------------------|
| 2D map | ✅ Implemented | Leaflet map initialized in `MapManager.init()` |
| Custom markers | ✅ Implemented | CVE, ransomware, APT marker types |
| Rich popups | ✅ Implemented | `buildPopupContent()` escapes popup fields |
| APT labels | ✅ Implemented | `MapManager.addLabel()` |
| Attack flow lines | ✅ Implemented | `MapManager.addAttackLine()` |
| Heatmap toggle | ⚠️ Partial | Implemented as circle-cluster overlay, not a true heatmap engine |
| 3D globe | ❌ Not implemented | No globe.gl/Three.js integration |
| Country detail hover panel | ❌ Not implemented | Leaflet tooltips exist, no country detail panel |
```

---

### Task 3: Replace Stale Bug and Recommendation Sections

**Files:**
- Modify: `IMPLEMENTATION_VS_SPEC.md`

- [ ] **Step 1: Delete outdated “Critical Logic Issues Found”**

Remove the old issue list that says severity null checks, marker clearing, search reset, and localStorage error handling are still broken.

- [ ] **Step 2: Add current known-risk section**

Insert this exact section:

```markdown
## Current Known Risks

| Risk | Status | Notes |
|------|--------|-------|
| CORS proxy trust | ⚠️ Partial | Browser-only RSS/proxy fetching cannot fully verify upstream/proxy integrity without a trusted backend. API data is escaped before rendering, but data authenticity is still limited by source/proxy trust. |
| Public API rate limits | ✅ Mitigated | Source fanout uses bounded concurrency via `mapWithConcurrency()`, but unauthenticated public APIs can still throttle or fail. |
| Browser-only architecture | ⚠️ Intentional tradeoff | No server means simpler hosting but weaker control over CORS, caching, auth, and data validation. |
| Test coverage | ⚠️ Partial | Playwright smoke test exists and skips cleanly if Playwright is absent; unit tests for mapping/filter helpers are still absent. |
```

- [ ] **Step 3: Add accurate recommendations**

Insert this exact section:

```markdown
## Recommendations

### High Priority
1. Add a small trusted backend/proxy if data integrity, API auth, or reliable CORS behavior matters.
2. Add unit tests for `api.js` mapping functions, source filters, search filtering, and cache snapshot trimming.
3. Keep `issues.md` as the operational issue tracker and update this document only for implementation-vs-spec drift.

### Medium Priority
1. Decide whether the project should remain a static vanilla-JS app or migrate to the larger Next.js/TypeScript architecture from earlier planning.
2. Add entity extraction for news articles so CVEs/APT names can link across panels.
3. Add real charting/trend views if analyst reporting is a product goal.

### Low Priority
1. Add 3D globe mode only if it has a clear analyst use case; Leaflet currently covers the core map workflow.
2. Add read/unread tracking for news if the dashboard becomes a daily workflow tool.
3. Split large source files if future changes make `api.js` or `app.js` harder to maintain.
```

---

### Task 4: Verify the Updated Document

**Files:**
- Read: `IMPLEMENTATION_VS_SPEC.md`

- [ ] **Step 1: Check stale false claims are gone**

Run:

```bash
rg -n "No KEV data fetched|No EPSS scores|Uses fallback data, not live API|Heatmap toggle exists but non-functional|MapManager.clearMarkers\\(\\) is never called|Silently fails on quota errors|No source selector" IMPLEMENTATION_VS_SPEC.md
```

Expected: no output.

- [ ] **Step 2: Check current facts are present**

Run:

```bash
rg -n "fetchCVEsFromNVD|fetchKEV|enrichWithEPSS|fetchAllMalwareSources|fetchMISPGalaxy|mapWithConcurrency|read-only `window.cyberData`|73 tracked" IMPLEMENTATION_VS_SPEC.md
```

Expected: output includes each current implementation marker.

- [ ] **Step 3: Check Markdown structure**

Run:

```bash
rg -n "^#|^##|^###|\\| Feature \\| Current Status \\| Evidence / Notes \\|" IMPLEMENTATION_VS_SPEC.md
```

Expected: headings are ordered and feature tables use the current status/evidence format.

- [ ] **Step 4: Commit the documentation refresh**

Run:

```bash
git add IMPLEMENTATION_VS_SPEC.md docs/superpowers/plans/2026-05-17-update-implementation-vs-spec.md
git commit -m "docs: refresh implementation vs spec analysis"
```

Expected: commit succeeds if the user wants the changes committed. If the user did not request a commit, skip this step and report the modified files.

---

## Self-Review

Spec coverage:
- CVE, malware, APT, news, map, UI architecture, risks, and recommendations are covered.
- The plan intentionally does not implement missing features; it updates documentation to reflect current implementation.

Placeholder scan:
- No `TBD`, `TODO`, “similar to,” or undefined follow-up work appears in execution steps.

Type/path consistency:
- All referenced files exist in the repository.
- All function and selector names match current code discovered with `rg`.
