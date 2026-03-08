# CyberVulnDB v2.0 — Complete Project Documentation

## Overview

CyberVulnDB is a real-time cybersecurity intelligence dashboard built with vanilla JavaScript, HTML, and CSS. It aggregates threat data from 15+ free public APIs and displays CVEs, malware/ransomware, APT groups, and security news in a terminal-styled dark UI with a Leaflet.js world map showing threat origins.

**Live URL:** https://1yuub.github.io  
**Stack:** Pure HTML/CSS/JS — no frameworks, no backend, no build tools  
**Architecture:** Client-side IIFE modules, CORS proxy fallback chains, localStorage caching

---

## What Was Built (Complete History)

### Phase 1: Initial Assessment & Bug Fixes
- Explored full project structure, started HTTP test servers
- Ran 6 Playwright tests — all passed
- Found: 20 CVEs from NVD, 5 mock ransomware, 5 mock APT, 0 news (broken feeds)
- **Fixed:** News feeds were broken — added HackerNews Algolia API + 10 RSS feeds with 3-proxy fallback chain
- Result: 60 live news items from 7+ sources

### Phase 2: CVE Real-Time Enhancement
- Added `fetchCVEsOnly()` for panel-only refresh every 2 minutes
- Rewrote `timeAgo()` to show relative time ("5m ago", "3h 12m ago") or exact date for items >2 days old
- Added NEW badge for freshly detected CVEs
- Implemented cvelistV5 (GitHub commits API) as primary source — parses commit messages for new CVE IDs, fetches individual JSON files — **0 lag**
- Added GitHub Advisory as secondary (1-day lag), NVD as tertiary (5-7 day lag)

### Phase 3: v2.0 Multi-Source Expansion
Deployed 4 parallel agents to implement:
- **Phase 1:** Multi-source CVE — 4 sources (CVEProject, GitHub Advisory, NVD, CVE.org) + EPSS enrichment + KEV badges
- **Phase 2:** Multi-source Malware — 5 sources (ransomware.live, URLhaus, ThreatFox, InQuest, HIBP) + source dropdown
- **Phase 3:** Live APT Intelligence — MISP Galaxy (953 actors) + RSS feeds from Mandiant/CrowdStrike/Kaspersky
- **Phase 4:** News Source Selector — 10 RSS feeds with per-outlet dropdown and source badges

### Phase 4: Design Enhancements (4 parallel agents)
- EPSS exploit probability badges on CVE cards (color-coded: critical >10%, high >5%, medium >1%, low)
- KEV "Exploited in Wild" badge with pulse animation on applicable CVEs
- Source badges on malware and APT cards showing data origin
- Statistics bar between header and content (CVE count, critical count, malware, APT, news)
- Glassmorphism hover effects on threat cards
- Keyboard shortcuts: 1-4 for tabs, R for refresh, S for search, Escape to close modals

### Phase 5: UI Polish & Count Selectors
- Fixed critical CSS bug: `flex-shrink: 0` on `.threat-card` — cards were being compressed to 26px by flex container
- Renamed dropdown labels: "All Sources" (removed "Merged"), "Smart Auto" (removed icon)
- Added dark-themed `option` styling for select dropdowns
- Added count selectors (10/50/100, default 50) for all 4 panels
- Increased default CVE fetch from 30 → 50

---

## Data Sources — Complete Reference

### CVE Sources (4 active)

| Source | API | Lag | CORS | Status |
|--------|-----|-----|------|--------|
| **CVEProject/cvelistV5** | GitHub commits API → individual CVE JSON | **0 lag** (real-time) | ✅ | ✅ Working — primary source |
| **GitHub Advisory** | `api.github.com/advisories` | ~1 day | ✅ | ✅ Working — 30 advisories |
| **NVD (NIST)** | `services.nvd.nist.gov/rest/json/cves/2.0` | 5-7 days | ✅ | ✅ Working — 30 CVEs |
| **CVE.org (MITRE)** | `cveawg.mitre.org/api/cve/{id}` | 0 lag | ✅ | ⚠️ Partial — list endpoint broken (returns 400), individual endpoint works |

**Enrichment:**
- **EPSS (first.org)** — Batch query exploit probability scores. CORS ✅. Shows colored badge on each CVE card.
- **CISA KEV** — 1536 known exploited vulnerabilities. Shows "Exploited in Wild" badge with pulse animation.

**How CVE merge works:**
1. All 4 sources fetched in parallel via `Promise.allSettled()` — each source has an 8-15s timeout
2. Results collected into a single array; deduplicated by CVE ID using a `Set` — first source wins
3. Priority order: CVEProject → GitHub Advisory → NVD → CVE.org (real-time sources first)
4. Each CVE object tagged with `_source` field (e.g., `_source: 'NVD'`)
5. Sorted by `published` date, newest first
6. Enriched with EPSS exploit probability scores via batch API call to first.org
7. Limited to user-selected count (10/50/100)
8. When user selects a specific source from dropdown, only that source is fetched (skips merge)

**How Malware merge works:**
1. 5 sources fetched in parallel: ransomware.live, URLhaus, ThreatFox, InQuest, HIBP
2. Simple concatenation (no deduplication — different data types per source)
3. Each item already has `source` field from its fetcher
4. Sorted by `discovered` date, newest first
5. Limited to count selector value

**How APT merge works:**
1. MISP Galaxy (primary: 953 actors) + RSS feeds (secondary) fetched in parallel
2. Simple concatenation — MISP actors listed first, then RSS items
3. MISP actors sorted: those with country attribution first, then alphabetical
4. Each APT has `country` field (ISO 2-letter code) mapped to lat/lng for map placement

**How News merge works:**
1. 10 RSS feeds + HackerNews Algolia API queried in parallel
2. Each feed goes through 3-proxy fallback chain (rss2json → allorigins → corsproxy)
3. Deduplicated by normalized title (lowercase, stripped punctuation)
4. Sorted by publish date, newest first

**NVD Date Fix (Critical):**
NVD API returns results in ASCENDING order (oldest first) with no way to reverse. Our fix uses a 2-step approach:
- Step 1: Count query with `resultsPerPage=1` to get `totalResults` count
- Step 2: Fetch with `startIndex = totalResults - limit` to get the NEWEST entries
- Window: last 7 days (yields ~1400 results; fetching from the end gives today's CVEs)

**Why dates may show older than today:**
CVEs have a `published` date that reflects when the vulnerability was originally disclosed, NOT when the API indexed it. NVD may add a CVE to its feed today, but the CVE itself was published days or weeks ago. cvelistV5 gives the most recent CVEs, but during quiet periods even those may be hours/days old. The dates shown are the real publication dates — this is correct behavior.

### Malware Sources (5 active)

| Source | API | CORS | Status |
|--------|-----|------|--------|
| **ransomware.live** | `/v1/recentvictims` — 50 recent victims | ❌ needs proxy | ✅ Working via corsproxy |
| **URLhaus (abuse.ch)** | `/downloads/json_recent/` — malicious URLs | ❌ needs proxy | ⚠️ Often fails — all proxies timeout |
| **ThreatFox (abuse.ch)** | `/export/json/recent/` — IOCs | ❌ needs proxy | ✅ Working — 50 IOCs |
| **InQuest Labs** | `/api/iocdb/list?limit=50` — IOC database | ✅ | ✅ Working — 50 IOCs |
| **HIBP** | `/api/v3/breaches` — 600+ data breaches | ✅ (needs User-Agent) | ⚠️ Inconsistent |

### APT Sources (3 active)

| Source | API | CORS | Status |
|--------|-----|------|--------|
| **MISP Galaxy** | GitHub raw JSON — 953 threat actors | ✅ | ✅ Working — 30-min cache |
| **MITRE ATT&CK (Curated)** | Static dataset in code | N/A | ✅ Working — 15 groups |
| **RSS Feeds** | Mandiant, CrowdStrike, Kaspersky blogs | ❌ needs proxy | ⚠️ Depends on proxy |

**APT on map:** All displayed APT groups are plotted on the Leaflet map using their country's coordinates (2-letter ISO → lat/lng lookup).

### News Sources (10 RSS feeds + 1 API)

| Source | Status |
|--------|--------|
| **The Hacker News** | ✅ Usually works via proxy chain |
| **Krebs on Security** | ✅ Works via corsproxy |
| **Dark Reading** | ✅ Works via corsproxy |
| **SecurityWeek** | ✅ Works via allorigins |
| **SANS ISC** | ✅ Works via corsproxy |
| **Malwarebytes** | ✅ Works via corsproxy |
| **Threatpost** | ✅ Works via corsproxy |
| **BleepingComputer** | ⚠️ Often blocked |
| **Schneier** | ⚠️ Often fails all proxies |
| **Wired Security** | ⚠️ Often fails all proxies |
| **HackerNews Algolia** | ⚠️ Inconsistent results |

**Typical result:** 40-70 unique articles after deduplication.

---

## What Works Well

1. **CVE pipeline** — cvelistV5 gives true real-time CVEs with 0 lag. EPSS enrichment adds exploit probability.
2. **MISP Galaxy** — 953 threat actors with country codes, aliases, target sectors. Single reliable API call.
3. **News aggregation** — 3-proxy fallback chain makes 7-8/10 feeds work consistently.
4. **ransomware.live** — 50 recent ransomware victims with group attribution.
5. **ThreatFox + InQuest** — 100 IOCs (malicious domains, IPs, hashes).
6. **Map visualization** — Threat markers plotted globally for CVEs, ransomware, and APT groups.
7. **Count selectors** — Users can choose 10/50/100 items per panel. Default 50.
8. **Source selectors** — Every panel has a dropdown to filter by individual source or see all.
9. **Keyboard shortcuts** — Quick navigation (1-4 tabs, R refresh, S search).
10. **Caching** — 15-min localStorage cache prevents redundant API calls.

## What Doesn't Work / Known Issues

1. **URLhaus** — All CORS proxies frequently timeout. Returns 0 items ~70% of the time.
2. **HIBP** — Requires specific User-Agent header that proxies may strip.
3. **CVE.org list endpoint** — Returns 400 for all query parameters. Only individual CVE lookup works.
4. **GitHub API rate limit** — 60 req/hour unauthenticated. Can hit 403 during rapid use.
5. **Schneier, Wired, BleepingComputer RSS** — Often blocked by all proxy services.
6. **HackerNews Algolia** — Sometimes returns 0 results for cybersecurity queries.
7. **allorigins.win** — Periodically goes down, causing CORS errors (non-critical due to fallback chain).
8. **Loading time** — Full load takes 15-35 seconds depending on proxy availability.

---

## Architecture

### Module Pattern
```
js/api.js   — IIFE module, all API logic, returns API object
js/app.js   — IIFE module, render functions, event handlers, UI logic
js/map.js   — MapManager IIFE, Leaflet map setup, marker management
js/ui.js    — UI utilities (toast, loading overlay, status bar)
js/utils.js — Shared utilities (localStorage helpers, date formatting)
```

### CORS Proxy Chain
```
RSS feeds:  rss2json.com → allorigins.win → corsproxy.io
Other APIs: corsproxy.io → allorigins.win → codetabs.com → direct
```

### Caching Strategy
- localStorage key: `cybervulndb_data_v8`, TTL: 15 minutes
- MISP Galaxy: in-memory, 30-min TTL
- KEV catalog: in-memory, 1-hour TTL
- Script cache-busting: `?v=10` on all script/style tags

### Auto-Refresh
- CVE panel: every 2 minutes
- News panel: every 3 minutes
- Full data reload: every 5 minutes

---

## File Structure

```
index.html      — Main page (~280 lines) — stats bar, 4 panels with dropdowns, map
css/style.css   — Styles (~1660 lines) — dark terminal theme, badges, animations
js/api.js       — API module (~1300 lines) — all data fetching and caching
js/app.js       — App logic (~900 lines) — rendering, filters, modals, keyboard shortcuts
js/map.js       — Map module (~100 lines) — Leaflet map, markers, legend
js/ui.js        — UI helpers (~80 lines) — toast, loading, status
js/utils.js     — Utilities (~50 lines) — storage, date formatting
lib/leaflet/    — Leaflet.js library (local copy)
data/           — Static data files (countries.json, etc.)
SPEC.md         — v2.0 specification document
test_app.py     — 6 Playwright tests
```

---

## Current Status (March 8, 2026)

| Feature | Status | Details |
|---------|--------|---------|
| CVE Panel | ✅ Live | 30-50 CVEs from 4 sources + EPSS + KEV |
| Malware Panel | ✅ Live | 50 items from ransomware.live + ThreatFox + InQuest |
| APT Panel | ✅ Live | 50 groups from MISP Galaxy (953 available) |
| News Panel | ✅ Live | 50 articles from 7-8 RSS feeds |
| Source Selectors | ✅ Done | All 4 panels have source dropdowns |
| Count Selectors | ✅ Done | 10/50/100 on all panels, default 50 |
| Stats Bar | ✅ Done | CVE count, critical, malware, APT, news |
| Map | ✅ Done | CVE, ransomware, APT markers plotted with popups |
| EPSS Badges | ✅ Done | Color-coded exploit probability |
| KEV Badges | ✅ Done | "Exploited in Wild" with pulse animation |
| Keyboard Shortcuts | ✅ Done | 1-4 tabs, R, S, Esc |
| Dark Theme | ✅ Done | Terminal-styled with cyan/green accents |
