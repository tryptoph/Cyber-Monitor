# CyberVulnDB — Issue Tracker

> Maintained from codebase analysis. Last updated: 2026-05-17.
> Status: ✅ Solved | ❌ Open | ⚠️ Partial

---

## 🔴 Security / XSS

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 1 | app.js | ~68–85 | `updateThreatTicker` injects unescaped API data (APT names, CVE IDs, news titles) into innerHTML — XSS | ✅ Solved |
| 2 | app.js | ~819 | `showAPTModal` — `apt.name` inserted unescaped into innerHTML while other fields are escaped — inconsistent XSS protection | ✅ Solved |
| 3 | api.js | ~1003 | `fetchHIBPBreaches` sets `User-Agent` header — forbidden browser header, silently ignored or throws | ✅ Solved |
| 4 | api.js | proxy fetch paths | CORS proxies can still MITM/poison upstream threat data; static browser apps cannot fully verify RSS/proxy integrity without a trusted backend | ⚠️ Partial — output is escaped and requests are bounded; full fix requires backend/proxy ownership |
| 5 | app.js | boot state | `window.cyberData` was globally writable — any script could overwrite displayed threat data | ✅ Solved — read-only getter plus internal snapshot updates |

---

## 🔴 Logic Bugs

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 6 | app.js | ~157 | Auto-refresh sets wrong cache key (`cybervulndb_ts`) instead of versioned key (`cybervulndb_ts_v8_*`) — auto-refresh is a no-op while cache is fresh | ✅ Solved |
| 7 | app.js | ~306 | `renderCVEs` calls `cves.sort()` in-place, mutating the `window.cyberData.cves` reference | ✅ Solved |
| 8 | map.js | ~221 | `clearMarkers()` has no null check on `map` — throws TypeError if called before map init | ✅ Solved |
| 9 | app.js | ~618 | `detectCountryFromText` (app.js) is incomplete vs `detectCountry` (api.js) — misses IN, JP, BR, AU etc.; api.js version never exported/used | ✅ Solved |
| 10 | api.js | ~288 | KEV cache check: empty array `[]` is falsy, causes re-fetch on every call when KEV returns empty | ✅ Solved |
| 11 | app.js | ~334–338 | `knownCveIds` size cap runs inside `.map()` — side effects in a transformation; cap allows Set to reach 501 | ✅ Solved |
| 12 | api.js | ~254 | `fetchAllNews` hardcodes limit of 60, ignoring `timeRangeCap()` used everywhere else | ✅ Solved |
| 13 | api.js | ~685–688 | `fetchAllCVESources` accesses `cvelist.value` directly without checking `status === 'fulfilled'` | ✅ Solved |
| 14 | api.js | ~437–438 | GitHub Advisory CVSS: always picks v3 over v4 even when v4 is the only score | ✅ Solved |
| 15 | api.js | ~374–379 | CVE ID extraction from commit messages uses fragile regex — breaks silently if CVEProject changes format | ✅ Solved |
| 16 | app.js | ~1316–1320 | Cache key versions mismatch: `CACHE_KEY` uses `v9`, `CACHE_TS_KEY` uses `v8` | ✅ Solved |
| 17 | api.js | ~1318–1320 | Old cache versions (`v7`, `v8` etc.) never cleaned up — localStorage accumulates orphaned entries | ✅ Solved |
| 18 | app.js | ~130 | `updateStatsBar` uses full unfiltered data — counts are wrong when search is active | ✅ Solved |
| 19 | app.js | ~1076–1087 | Map markers not cleared when search is active — map always shows all data regardless of filter | ✅ Solved |
| 20 | api.js | ~620–624 | EPSS `parseFloat` has no NaN validation — can store NaN in epss.score/percentile | ✅ Solved |
| 21 | app.js | ~348 | EPSS percentile tooltip shows "NaN" if `cve.epss.percentile` is undefined | ✅ Solved |
| 22 | app.js | ~501 | `apt.targetSectors.slice()` throws if `targetSectors` is undefined (RSS APT items) | ✅ Solved |
| 23 | api.js | ~1220–1232 | APT time-range filter has no effect — `timeRange` passed as count cap, not date filter | ✅ Solved |
| 24 | api.js | ~870–872 | `fetchURLhaus` / `fetchThreatFox` use `Object.keys(data).filter(k => !isNaN(k))` — fragile numeric key detection | ✅ Solved |
| 25 | api.js | ~1299 | `getCoords` returns `[20, 0]` (off West Africa coast) for unknown countries — misleads map | ✅ Solved |

---

## 🟠 Performance

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 26 | app.js | ~1070 | Search input has no debounce — re-renders all 4 panels on every keystroke | ✅ Solved |
| 27 | app.js | ~374–393 | O(n²) `array.find` inside `querySelectorAll.forEach` in renderCVEs/renderRansomware/renderAPT | ✅ Solved |
| 28 | app.js | ~29–44 | `animateCounter` doesn't cancel previous rAF — multiple animations run concurrently on rapid updates | ✅ Solved |
| 29 | api.js | ~481–498 | NVD double-fetch (count then data) wastes a rate-limited request slot | ✅ Solved |
| 30 | api.js | ~1350 | `enrichWithEPSS` awaited in `loadAllData` — blocks full render until EPSS completes | ✅ Solved |
| 31 | api.js | source aggregators | All 4 data sources + sub-sources fetched simultaneously — 20+ parallel requests triggers API rate limits | ✅ Solved — source fanout now uses bounded concurrency |
| 32 | api.js | cache write | Large MISP/CVE/news payloads stored in localStorage via `CACHE_KEY` — risks QuotaExceeded | ✅ Solved — cache snapshot now trims bulky references/descriptions |
| 33 | app.js | ~662–667 | `querySelectorAll('[data-ts]')` updates every timestamp element every 60s — layout thrashing | ✅ Solved |

---

## 🟠 Race Conditions

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 34 | app.js | multiple | No request serialization — CVE/news/auto-refresh timers + user filter changes can render concurrently | ✅ Solved — stale async responses are ignored and user panel requests suppress timer overwrites |
| 35 | app.js | ~288–299 | `loadKEVData` is non-blocking; first render always shows no KEV badges | ✅ Solved |
| 36 | api.js | ~104 | `Promise.race` with `timeout()` — timed-out fetch continues in background with no AbortController | ✅ Solved |
| 37 | app.js | ~29–44 | `animateCounter` starts new rAF without cancelling previous — counters jump on rapid stat updates | ✅ Solved |

---

## 🟡 Code Quality / Consistency

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 38 | app.js | ~656 | Duplicate `escapeHtml` — utils.js uses string replace, app.js uses DOM (textContent/innerHTML) | ✅ Solved |
| 39 | app.js | ~654 | `formatDate` is aliased to `timeAgo` — opposite semantics to `Utils.formatDate` | ✅ Solved |
| 40 | api.js | ~16–20 | `RSS_PROXIES` array defined but never used (inline hardcoding instead) — dead code | ✅ Solved |
| 41 | api.js | ~734–739 | `fetchCVEsOnly`, `fetchNewsOnly`, `getMockCVEs`, `detectCountry` — exported or defined but never called | ✅ Solved |
| 42 | map.js | ~186 | `addAttackLine` uses `Math.random()` for curve — non-deterministic, lines jitter on every re-render | ✅ Solved |
| 43 | app.js | ~878–882 | Severity filter empty-string check: user can't "un-set" severity without explicit "All" selection | ✅ Solved |
| 44 | ui.js | ~89–93 | Export anchor not appended to document body — download fails in Firefox | ✅ Solved |
| 45 | api.js | ~895 | All proxy fallback `catch` blocks swallow errors silently — impossible to debug failures | ✅ Solved |
| 46 | api.js | ~16 | `RSS_FEEDS` includes `wired` key but no dropdown option in HTML — invisible data source | ✅ Solved |
| 47 | app.js | ~819 | `window.cyberData` never cleared between refreshes — memory leak from replaced-but-referenced objects | ✅ Solved |

---

## Summary

| Category | Count | Solved |
|----------|-------|--------|
| Security/XSS | 9 | 8 solved, 1 partial |
| Logic Bugs | 20 | 20 |
| Performance | 8 | 8 |
| Race Conditions | 4 | 4 |
| Code Quality | 10 | 10 |
| Duck-found | 14 | 14 |
| Remaining architectural | 7 | 0 |
| **Total** | **72** | **71 solved, 1 partial, 0 open** |

---

## 🦆 RUBBER_DUCK_AGENT — Additional Issues Found

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 48 | app.js | ~442–443 | `renderRansomware` injects `v.group` and `v.country` unescaped into innerHTML — XSS | ✅ Solved |
| 49 | app.js | ~501 | `renderAPT` card injects `apt.country` unescaped into innerHTML — XSS | ✅ Solved |
| 50 | app.js | ~827–828 | `showAPTModal` calls `.join()` on `apt.aliases` / `apt.targetSectors` without `|| []` guard — crashes if undefined | ✅ Solved |
| 51 | api.js | ~693 + 1346 | `enrichWithEPSS` called twice for `all` source path — once in `fetchAllCVESources`, once in `loadAllData` non-blocking | ✅ Solved |
| 52 | api.js | ~1340 | Non-blocking `enrichWithEPSS` runs after `storageSet` — cached data has no EPSS scores, badges missing on cache load | ✅ Solved |
| 53 | api.js | ~769 | `detectCountry` defaults to `'US'` for unmatched text — all unknown-origin CVEs cluster as US map markers | ✅ Solved |

---

## 🔍 KILO_AGENT — Deep Analysis Issues (Apr 2026)

### 🔴 Security / XSS

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 54 | api.js | ~413 | `fetchGitHubAdvisories` uses `Promise.race([fetch, timeout()])` — missed migration to `fetchWithAbort`; fetch continues after timeout | ✅ Solved |
| 55 | ui.js | ~43 | `showToast` injects `message` unescaped into innerHTML — latent XSS | ✅ Solved |
| 56 | map.js | ~89-127 | `buildPopupContent` injects `data.name`, `data.organization`, `data.country`, `data.description` unescaped into popup HTML — XSS from malicious API data | ✅ Solved |
| 57 | app.js | ~725,785,810 | Modal close uses inline `onclick` — CSP violation, anti-pattern | ✅ Solved |

### 🔴 Logic Bugs

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 58 | api.js | ~825,870 | `Math.random()` as fallback IDs in URLhaus/ThreatFox — breaks dedup on re-render | ✅ Solved |
| 59 | app.js | ~274 | `filterForSearch` uses `a.targets` but APT model has `targetSectors` — APT search by sector always fails | ✅ Solved |
| 60 | api.js | ~1301-1303 | `loadAllData` caches data via `.then()` after EPSS — race condition: cache may write before EPSS finishes | ✅ Solved |
| 61 | app.js | ~655 | `timeAgo(Number(el.dataset.ts))` but `data-ts` values are ISO strings — `Number("2026-03-07...")` = NaN → broken timestamps | ✅ Solved |
| 62 | api.js | ~978,1013-1014 | `fetchLiveRansomware` called twice — once in `fetchAllMalwareSources`, once in `fetchMalwareBySource('ransomware-victims')` — no caching | ✅ Solved |
| 63 | api.js | ~354,522 | `fetchCVEsFromCveList` and `fetchCVEsFromCVEOrg` both call same GitHub commits API independently — duplicate request | ✅ Solved |
| 64 | api.js | ~294-297 | `fetchKEV` on error leaves `kevCache=null` — re-fetches on every `isInKEV` call instead of caching empty result | ✅ Solved |
| 65 | api.js | ~44-51 | `filterByTimeRange` filters out static data (MISP/mock APT) with no date field — `new Date(undefined)` = Invalid Date | ✅ Solved |
| 66 | app.js | ~335,425 | `getCoords()` returns `null` for unknown countries — `coords.join(',')` throws TypeError | ✅ Solved |

### 🟠 Performance

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 67 | api.js | ~303 | `isInKEV` uses O(n) `.some()` per CVE — O(n*m) total; should use Set | ✅ Solved |
| 68 | map.js | ~133 | `markers.find(m => m._id === id)` is O(n) per add — O(n²) total for all markers | ✅ Solved |
| 69 | app.js | ~310 | `renderCVEs` always sorts `[...cves].sort()` — redundant, data already sorted from API | ✅ Solved |

### 🟡 Code Quality / Consistency

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 70 | app.js | ~626-646 | Duplicate `timeAgo` — `Utils.timeAgo` handles timestamps, local `timeAgo` handles ISO strings; different logic | ✅ Solved |
| 71 | api.js | ~189-191 | `fetchRSS` is dead code — wrapper that just calls `fetchRSSWithFallbacks`, not exported or called | ✅ Solved |
| 72 | style.css | ~1598,1615,1632,1649 | CSS references undefined `var(--surface)` and `var(--primary)` — not defined in `:root` | ✅ Solved |

---

## 🧪 Test / Tooling Issues

| # | File | Line | Description | Status |
|---|------|------|-------------|--------|
| 73 | test_app.py | import/startup | Pytest collection failed when Playwright was missing; smoke test also assumed an external server on port 8082 | ✅ Solved — optional Playwright import, pytest skip, and local static server wrapper |

---

## Updated Summary

| Category | Count | Solved |
|----------|-------|--------|
| Security/XSS | 9 | 8 solved, 1 partial |
| Logic Bugs | 20 | 20 |
| Performance | 8 | 8 |
| Race Conditions | 4 | 4 |
| Code Quality | 10 | 10 |
| Duck-found | 14 | 14 |
| Test / Tooling | 1 | 1 |
| Remaining architectural | 7 | 0 |
| **Total** | **73** | **72 solved, 1 partial, 0 open** |
