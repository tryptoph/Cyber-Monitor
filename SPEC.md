# CyberVulnDB - Cybersecurity Intelligence Dashboard

## Project Overview

**Project Name:** CyberVulnDB  
**Type:** Real-time Cybersecurity Intelligence Dashboard (Web Application)  
**Core Functionality:** AI-powered cybersecurity news aggregation, CVE tracking, ransomware monitoring, APT intelligence, and threat visualization in a unified situational awareness interface.  
**Target Users:** Security analysts, vulnerability researchers, SOC teams, CTI analysts, and cybersecurity professionals.

---

## Research Summary

### Similar Projects Analyzed

| Project | Type | Key Features |
|---------|------|--------------|
| WorldMonitor | Open Source | 170+ RSS feeds, dual map engine, AI summaries |
| Cybergeist | Commercial | AI-enriched news, STIX export, threat profiles |
| Ransomware.live | Free | Real-time ransomware victim tracking, maps |
| CVE.ICU | Open Source | CVE search with CVSS, EPSS scoring |
| OpenCVE | Commercial | CVE management platform, vendor alerts |
| MITRE ATT&CK | Free | APT group tracking, technique heatmaps |

### Best Cybersecurity RSS Feeds (Curated)

**Tier 1 - Primary Sources (Must Have):**
1. The Hacker News - https://feeds.feedburner.com/TheHackersNews
2. Krebs on Security - https://krebsonsecurity.com/feed/
3. BleepingComputer - https://www.bleepingcomputer.com/feed/
4. Dark Reading - https://www.darkreading.com/rss.xml
5. SecurityWeek - https://www.securityweek.com/feed/

**Tier 2 - Vulnerability Sources:**
6. NVD (NIST) - https://nvd.nist.gov/general/nvd-rss.xml
7. US-CERT Alerts - https://www.cisa.gov/uscert/ncas/alerts.xml
8. ZeroDayInitiative - https://www.zerodayinitiative.com/rss.xml

**Tier 3 - Enterprise Security:**
9. Microsoft Security Blog - https://www.microsoft.com/en-us/security/blog/rss-feed/
10. Google Security Blog - https://googleonlinesecurity.blogspot.com/atom.xml
11. Cisco Security - https://blogs.cisco.com/security/feed
12. Palo Alto Networks - https://unit42.paloaltonetworks.com/feed/

**Tier 4 - Research & Malware:**
13. SANS Internet Storm Center - https://isc.sans.edu/rssfeed.xml
14. Malwarebytes Labs - https://blog.malwarebytes.com/feed/
15. Securelist (Kaspersky) - https://securelist.com/feed/
16. Schneier on Security - https://www.schneier.com/blog/atom.xml

**Tier 5 - Government & Policy:**
17. CISA News - https://www.cisa.gov/news-events/cybersecurity-advisories/feed
18. NSA Cybersecurity Advisories - https://www.nsa.gov/News-Features/News-Stories/News-Features-RSS.xml
19. NCSC UK - https://www.ncsc.gov.uk/api/rssfeed/alerts

---

## Technical Architecture

### Stack
- **Frontend:** Next.js 14+ with TypeScript, React 18+
- **Styling:** CSS Modules with CSS Variables
- **State Management:** Zustand
- **Maps:** globe.gl + Three.js (3D), deck.gl + MapLibre (2D)
- **Backend:** Next.js API Routes + Serverless
- **Caching:** In-memory cache (production: Redis/Upstash)
- **AI:** Ollama (local) / Groq (cloud) / Transformers.js fallback

### Project Structure
```
cybervulndb/
├── src/
│   ├── app/
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   └── globals.css
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Header.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   └── Dashboard.tsx
│   │   ├── cve/
│   │   │   ├── CVESearch.tsx
│   │   │   ├── CVEList.tsx
│   │   │   └── CVEDetail.tsx
│   │   ├── ransomware/
│   │   │   ├── RansomwareTracker.tsx
│   │   │   └── VictimList.tsx
│   │   ├── apt/
│   │   │   ├── APTGroups.tsx
│   │   │   └── ATTACKMatrix.tsx
│   │   ├── news/
│   │   │   ├── NewsFeed.tsx
│   │   │   └── NewsItem.tsx
│   │   ├── map/
│   │   │   ├── ThreatMap.tsx
│   │   │   └── MapControls.tsx
│   │   └── ai/
│   │       └── AIBrief.tsx
│   ├── lib/
│   │   ├── api/
│   │   │   ├── nvd.ts
│   │   │   ├── cisa.ts
│   │   │   ├── rss.ts
│   │   │   └── epss.ts
│   │   ├── utils/
│   │   │   ├── cache.ts
│   │   │   └── parser.ts
│   │   └── types/
│   │       └── index.ts
│   └── stores/
│       └── useStore.ts
├── public/
│   └── data/
├── package.json
├── tsconfig.json
└── next.config.js
```

---

## Feature Specifications

### 1. CVE Tracking System

**Data Sources:**
- NVD API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
- CISA KEV Catalog (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- EPSS API (https://api.first.org/data/v1/epss)

**Features:**
- Real-time CVE search with filters:
  - Date range (published, modified)
  - CVSS severity (Critical: 9.0+, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9)
  - Vendor/Product (CPE matching)
  - Keyword search
  - CISA KEV status (in KEV or not)
  - EPSS score threshold
- CVE detail view with:
  - Description, CVSS v3.1 vector
  - Affected products (CPE)
  - References
  - CISA KEV status with date added
  - EPSS score and percentile
- Trend charts (CVEs by severity over time)
- Export to CSV/JSON

**UI Components:**
- Search bar with autocomplete
- Filter sidebar
- Paginated results table
- Severity badges (color-coded)
- Detail modal/panel

### 2. Ransomware Monitor

**Data Sources:**
- RansomDB API (https://ransomdb.io/api/)
- Live scraping of major ransomware group leak sites
- RansomWatch (https://raw.githubusercontent.com/k4m4/onions/master/ransomwatch.json)

**Features:**
- Live victim list with:
  - Organization name
  - Ransomware group
  - Country
  - Discovery date
  - Status (published,谈判中,已赎)
- Group profiles:
  - Active periods
  - Victim count
  - Known aliases
  - Targeting sectors
- Statistics dashboard:
  - Total victims (all time, this year, this month)
  - Most active groups
  - Most targeted countries
  - Most targeted sectors

**UI Components:**
- Filterable/sortable table
- Group cards with logos
- Timeline charts
- Country breakdown map

### 3. APT Intelligence

**Data Sources:**
- MITRE ATT&CK API (https://attack-api.mitre.org/)
- ATT&CK data JSON (https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json)

**Features:**
- APT group database:
  - Group name and aliases
  - Associated countries
  - Target sectors
  - Known tools and malware
  - Attack patterns (ATT&CK techniques)
- Technique heatmap by group
- Search by country, sector, tool
- ATT&CK Navigator integration

**UI Components:**
- Group listing with search/filter
- Group detail page
- Technique matrix visualization
- Related groups suggestions

### 4. Security News Aggregation

**RSS Feeds:** 20 curated feeds (Tier 1-3 from research)

**Features:**
- Unified news feed from all sources
- Entity extraction:
  - CVE IDs (auto-linked)
  - Ransomware groups
  - APT groups
  - Malware families
  - Target organizations
- Keyword filtering
- Read/unread tracking
- Full-text search
- Category tabs (All, Vulnerabilities, Breaches, Malware, Policy)

**UI Components:**
- News card list
- Category tabs
- Search/filter bar
- Entity highlight badges
- External link to original

### 5. Threat Map

**Visualization:**
- Dual mode: Globe (3D) + Flat map (2D)
- Interactive markers for:
  - Ransomware attacks (by country)
  - CVE concentrations (by vendor HQ)
  - APT activity regions

**Features:**
- Time filtering (24h, 7d, 30d, all)
- Layer toggles
- Country detail on hover
- Zoom and pan

### 6. AI-Powered Briefs

**AI Providers (fallback chain):**
1. Ollama (local) - llama3.1:8b default
2. Groq (cloud) - llama-3.1-70b-versatile
3. Transformers.js (browser) - T5-small

**Features:**
- Daily threat brief generation
- Topic-specific queries
- CVE summary for selected items
- Natural language search

---

## UI/UX Specification

### Color Palette (Cybersecurity Theme)
```css
:root {
  /* Backgrounds */
  --bg-primary: #0a0e17;
  --bg-secondary: #111827;
  --bg-tertiary: #1f2937;
  --bg-card: #1a1f2e;
  
  /* Text */
  --text-primary: #f9fafb;
  --text-secondary: #9ca3af;
  --text-muted: #6b7280;
  
  /* Accents */
  --accent-cyan: #06b6d4;
  --accent-blue: #3b82f6;
  --accent-purple: #8b5cf6;
  
  /* Severity */
  --critical: #dc2626;
  --high: #ea580c;
  --medium: #f59e0b;
  --low: #22c55e;
  --info: #3b82f6;
  
  /* Status */
  --success: #10b981;
  --warning: #f59e0b;
  --error: #ef4444;
  
  /* Borders */
  --border: #374151;
  --border-light: #4b5563;
}
```

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────┐
│ HEADER: Logo | Search | AI Brief | Settings | Theme           │
├────────────┬────────────────────────────────────────────────────┤
│            │                                                    │
│  SIDEBAR   │                    MAIN CONTENT                   │
│            │                                                    │
│ - Dashboard│  ┌──────────────┬──────────────┬──────────────┐    │
│ - CVE      │  │ CVE Tracker  │ Ransomware   │ APT Groups  │    │
│ - Ransomware│  │ (primary)    │ Monitor      │ Intelligence│    │
│ - APT      │  └──────────────┴──────────────┴──────────────┘    │
│ - News     │  ┌──────────────────────────────────────────┐    │
│ - Map      │  │ Security News Feed                       │    │
│ - AI Brief │  │ (scrollable list)                       │    │
│            │  └──────────────────────────────────────────┘    │
├────────────┴────────────────────────────────────────────────────┤
│ FOOTER: Status | Last Updated | Data Sources                   │
└─────────────────────────────────────────────────────────────────┘
```

### Responsive Breakpoints
- **Desktop:** 1280px+ (full layout)
- **Tablet:** 768px-1279px (collapsed sidebar)
- **Mobile:** <768px (bottom nav, stacked panels)

---

## API Specifications

### NVD API 2.0
```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
Parameters:
  - cveId: string (e.g., CVE-2024-1234)
  - pubStartDate, pubEndDate: ISO 8601
  - cvssV3Severity: CRITICAL|HIGH|MEDIUM|LOW
  - cpeName: string
  - keywordSearch: string
  - resultsPerPage: number (1-2000)
```

### EPSS API
```
GET https://api.first.org/data/v1/epss
Parameters:
  - cve: string (comma-separated)
  - days: number (1-180)
```

### CISA KEV
```
GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

### MITRE ATT&CK
```
GET https://attack-api.mitre.org/groups/v{version}
GET https://attack-api.mitre.org/techniques/v{version}
```

---

## Data Models

### CVE
```typescript
interface CVE {
  id: string;
  description: string;
  published: string;
  modified: string;
  cvss: {
    score: number;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
    vector: string;
  };
  cpe: string[];
  references: string[];
  inKEV: boolean;
  kevDateAdded?: string;
  epss: {
    score: number;
    percentile: number;
  };
}
```

### RansomwareVictim
```typescript
interface RansomwareVictim {
  id: string;
  organization: string;
  group: string;
  country: string;
  sector: string;
  discovered: string;
  status: 'published' | 'negotiating' | 'paid' | 'decrypted';
  revenue?: number;
  employees?: number;
}
```

### APTGroup
```typescript
interface APTGroup {
  id: string;
  name: string;
  aliases: string[];
  country: string;
  targetSectors: string[];
  malware: string[];
  tools: string[];
  techniques: string[];
  description: string;
}
```

---

## Implementation Phases

### Phase 1: Foundation (Week 1)
- [ ] Set up Next.js project with TypeScript
- [ ] Implement CSS variables and base styling
- [ ] Create layout components (Header, Sidebar, Main)
- [ ] Set up state management (Zustand)

### Phase 2: CVE System (Week 2)
- [ ] Implement NVD API client
- [ ] Create CVE search UI
- [ ] Add CISA KEV integration
- [ ] Add EPSS scoring display

### Phase 3: Ransomware Tracker (Week 3)
- [ ] Implement ransomware data client
- [ ] Create victim list UI
- [ ] Build group profiles
- [ ] Add statistics dashboard

### Phase 4: APT Intelligence (Week 4)
- [ ] Import MITRE ATT&CK data
- [ ] Create group listing/search
- [ ] Build technique matrix
- [ ] Add country/sector filters

### Phase 5: News & Map (Week 5)
- [ ] Implement RSS feed aggregation
- [ ] Create news feed UI
- [ ] Add threat map visualization
- [ ] Implement entity extraction

### Phase 6: AI Features (Week 6)
- [ ] Integrate Ollama client
- [ ] Add Groq fallback
- [ ] Create AI brief generator
- [ ] Implement semantic search

---

## Acceptance Criteria

### Must Have (MVP)
- [ ] CVE search with CVSS filtering
- [ ] CISA KEV indicator on CVEs
- [ ] Ransomware victim list with filters
- [ ] APT group database
- [ ] Security news aggregation (10+ feeds)
- [ ] Responsive design

### Should Have
- [ ] EPSS scoring on CVEs
- [ ] Ransomware statistics dashboard
- [ ] AI-powered summaries
- [ ] Threat map visualization

### Nice to Have
- [ ] Full ATT&CK technique matrix
- [ ] Mobile PWA
- [ ] Custom keyword alerts
- [ ] Export features

---

## Dependencies

### Core
```json
{
  "next": "^14.0.0",
  "react": "^18.2.0",
  "typescript": "^5.3.0",
  "zustand": "^4.4.0"
}
```

### Data & API
```json
{
  "rss-parser": "^3.13.0",
  "date-fns": "^3.0.0"
}
```

### Maps
```json
{
  "globe.gl": "^2.27.0",
  "three": "^0.160.0",
  "maplibre-gl": "^3.6.0"
}
```

### AI
```json
{
  "ollama": "^0.1.0",
  "@xenova/transformers": "^2.17.0"
}
```

---

## Security Considerations

- All API keys stored server-side only
- Rate limiting on external APIs (NVD: 6 req/sec)
- Input sanitization on all user queries
- CORS proxy for RSS feeds
- No PII stored in analytics
- HTTPS only in production
