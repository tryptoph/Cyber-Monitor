# CyberMonitor

Real-time cybersecurity intelligence dashboard for CVEs, ransomware and malware activity, APT groups, Morocco-focused cyber news, and global security reporting.

Live site: https://tryptoph.github.io/Cyber-Monitor/

## Highlights

- Interactive Leaflet world map with CVE, ransomware, APT, and threat-news markers.
- Live CVE aggregation from CVEProject cvelistV5, GitHub Advisory DB, NVD, CVE.org, FIRST EPSS, and CISA KEV.
- Malware and ransomware feeds from ransomware.live, URLhaus, ThreatFox, InQuest Labs, and HIBP.
- APT actor intelligence from MISP Galaxy plus security research RSS feeds.
- Morocco focus mode with DGSSI / maCERT, generated Morocco cyber feed, local Moroccan sources, and official-source badges.
- Scheduled GitHub Actions refresh for `data/morocco-cyber-feed.json` every 6 hours.
- Atlas Signal Command visual design with responsive panels, accessible focus states, reduced-motion support, and cache-busted static assets.

## Data Sources

| Area | Sources |
| --- | --- |
| CVEs | CVEProject cvelistV5, GitHub Advisory DB, NVD API 2.0, CVE.org |
| Enrichment | FIRST EPSS, CISA KEV |
| Malware | ransomware.live, URLhaus, ThreatFox, InQuest Labs, HIBP |
| APT | MISP Galaxy, Mandiant, CrowdStrike, Securelist |
| News | The Hacker News, Krebs, BleepingComputer, SANS ISC, SecurityWeek, Dark Reading, Malwarebytes, Schneier, Wired, HackerNews Algolia |
| Morocco | DGSSI / maCERT, generated static feed, Hespress, Aujourd'hui le Maroc, La Vie Eco |

## Features

- Global and Morocco country focus selector.
- Per-panel source and time-range filters.
- Global search across CVEs, malware, news, and APT data.
- CVE severity filtering, EPSS badges, KEV indicators, and fallback-data warnings.
- Live panel refresh with stale/failure feedback.
- Export current dashboard data as JSON.
- Keyboard shortcuts: `1` CVE, `2` Malware, `3` News, `4` APT, `R` refresh, `S` or `/` search, `Esc` close modal.

## Project Structure

```text
Cyber-Monitor/
├── index.html
├── css/style.css
├── js/
│   ├── api.js
│   ├── app.js
│   ├── map.js
│   ├── ui.js
│   └── utils.js
├── data/
│   ├── countries.json
│   └── morocco-cyber-feed.json
├── scripts/build_morocco_feed.py
├── workers/dgssi-feed-worker.js
├── lib/
└── images/
```

## Running Locally

No build step is required.

```bash
git clone https://github.com/tryptoph/Cyber-Monitor.git
cd Cyber-Monitor
python3 -m http.server 8080
```

Open `http://localhost:8080`.

## Verification

```bash
node --check js/api.js js/app.js js/ui.js js/utils.js js/map.js workers/dgssi-feed-worker.js
python3 -m py_compile scripts/build_morocco_feed.py
```

Additional local smoke tests may exist in ignored files such as `test_app.py`.

## GitHub Actions

`.github/workflows/update-morocco-cyber-feed.yml` refreshes the Morocco feed on a schedule and can also be run manually from the Actions tab.

If you configure a repository secret named `FEED_UPDATE_PAT`, the workflow uses it for checkout and push. If not, it falls back to the default `GITHUB_TOKEN`.

Required permissions:

- Workflow file: `permissions: contents: write`
- Optional PAT scopes for a public repo: `public_repo` and `workflow`
