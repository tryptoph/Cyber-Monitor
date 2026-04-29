/**
 * api.js — CyberVulnDB Data Fetching
 * 
 * Sources:
 *  - NVD API (NIST) - CVE data
 *  - RSS Feeds - Security news
 *  - Mock data - Ransomware, APT
 */

const API = (() => {
  const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

  // Ordered proxy fallback chain for RSS feeds

  // Timeout helper — used only for non-fetch Promise.race guards
  function timeout(ms) {
    return new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Timeout')), ms)
    );
  }

  // Fetch with AbortSignal timeout — replaces Promise.race([fetch, timeout]) pattern
  function fetchWithAbort(url, options = {}, ms = 8000) {
    return fetch(url, { ...options, signal: AbortSignal.timeout(ms) });
  }

  // ── Time range helpers ──────────────────────────────────
  // Returns the start Date for a given range key
  function timeRangeToStart(range) {
    const now = Date.now();
    const ms = { '24h': 1, '1w': 7, '1m': 30 }[range] || 7;
    return new Date(now - ms * 24 * 60 * 60 * 1000);
  }

  // Returns a sensible item cap for each range
  function timeRangeCap(range) {
    return { '24h': 50, '1w': 100, '1m': 200 }[range] || 100;
  }

  // Filter an array of items to those within the time range
  // dateField: the property name holding an ISO date string
function filterByTimeRange(items, dateField, range) {
  if (!range || range === 'all') return items;
  const start = timeRangeToStart(range);
  return items.filter(item => {
    const val = item[dateField];
    if (!val) return true;
    const d = new Date(val);
    return !isNaN(d.getTime()) && d >= start;
  });
}

// Cache for KEV data
let kevCache = null;
let kevCacheTime = null;
let kevIdSet = null;
const KEV_CACHE_DURATION = 60 * 60 * 1000; // 1 hour

  // Cache for MISP Galaxy data (3MB payload, 30 min TTL)
  let mispCache = null;
  let mispCacheTime = null;
  const MISP_CACHE_DURATION = 30 * 60 * 1000;
  
  // Security RSS Feeds — broader, more reliable sources
  const RSS_FEEDS = [
    { name: 'The Hacker News',  key: 'hackernews-rss', url: 'https://feeds.feedburner.com/TheHackersNews',           category: 'vulnerabilities' },
    { name: 'Krebs on Security', key: 'krebs', url: 'https://krebsonsecurity.com/feed/',                    category: 'breaches' },
    { name: 'BleepingComputer', key: 'bleeping', url: 'https://www.bleepingcomputer.com/feed/',                 category: 'vulnerabilities' },
    { name: 'SANS ISC',         key: 'sans', url: 'https://isc.sans.edu/rssfeed.xml',                       category: 'malware' },
    { name: 'SecurityWeek',     key: 'securityweek', url: 'https://www.securityweek.com/feed/',                     category: 'enterprise' },
    { name: 'Dark Reading',     key: 'darkreading', url: 'https://www.darkreading.com/rss.xml',                    category: 'enterprise' },
    { name: 'Malwarebytes',     key: 'malwarebytes', url: 'https://blog.malwarebytes.com/feed/',                    category: 'malware' },
    { name: 'Threatpost',       key: 'threatpost', url: 'https://threatpost.com/feed/',                           category: 'vulnerabilities' },
    { name: 'Schneier',         key: 'schneier', url: 'https://www.schneier.com/blog/atom.xml',                 category: 'policy' },
    { name: 'Wired Security',   key: 'wired', url: 'https://www.wired.com/category/security/feed/rss/',      category: 'enterprise' },
  ];

  // Country code mapping for CVEs
  const COUNTRY_KEYWORDS = {
    US: ['united states', 'usa', 'america', 'american'],
    CN: ['china', 'chinese', 'beijing', 'shanghai'],
    RU: ['russia', 'russian', 'moscow'],
    KR: ['south korea', 'korea', 'korean', 'seoul'],
    IR: ['iran', 'iranian', 'tehran'],
    KP: ['north korea', 'dprk', 'pyongyang'],
    IN: ['india', 'indian', 'bangalore', 'delhi'],
    DE: ['germany', 'german', 'berlin'],
    GB: ['uk', 'united kingdom', 'british', 'london'],
    BR: ['brazil', 'brazilian'],
    JP: ['japan', 'japanese', 'tokyo'],
  };

  // ── HackerNews Algolia API ────────────────────────────────
  // Primary news source — no CORS issues, always live, proper JSON
  async function fetchHackerNews() {
    const QUERIES = [
      { q: 'cybersecurity vulnerability CVE exploit zero-day', category: 'vulnerabilities' },
      { q: 'ransomware breach data leak hacked attack',        category: 'breaches' },
      { q: 'malware threat actor apt trojan backdoor',         category: 'malware' },
    ];

    try {
      const promises = QUERIES.map(({ q, category }) => {
        const url = `https://hn.algolia.com/api/v1/search_by_date?tags=story&query=${encodeURIComponent(q)}&hitsPerPage=8&numericFilters=points%3E2`;
        return fetchWithAbort(url, {}, 8000)
          .then(r => r.ok ? r.json() : { hits: [] })
          .then(data => (data.hits || [])
            .filter(h => h.url && h.title)
            .map(h => ({
              id: `hn-${h.objectID}`,
              title: h.title,
              link: h.url || `https://news.ycombinator.com/item?id=${h.objectID}`,
              description: (h.story_text || '').replace(/<[^>]+>/g, '').substring(0, 200) || h.title,
              source: 'HackerNews',
              sourceKey: 'hn-algolia',
              category,
              published: h.created_at,
              type: 'news',
              points: h.points || 0,
            }))
          )
          .catch(() => []);
      });

      const results = await Promise.all(promises);
      const items = results.flat().filter(i => i.title && i.link);
      console.log(`[API] HackerNews: ${items.length} items`);
      return items;
    } catch (err) {
      console.warn('[API] HackerNews fetch failed:', err.message);
      return [];
    }
  }

  // ── RSS with proxy fallback chain ─────────────────────────
  // Tries rss2json (JSON) → allorigins (raw XML) → corsproxy.io (raw XML)
  async function fetchRSSWithFallbacks(feed) {
    // 1. rss2json — converts RSS to clean JSON, most reliable
    try {
      const url = `https://api.rss2json.com/v1/api.json?rss_url=${encodeURIComponent(feed.url)}&count=10`;
      const res = await fetchWithAbort(url, {}, 7000);
      if (res.ok) {
        const data = await res.json();
        if (data.status === 'ok' && data.items?.length > 0) {
          console.log(`[API] rss2json ✓ ${feed.name} (${data.items.length})`);
          return data.items.map(item => ({
            id: item.guid || item.link || Utils.uid(),
            title: (item.title || '').trim(),
            link: item.link || '',
            description: (item.description || '').replace(/<[^>]+>/g, '').substring(0, 200),
            source: feed.name,
            sourceKey: feed.key,
            category: feed.category,
            published: item.pubDate || new Date().toISOString(),
            type: 'news',
          })).filter(i => i.title && i.link);
        }
      }
    } catch { /* try next */ }

    // 2. allorigins raw proxy → parse XML ourselves
    try {
      const res = await fetchWithAbort(`https://api.allorigins.win/raw?url=${encodeURIComponent(feed.url)}`, {}, 6000);
      if (res.ok) {
        const items = parseRSSItems(await res.text(), feed);
        if (items.length > 0) {
          console.log(`[API] allorigins ✓ ${feed.name} (${items.length})`);
          return items;
        }
      }
    } catch { /* try next */ }

    // 3. corsproxy.io
    try {
      const res = await fetchWithAbort(`https://corsproxy.io/?${encodeURIComponent(feed.url)}`, {}, 6000);
      if (res.ok) {
        const items = parseRSSItems(await res.text(), feed);
        if (items.length > 0) {
          console.log(`[API] corsproxy ✓ ${feed.name} (${items.length})`);
          return items;
        }
      }
    } catch { /* all proxies failed */ }

  console.warn(`[API] All proxies failed: ${feed.name}`);
  return [];
}

// ── Parse RSS XML ─────────────────────────────────────────
  function parseRSSItems(xml, feed) {
    const items = [];
    const itemRegex = /<item>([\s\S]*?)<\/item>/g;
    let match;
    
    while ((match = itemRegex.exec(xml)) !== null) {
      const itemXml = match[1];
      
      const getContent = (tag) => {
        const tagRegex = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
        const m = itemXml.match(tagRegex);
        return m ? m[1].replace(/<[^>]+>/g, '').trim() : '';
      };
      
      items.push({
        id: getContent('guid') || getContent('link') || Utils.uid(),
        title: getContent('title'),
        link: getContent('link'),
        description: getContent('description').substring(0, 200),
        source: feed.name,
        sourceKey: feed.key,
        category: feed.category,
        published: getContent('pubDate') || new Date().toISOString(),
        type: 'news'
      });
    }
    
    return items.slice(0, 10); // Limit per feed
  }

  // ── Aggregate all news sources ────────────────────────────
  async function fetchAllNews() {
    console.log('[API] Fetching news from all sources...');

    const [hnItems, ...rssResults] = await Promise.all([
      fetchHackerNews(),
      ...RSS_FEEDS.map(feed => fetchRSSWithFallbacks(feed)),
    ]);

    const allItems = [...hnItems, ...rssResults.flat()];

    // Deduplicate by normalised URL
    const seen = new Set();
    const deduped = allItems.filter(item => {
      if (!item.link || !item.title) return false;
      const key = item.link.toLowerCase().replace(/\/$/, '').replace(/^https?:\/\//, '');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    deduped.sort((a, b) => new Date(b.published) - new Date(a.published));

    console.log(`[API] News: ${hnItems.length} HN + ${rssResults.flat().length} RSS → ${deduped.length} unique`);
    return deduped.slice(0, 200);
  }

  // Fetch news filtered by source key and time range
  async function fetchNewsBySource(source = 'all', timeRange = '1w') {
    const limit = timeRangeCap(timeRange);
    let items;
    if (source === 'all') {
      items = await fetchAllNews();
    } else if (source === 'hn-algolia') {
      console.log('[API] Fetching news from HackerNews only...');
      items = await fetchHackerNews();
    } else {
      const feed = RSS_FEEDS.find(f => f.key === source);
      if (!feed) {
        console.warn(`[API] Unknown news source: ${source}`);
        return [];
      }
      console.log(`[API] Fetching news from ${feed.name} only...`);
      items = await fetchRSSWithFallbacks(feed);
    }
    items = filterByTimeRange(items, 'published', timeRange);
    items.sort((a, b) => new Date(b.published) - new Date(a.published));
    return items.slice(0, limit);
  }

  // Fetch CISA KEV data
  async function fetchKEV() {
    // Check cache
    if (kevCache !== null && kevCacheTime && (Date.now() - kevCacheTime) < KEV_CACHE_DURATION) {
      console.log('[API] Using cached KEV data');
      return kevCache;
    }

  try {
    const response = await fetch(`${CORS_PROXY}${encodeURIComponent(CISA_KEV_URL)}`);
    if (!response.ok) {
      console.warn('[API] KEV fetch failed, using empty catalog');
      kevCache = [];
      kevCacheTime = Date.now();
      return [];
    }
    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];
    kevCache = vulnerabilities;
    kevCacheTime = Date.now();
    kevIdSet = new Set(vulnerabilities.map(v => v.cveID));
    console.log(`[API] Loaded ${vulnerabilities.length} KEV entries`);
    return vulnerabilities;
  } catch (err) {
    console.warn('[API] KEV fetch error:', err.message);
    kevCache = [];
    kevCacheTime = Date.now();
    return [];
  }
  }

  // Check if a CVE is in KEV catalog
function isInKEV(cveId, kevList) {
  if (kevIdSet) return kevIdSet.has(cveId);
  if (!kevList || !kevList.length) return false;
  return kevList.some(kev => kev.cveID === cveId);
}

function getKEVDetails(cveId, kevList) {
  if (!kevList || !kevList.length) return null;
  return kevList.find(kev => kev.cveID === cveId) || null;
}

  // ── CVEProject/cvelistV5 — Real-time CVEs (0 lag) ────────
  const CVELIST_COMMITS_API = 'https://api.github.com/repos/CVEProject/cvelistV5/commits';
  const CVELIST_RAW = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves';

  function cveIdToPath(cveId) {
    const parts = cveId.split('-');
    const year = parts[1];
    const num = parts[2];
    const dir = num.length > 3 ? num.slice(0, num.length - 3) + 'xxx' : '0xxx';
    return `${CVELIST_RAW}/${year}/${dir}/${cveId}.json`;
  }

  function mapCveListEntry(data) {
    const meta = data.cveMetadata || {};
    const cna = data.containers?.cna || {};
    const desc = cna.descriptions?.find(d => d.lang === 'en')?.value
              || cna.descriptions?.[0]?.value || 'No description';
    const metrics = cna.metrics || [];
    let score = 0, severity = 'NONE', vector = '';
    for (const m of metrics) {
      const v31 = m.cvssV3_1 || m.cvssV3_0;
      const v4 = m.cvssV4_0;
      if (v31) { score = v31.baseScore; severity = v31.baseSeverity; vector = v31.vectorString || ''; break; }
      if (v4)  { score = v4.baseScore;  severity = v4.baseSeverity;  vector = v4.vectorString || ''; break; }
    }
    return {
      id: meta.cveId,
      description: desc,
      published: meta.datePublished || meta.dateUpdated,
      modified: meta.dateUpdated || meta.datePublished,
      cvss: { score, severity: (severity || 'NONE').toUpperCase(), vector },
      references: (cna.references || []).map(r => r.url),
      cpe: [],
      source: 'cvelist',
      type: 'cve'
    };
  }

  let sharedCvelistCommits = null;
let sharedCvelistCommitsTime = 0;
const SHARED_COMMITS_TTL = 60 * 1000;

async function getSharedCvelistCommits(perPage = 30) {
  const now = Date.now();
  if (sharedCvelistCommits && (now - sharedCvelistCommitsTime < SHARED_COMMITS_TTL)) {
    return sharedCvelistCommits;
  }
  const resp = await fetchWithAbort(`${CVELIST_COMMITS_API}?per_page=${perPage}`, {}, 8000);
  if (!resp.ok) throw new Error(`GitHub commits API: ${resp.status}`);
  const commits = await resp.json();
  sharedCvelistCommits = commits;
  sharedCvelistCommitsTime = now;
  return commits;
}

async function fetchCVEsFromCveList(timeRange = '1w') {
    const limit = timeRangeCap(timeRange);
    const startDate = timeRangeToStart(timeRange);
    try {
    const commitsResp = await getSharedCvelistCommits(30);
      const commits = await commitsResp.json();

      const cveIds = new Set();
      for (const c of commits) {
        const msg = c.commit?.message || '';
        const newBlock = msg.match(/new CVEs?:\s*(CVE[\s\S]*?)(?:\n|$)/i);
        if (newBlock) {
          const cveMatches = (newBlock[1].match(/CVE-\d{4}-\d{4,}/gi) || [])
            .map(id => id.toUpperCase())
            .filter((id, i, arr) => arr.indexOf(id) === i);
          cveMatches.forEach(id => cveIds.add(id));
        }
      }
      if (cveIds.size === 0) throw new Error('No CVE IDs found in commits');

      const idsToFetch = [...cveIds].slice(0, Math.min(limit + 5, 35));
      console.log(`[API] cvelistV5: fetching ${idsToFetch.length} CVEs from ${cveIds.size} found`);

      const results = await Promise.allSettled(
        idsToFetch.map(id =>
          fetchWithAbort(cveIdToPath(id), {}, 5000)
            .then(r => r.ok ? r.json() : null)
            .then(data => data ? mapCveListEntry(data) : null)
        )
      );

      const cves = results
        .filter(r => r.status === 'fulfilled' && r.value)
        .map(r => r.value)
        .filter(c => !c.published || new Date(c.published) >= startDate);

      cves.sort((a, b) => new Date(b.published) - new Date(a.published));
      console.log(`[API] cvelistV5: got ${cves.length} real-time CVEs`);
      return cves.length >= 5 ? cves : null;
    } catch (err) {
      console.warn('[API] cvelistV5 fetch failed:', err.message);
      return null;
    }
  }

  // ── GitHub Advisory Database ─────────────────────────────
  const GITHUB_ADVISORY_API = 'https://api.github.com/advisories';

  async function fetchGitHubAdvisories(timeRange = '1w', severity = '') {
    const limit = timeRangeCap(timeRange);
    try {
      const params = new URLSearchParams({
        per_page: String(Math.min(limit, 100)),
        sort: 'published',
        direction: 'desc',
        type: 'reviewed'
      });
      if (severity) params.append('severity', severity.toLowerCase());

      const url = `${GITHUB_ADVISORY_API}?${params.toString()}`;
      console.log('[API] Fetching from GitHub Advisory DB:', url);

	const response = await fetchWithAbort(url, { headers: { Accept: 'application/vnd.github+json' } }, 10000);
    if (!response.ok) throw new Error(`GitHub Advisory API returned ${response.status}`);

      const data = await response.json();
      if (!Array.isArray(data) || data.length === 0) return null;

      const startDate = timeRangeToStart(timeRange);
      const mapped = data
        .map(adv => {
          const v4Score = adv.cvss_severities?.cvss_v4?.score;
          const v3Score = adv.cvss_severities?.cvss_v3?.score;
          const score = (v4Score && v4Score > 0) ? v4Score : (v3Score && v3Score > 0) ? v3Score : 0;
          const sevMap = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };
          const sev = sevMap[adv.severity] || 'NONE';
          const pkg = adv.vulnerabilities?.[0]?.package;
          return {
            id: adv.cve_id || adv.ghsa_id,
            description: adv.summary || 'No description',
            published: adv.published_at,
            modified: adv.updated_at,
            cvss: { score, severity: sev, vector: adv.cvss_severities?.cvss_v4?.vector_string || adv.cvss_severities?.cvss_v3?.vector_string || '' },
            references: adv.references || [],
            cpe: pkg ? [`${pkg.ecosystem}:${pkg.name}`] : [],
            link: adv.html_url,
            source: 'github',
            type: 'cve'
          };
        })
        .filter(c => !c.published || new Date(c.published) >= startDate);

      mapped.sort((a, b) => new Date(b.published) - new Date(a.published));
      console.log(`[API] GitHub Advisory DB returned ${mapped.length} advisories`);
      return mapped;
    } catch (err) {
      console.warn('[API] GitHub Advisory fetch failed, falling back to NVD:', err.message);
      return null;
    }
  }

  // Fetch CVEs from NVD API 2.0
  async function fetchCVEsFromNVD(timeRange = '1w', severity = '') {
    try {
      const limit = timeRangeCap(timeRange);
      const endDate = new Date();
      const startDate = timeRangeToStart(timeRange);

      const baseParams = new URLSearchParams();
      baseParams.append('pubStartDate', startDate.toISOString());
      baseParams.append('pubEndDate', endDate.toISOString());
      if (severity) baseParams.append('cvssV3Severity', severity.toUpperCase());

      // Fetch directly — read totalResults from the response itself
      const fetchParams = new URLSearchParams(baseParams);
      fetchParams.append('resultsPerPage', String(limit));
      fetchParams.append('startIndex', '0');

      const url = `${NVD_API}?${fetchParams.toString()}`;
      console.log('[API] Fetching from NVD:', url);

      const response = await fetchWithAbort(url, {}, 8000);
      if (!response.ok) throw new Error(`NVD API returned ${response.status}`);

      const data = await response.json();
      const totalResults = data.totalResults || 0;
      const vulnerabilities = data.vulnerabilities || [];
      console.log(`[API] Fetched ${vulnerabilities.length} CVEs from NVD (${totalResults} total in range)`);

      const mapped = vulnerabilities.map(item => {
        const cve = item.cve;
        const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
        const cvssData = metrics?.cvssData;
        return {
          id: cve.id,
          description: cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description',
          published: cve.published,
          modified: cve.lastModified,
          cvss: cvssData ? {
            score: cvssData.baseScore,
            severity: cvssData.baseSeverity,
            vector: cvssData.vectorString
          } : { score: 0, severity: 'NONE', vector: '' },
          references: cve.references?.map(r => r.url) || [],
          cpe: cve.configurations?.flatMap(c =>
            c.nodes?.flatMap(n => n.cpeMatch?.map(m => m.criteria) || []) || []
          ) || [],
          source: 'nvd',
          type: 'cve'
        };
      });

      // Sort by published date — newest first
      mapped.sort((a, b) => new Date(b.published) - new Date(a.published));
      return mapped;
    } catch (err) {
      console.error('[API] NVD fetch failed:', err);
      return null;
    }
  }

  // ── CVE.org (MITRE) — Official CVE API ──────────────────
  const CVEORG_API = 'https://cveawg.mitre.org/api/cve';

  async function fetchCVEsFromCVEOrg(timeRange = '1w') {
    const limit = timeRangeCap(timeRange);
    const startDate = timeRangeToStart(timeRange);
    try {
    const commits = await getSharedCvelistCommits(15);

      const cveIds = new Set();
      for (const c of commits) {
        const msg = c.commit?.message || '';
        const newBlock = msg.match(/new CVEs?:\s*(CVE[\s\S]*?)(?:\n|$)/i);
        if (newBlock) {
          const cveMatches = (newBlock[1].match(/CVE-\d{4}-\d{4,}/gi) || [])
            .map(id => id.toUpperCase())
            .filter((id, i, arr) => arr.indexOf(id) === i);
          cveMatches.forEach(id => cveIds.add(id));
        }
      }
      if (cveIds.size === 0) throw new Error('No CVE IDs found');

      const idsToFetch = [...cveIds].slice(0, Math.min(limit + 5, 30));
      console.log(`[API] CVE.org: fetching ${idsToFetch.length} CVEs via official API`);

      const results = await Promise.allSettled(
        idsToFetch.map(id =>
          fetchWithAbort(`${CVEORG_API}/${id}`, {}, 5000)
            .then(r => r.ok ? r.json() : null)
            .then(data => {
              if (!data) return null;
              const entry = mapCveListEntry(data);
              if (entry) entry.source = 'cveorg';
              return entry;
            })
        )
      );

      const cves = results
        .filter(r => r.status === 'fulfilled' && r.value)
        .map(r => r.value)
        .filter(c => !c.published || new Date(c.published) >= startDate);

      cves.sort((a, b) => new Date(b.published) - new Date(a.published));
      console.log(`[API] CVE.org: got ${cves.length} CVEs`);
      return cves.length >= 3 ? cves.slice(0, limit) : null;
    } catch (err) {
      console.warn('[API] CVE.org fetch failed:', err.message);
      return null;
    }
  }

  // ── EPSS Enrichment — Exploit Prediction Scoring ────────
  const EPSS_API = 'https://api.first.org/data/v1/epss';

  async function enrichWithEPSS(cves) {
    if (!Array.isArray(cves) || cves.length === 0) return cves;
    try {
      const ids = cves.map(c => c.id).filter(Boolean);
      if (ids.length === 0) return cves;

      // Batch in groups of 30
      const batches = [];
      for (let i = 0; i < ids.length; i += 30) {
        batches.push(ids.slice(i, i + 30));
      }

      const epssMap = new Map();
      const results = await Promise.allSettled(
        batches.map(batch =>
          fetchWithAbort(`${EPSS_API}?cve=${batch.join(',')}`, {}, 8000)
            .then(r => r.ok ? r.json() : null)
        )
      );

      for (const r of results) {
        if (r.status !== 'fulfilled' || !r.value?.data) continue;
        for (const entry of r.value.data) {
          epssMap.set(entry.cve, {
            score: isNaN(parseFloat(entry.epss)) ? 0 : parseFloat(entry.epss),
            percentile: isNaN(parseFloat(entry.percentile)) ? 0 : parseFloat(entry.percentile)
          });
        }
      }

      // Enrich CVE objects in-place
      for (const cve of cves) {
        const epss = epssMap.get(cve.id);
        if (epss) cve.epss = epss;
      }

      console.log(`[API] EPSS enrichment: ${epssMap.size}/${cves.length} CVEs scored`);
    } catch (err) {
      console.warn('[API] EPSS enrichment failed (non-fatal):', err.message);
    }
    return cves;
  }

  // Fetch CVEs from a specific source
  async function fetchCVEsBySource(source = 'auto', timeRange = '1w', severity = '') {
    switch (source) {
      case 'cvelist':
        return (await fetchCVEsFromCveList(timeRange)) || [];
      case 'github':
        return (await fetchGitHubAdvisories(timeRange, severity)) || [];
      case 'nvd':
        return (await fetchCVEsFromNVD(timeRange, severity)) || [];
      case 'cveorg':
        return (await fetchCVEsFromCVEOrg(timeRange)) || [];
      case 'all':
        return fetchAllCVESources(timeRange, severity);
      case 'auto':
      default:
        return fetchCVEs(timeRange, severity);
    }
  }

  // Fetch from ALL sources, merge, deduplicate, newest first
  async function fetchAllCVESources(timeRange = '1w', severity = '') {
    const limit = timeRangeCap(timeRange);
    console.log('[API] Fetching from ALL CVE sources...');
    const [cvelist, github, nvd, cveorg] = await Promise.allSettled([
      fetchCVEsFromCveList(timeRange),
      fetchGitHubAdvisories(timeRange, severity),
      fetchCVEsFromNVD(timeRange, severity),
      fetchCVEsFromCVEOrg(timeRange)
    ]);

    const all = [];
    const seen = new Set();

    function addUnique(arr, src) {
      if (!Array.isArray(arr)) return;
      for (const cve of arr) {
        if (!seen.has(cve.id)) {
          seen.add(cve.id);
          cve._source = src;
          all.push(cve);
        }
      }
    }

  addUnique(cvelist.status === 'fulfilled' ? cvelist.value : null, 'CVEProject');
  addUnique(github.status === 'fulfilled' ? github.value : null, 'GitHub');
  addUnique(nvd.status === 'fulfilled' ? nvd.value : null, 'NVD');
  addUnique(cveorg.status === 'fulfilled' ? cveorg.value : null, 'CVE.org');

    all.sort((a, b) => new Date(b.published) - new Date(a.published));

    let filtered = all;
    if (severity) filtered = all.filter(c => c.cvss?.severity === severity.toUpperCase());

    console.log(`[API] All sources merged: ${all.length} unique CVEs (${cvelist.value?.length || 0} CVEProject + ${github.value?.length || 0} GitHub + ${nvd.value?.length || 0} NVD + ${cveorg.value?.length || 0} CVE.org)`);

    const result = filtered.slice(0, limit);
    return result;
  }

  // Fetch CVEs — cvelistV5 (real-time) → GitHub Advisory (~1d) → NVD (~6d) → fallback
  async function fetchCVEs(timeRange = '1w', severity = '') {
    const limit = timeRangeCap(timeRange);
    if (!severity) {
      const realtime = await fetchCVEsFromCveList(timeRange);
      if (realtime) {
        console.log(`[API] Using real-time cvelistV5 data (${realtime.length} CVEs)`);
        return realtime.slice(0, limit);
      }
    }

    const ghAdvisories = await fetchGitHubAdvisories(timeRange, severity);
    if (Array.isArray(ghAdvisories) && ghAdvisories.length >= 5) {
      console.log(`[API] Using GitHub Advisory data (${ghAdvisories.length} entries)`);
      return ghAdvisories.slice(0, limit);
    }

    const live = await fetchCVEsFromNVD(timeRange, severity);
    if (Array.isArray(live) && live.length > 0) {
      console.log(`[API] Using live NVD data (${live.length} CVEs)`);
      return live.slice(0, limit);
    }

    console.log('[API] Live sources unavailable, using fallback CVE data');
    let fallback = getFallbackCVEs();
    if (severity) fallback = fallback.filter(c => c.cvss?.severity === severity.toUpperCase());
    // Don't filter fallback by time range — it's last-resort data when all live sources fail
    fallback.sort((a, b) => new Date(b.published) - new Date(a.published));
    return fallback.slice(0, limit);
  }
  
  // Fallback CVEs - actually recent from NVD (verified latest - March 7, 2026)
  function getFallbackCVEs() {
    const now = new Date();
    return [
      // March 7, 2026 (TODAY)
      { id: 'CVE-2026-30823', description: 'Flowise before 3.0.13 IDOR vulnerability leading to account takeover and enterprise feature bypass via SSO configuration', published: '2026-03-07T06:16:00.000Z', modified: '2026-03-07T06:16:00.000Z', cvss: { score: 8.8, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-30823'], cpe: [], type: 'cve' },
      { id: 'CVE-2026-28802', description: 'Authlib Python library from 1.6.5 to before 1.6.7 - malicious JWT with alg: none can bypass signature verification', published: '2026-03-07T00:00:00.000Z', modified: '2026-03-07T00:00:00.000Z', cvss: { score: 7.5, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-28802'], cpe: ['cpe:2.3:a:authlib:authlib:*:*:*:*:*:*:*:*'], type: 'cve' },
      // March 6, 2026
      { id: 'CVE-2026-3537', description: 'Object lifecycle issue in PowerVR in Google Chrome on Android prior to 145.0.7632.159 - heap corruption via crafted HTML', published: '2026-03-06T00:00:00.000Z', modified: '2026-03-06T00:00:00.000Z', cvss: { score: 8.8, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H' }, references: ['https://chromereleases.googleblog.com/'], cpe: ['cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*'], type: 'cve' },
      { id: 'CVE-2026-28133', description: 'WP Chill Filr filr-protection unrestricted file upload vulnerability allowing web shell upload', published: '2026-03-06T00:00:00.000Z', modified: '2026-03-06T00:00:00.000Z', cvss: { score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-28133'], cpe: ['cpe:2.3:a:wpchill:filr:*:*:*:*:*:*:*:*'], type: 'cve' },
      { id: 'CVE-2026-28485', description: 'OpenClaw fail to enforce mandatory authentication on /agent/act browser-control HTTP route', published: '2026-03-06T00:00:00.000Z', modified: '2026-03-06T00:00:00.000Z', cvss: { score: 8.4, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-28485'], cpe: [], type: 'cve' },
      { id: 'CVE-2026-3383', description: 'ChaiScript up to 6.1.0 weakness in chaiscript::Boxed_Number::go function', published: '2026-03-06T00:00:00.000Z', modified: '2026-03-06T00:00:00.000Z', cvss: { score: 6.5, severity: 'MEDIUM', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-3383'], cpe: ['cpe:2.3:a:chaiscript:chaiscript:*:*:*:*:*:*:*:*'], type: 'cve' },
      // March 5, 2026
      { id: 'CVE-2026-26720', description: 'Twenty CRM v1.15.0 remote attacker execute arbitrary code via local.driver.ts module', published: '2026-03-05T00:00:00.000Z', modified: '2026-03-05T00:00:00.000Z', cvss: { score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-26720'], cpe: ['cpe:2.3:a:twenty:crm:*:*:*:*:*:*:*:*'], type: 'cve' },
      { id: 'CVE-2026-27971', description: 'Qwik <=1.19.0 vulnerable to RCE due to unsafe deserialization in server$ RPC mechanism', published: '2026-03-05T00:00:00.000Z', modified: '2026-03-05T00:00:00.000Z', cvss: { score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-27971'], cpe: ['cpe:2.3:a:builderio:qwik:*:*:*:*:*:*:*:*'], type: 'cve' },
      { id: 'CVE-2026-27820', description: 'Buffer overflow vulnerability in Zlib::GzipReader in Ruby zlib gem', published: '2026-03-05T00:00:00.000Z', modified: '2026-03-05T00:00:00.000Z', cvss: { score: 7.5, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-27820'], cpe: ['cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*'], type: 'cve' },
      // March 3, 2026
      { id: 'CVE-2026-3136', description: 'Improper authorization vulnerability in Google Cloud Build Trigger Comment Control', published: '2026-03-03T12:16:19.000Z', modified: '2026-03-03T12:16:19.000Z', cvss: { score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-3136'], cpe: ['cpe:2.3:a:google:google_cloud_build:*:*:*:*:*:*:*:*'], type: 'cve' },
      // Known Exploited (for demo purposes, marking some as KEV)
      { id: 'CVE-2023-38408', description: 'OpenSSH forward command injection vulnerability - KNOWN EXPLOITED', published: new Date(now - 30*24*60*60*1000).toISOString(), modified: new Date(now - 30*24*60*60*1000).toISOString(), cvss: { score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-38408', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'], cpe: ['cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*'], type: 'cve' },
      { id: 'CVE-2023-34362', description: 'MOVEit Transfer SQL injection vulnerability - KNOWN EXPLOITED', published: new Date(now - 45*24*60*60*1000).toISOString(), modified: new Date(now - 45*24*60*60*1000).toISOString(), cvss: { score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-34362', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'], cpe: ['cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*'], type: 'cve' },
    ];
  }

  // Detect country from CVE description
  function detectCountry(text = '') {
    const lower = text.toLowerCase();
    for (const [code, keywords] of Object.entries(COUNTRY_KEYWORDS)) {
      for (const kw of keywords) {
        if (lower.includes(kw)) return code;
      }
    }
    return null;
  }

  // ── ransomware.live API — Real-time ransomware victims ───
  const RANSOMWARE_LIVE_API = 'https://api.ransomware.live/v1';

  // Country code to name mapping for ransomware victims
  const COUNTRY_NAME_MAP = {
    US: 'United States', GB: 'United Kingdom', DE: 'Germany', FR: 'France',
    CA: 'Canada', AU: 'Australia', IT: 'Italy', BR: 'Brazil', IN: 'India',
    JP: 'Japan', CN: 'China', RU: 'Russia', KR: 'South Korea', MX: 'Mexico',
    ES: 'Spain', NL: 'Netherlands', SE: 'Sweden', CH: 'Switzerland',
    SG: 'Singapore', IL: 'Israel', AE: 'UAE', ZA: 'South Africa',
    PL: 'Poland', BE: 'Belgium', AT: 'Austria', CZ: 'Czech Republic'
  };

  async function fetchLiveRansomware() {
    const proxies = [
      url => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
      url => `https://corsproxy.io/?${encodeURIComponent(url)}`,
      url => url // direct (in case CORS is added)
    ];

    for (const proxy of proxies) {
      try {
        const url = proxy(`${RANSOMWARE_LIVE_API}/recentvictims`);
        const resp = await fetchWithAbort(url, {}, 8000);
        if (!resp.ok) continue;
        const data = await resp.json();
        if (!Array.isArray(data) || data.length === 0) continue;

        const mapped = data.slice(0, 50).map((v, i) => ({
          id: `rv-${i}-${v.group_name}`,
          organization: v.post_title || 'Unknown',
          group: v.group_name || 'Unknown',
          country: COUNTRY_NAME_MAP[v.country] || v.country || 'Unknown',
          countryCode: v.country || 'US',
          sector: v.activity || 'Unknown',
          discovered: v.discovered || v.published,
          description: v.description ? v.description.replace(/\[AI generated\]\s*/i, '').slice(0, 200) : `${v.group_name} ransomware attack on ${v.post_title}`,
          website: v.website || '',
          source: 'ransomware',
          type: 'ransomware'
        }));

        console.log(`[API] ransomware.live: ${mapped.length} live victims`);
        return mapped;
      } catch (err) { console.warn('[proxy fallback]', err.message); continue; }
    }
    console.warn('[API] ransomware.live unreachable, using fallback');
    return null;
  }

  async function fetchRansomware() {
    const live = await fetchLiveRansomware();
    return live || getMockRansomware();
  }

  // ── URLhaus API — Recent malicious URLs ───────────────────
  function parseURLhausDate(dateStr) {
    if (!dateStr) return new Date().toISOString();
    // "2026-03-08 15:16:23 UTC" → ISO
    return new Date(dateStr.replace(' UTC', 'Z').replace(' ', 'T')).toISOString();
  }

  async function fetchURLhaus(limit = 30) {
    const apiUrl = 'https://urlhaus.abuse.ch/downloads/json_recent/';
    const proxies = [
      url => `https://corsproxy.io/?${encodeURIComponent(url)}`,
      url => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
      url => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`,
      url => url
    ];

    for (const proxy of proxies) {
      try {
        const url = proxy(apiUrl);
        const resp = await fetchWithAbort(url, {}, 8000);
        if (!resp.ok) continue;
        const data = await resp.json();
        if (!data || typeof data !== 'object') continue;

        const items = Array.isArray(data) ? data : Object.values(data).filter(v => typeof v === 'object' && v !== null);
        const mapped = items.slice(0, limit).map(item => {
          const entry = Array.isArray(item) ? item[0] : item;
          if (!entry) return null;
          return {
            id: `urlhaus-${entry.id || Utils.slugify(entry.url || '') || Utils.uid()}`,
            organization: entry.url || 'Unknown URL',
            group: entry.threat || 'Unknown',
            country: 'Unknown',
            countryCode: 'XX',
            sector: (entry.tags || []).join(', ') || 'Malware',
            discovered: parseURLhausDate(entry.dateadded),
            description: `${entry.threat || 'malware'}: ${entry.url || ''} [${(entry.tags || []).join(', ')}]`,
            website: entry.urlhaus_reference || '',
            source: 'urlhaus',
            threatType: 'malware_url',
            type: 'ransomware'
          };
        }).filter(Boolean);

        console.log(`[API] URLhaus: ${mapped.length} malicious URLs`);
        return mapped;
      } catch (err) { console.warn('[proxy fallback]', err.message); continue; }
    }
    console.warn('[API] URLhaus unreachable');
    return [];
  }

  // ── ThreatFox API — Recent IOCs ───────────────────────────
  async function fetchThreatFox(limit = 30) {
    const apiUrl = 'https://threatfox.abuse.ch/export/json/recent/';
    const proxies = [
      url => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
      url => `https://corsproxy.io/?${encodeURIComponent(url)}`,
      url => url
    ];

    for (const proxy of proxies) {
      try {
        const url = proxy(apiUrl);
        const resp = await fetchWithAbort(url, {}, 8000);
        if (!resp.ok) continue;
        const data = await resp.json();
        if (!data || typeof data !== 'object') continue;

        const items = Array.isArray(data) ? data : Object.values(data).filter(v => typeof v === 'object' && v !== null);
        const mapped = items.slice(0, limit).map(item => {
          const entry = Array.isArray(item) ? item[0] : item;
          if (!entry) return null;
          return {
            id: `tf-${entry.id || Utils.slugify(entry.ioc_value || '') || Utils.uid()}`,
            organization: entry.ioc_value || 'Unknown IOC',
            group: entry.malware_printable || entry.malware || 'Unknown',
            country: 'Unknown',
            countryCode: 'XX',
            sector: entry.threat_type || 'IOC',
            discovered: entry.first_seen_utc || new Date().toISOString(),
            description: `${entry.threat_type || 'ioc'}: ${entry.ioc_type || ''} ${entry.ioc_value || ''} — ${entry.malware_printable || ''}`,
            website: entry.reference || '',
            source: 'threatfox',
            threatType: 'ioc',
            type: 'ransomware'
          };
        }).filter(Boolean);

        console.log(`[API] ThreatFox: ${mapped.length} IOCs`);
        return mapped;
      } catch (err) { console.warn('[proxy fallback]', err.message); continue; }
    }
    console.warn('[API] ThreatFox unreachable');
    return [];
  }

  // ── InQuest Labs IOC DB ───────────────────────────────────
  async function fetchInQuestIOCs(limit = 30) {
    const apiUrl = `https://labs.inquest.net/api/iocdb/list?limit=${Math.min(limit, 50)}`;

    // Try direct first (InQuest may support CORS), then proxies
    const proxies = [
      url => url,
      url => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
      url => `https://corsproxy.io/?${encodeURIComponent(url)}`
    ];

    for (const proxy of proxies) {
      try {
        const url = proxy(apiUrl);
        const resp = await fetchWithAbort(url, {}, 8000);
        if (!resp.ok) continue;
        const data = await resp.json();
        const items = data.data || data;
        if (!Array.isArray(items) || items.length === 0) continue;

        const mapped = items.slice(0, limit).map((item, i) => ({
          id: `inquest-${i}-${(item.artifact || '').slice(0, 12)}`,
          organization: item.artifact || 'Unknown',
          group: item.artifact_type || 'IOC',
          country: 'Unknown',
          countryCode: 'XX',
          sector: item.artifact_type || 'IOC',
          discovered: item.created_date || new Date().toISOString(),
          description: `${item.artifact_type || 'IOC'}: ${item.artifact || ''} — ${(item.reference_text || '').slice(0, 120)}`,
          website: item.reference_link || '',
          source: 'inquest',
          threatType: 'ioc',
          type: 'ransomware'
        }));

        console.log(`[API] InQuest: ${mapped.length} IOCs`);
        return mapped;
      } catch (err) { console.warn('[proxy fallback]', err.message); continue; }
    }
    console.warn('[API] InQuest unreachable');
    return [];
  }

  // ── Have I Been Pwned — Recent Breaches ───────────────────
  async function fetchHIBPBreaches(limit = 30) {
    const apiUrl = 'https://haveibeenpwned.com/api/v3/breaches';

    try {
      const resp = await fetchWithAbort(apiUrl, {}, 8000);
      if (!resp.ok) throw new Error(`HIBP ${resp.status}`);
      const breaches = await resp.json();
      if (!Array.isArray(breaches)) throw new Error('Bad HIBP response');

      const sorted = breaches
        .sort((a, b) => new Date(b.ModifiedDate || b.AddedDate || 0) - new Date(a.ModifiedDate || a.AddedDate || 0))
        .slice(0, limit);

      const mapped = sorted.map(breach => ({
        id: `hibp-${breach.Name}`,
        organization: breach.Title || breach.Name,
        group: 'Data Breach',
        country: 'Unknown',
        countryCode: 'XX',
        sector: (breach.DataClasses || []).slice(0, 3).join(', ') || 'Breach',
        discovered: breach.ModifiedDate || breach.AddedDate || new Date().toISOString(),
        description: `${breach.Title || breach.Name} (${breach.Domain || ''}) — ${(breach.PwnCount || 0).toLocaleString()} accounts compromised`,
        website: `https://haveibeenpwned.com/breaches#${breach.Name}`,
        source: 'hibp',
        threatType: 'breach',
        pwnCount: breach.PwnCount,
        type: 'ransomware'
      }));

      console.log(`[API] HIBP: ${mapped.length} breaches`);
      return mapped;
    } catch (err) {
      console.warn('[API] HIBP unreachable:', err.message);
      return [];
    }
  }

  // ── Unified malware/threat source fetcher ─────────────────
  async function fetchAllMalwareSources(timeRange = '1w') {
    const limit = timeRangeCap(timeRange);
    const results = await Promise.allSettled([
      fetchLiveRansomware().then(r => r || getMockRansomware()),
      fetchURLhaus(limit),
      fetchThreatFox(limit),
      fetchInQuestIOCs(limit),
      fetchHIBPBreaches(limit)
    ]);

    let merged = [];
    const labels = ['ransomware.live', 'URLhaus', 'ThreatFox', 'InQuest', 'HIBP'];
    results.forEach((r, i) => {
      if (r.status === 'fulfilled' && Array.isArray(r.value)) {
        console.log(`[API] ${labels[i]}: ${r.value.length} items merged`);
        merged = merged.concat(r.value);
      } else {
        console.warn(`[API] ${labels[i]}: failed or empty`);
      }
    });

    // Filter by time range
    merged = filterByTimeRange(merged, 'discovered', timeRange);

    // Sort by discovered date newest first
    merged.sort((a, b) => new Date(b.discovered || 0) - new Date(a.discovered || 0));
    const final = merged.slice(0, limit);
    console.log(`[API] All malware sources merged: ${final.length} items from ${merged.length} total`);
    return final;
  }

  async function fetchMalwareBySource(source = 'all', timeRange = '1w') {
    const limit = timeRangeCap(timeRange);
    const sortAndSlice = (items) => {
      items.sort((a, b) => new Date(b.discovered || 0) - new Date(a.discovered || 0));
      return items.slice(0, limit);
    };
    switch (source) {
      case 'ransomware-victims': {
        const items = (await fetchLiveRansomware()) || getMockRansomware();
        return sortAndSlice(filterByTimeRange(items, 'discovered', timeRange));
      }
      case 'urlhaus': return sortAndSlice(filterByTimeRange(await fetchURLhaus(limit), 'discovered', timeRange));
      case 'threatfox': return sortAndSlice(filterByTimeRange(await fetchThreatFox(limit), 'discovered', timeRange));
      case 'inquest': return sortAndSlice(filterByTimeRange(await fetchInQuestIOCs(limit), 'discovered', timeRange));
      case 'hibp': return sortAndSlice(filterByTimeRange(await fetchHIBPBreaches(limit), 'discovered', timeRange));
      case 'all': return fetchAllMalwareSources(timeRange);
      default: return fetchMalwareBySource('ransomware-victims', timeRange);
    }
  }

  // Mock Ransomware data (fallback)
  function getMockRansomware() {
    const now = new Date();
    return [
      { id: 'r1', organization: 'Healthcare Corp International', group: 'LockBit', country: 'US', countryCode: 'US', sector: 'Healthcare', discovered: new Date(now - 1*24*60*60*1000).toISOString(), description: 'Ransomware attack on healthcare provider', type: 'ransomware' },
      { id: 'r2', organization: 'Tech Solutions Ltd', group: 'BlackCat', country: 'Germany', countryCode: 'DE', sector: 'Technology', discovered: new Date(now - 2*24*60*60*1000).toISOString(), description: 'Data exfiltration reported', type: 'ransomware' },
      { id: 'r3', organization: 'Financial Services Group', group: 'Clop', country: 'UK', countryCode: 'GB', sector: 'Finance', discovered: new Date(now - 3*24*60*60*1000).toISOString(), description: 'Banking sector targeted', type: 'ransomware' },
      { id: 'r4', organization: 'Manufacturing Inc', group: 'Play', country: 'Brazil', countryCode: 'BR', sector: 'Manufacturing', discovered: new Date(now - 1*24*60*60*1000).toISOString(), description: 'Production systems encrypted', type: 'ransomware' },
      { id: 'r5', organization: 'Government Agency', group: 'Unknown', country: 'India', countryCode: 'IN', sector: 'Government', discovered: new Date(now - 4*24*60*60*1000).toISOString(), description: 'Critical infrastructure affected', type: 'ransomware' },
    ];
  }

  // Mock APT data — enriched with real MITRE ATT&CK data
  function getMockAPT() {
    return [
      // Russia
      { id: 'G0007', name: 'APT28', aliases: ['Fancy Bear', 'Strontium', 'Sofacy', 'Sednit'], country: 'RU', targetSectors: ['Government', 'Defense', 'Energy', 'Media'], description: 'Russian GRU Unit 26165. Active since 2004, targeting NATO allies, election interference, and defense contractors. Uses spearphishing, zero-days, and credential harvesting.', techniques: ['T1566', 'T1059', 'T1071'], type: 'apt' },
      { id: 'G0016', name: 'APT29', aliases: ['Cozy Bear', 'The Dukes', 'Midnight Blizzard', 'Nobelium'], country: 'RU', targetSectors: ['Government', 'Healthcare', 'Think Tanks', 'Technology'], description: 'Russian SVR intelligence. Behind SolarWinds (2020) and Microsoft breach (2024). Highly sophisticated supply-chain attacks.', techniques: ['T1195', 'T1078', 'T1550'], type: 'apt' },
      { id: 'G0034', name: 'Sandworm', aliases: ['Voodoo Bear', 'IRIDIUM', 'Seashell Blizzard'], country: 'RU', targetSectors: ['Energy', 'Government', 'Critical Infrastructure'], description: 'Russian GRU Unit 74455. Responsible for NotPetya (2017), Ukraine power grid attacks, and Olympic Destroyer.', techniques: ['T1498', 'T1485', 'T1486'], type: 'apt' },
      { id: 'G0010', name: 'Turla', aliases: ['Snake', 'Venomous Bear', 'Waterbug'], country: 'RU', targetSectors: ['Government', 'Diplomatic', 'Military', 'Research'], description: 'Russian FSB-linked. One of the most sophisticated APTs, known for hijacking other groups\' infrastructure and satellite-based C2.', techniques: ['T1071', 'T1102', 'T1573'], type: 'apt' },
      // China
      { id: 'G0006', name: 'APT1', aliases: ['Comment Crew', 'PLA Unit 61398'], country: 'CN', targetSectors: ['Technology', 'Aerospace', 'Energy', 'Manufacturing'], description: 'Chinese PLA Unit 61398. Prolific espionage group first exposed by Mandiant in 2013. Economic espionage focus.', techniques: ['T1566', 'T1003', 'T1005'], type: 'apt' },
      { id: 'G0096', name: 'APT41', aliases: ['Winnti', 'Barium', 'Wicked Panda'], country: 'CN', targetSectors: ['Healthcare', 'Pharmaceuticals', 'Software', 'Gaming'], description: 'Chinese dual-purpose group conducting both state espionage and financially motivated operations. Supply-chain attacks on software companies.', techniques: ['T1195', 'T1059', 'T1055'], type: 'apt' },
      { id: 'G0065', name: 'APT40', aliases: ['Leviathan', 'TEMP.Periscope', 'Bronze Mohawk'], country: 'CN', targetSectors: ['Maritime', 'Defense', 'Aviation', 'Research'], description: 'Chinese MSS-affiliated, targeting South China Sea geopolitical interests. Known for exploiting public-facing applications.', techniques: ['T1190', 'T1133', 'T1505'], type: 'apt' },
      { id: 'G1030', name: 'Volt Typhoon', aliases: ['Bronze Silhouette', 'Vanguard Panda'], country: 'CN', targetSectors: ['Critical Infrastructure', 'Telecommunications', 'Energy'], description: 'Chinese state-sponsored group pre-positioning in US critical infrastructure. Uses living-off-the-land techniques to avoid detection.', techniques: ['T1059', 'T1218', 'T1003'], type: 'apt' },
      { id: 'G1029', name: 'Salt Typhoon', aliases: ['GhostEmperor', 'FamousSparrow'], country: 'CN', targetSectors: ['Telecommunications', 'ISP', 'Government'], description: 'Chinese group that infiltrated major US telecom providers in 2024, accessing call records and surveillance systems.', techniques: ['T1190', 'T1071', 'T1005'], type: 'apt' },
      // North Korea
      { id: 'G0032', name: 'Lazarus Group', aliases: ['Hidden Cobra', 'Zinc', 'Diamond Sleet'], country: 'KP', targetSectors: ['Finance', 'Cryptocurrency', 'Defense', 'Media'], description: 'North Korean state-sponsored. Behind Sony hack (2014), WannaCry (2017), $620M Ronin bridge theft. Funds nuclear program.', techniques: ['T1566', 'T1059', 'T1486'], type: 'apt' },
      { id: 'G0082', name: 'Kimsuky', aliases: ['Velvet Chollima', 'Emerald Sleet', 'Thallium'], country: 'KP', targetSectors: ['Government', 'Research', 'Think Tanks', 'Defense'], description: 'North Korean intelligence-gathering group. Targets South Korean and US policy experts via social engineering and credential theft.', techniques: ['T1566', 'T1598', 'T1078'], type: 'apt' },
      // Iran
      { id: 'G0059', name: 'APT33', aliases: ['Elfin', 'Refined Kitten', 'Peach Sandstorm'], country: 'IR', targetSectors: ['Aviation', 'Energy', 'Petrochemical', 'Defense'], description: 'Iranian MOIS-linked. Targets aviation and energy sectors with destructive malware. Connected to Shamoon campaigns.', techniques: ['T1566', 'T1110', 'T1486'], type: 'apt' },
      { id: 'G0064', name: 'APT34', aliases: ['OilRig', 'Helix Kitten', 'Hazel Sandstorm'], country: 'IR', targetSectors: ['Government', 'Finance', 'Energy', 'Telecommunications'], description: 'Iranian cyber espionage group targeting Middle Eastern organizations. Uses custom backdoors and DNS tunneling.', techniques: ['T1071', 'T1059', 'T1105'], type: 'apt' },
      { id: 'G1031', name: 'MuddyWater', aliases: ['Mercury', 'Mango Sandstorm', 'Static Kitten'], country: 'IR', targetSectors: ['Government', 'Telecommunications', 'Oil & Gas'], description: 'Iranian MOIS subordinate. Targets Middle East, Central/South Asia. Uses living-off-the-land and legitimate tools.', techniques: ['T1059', 'T1218', 'T1105'], type: 'apt' },
      // Others
      { id: 'G1028', name: 'Scattered Spider', aliases: ['UNC3944', 'Octo Tempest', 'Star Fraud'], country: 'US', targetSectors: ['Telecommunications', 'Technology', 'Finance', 'Hospitality'], description: 'English-speaking cybercriminal group. Social-engineering help desks for MFA bypass. MGM and Caesars attacks (2023).', techniques: ['T1566', 'T1078', 'T1199'], type: 'apt' },
    ];
  }

  // ── MISP Galaxy — Comprehensive threat actor database ────
  const MISP_GALAXY_URL = 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json';

  async function fetchMISPGalaxy(limit = 50) {
    if (mispCache && mispCacheTime && (Date.now() - mispCacheTime < MISP_CACHE_DURATION)) {
      console.log(`[API] MISP Galaxy: ${mispCache.length} threat actors (cached)`);
      return mispCache.slice(0, limit);
    }

    try {
      const res = await fetchWithAbort(MISP_GALAXY_URL, {}, 8000);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const values = data.values || [];

      const actors = values.map((entry, index) => ({
        id: entry.uuid || `misp-${index}`,
        name: entry.value,
        aliases: entry.meta?.synonyms || [],
        country: entry.meta?.country || 'Unknown',
        targetSectors: entry.meta?.['cfr-target-category'] || [],
        suspectedVictims: entry.meta?.['cfr-suspected-victims'] || [],
        description: entry.description || `Threat actor: ${entry.value}`,
        techniques: [],
        refs: entry.meta?.refs || [],
        source: 'misp',
        type: 'apt'
      }));

      // Sort: actors with country attribution first, then by name
      actors.sort((a, b) => {
        const aHasCountry = a.country !== 'Unknown' ? 0 : 1;
        const bHasCountry = b.country !== 'Unknown' ? 0 : 1;
        if (aHasCountry !== bHasCountry) return aHasCountry - bHasCountry;
        return a.name.localeCompare(b.name);
      });

      mispCache = actors;
      mispCacheTime = Date.now();
      console.log(`[API] MISP Galaxy: ${actors.length} threat actors`);
      return actors.slice(0, limit);
    } catch (err) {
      console.warn('[API] MISP Galaxy fetch failed:', err.message);
      return [];
    }
  }

  // ── APT RSS feeds — Recent threat actor activity ───────
  const APT_RSS_FEEDS = [
    { name: 'Mandiant',    key: 'mandiant',    url: 'https://www.mandiant.com/resources/blog/rss.xml' },
    { name: 'CrowdStrike', key: 'crowdstrike', url: 'https://www.crowdstrike.com/blog/feed/' },
    { name: 'Securelist',  key: 'securelist',  url: 'https://securelist.com/feed/' },
  ];

  async function fetchAPTNews(sourceKey = null) {
    const feeds = sourceKey
      ? APT_RSS_FEEDS.filter(f => f.key === sourceKey)
      : APT_RSS_FEEDS;

    const results = await Promise.allSettled(
      feeds.map(feed => fetchRSSWithFallbacks({
        ...feed,
        category: 'apt'
      }))
    );

    const items = [];
    results.forEach((result, i) => {
      if (result.status === 'fulfilled' && result.value.length > 0) {
        result.value.forEach((item, j) => {
          items.push({
            id: `apt-rss-${feeds[i].key}-${j}`,
            name: item.title || 'Untitled',
            aliases: [],
            country: 'Unknown',
            targetSectors: [],
            description: item.description || '',
            techniques: [],
            source: feeds[i].key,
            published: item.published || new Date().toISOString(),
            link: item.link || '',
            type: 'apt'
          });
        });
      }
    });

    return items;
  }

  // ── APT source dispatcher ─────────────────────────────
  async function fetchAllAPTSources(timeRange = '1w') {
    const limit = timeRangeCap(timeRange);
    const [misp, rss] = await Promise.allSettled([
      fetchMISPGalaxy(limit),
      fetchAPTNews()
    ]);

    const mispActors = misp.status === 'fulfilled' ? misp.value : [];
    const rssItems = rss.status === 'fulfilled' ? rss.value : [];

    const dateFiltered = filterByTimeRange(rssItems, 'published', timeRange);
    // MISP Galaxy actors are static (no date field) — scale their count by time range
    // so shorter ranges emphasise recent RSS intel over the full static catalogue
    const mispRatio = { '24h': 0.1, '1w': 0.3, '1m': 0.6 }[timeRange] ?? 0.3;
    const mispSlice = mispActors.slice(0, Math.ceil(limit * mispRatio));
    const merged = [...mispSlice, ...dateFiltered];
    return merged.slice(0, limit);
  }

  async function fetchAPTBySource(source = 'all', timeRange = '1w') {
    const limit = timeRangeCap(timeRange);
    switch (source) {
      case 'misp':        return fetchMISPGalaxy(limit);
      case 'static':      return getMockAPT();
      case 'mandiant':    return fetchAPTNews('mandiant');
      case 'crowdstrike': return fetchAPTNews('crowdstrike');
      case 'securelist':  return fetchAPTNews('securelist');
      case 'all':         return fetchAllAPTSources(timeRange);
      default:            return getMockAPT();
    }
  }

  // Country coordinates for map
  const COUNTRY_COORDS = {
    US: [37.0902, -95.7129], CN: [35.8617, 104.1954], RU: [61.5240, 105.3188],
    DE: [51.1657, 10.4515], GB: [55.3781, -3.4360], FR: [46.2276, 2.2137],
    JP: [36.2048, 138.2529], IN: [20.5937, 78.9629], KR: [35.9078, 127.7669],
    BR: [-14.2350, -51.9253], AU: [-25.2744, 133.7751], IL: [31.0461, 34.8516],
    IR: [32.4279, 53.6880], UA: [48.3794, 31.1656], SG: [1.3521, 103.8198],
    KP: [40.3399, 127.5101], CA: [56.1304, -106.3468], IT: [41.8719, 12.5674],
    ES: [40.4637, -3.7492], NL: [52.1326, 5.2913], SE: [60.1282, 18.6435],
    CH: [46.8182, 8.2275], PL: [51.9194, 19.1451], MX: [23.6345, -102.5528],
    ZA: [-30.5595, 22.9375], AE: [23.4241, 53.8478], SA: [23.8859, 45.0792],
    BE: [50.5039, 4.4699], AT: [47.5162, 14.5501], CZ: [49.8175, 15.4730],
    PH: [12.8797, 121.7740], TH: [15.8700, 100.9925], ID: [-0.7893, 113.9213],
    CO: [4.5709, -74.2973], AR: [-38.4161, -63.6167], CL: [-35.6751, -71.5430],
    NG: [9.0820, 8.6753], EG: [26.8206, 30.8025], TR: [38.9637, 35.2433],
    MY: [4.2105, 101.9758], VN: [14.0583, 108.2772], PK: [30.3753, 69.3451],
    IQ: [33.2232, 43.6793], SY: [34.8021, 38.9968], TW: [23.6978, 120.9605],
    PS: [31.9522, 35.2332], LB: [33.8547, 35.8623], YE: [15.5527, 48.5164],
    AF: [33.9391, 67.7100], LY: [26.3351, 17.2283], SD: [12.8628, 30.2176],
    KE: [0.0236, 37.9062], GH: [7.9465, -1.0232], BD: [23.685, 90.3563],
    MM: [21.9162, 95.956], KH: [12.5657, 104.991], LA: [19.8563, 102.4955],
    GE: [42.3154, 43.3569], AM: [40.0691, 45.0382], AZ: [40.1431, 47.5769],
    KZ: [48.0196, 66.9237], UZ: [41.3775, 64.5853], BY: [53.7098, 27.9534]
  };

  const COUNTRY_NAMES = {
    US:'United States',CN:'China',RU:'Russia',DE:'Germany',GB:'United Kingdom',
    FR:'France',JP:'Japan',IN:'India',KR:'South Korea',BR:'Brazil',AU:'Australia',
    IL:'Israel',IR:'Iran',UA:'Ukraine',SG:'Singapore',KP:'North Korea',CA:'Canada',
    IT:'Italy',ES:'Spain',NL:'Netherlands',SE:'Sweden',CH:'Switzerland',PL:'Poland',
    MX:'Mexico',ZA:'South Africa',AE:'UAE',SA:'Saudi Arabia',BE:'Belgium',AT:'Austria',
    CZ:'Czechia',PH:'Philippines',TH:'Thailand',ID:'Indonesia',CO:'Colombia',
    AR:'Argentina',CL:'Chile',NG:'Nigeria',EG:'Egypt',TR:'Turkey',MY:'Malaysia',
    VN:'Vietnam',PK:'Pakistan',IQ:'Iraq',SY:'Syria',TW:'Taiwan',PS:'Palestine',
    LB:'Lebanon',YE:'Yemen',AF:'Afghanistan',LY:'Libya',SD:'Sudan',KE:'Kenya',
    GH:'Ghana',BD:'Bangladesh',MM:'Myanmar',KH:'Cambodia',LA:'Laos',GE:'Georgia',
    AM:'Armenia',AZ:'Azerbaijan',KZ:'Kazakhstan',UZ:'Uzbekistan',BY:'Belarus'
  };

  const COUNTRY_FLAGS = {
    US:'🇺🇸',CN:'🇨🇳',RU:'🇷🇺',DE:'🇩🇪',GB:'🇬🇧',FR:'🇫🇷',JP:'🇯🇵',IN:'🇮🇳',
    KR:'🇰🇷',BR:'🇧🇷',AU:'🇦🇺',IL:'🇮🇱',IR:'🇮🇷',UA:'🇺🇦',SG:'🇸🇬',KP:'🇰🇵',
    CA:'🇨🇦',IT:'🇮🇹',ES:'🇪🇸',NL:'🇳🇱',SE:'🇸🇪',CH:'🇨🇭',PL:'🇵🇱',MX:'🇲🇽',
    ZA:'🇿🇦',AE:'🇦🇪',SA:'🇸🇦',BE:'🇧🇪',AT:'🇦🇹',CZ:'🇨🇿',PH:'🇵🇭',TH:'🇹🇭',
    ID:'🇮🇩',CO:'🇨🇴',AR:'🇦🇷',CL:'🇨🇱',NG:'🇳🇬',EG:'🇪🇬',TR:'🇹🇷',MY:'🇲🇾',
    VN:'🇻🇳',PK:'🇵🇰',IQ:'🇮🇶',SY:'🇸🇾',TW:'🇹🇼',PS:'🇵🇸',LB:'🇱🇧',YE:'🇾🇪',
    AF:'🇦🇫',LY:'🇱🇾',SD:'🇸🇩',KE:'🇰🇪',GH:'🇬🇭',BD:'🇧🇩',MM:'🇲🇲',KH:'🇰🇭',
    LA:'🇱🇦',GE:'🇬🇪',AM:'🇦🇲',AZ:'🇦🇿',KZ:'🇰🇿',UZ:'🇺🇿',BY:'🇧🇾'
  };

  // Get coordinates for a threat
  function getCoords(countryCode) {
    return COUNTRY_COORDS[countryCode] || null;
  }

  function getCountryName(code) {
    return COUNTRY_NAMES[code] || code || 'Unknown';
  }

  function getCountryFlag(code) {
    return COUNTRY_FLAGS[code] || '🌍';
  }

  // Main entry: load all data
  async function loadAllData(timeRanges = {}) {
    const cveRange     = timeRanges.cve      || '1w';
    const malwareRange = timeRanges.malware  || '1w';
    const newsRange    = timeRanges.news     || '1w';
    const aptRange     = timeRanges.apt      || '1w';

    // Include time range in cache key so changing range busts cache
    const rangeKey = `${cveRange}-${malwareRange}-${newsRange}-${aptRange}`;
    const CACHE_KEY = `cybervulndb_data_v9_${rangeKey}`;
    const CACHE_TS_KEY = `cybervulndb_ts_v9_${rangeKey}`;
    const CACHE_MAX_AGE = 15 * 60 * 1000; // 15 minutes

    // Clean up stale versioned cache keys
    (function cleanOldCacheKeys() {
      const staleVersions = ['v1','v2','v3','v4','v5','v6','v7','v8'];
      const prefixes = staleVersions.flatMap(v => [`cybervulndb_data_${v}_`, `cybervulndb_ts_${v}_`]);
      Object.keys(localStorage).forEach(k => {
        if (prefixes.some(p => k.startsWith(p))) localStorage.removeItem(k);
      });
    })();

    const cachedTs = Utils.storageGet(CACHE_TS_KEY);
    if (Utils.isCacheFresh(cachedTs, CACHE_MAX_AGE)) {
      const cached = Utils.storageGet(CACHE_KEY);
      if (cached) {
        console.log('[API] Using cached data');
        return cached;
      }
    }

    console.log('[API] Loading fresh data...', { cveRange, malwareRange, newsRange, aptRange });
    
    const [cves, ransomware, news, apt] = await Promise.all([
      fetchAllCVESources(cveRange),
      Promise.race([
        fetchAllMalwareSources(malwareRange),
        timeout(30000).catch(() => getMockRansomware())
      ]),
      Promise.race([
        fetchNewsBySource('all', newsRange).catch(() => []),
        timeout(20000).catch(() => [])
      ]),
      Promise.race([
        fetchAllAPTSources(aptRange),
        timeout(25000).catch(() => getMockAPT())
      ])
    ]);

  const data = { cves, ransomware, apt, news };

  await enrichWithEPSS(cves);
  Utils.storageSet(CACHE_KEY, data);
  Utils.storageSet(CACHE_TS_KEY, Date.now());
    
    console.log('[API] Data loaded:', {
      cves: cves.length,
      ransomware: ransomware.length,
      apt: apt.length,
      news: news.length
    });
    
    return data;
  }

  return {
    loadAllData,
    fetchCVEs,
    fetchCVEsBySource,
    fetchCVEsFromCVEOrg,
    enrichWithEPSS,
    fetchRansomware,
    fetchMalwareBySource,
    fetchURLhaus,
    fetchThreatFox,
    fetchInQuestIOCs,
    fetchHIBPBreaches,
    fetchAllNews,
    fetchNewsBySource,
    fetchKEV,
    isInKEV,
    getKEVDetails,
    fetchMISPGalaxy,
    fetchAPTBySource,
    getCoords,
    getCountryName,
    getCountryFlag,
    detectCountry,
    COUNTRY_COORDS,
    COUNTRY_KEYWORDS
  };
})();
