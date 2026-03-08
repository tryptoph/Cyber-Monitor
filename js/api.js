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
  const RSS_PROXIES = [
    url => `https://api.rss2json.com/v1/api.json?rss_url=${encodeURIComponent(url)}&count=10`,
    url => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
    url => `https://corsproxy.io/?${encodeURIComponent(url)}`,
  ];

  // Timeout helper
  function timeout(ms) {
    return new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Timeout')), ms)
    );
  }

  // Cache for KEV data
  let kevCache = null;
  let kevCacheTime = null;
  const KEV_CACHE_DURATION = 60 * 60 * 1000; // 1 hour
  
  // Security RSS Feeds — broader, more reliable sources
  const RSS_FEEDS = [
    { name: 'The Hacker News',  url: 'https://feeds.feedburner.com/TheHackersNews',           category: 'vulnerabilities' },
    { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/',                    category: 'breaches' },
    { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/',                 category: 'vulnerabilities' },
    { name: 'SANS ISC',         url: 'https://isc.sans.edu/rssfeed.xml',                       category: 'malware' },
    { name: 'SecurityWeek',     url: 'https://www.securityweek.com/feed/',                     category: 'enterprise' },
    { name: 'Dark Reading',     url: 'https://www.darkreading.com/rss.xml',                    category: 'enterprise' },
    { name: 'Malwarebytes',     url: 'https://blog.malwarebytes.com/feed/',                    category: 'malware' },
    { name: 'Threatpost',       url: 'https://threatpost.com/feed/',                           category: 'vulnerabilities' },
    { name: 'Schneier',         url: 'https://www.schneier.com/blog/atom.xml',                 category: 'policy' },
    { name: 'Wired Security',   url: 'https://www.wired.com/category/security/feed/rss/',      category: 'enterprise' },
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
        return Promise.race([fetch(url), timeout(8000)])
          .then(r => r.ok ? r.json() : { hits: [] })
          .then(data => (data.hits || [])
            .filter(h => h.url && h.title)
            .map(h => ({
              id: `hn-${h.objectID}`,
              title: h.title,
              link: h.url || `https://news.ycombinator.com/item?id=${h.objectID}`,
              description: (h.story_text || '').replace(/<[^>]+>/g, '').substring(0, 200) || h.title,
              source: 'HackerNews',
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
      const res = await Promise.race([fetch(url), timeout(7000)]);
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
            category: feed.category,
            published: item.pubDate || new Date().toISOString(),
            type: 'news',
          })).filter(i => i.title && i.link);
        }
      }
    } catch { /* try next */ }

    // 2. allorigins raw proxy → parse XML ourselves
    try {
      const res = await Promise.race([
        fetch(`https://api.allorigins.win/raw?url=${encodeURIComponent(feed.url)}`),
        timeout(6000)
      ]);
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
      const res = await Promise.race([
        fetch(`https://corsproxy.io/?${encodeURIComponent(feed.url)}`),
        timeout(6000)
      ]);
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

  // Keep legacy fetchRSS for backward compat
  async function fetchRSS(feed) {
    return fetchRSSWithFallbacks(feed);
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
    return deduped.slice(0, 60);
  }

  // Fetch only news (bypasses main data cache — use for live panel updates)
  async function fetchNewsOnly() {
    return fetchAllNews();
  }

  // Fetch CISA KEV data
  async function fetchKEV() {
    // Check cache
    if (kevCache && kevCacheTime && (Date.now() - kevCacheTime) < KEV_CACHE_DURATION) {
      console.log('[API] Using cached KEV data');
      return kevCache;
    }

    try {
      const response = await fetch(`${CORS_PROXY}${encodeURIComponent(CISA_KEV_URL)}`);
      if (!response.ok) {
        console.warn('[API] KEV fetch failed, using empty catalog');
        return [];
      }
      const data = await response.json();
      const vulnerabilities = data.vulnerabilities || [];
      kevCache = vulnerabilities;
      kevCacheTime = Date.now();
      console.log(`[API] Loaded ${vulnerabilities.length} KEV entries`);
      return vulnerabilities;
    } catch (err) {
      console.warn('[API] KEV fetch error:', err.message);
      return [];
    }
  }

  // Check if a CVE is in KEV catalog
  function isInKEV(cveId, kevList) {
    if (!kevList || !kevList.length) return false;
    return kevList.some(kev => kev.cveID === cveId);
  }

  // Get KEV details for a CVE
  function getKEVDetails(cveId, kevList) {
    if (!kevList || !kevList.length) return null;
    return kevList.find(kev => kev.cveID === cveId) || null;
  }

  // Fetch CVEs from NVD API 2.0
  async function fetchCVEsFromNVD(limit = 30, severity = '') {
    try {
      const params = new URLSearchParams();

      // Last 30 days — NVD has a 5-7 day processing lag, so 7 days would miss most recent entries
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 30);

      params.append('pubStartDate', startDate.toISOString());
      params.append('pubEndDate', endDate.toISOString());
      params.append('resultsPerPage', String(limit));

      if (severity) params.append('cvssV3Severity', severity.toUpperCase());

      const url = `${NVD_API}?${params.toString()}`;
      console.log('[API] Fetching from NVD:', url);

      const response = await Promise.race([fetch(url), timeout(15000)]);
      if (!response.ok) throw new Error(`NVD API returned ${response.status}`);

      const data = await response.json();
      const vulnerabilities = data.vulnerabilities || [];
      console.log(`[API] Fetched ${vulnerabilities.length} CVEs from NVD`);

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

  // Fetch CVEs - live NVD first, fallback data on failure
  async function fetchCVEs(limit = 30, severity = '') {
    const live = await fetchCVEsFromNVD(limit, severity);
    if (Array.isArray(live) && live.length > 0) {
      console.log(`[API] Using live NVD data (${live.length} CVEs)`);
      return live.slice(0, limit);
    }

    console.log('[API] Live NVD unavailable, using fallback CVE data');
    let fallback = getFallbackCVEs();
    if (severity) fallback = fallback.filter(c => c.cvss?.severity === severity.toUpperCase());
    fallback.sort((a, b) => new Date(b.published) - new Date(a.published));
    return fallback.slice(0, limit);
  }

  // Dedicated live CVE fetch — always bypasses cache, used for panel-only refresh
  async function fetchCVEsOnly() {
    return fetchCVEsFromNVD(30);
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
    return 'US'; // Default
  }

  // Mock CVE data for fallback
  function getMockCVEs() {
    const now = new Date();
    return [
      { id: 'CVE-2026-0001', description: 'Critical buffer overflow in popular authentication library allows remote code execution', published: new Date(now - 2*24*60*60*1000).toISOString(), cvss: { score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1' }, type: 'cve' },
      { id: 'CVE-2026-0002', description: 'SQL injection vulnerability in content management system', published: new Date(now - 1*24*60*60*1000).toISOString(), cvss: { score: 8.2, severity: 'HIGH', vector: 'CVSS:3.1' }, type: 'cve' },
      { id: 'CVE-2026-0003', description: 'Cross-site scripting vulnerability in web application firewall', published: new Date(now - 3*24*60*60*1000).toISOString(), cvss: { score: 6.1, severity: 'MEDIUM', vector: 'CVSS:3.1' }, type: 'cve' },
      { id: 'CVE-2026-0004', description: 'Privilege escalation vulnerability in cloud container runtime', published: new Date(now - 5*24*60*60*1000).toISOString(), cvss: { score: 7.5, severity: 'HIGH', vector: 'CVSS:3.1' }, type: 'cve' },
      { id: 'CVE-2026-0005', description: 'Information disclosure in API endpoint exposes sensitive headers', published: new Date(now - 4*24*60*60*1000).toISOString(), cvss: { score: 5.3, severity: 'MEDIUM', vector: 'CVSS:3.1' }, type: 'cve' },
    ];
  }

  // Mock Ransomware data
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

  // Mock APT data
  function getMockAPT() {
    return [
      { id: 'apt1', name: 'APT28', aliases: ['Fancy Bear', 'Strontium'], country: 'RU', targetSectors: ['Government', 'Defense', 'Energy'], description: 'Russian state-sponsored group targeting NATO allies', type: 'apt' },
      { id: 'apt2', name: 'APT29', aliases: ['Cozy Bear', 'The Dukes'], country: 'RU', targetSectors: ['Government', 'Healthcare', 'Think Tanks'], description: 'Russian intelligence targeting diplomatic entities', type: 'apt' },
      { id: 'apt3', name: 'APT40', aliases: ['Barium', 'GREF'], country: 'CN', targetSectors: ['Maritime', 'Defense', 'Research'], description: 'Chinese group targeting Southeast Asia', type: 'apt' },
      { id: 'apt4', name: 'Lazarus', aliases: ['Hidden Cobra', 'Zinc'], country: 'KP', targetSectors: ['Finance', 'Cryptocurrency', 'Defense'], description: 'North Korean financially-motivated group', type: 'apt' },
      { id: 'apt5', name: 'APT41', aliases: ['Winnti', 'Barium'], country: 'CN', targetSectors: ['Healthcare', 'Pharmaceuticals', 'Software'], description: 'Chinese state-sponsored with criminal operations', type: 'apt' },
    ];
  }

  // Country coordinates for map
  const COUNTRY_COORDS = {
    US: [37.0902, -95.7129], CN: [35.8617, 104.1954], RU: [61.5240, 105.3188],
    DE: [51.1657, 10.4515], GB: [55.3781, -3.4360], FR: [46.2276, 2.2137],
    JP: [36.2048, 138.2529], IN: [20.5937, 78.9629], KR: [35.9078, 127.7669],
    BR: [-14.2350, -51.9253], AU: [-25.2744, 133.7751], IL: [31.0461, 34.8516],
    IR: [32.4279, 53.6880], UA: [48.3794, 31.1656], SG: [1.3521, 103.8198]
  };

  // Get coordinates for a threat
  function getCoords(countryCode) {
    return COUNTRY_COORDS[countryCode] || [20, 0];
  }

  // Main entry: load all data
  async function loadAllData() {
    const CACHE_KEY = 'cybervulndb_data';
    const CACHE_TS_KEY = 'cybervulndb_ts';
    const CACHE_MAX_AGE = 15 * 60 * 1000; // 15 minutes

    const cachedTs = Utils.storageGet(CACHE_TS_KEY);
    if (Utils.isCacheFresh(cachedTs, CACHE_MAX_AGE)) {
      const cached = Utils.storageGet(CACHE_KEY);
      if (cached) {
        console.log('[API] Using cached data');
        return cached;
      }
    }

    console.log('[API] Loading fresh data...');
    
    // Load data with resilient fallbacks
    const cves = await fetchCVEs(30);
    const ransomware = getMockRansomware();
    const apt = getMockAPT();
    const news = await Promise.race([
      fetchAllNews().catch(() => []),
      timeout(20000).catch(() => [])  // allow more time for multi-source news
    ]);

    const data = { cves, ransomware, apt, news };
    
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
    fetchCVEsOnly,
    fetchAllNews,
    fetchNewsOnly,
    fetchKEV,
    isInKEV,
    getKEVDetails,
    getCoords,
    COUNTRY_COORDS,
    COUNTRY_KEYWORDS
  };
})();
