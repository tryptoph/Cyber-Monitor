const DGSSI_RSS_URLS = [
  'https://www.dgssi.gov.ma/rss.xml',
  'https://www.dgssi.gov.ma/en/rss.xml',
];

const BULLETIN_TERMS = [
  'bulletin', 'vulnerabilite', 'vulnérabilité', 'vulnerabilites',
  'vulnérabilités', 'faille', 'failles', 'malware', 'ransomware',
  'attaque', 'attaques', 'exploite', 'exploitée', 'critique', 'cve-',
  'zero-day', 'zero day',
];

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function stripTags(value) {
  return String(value || '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

function getTag(itemXml, tag) {
  const match = itemXml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'));
  return match ? stripTags(match[1]) : '';
}

function isSecurityBulletin(item) {
  const link = String(item.link || '').toLowerCase();
  const text = `${item.title || ''} ${item.description || ''}`.toLowerCase();
  return link.includes('/bulletins/') || BULLETIN_TERMS.some(term => text.includes(term.toLowerCase()));
}

function parseRSS(xml) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
  let match;

  while ((match = itemRegex.exec(xml)) !== null) {
    const itemXml = match[1];
    const item = {
      id: getTag(itemXml, 'guid') || getTag(itemXml, 'link'),
      title: getTag(itemXml, 'title'),
      link: getTag(itemXml, 'link'),
      description: getTag(itemXml, 'description').slice(0, 500),
      source: 'DGSSI / maCERT',
      sourceKey: 'dgssi',
      category: 'official',
      published: getTag(itemXml, 'pubDate') || new Date().toISOString(),
      countryCode: 'MA',
      official: true,
      type: 'news',
    };
    if (item.title && item.link && isSecurityBulletin(item)) items.push(item);
  }

  return items;
}

function dedupe(items) {
  const seen = new Set();
  return items
    .filter(item => {
      const key = String(item.link || item.title || '').toLowerCase().replace(/\/$/, '');
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((a, b) => new Date(b.published) - new Date(a.published));
}

async function fetchDGSSI() {
  const results = await Promise.allSettled(DGSSI_RSS_URLS.map(async url => {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'CyberVulnDB DGSSI feed worker' },
      cf: { cacheTtl: 900, cacheEverything: true },
    });
    if (!res.ok) return [];
    return parseRSS(await res.text());
  }));

  return dedupe(results.flatMap(result => result.status === 'fulfilled' ? result.value : []));
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    if (request.method !== 'GET') {
      return new Response('Method not allowed', { status: 405, headers: CORS_HEADERS });
    }

    const items = await fetchDGSSI();
    return Response.json({
      countryFocus: 'MA',
      generatedAt: new Date().toISOString(),
      source: 'DGSSI RSS',
      items,
    }, {
      headers: {
        ...CORS_HEADERS,
        'Cache-Control': 'public, max-age=900',
      },
    });
  },
};
