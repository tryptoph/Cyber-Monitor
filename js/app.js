/**
 * app.js — CyberVulnDB Main Application
 */

(async () => {
  // ── Boot ─────────────────────────────────────────────────
  UI.cacheEls();
  UI.showLoading();

  // ── Initialize Map ────────────────────────────────────────
  MapManager.init('map');

  // ── Refresh handler ───────────────────────────────────────
  async function refreshData() {
    UI.showLoading();
    // Clear all versioned cybervulndb cache entries so the next load fetches fresh data
    Object.keys(localStorage)
      .filter(k => k.startsWith('cybervulndb_'))
      .forEach(k => localStorage.removeItem(k));
    await loadAndRender();
    UI.showToast('Data refreshed!', 'success');
  }

  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', refreshData);
  let handlersInitialized = false;

  // ── Stats bar updater with animated counting ──────────────
  function animateCounter(el, target) {
    const current = parseInt(el.textContent);
    if (isNaN(current) || current === target) {
      el.textContent = target;
      return;
    }
    const duration = 600;
    const start = performance.now();
    const step = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(current + (target - current) * eased);
      if (progress < 1) el._rafHandle = requestAnimationFrame(step);
    };
    if (el._rafHandle) cancelAnimationFrame(el._rafHandle);
    el._rafHandle = requestAnimationFrame(step);
  }

  function updateStatsBar(data) {
    const set = (id, val) => {
      const el = document.querySelector(`#${id} .stat-value`);
      if (el) animateCounter(el, val);
    };
    set('stat-cves', data.cves.length);
    set('stat-critical', data.cves.filter(c => c.cvss?.severity === 'CRITICAL').length);
    set('stat-malware', data.ransomware.length);
    set('stat-apt', data.apt.length);
    set('stat-news', data.news.length);
  }

  // ── Threat activity ticker ──────────────────────────────────
  function updateThreatTicker(data) {
    const tickerEl = document.getElementById('ticker-content');
    if (!tickerEl) return;

    const items = [];

    // Add latest CVEs
    data.cves.slice(0, 8).forEach(cve => {
      const sev = cve.cvss?.severity || '';
      items.push(`<span class="ticker-item ticker-cve">⚡ ${escapeHtml(cve.id)} [${escapeHtml(sev)}]</span>`);
    });

    // Add latest malware
    data.ransomware.slice(0, 5).forEach(m => {
      items.push(`<span class="ticker-item ticker-malware">🔒 ${escapeHtml(m.group || 'Malware')}: ${escapeHtml((m.organization || '').substring(0, 30))}</span>`);
    });

    // Add APT groups
    data.apt.slice(0, 5).forEach(apt => {
      const flag = API.getCountryFlag(apt.country);
      items.push(`<span class="ticker-item ticker-apt">${flag} ${escapeHtml(apt.name)} [${escapeHtml(apt.country)}]</span>`);
    });

    // Add latest news
    data.news.slice(0, 5).forEach(n => {
      items.push(`<span class="ticker-item ticker-news">📰 ${escapeHtml((n.title || '').substring(0, 50))}</span>`);
    });

    if (items.length) {
      // Duplicate items for seamless loop
      const content = items.join('<span class="ticker-sep">│</span>');
      tickerEl.innerHTML = content + '<span class="ticker-sep">│</span>' + content;
    }
  }

  // ── Core load + render cycle ───────────────────────────────
  // Helper — read current time range from a panel selector
  function getTimeRange(panelId) {
    return document.getElementById(`${panelId}-time-filter`)?.value || '1w';
  }

  async function loadAndRender() {
    let data = { cves: [], ransomware: [], apt: [], news: [] };
    let sourceOk = false;

    try {
      data = await API.loadAllData({
        cve:     getTimeRange('cve'),
        malware: getTimeRange('malware'),
        news:    getTimeRange('news'),
        apt:     getTimeRange('apt')
      });
      sourceOk = true;
    } catch (err) {
      console.error('[App] Failed to load data:', err);
      UI.showToast('Could not fetch live data.', 'error');
    }

    // Store data globally for UI to access
    window.cyberData = null; // release old reference for GC
    window.cyberData = data;

    // Clear existing markers before re-rendering
    MapManager.clearMarkers();

    // Render all panels (data is already time-range filtered from loadAndRender)
    loadKEVData(); // fire-and-forget — enriches KEV badges after initial render
    renderCVEs(filterForSearch(data.cves, 'cve'));
    renderRansomware(filterForSearch(data.ransomware, 'ransomware'));
    renderAPT(filterForSearch(data.apt, 'apt'));
    renderNews(filterForSearch(data.news, 'news'));

    // Update stats bar
    updateStatsBar(data);

    // Update threat ticker
    updateThreatTicker(data);

    // Update map marker count
    const markerCountEl = document.getElementById('status-markers');
    if (markerCountEl) markerCountEl.textContent = `Map: ${MapManager.getMarkerCount()} markers`;

    // Update status
    UI.updateStatus(sourceOk, data.cves.length + data.ransomware.length + data.apt.length + data.news.length);
    UI.hideLoading();

    if (!handlersInitialized) {
      // ── Wire up static event handlers only once ─────────────
      initTabs();
      initFilters();
      initSearch();
      UI.initSidebarToggle();
      UI.initExport();
      handlersInitialized = true;
    }
  }

  // ── Auto-refresh every 5 minutes ─────────────────────────
  setInterval(async () => {
    console.log('[App] Auto-refreshing data...');
    Object.keys(localStorage)
      .filter(k => k.startsWith('cybervulndb_ts_'))
      .forEach(k => localStorage.removeItem(k));
    await loadAndRender();
    UI.showToast('Data auto-refreshed', 'info');
  }, 5 * 60 * 1000);

  // ── Live news refresh every 3 minutes (silent, no full reload) ─
  let newsLastFetchTime = null;

  async function refreshNewsPanel() {
    try {
      const timeRange = getTimeRange('news');
      const news = await API.fetchNewsBySource('all', timeRange);
      if (news.length > 0) {
        if (window.cyberData) window.cyberData.news = news;
        newsLastFetchTime = Date.now();
        renderNews(filterForSearch(news, 'news'));
        updateNewsTimestamp();
        console.log(`[App] News live-refreshed: ${news.length} items`);
      }
    } catch (err) {
      console.warn('[App] News refresh failed:', err.message);
    }
  }

  function updateNewsTimestamp() {
    const el = document.getElementById('news-last-updated');
    if (!el || !newsLastFetchTime) return;
    const s = Math.floor((Date.now() - newsLastFetchTime) / 1000);
    el.textContent = s < 60 ? 'just now' : `${Math.floor(s / 60)}m ago`;
  }

  // Tick the "last updated" label every 30 s
  setInterval(updateNewsTimestamp, 30 * 1000);

  // Refresh only the news panel every 3 minutes
  setInterval(refreshNewsPanel, 3 * 60 * 1000);

  // ── Live CVE refresh every 2 minutes (silent, panel-only) ─
  let cveLastFetchTime = null;
  let knownCveIds = new Set();   // track IDs we've already shown

  function updateCveTimestamp() {
    const el = document.getElementById('cve-last-updated');
    if (!el || !cveLastFetchTime) return;
    const s = Math.floor((Date.now() - cveLastFetchTime) / 1000);
    el.textContent = s < 60 ? 'just now' : `${Math.floor(s / 60)}m ago`;
  }

  setInterval(updateCveTimestamp, 30 * 1000);

  async function refreshCVEPanel() {
    try {
      const timeRange = getTimeRange('cve');
      const fresh = await API.fetchCVEsBySource(currentCVESource, timeRange, currentSeverityFilter);
      if (!fresh || !fresh.length) return;

      // Enrich with EPSS
      await API.enrichWithEPSS(fresh);

      // Find IDs that are truly new since last render
      const newIds = fresh.filter(c => !knownCveIds.has(c.id)).map(c => c.id);

      // Merge: new CVEs first, then existing ones not in fresh list
      const existing = (window.cyberData?.cves || []).filter(
        c => !fresh.find(f => f.id === c.id)
      );
      const merged = [...fresh, ...existing].slice(0, 50);

      if (window.cyberData) window.cyberData.cves = merged;
      cveLastFetchTime = Date.now();

      // Re-render with "new" IDs flagged (respect active search)
      renderCVEs(filterForSearch(merged, 'cve'), new Set(newIds));
      updateCveTimestamp();

      // Update count badge
      const badge = document.getElementById('cve-count-badge');
      if (badge) badge.textContent = merged.length || '';

      if (newIds.length > 0) {
        UI.showToast(`${newIds.length} new CVE${newIds.length > 1 ? 's' : ''} detected`, 'info');
        console.log(`[App] CVE live-refresh: ${newIds.length} new, ${fresh.length} total`);
      }
    } catch (err) {
      console.warn('[App] CVE refresh failed:', err.message);
    }
  }

  // Refresh CVE panel every 2 minutes
  setInterval(refreshCVEPanel, 2 * 60 * 1000);

  // ── Search state & filter helper ─────────────────────────
  let currentSearchQuery = '';

  function filterForSearch(items, type) {
    if (!currentSearchQuery) return items;
    const q = currentSearchQuery;
    switch (type) {
      case 'cve':
        return items.filter(c =>
          c.id.toLowerCase().includes(q) ||
          (c.description || '').toLowerCase().includes(q)
        );
      case 'ransomware':
        return items.filter(r =>
          (r.organization || '').toLowerCase().includes(q) ||
          (r.group || '').toLowerCase().includes(q) ||
          (r.country || '').toLowerCase().includes(q)
        );
      case 'apt':
        return items.filter(a =>
      (a.name || '').toLowerCase().includes(q) ||
      (a.aliases || []).some(alias => alias.toLowerCase().includes(q)) ||
      (a.targetSectors || []).some(t => t.toLowerCase().includes(q))
        );
      case 'news':
        return items.filter(n =>
          (n.title || '').toLowerCase().includes(q) ||
          (n.description || '').toLowerCase().includes(q)
        );
      default:
        return items;
    }
  }

  // ── Render functions ──────────────────────────────────────
  // Store current filter
  let currentSeverityFilter = '';
  let cachedKEVList = null;

  // Load KEV data (non-blocking) — returns a promise
  function loadKEVData() {
    if (cachedKEVList !== null) return Promise.resolve();
    return API.fetchKEV().then(kev => {
      cachedKEVList = kev || [];
      const data = window.cyberData;
      if (data && data.cves && data.cves.length) {
        renderCVEs(filterForSearch(data.cves, 'cve'));
      }
    }).catch(() => {
      cachedKEVList = [];
    });
  }

  function renderCVEs(cves, newIds = new Set()) {
    const container = document.getElementById('cve-list');
    if (!container) return;

    // Sort by published — newest first
    const sorted = [...cves];

    // Apply severity filter
    let filteredCves = sorted;
    if (currentSeverityFilter) {
      filteredCves = sorted.filter(c => c.cvss && c.cvss.severity === currentSeverityFilter);
    }

    // Update count badge on CVE tab
    const badge = document.getElementById('cve-count-badge');
    if (badge) badge.textContent = filteredCves.length || '';

    if (!filteredCves.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟩</div><div class="empty-state-text">No CVEs found</div></div>';
      return;
    }

    // Build knownCveIds set before map to avoid side-effects inside transform
    filteredCves.forEach(cve => {
      if (knownCveIds.size < 500) knownCveIds.add(cve.id);
    });

    container.innerHTML = filteredCves.map(cve => {
      const severityClass = getSeverityClass(cve.cvss?.severity);
  const countryCode = detectCountryFromText(cve.description);
  const coords = API.getCoords(countryCode) || [];
      const isKEV = cachedKEVList && cachedKEVList.length > 0 && API.isInKEV(cve.id, cachedKEVList);
      const isNew = newIds.has(cve.id);

      // EPSS badge
      let epssBadge = '';
      if (cve.epss && cve.epss.score != null) {
        const epssPercent = (cve.epss.score * 100).toFixed(1);
        let epssClass = 'epss-low';
        if (cve.epss.score > 0.5) epssClass = 'epss-critical';
        else if (cve.epss.score > 0.1) epssClass = 'epss-high';
        else if (cve.epss.score > 0.01) epssClass = 'epss-medium';
        epssBadge = `<span class="badge epss-badge ${epssClass}" title="EPSS Exploit Probability: ${epssPercent}% (Percentile: ${(cve.epss.percentile * 100).toFixed(0)}%)">EPSS: ${epssPercent}%</span>`;
      }

      // KEV badge
      const kevBadge = isKEV ? '<span class="badge kev-badge" title="CISA Known Exploited Vulnerability">⚠ KEV</span>' : '';

      return `
        <div class="threat-card cve ${isKEV ? 'kev' : ''} ${isNew ? 'cve-new' : ''}" data-id="${cve.id}" data-coords="${coords ? coords.join(',') : ''}">
          <div class="threat-card-header">
            <span class="threat-card-type">
              ${isNew ? '<span class="cve-new-badge">NEW</span> ' : ''}${isKEV ? '⚠ CVE (KEV)' : 'CVE'}
            </span>
            <span class="threat-card-date" data-ts="${cve.published}">${timeAgo(cve.published)}</span>
          </div>
          <div class="threat-card-title">${escapeHtml((cve.description || '').substring(0, 100))}...</div>
          <div class="threat-card-meta">
            <span class="cve-id">${escapeHtml(cve.id)}</span>
            <span class="badge ${severityClass}">${escapeHtml(cve.cvss?.severity || 'N/A')} ${cve.cvss?.score ? cve.cvss.score.toFixed(1) : ''}</span>
            ${epssBadge}
            ${kevBadge}
          </div>
        </div>
      `;
    }).join('');

    // Add click handlers
    const cveMap = new Map(cves.map(c => [c.id, c]));
    container.querySelectorAll('.threat-card').forEach(card => {
      card.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const cve = cveMap.get(card.dataset.id);
        if (cve) showCVEModal(cve);
      });

      // Add to map with popup data
      const coords = card.dataset.coords.split(',').map(Number);
      if (Number.isFinite(coords[0]) && Number.isFinite(coords[1])) {
        const cve = cveMap.get(card.dataset.id);
        MapManager.addMarker(coords[0], coords[1], 'cve', card.dataset.id, {
          id: cve?.id,
          severity: cve?.cvss?.severity,
          score: cve?.cvss?.score,
          description: cve?.description,
        });
      }
    });
  }

  function renderRansomware(victims) {
    const container = document.getElementById('ransomware-list');
    if (!container) return;

    const badge = document.getElementById('malware-count-badge');
    if (badge) badge.textContent = victims.length > 0 ? victims.length : '';
    
    if (!victims.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟩</div><div class="empty-state-text">No ransomware data</div></div>';
      return;
    }

    const malwareSourceNames = {
      ransomware: 'ransomware.live',
      threatfox: 'ThreatFox',
      inquest: 'InQuest',
      hibp: 'HIBP',
      urlhaus: 'URLhaus'
    };

    const malwareTypeLabels = {
      ransomware: 'RANSOMWARE',
      threatfox: 'IOC',
      inquest: 'IOC',
      hibp: 'BREACH',
      urlhaus: 'MALWARE URL'
    };

    container.innerHTML = victims.map(v => {
      const coords = API.getCoords(v.countryCode) || [];
      const sourceName = malwareSourceNames[v.source] || v.source || 'Unknown';
      const typeLabel = malwareTypeLabels[v.source] || 'RANSOMWARE';
      
      return `
        <div class="threat-card ransomware" data-id="${v.id}" data-coords="${coords ? coords.join(',') : ''}">
          <div class="threat-card-header">
            <span class="threat-card-type">${typeLabel}</span>
            <span class="source-badge">${escapeHtml(sourceName)}</span>
            <span class="threat-card-date">${timeAgo(v.discovered)}</span>
          </div>
          <div class="threat-card-title">${escapeHtml(v.organization)}</div>
          <div class="threat-card-meta">
            <span class="badge high">${escapeHtml(v.group || '')}</span>
            <span>${escapeHtml(v.country || '')}</span>
          </div>
        </div>
      `;
    }).join('');

    // Add click handlers and map markers
    const victimMap = new Map(victims.map(v => [v.id, v]));
    container.querySelectorAll('.threat-card').forEach(card => {
      card.addEventListener('click', () => {
        const id = card.dataset.id;
        const victim = victimMap.get(id);
        if (victim) showRansomwareModal(victim);
      });
      
      const coords = card.dataset.coords.split(',').map(Number);
      if (Number.isFinite(coords[0]) && Number.isFinite(coords[1])) {
        const victim = victimMap.get(card.dataset.id);
        MapManager.addMarker(coords[0], coords[1], 'ransomware', card.dataset.id, {
          organization: victim?.organization,
          group: victim?.group,
          country: victim?.country,
          name: victim?.organization,
        });
      }
    });
  }

  function renderAPT(groups) {
    const container = document.getElementById('apt-list');
    if (!container) return;

    const badge = document.getElementById('apt-count-badge');
    if (badge) badge.textContent = groups.length > 0 ? groups.length : '';
    
    if (!groups.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟩</div><div class="empty-state-text">No APT data</div></div>';
      return;
    }

    const aptSourceNames = {
      misp: 'MISP',
      mandiant: 'Mandiant',
      crowdstrike: 'CrowdStrike',
      securelist: 'Securelist'
    };

    container.innerHTML = groups.map(apt => {
      const coords = API.getCoords(apt.country);
      const sourceName = aptSourceNames[apt.source] || apt.source || 'ATT&CK';
      const flag = API.getCountryFlag(apt.country);
      const countryName = API.getCountryName(apt.country);
      
      return `
        <div class="threat-card apt" data-id="${apt.id}" data-coords="${coords ? coords.join(',') : ''}">
          <div class="threat-card-header">
            <span class="threat-card-type">APT GROUP</span>
            <span class="source-badge">${escapeHtml(sourceName)}</span>
            <span>${flag} ${escapeHtml(apt.country || '')}</span>
          </div>
          <div class="threat-card-title">${escapeHtml(apt.name)}</div>
          <div class="threat-card-meta">
            <span>${escapeHtml(countryName)}</span>
            <span>${escapeHtml((apt.targetSectors || []).slice(0, 2).join(', '))}</span>
          </div>
        </div>
      `;
    }).join('');

    // Clear old attack lines before adding new ones
    MapManager.clearAttackLines();

    // Track which countries have APT labels already
    const labeledCountries = new Set();

    // Add click handlers, map markers, labels, and attack lines
    const aptMap = new Map(groups.map(a => [a.id, a]));
    container.querySelectorAll('.threat-card').forEach(card => {
      card.addEventListener('click', () => {
        const id = card.dataset.id;
        const apt = aptMap.get(id);
        if (apt) showAPTModal(apt);
      });
      
      const coords = card.dataset.coords.split(',').map(Number);
      if (Number.isFinite(coords[0]) && Number.isFinite(coords[1])) {
        const apt = aptMap.get(card.dataset.id);
        const countryCode = apt?.country || '';

        // Add marker with rich popup data
        MapManager.addMarker(coords[0], coords[1], 'apt', card.dataset.id, {
          name: apt?.name,
          country: countryCode,
          countryName: API.getCountryName(countryCode),
          countryFlag: API.getCountryFlag(countryCode),
          aliases: apt?.aliases,
          targetSectors: apt?.targetSectors,
          victims: apt?.suspectedVictims,
        });

        // Add country label on map (once per country)
        if (countryCode && countryCode !== 'Unknown' && !labeledCountries.has(countryCode)) {
          labeledCountries.add(countryCode);
          MapManager.addLabel(coords[0], coords[1], API.getCountryName(countryCode), '#8b5cf6');
        }

        // Draw attack lines to target countries
        if (apt?.suspectedVictims && apt.suspectedVictims.length > 0) {
          const victimCountries = apt.suspectedVictims.slice(0, 5);
          victimCountries.forEach(victim => {
            // Try to match victim name to country code
            const targetCode = Object.entries(API.COUNTRY_COORDS).find(([code]) => {
              const name = API.getCountryName(code);
              return name && victim.toLowerCase().includes(name.toLowerCase());
            });
            if (targetCode) {
              const targetCoords = API.getCoords(targetCode[0]);
              if (!targetCoords) return;
              MapManager.addAttackLine(coords[0], coords[1], targetCoords[0], targetCoords[1], '#8b5cf680');
            }
          });
        }
      }
    });
  }

  function renderNews(news) {
    const container = document.getElementById('news-list');
    if (!container) return;
    
    // Update count badge on the NEWS tab
    const badge = document.getElementById('news-count-badge');
    if (badge) badge.textContent = news.length > 0 ? news.length : '';

    if (!news.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟩</div><div class="empty-state-text">Fetching live news...</div></div>';
      return;
    }

    const now = Date.now();
    const FRESH_MS = 30 * 60 * 1000; // highlight items under 30 minutes old

    container.innerHTML = news.map(item => {
      const isFresh = (now - new Date(item.published).getTime()) < FRESH_MS;
      const categoryLabel = (item.category || 'news').toUpperCase();
      return `
        <div class="threat-card news ${isFresh ? 'news-fresh' : ''}" data-link="${escapeHtml(item.link)}">
          <div class="threat-card-header">
            <span class="threat-card-type${isFresh ? ' news-live-badge' : ''}">
              ${isFresh ? '<span class="news-dot"></span>' : ''}${categoryLabel}
            </span>
            <span class="source-badge">${escapeHtml(item.source || item.sourceKey || 'Unknown')}</span>
            <span class="threat-card-date" data-ts="${item.published}">${timeAgo(item.published)}</span>
          </div>
          <div class="threat-card-title">${escapeHtml(item.title)}</div>
          <div class="threat-card-meta">
            ${item.points ? `<span class="news-points">▲ ${escapeHtml(String(item.points))}</span>` : ''}
          </div>
        </div>
      `;
    }).join('');

    // Add click handlers - open in new tab
    container.querySelectorAll('.threat-card').forEach(card => {
      card.addEventListener('click', () => {
        const link = card.dataset.link;
        if (link) window.open(link, '_blank');
      });
    });
  }

  // ── Helper functions ─────────────────────────────────────
  function getSeverityClass(severity) {
    if (!severity) return 'info';
    const s = String(severity).toUpperCase();
    if (s === 'CRITICAL') return 'critical';
    if (s === 'HIGH') return 'high';
    if (s === 'MEDIUM') return 'medium';
    if (s === 'LOW') return 'low';
    return 'info';
  }

  function detectCountryFromText(text) {
    return API.detectCountry(text);
}

const { escapeHtml, timeAgo } = Utils;

// Tick every minute — re-render all visible date spans in-place
  setInterval(() => {
    requestAnimationFrame(() => {
    document.querySelectorAll('[data-ts]').forEach(el => {
      const raw = el.dataset.ts;
      const parsed = Number(raw);
      el.textContent = timeAgo(isNaN(parsed) ? raw : parsed);
      });
    });
  }, 60000);

// ── Modal functions ─────────────────────────────────────
document.addEventListener('click', (e) => {
  if (e.target.matches('[data-action="close-modal"]')) {
    const overlay = document.getElementById('modal-overlay');
    if (overlay) overlay.classList.add('hidden');
  }
});

function showCVEModal(cve) {
    const overlay = document.getElementById('modal-overlay');
    const content = document.getElementById('modal-content');
    if (!overlay || !content) return;

    const severityClass = getSeverityClass(cve.cvss?.severity);
    const isKEV = cachedKEVList && cachedKEVList.length > 0 && API.isInKEV(cve.id, cachedKEVList);
    const kevDetails = isKEV ? API.getKEVDetails(cve.id, cachedKEVList) : null;

    // Build EPSS section
    let epssSection = '';
    if (cve.epss && cve.epss.score != null) {
      const epssPercent = (cve.epss.score * 100).toFixed(1);
      const epssPercentile = (cve.epss.percentile * 100).toFixed(0);
      let epssClass = 'epss-low';
      if (cve.epss.score > 0.5) epssClass = 'epss-critical';
      else if (cve.epss.score > 0.1) epssClass = 'epss-high';
      else if (cve.epss.score > 0.01) epssClass = 'epss-medium';
      epssSection = `
        <div class="modal-section">
          <h4>EPSS — Exploit Prediction</h4>
          <div class="epss-detail">
            <div class="epss-detail-row">
              <span class="badge epss-badge ${epssClass}">Probability: ${epssPercent}%</span>
              <span class="badge epss-badge epss-percentile">Percentile: ${epssPercentile}th</span>
            </div>
            <p class="epss-description">This vulnerability has a <strong>${epssPercent}%</strong> probability of being exploited in the next 30 days, placing it in the <strong>${epssPercentile}th</strong> percentile of all scored CVEs.</p>
          </div>
        </div>`;
    }

    // Build KEV section
    let kevSection = '';
    if (isKEV) {
      kevSection = `
        <div class="kev-banner">
          <span class="kev-icon">⚠</span>
          <span><strong>Known Exploited Vulnerability</strong> — This CVE is in the CISA KEV catalog and has confirmed active exploitation.</span>
          ${kevDetails?.dateAdded ? `<span class="kev-date">Added: ${kevDetails.dateAdded}</span>` : ''}
        </div>
        ${kevDetails?.requiredAction ? `
        <div class="modal-section">
          <h4>Required Action</h4>
          <p class="modal-description">${escapeHtml(kevDetails.requiredAction)}</p>
          ${kevDetails?.dueDate ? `<p class="text-muted" style="margin-top:6px;">Due: ${kevDetails.dueDate}</p>` : ''}
        </div>` : ''}`;
    }

    // Build references list
    const refs = cve.references?.length > 0
      ? cve.references.map(ref => `<a href="${escapeHtml(ref)}" target="_blank" class="modal-link">${escapeHtml(ref.substring(0, 60))}...</a>`).join('<br>')
      : '';

    // Build CPE list
    const cpeList = cve.cpe?.length > 0
      ? cve.cpe.slice(0, 5).map(c => `<span class="cpe-tag">${escapeHtml(c)}</span>`).join(' ')
      : '<span class="text-muted">No CPE data</span>';

    content.innerHTML = `
      <div class="modal-header">
        <div>
          <div class="modal-type-badge badge-${severityClass}">CVE</div>
          <div class="modal-title">${escapeHtml(cve.id)}</div>
        </div>
    <button class="modal-close" data-action="close-modal">×</button>
  </div>
  <div class="modal-body">
    <div class="modal-meta-row">
      ${cve.cvss?.score ? `<span class="badge ${severityClass}">CVSS: ${cve.cvss.score.toFixed(1)}</span>` : ''}
          ${cve.cvss?.severity ? `<span class="badge info">${escapeHtml(cve.cvss.severity)}</span>` : ''}
          ${cve.epss?.score != null ? `<span class="badge epss-badge ${cve.epss.score > 0.5 ? 'epss-critical' : cve.epss.score > 0.1 ? 'epss-high' : cve.epss.score > 0.01 ? 'epss-medium' : 'epss-low'}">EPSS: ${(cve.epss.score * 100).toFixed(1)}%</span>` : ''}
          ${isKEV ? '<span class="badge kev-badge">⚠ KEV</span>' : ''}
          <span>Published: ${timeAgo(cve.published)}</span>
          ${cve.modified ? `<span>Modified: ${timeAgo(cve.modified)}</span>` : ''}
        </div>

        ${kevSection}

        <div class="modal-section">
          <h4>Description</h4>
          <p class="modal-description">${escapeHtml(cve.description)}</p>
        </div>

        ${epssSection}

        ${cve.cvss?.vector ? `
        <div class="modal-section">
          <h4>CVSS Vector</h4>
          <code class="cvss-vector">${escapeHtml(cve.cvss.vector)}</code>
        </div>
        ` : ''}

        <div class="modal-section">
          <h4>Affected Products (CPE)</h4>
          <div class="cpe-list">${cpeList}</div>
        </div>

        ${refs ? `
        <div class="modal-section">
          <h4>References</h4>
          <div class="modal-references">${refs}</div>
        </div>
        ` : ''}

        <div class="modal-actions">
          <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}" target="_blank" class="btn-primary">View on NVD →</a>
        </div>
      </div>
    `;
    
    overlay.classList.remove('hidden');
  }

  function showRansomwareModal(victim) {
    const overlay = document.getElementById('modal-overlay');
    const content = document.getElementById('modal-content');
    if (!overlay || !content) return;

    content.innerHTML = `
      <div class="modal-header">
        <div>
          <div class="modal-type-badge badge-security">RANSOMWARE</div>
          <div class="modal-title">${escapeHtml(victim.organization)}</div>
        </div>
    <button class="modal-close" data-action="close-modal">×</button>
  </div>
  <div class="modal-body">
    <div class="modal-meta-row">
      <span class="badge high">${escapeHtml(victim.group)}</span>
          <span>${escapeHtml(victim.country)}</span>
          <span>${escapeHtml(victim.sector)}</span>
        </div>
        <p class="modal-description">${escapeHtml(victim.description || 'Ransomware attack reported.')}</p>
        <p class="modal-meta-item">Discovered: ${timeAgo(victim.discovered)}</p>
      </div>
    `;
    
    overlay.classList.remove('hidden');
  }

  function showAPTModal(apt) {
    const overlay = document.getElementById('modal-overlay');
    const content = document.getElementById('modal-content');
    if (!overlay || !content) return;

    content.innerHTML = `
      <div class="modal-header">
        <div>
          <div class="modal-type-badge" style="background: rgba(139,92,246,0.15); color: #8b5cf6;">APT</div>
          <div class="modal-title">${escapeHtml(apt.name)}</div>
        </div>
        <button class="modal-close" data-action="close-modal">×</button>
      </div>
      <div class="modal-body">
        <div class="modal-meta-row">
          <span>Country: ${escapeHtml(apt.country)}</span>
        </div>
        <p class="modal-description">${escapeHtml(apt.description)}</p>
        <p><strong>Aliases:</strong> ${escapeHtml((apt.aliases || []).join(', '))}</p>
        <p><strong>Target Sectors:</strong> ${escapeHtml((apt.targetSectors || []).join(', '))}</p>
      </div>
    `;
    
    overlay.classList.remove('hidden');
  }

  // ── Tab navigation ───────────────────────────────────────
  function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const panels = document.querySelectorAll('.panel');

    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const tabId = btn.dataset.tab;
        
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        panels.forEach(p => {
          p.classList.remove('active');
          if (p.id === `panel-${tabId}`) {
            p.classList.add('active');
          }
        });

        // Re-apply active search filter when switching tabs
        if (currentSearchQuery) {
          const data = window.cyberData || { cves: [], ransomware: [], apt: [], news: [] };
          if (tabId === 'cve') renderCVEs(filterForSearch(data.cves, 'cve'));
          else if (tabId === 'ransomware') renderRansomware(filterForSearch(data.ransomware, 'ransomware'));
          else if (tabId === 'apt') renderAPT(filterForSearch(data.apt, 'apt'));
          else if (tabId === 'news') renderNews(filterForSearch(data.news, 'news'));
        }
      });
    });
  }

  // ── Filters ───────────────────────────────────────────
  // Track current CVE source selection
  let currentCVESource = 'all';

  function initFilters() {
    const cveFilter = document.getElementById('cve-severity-filter');
    if (cveFilter) {
      cveFilter.addEventListener('change', async () => {
        currentSeverityFilter = cveFilter.value;
        // If not auto, refetch from the selected source with new severity
        if (currentCVESource !== 'auto') {
          await refetchCVESource();
        } else {
          const data = window.cyberData || { cves: [] };
          renderCVEs(filterForSearch(data.cves, 'cve'));
        }
      });
    }

    // CVE source selector
    const sourceFilter = document.getElementById('cve-source-filter');
    if (sourceFilter) {
      sourceFilter.addEventListener('change', async () => {
        currentCVESource = sourceFilter.value;
        await refetchCVESource();
      });
    }

    // CVE time range selector
    const cveTimeFilter = document.getElementById('cve-time-filter');
    if (cveTimeFilter) {
      cveTimeFilter.addEventListener('change', async () => {
        await refetchCVESource();
      });
    }

    // News source selector
    const newsSourceFilter = document.getElementById('news-source-filter');
    if (newsSourceFilter) {
      newsSourceFilter.addEventListener('change', async () => {
        const source = newsSourceFilter.value;
        const timeRange = getTimeRange('news');
        const container = document.getElementById('news-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading news...</div></div>';
        }
        try {
          const items = await API.fetchNewsBySource(source, timeRange);
          if (window.cyberData) window.cyberData.news = items;
          renderNews(filterForSearch(items, 'news'));
          const badge = document.getElementById('news-count-badge');
          if (badge) badge.textContent = items.length || '';
          UI.showToast(`Loaded ${items.length} articles from ${source === 'all' ? 'all sources' : source}`, 'info');
        } catch (err) {
          UI.showToast('Failed to fetch news', 'error');
        }
      });
    }

    // News time range selector
    const newsTimeFilter = document.getElementById('news-time-filter');
    if (newsTimeFilter) {
      newsTimeFilter.addEventListener('change', async () => {
        const source = document.getElementById('news-source-filter')?.value || 'all';
        const timeRange = newsTimeFilter.value;
        const container = document.getElementById('news-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading news...</div></div>';
        }
        try {
          const items = await API.fetchNewsBySource(source, timeRange);
          if (window.cyberData) window.cyberData.news = items;
          renderNews(filterForSearch(items, 'news'));
          const badge = document.getElementById('news-count-badge');
          if (badge) badge.textContent = items.length || '';
          UI.showToast(`Loaded ${items.length} articles`, 'info');
        } catch (err) {
          UI.showToast('Failed to fetch news', 'error');
        }
      });
    }

    // Malware source selector
    const malwareFilter = document.getElementById('malware-source-filter');
    if (malwareFilter) {
      malwareFilter.addEventListener('change', async () => {
        const source = malwareFilter.value;
        const timeRange = getTimeRange('malware');
        const container = document.getElementById('ransomware-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading from source...</div></div>';
        }
        try {
          const items = await API.fetchMalwareBySource(source, timeRange);
          if (window.cyberData) window.cyberData.ransomware = items;
          renderRansomware(filterForSearch(items, 'ransomware'));
          UI.showToast(`Loaded ${items.length} threats from ${source === 'all' ? 'all sources' : source}`, 'info');
        } catch (err) {
          UI.showToast('Failed to fetch malware data', 'error');
        }
      });
    }

    // Malware time range selector
    const malwareTimeFilter = document.getElementById('malware-time-filter');
    if (malwareTimeFilter) {
      malwareTimeFilter.addEventListener('change', async () => {
        const source = document.getElementById('malware-source-filter')?.value || 'all';
        const timeRange = malwareTimeFilter.value;
        const container = document.getElementById('ransomware-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading from source...</div></div>';
        }
        try {
          const items = await API.fetchMalwareBySource(source, timeRange);
          if (window.cyberData) window.cyberData.ransomware = items;
          renderRansomware(filterForSearch(items, 'ransomware'));
          UI.showToast(`Loaded ${items.length} threats`, 'info');
        } catch (err) {
          UI.showToast('Failed to fetch malware data', 'error');
        }
      });
    }

    // APT source selector
    const aptFilter = document.getElementById('apt-source-filter');
    if (aptFilter) {
      aptFilter.addEventListener('change', async () => {
        const source = aptFilter.value;
        const timeRange = getTimeRange('apt');
        const container = document.getElementById('apt-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading APT data...</div></div>';
        }
        try {
          const items = await API.fetchAPTBySource(source, timeRange);
          if (window.cyberData) window.cyberData.apt = items;
          renderAPT(filterForSearch(items, 'apt'));
          UI.showToast(`Loaded ${items.length} APT groups from ${source === 'all' ? 'all sources' : source}`, 'info');
        } catch (err) {
          UI.showToast('Failed to fetch APT data', 'error');
        }
      });
    }

    // APT time range selector
    const aptTimeFilter = document.getElementById('apt-time-filter');
    if (aptTimeFilter) {
      aptTimeFilter.addEventListener('change', async () => {
        const source = document.getElementById('apt-source-filter')?.value || 'all';
        const timeRange = aptTimeFilter.value;
        const container = document.getElementById('apt-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading APT data...</div></div>';
        }
        try {
          const items = await API.fetchAPTBySource(source, timeRange);
          if (window.cyberData) window.cyberData.apt = items;
          renderAPT(filterForSearch(items, 'apt'));
          UI.showToast(`Loaded ${items.length} APT groups`, 'info');
        } catch (err) {
          UI.showToast('Failed to fetch APT data', 'error');
        }
      });
    }
  }

  // Fetch CVEs from the selected source and re-render
  async function refetchCVESource() {
    const container = document.getElementById('cve-list');
    if (container) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading from source...</div></div>';
    }

    try {
      const timeRange = getTimeRange('cve');
      const cves = await API.fetchCVEsBySource(currentCVESource, timeRange, currentSeverityFilter);
      if (window.cyberData) window.cyberData.cves = cves;
      renderCVEs(filterForSearch(cves, 'cve'));
      cveLastFetchTime = Date.now();
      updateCveTimestamp();

      const badge = document.getElementById('cve-count-badge');
      if (badge) badge.textContent = cves.length || '';

      // Update threat counter
      const data = window.cyberData || {};
      const total = (data.cves || []).length + (data.ransomware || []).length + (data.apt || []).length + (data.news || []).length;
      const statusCount = document.getElementById('status-count');
      if (statusCount) statusCount.innerHTML = `<span class="status-icon">›</span> ${total} threats`;

      UI.showToast(`Loaded ${cves.length} CVEs from ${currentCVESource === 'auto' ? 'best source' : currentCVESource}`, 'info');
    } catch (err) {
      UI.showToast('Failed to fetch CVEs from source', 'error');
      console.error('[App] Source fetch error:', err);
    }
  }

  // ── Search ──────────────────────────────────────────────
  function initSearch() {
    const searchInput = document.getElementById('search-input');
    if (!searchInput) return;

    searchInput.addEventListener('input', Utils.debounce((e) => {
      currentSearchQuery = e.target.value.toLowerCase().trim();
      const data = window.cyberData || { cves: [], ransomware: [], apt: [], news: [] };

      if (!currentSearchQuery) {
        // Clear search — restore all panels (data already time-filtered in window.cyberData)
        MapManager.clearMarkers();
        renderCVEs(data.cves);
        renderRansomware(data.ransomware);
        renderAPT(data.apt);
        renderNews(data.news);
        updateStatsBar(data);
        return;
      }

      MapManager.clearMarkers();
      const filteredCVEs = filterForSearch(data.cves, 'cve');
      const filteredRansomware = filterForSearch(data.ransomware, 'ransomware');
      const filteredApt = filterForSearch(data.apt, 'apt');
      const filteredNews = filterForSearch(data.news, 'news');
      renderCVEs(filteredCVEs);
      renderRansomware(filteredRansomware);
      renderAPT(filteredApt);
      renderNews(filteredNews);
      updateStatsBar({ cves: filteredCVEs, ransomware: filteredRansomware, apt: filteredApt, news: filteredNews });
    }, 250));
  }

  // Map reset button
  const resetBtn = document.getElementById('reset-view-btn');
  if (resetBtn) resetBtn.addEventListener('click', () => MapManager.resetView());

  // Heatmap toggle button
  const heatmapBtn = document.getElementById('heatmap-toggle');
  if (heatmapBtn) {
    heatmapBtn.addEventListener('click', () => {
      const active = MapManager.toggleHeatmap();
      heatmapBtn.classList.toggle('active', active);
      heatmapBtn.style.color = active ? 'var(--accent-cyan)' : '';
      heatmapBtn.style.borderColor = active ? 'var(--accent-cyan)' : '';
    });
  }

  // ── Keyboard shortcuts ──────────────────────────────────
  function initKeyboardShortcuts() {
    const tabKeys = { '1': 'cve', '2': 'ransomware', '3': 'news', '4': 'apt' };
    document.addEventListener('keydown', (e) => {
      const tag = e.target.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

      if (tabKeys[e.key]) {
        const btn = document.querySelector(`.tab-btn[data-tab="${tabKeys[e.key]}"]`);
        if (btn) btn.click();
      } else if (e.key === 'r') {
        const rb = document.getElementById('refresh-btn');
        if (rb) rb.click();
      } else if (e.key === 's' || e.key === '/') {
        e.preventDefault();
        const si = document.getElementById('search-input');
        if (si) si.focus();
      } else if (e.key === 'Escape') {
        const overlay = document.getElementById('modal-overlay');
        if (overlay && !overlay.classList.contains('hidden')) overlay.click();
      }
    });
  }
  initKeyboardShortcuts();

  // ── Kick off ───────────────────────────────────────────
  await loadAndRender();

  // Seed known IDs so first refresh only flags genuinely new CVEs
  (window.cyberData?.cves || []).forEach(c => knownCveIds.add(c.id));
  cveLastFetchTime = Date.now();
  updateCveTimestamp();

  // Set initial news timestamp after first load
  newsLastFetchTime = Date.now();
  updateNewsTimestamp();
})();
