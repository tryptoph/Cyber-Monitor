/**
 * app.js — CyberVulnDB Main Application
 */

(async () => {
  // ── Boot ─────────────────────────────────────────────────
  UI.cacheEls();
  UI.showLoading();

  // ── Initialize Map ────────────────────────────────────────
  MapManager.init('map');

  let cyberData = Object.freeze({ cves: [], ransomware: [], apt: [], news: [] });
  Object.defineProperty(window, 'cyberData', {
    get: () => cyberData,
    configurable: false
  });

  function freezeDataSnapshot(data) {
    return Object.freeze({
      cves: Object.freeze([...(data?.cves || [])]),
      ransomware: Object.freeze([...(data?.ransomware || [])]),
      apt: Object.freeze([...(data?.apt || [])]),
      news: Object.freeze([...(data?.news || [])])
    });
  }

  function setCyberData(data) {
    cyberData = freezeDataSnapshot(data);
    return cyberData;
  }

  function updateCyberDataSection(section, items) {
    return setCyberData({ ...cyberData, [section]: items });
  }

  // ── Refresh handler ───────────────────────────────────────
  async function refreshData() {
    UI.showLoading();
    // Clear all versioned cybervulndb cache entries so the next load fetches fresh data
    Object.keys(localStorage)
      .filter(k => k.startsWith('cybervulndb_'))
      .forEach(k => localStorage.removeItem(k));
    const rendered = await loadAndRender();
    if (rendered) UI.showToast('Data refreshed!', 'success');
  }

  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', refreshData);
  let handlersInitialized = false;
  let fullLoadToken = 0;
  let activeFullLoadToken = 0;
  const panelTokens = { cve: 0, news: 0, malware: 0, apt: 0 };
  const panelUserLocks = { cve: 0, news: 0, malware: 0, apt: 0 };
  const refreshWarningShownAt = { cve: 0, news: 0 };
  const REFRESH_WARNING_INTERVAL = 5 * 60 * 1000;

  function invalidatePanelRequests() {
    Object.keys(panelTokens).forEach(key => { panelTokens[key]++; });
  }

  function beginPanelRequest(type, cancelFullLoad = false) {
    if (cancelFullLoad) {
      fullLoadToken++;
      activeFullLoadToken = 0;
      panelUserLocks[type] = Date.now() + 30000;
      UI.hideLoading();
    }
    panelTokens[type]++;
    return panelTokens[type];
  }

  function isPanelRequestStale(type, token) {
    return token !== panelTokens[type] || activeFullLoadToken !== 0;
  }

  function hasRecentUserPanelRequest(type) {
    return Date.now() < panelUserLocks[type];
  }

  function showRefreshWarning(type, message) {
    const now = Date.now();
    if (now - refreshWarningShownAt[type] < REFRESH_WARNING_INTERVAL) return;
    refreshWarningShownAt[type] = now;
    UI.showToast(message, 'error');
  }

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
    const token = ++fullLoadToken;
    activeFullLoadToken = token;
    invalidatePanelRequests();
    let data = { cves: [], ransomware: [], apt: [], news: [] };
    let sourceOk = false;
    let statusLabel;

    try {
      data = await API.loadAllData({
        cve:     getTimeRange('cve'),
        malware: getTimeRange('malware'),
        news:    getTimeRange('news'),
        apt:     getTimeRange('apt'),
        countryFocus: currentCountryFocus
      });
      sourceOk = !data._meta?.usingFallback;
      statusLabel = data._meta?.usingFallback ? '[WARN] Using fallback data' : undefined;
    } catch (err) {
      console.error('[App] Failed to load data:', err);
      UI.showToast('Could not fetch live data.', 'error');
    }

    if (token !== fullLoadToken) return false;

    // Store a read-only data snapshot globally for UI/testing access.
    data = setCyberData(data);

    // Render all panels (data is already time-range filtered from loadAndRender)
    loadKEVData(); // fire-and-forget — enriches KEV badges after initial render
    const visibleData = renderActiveData(data);

    // Update status
    UI.updateStatus(sourceOk, visibleData.cves.length + visibleData.ransomware.length + visibleData.apt.length + visibleData.news.length, statusLabel);
    UI.hideLoading();
    activeFullLoadToken = 0;

    if (!handlersInitialized) {
      // ── Wire up static event handlers only once ─────────────
      initTabs();
      initFilters();
      initSearch();
      UI.initSidebarToggle();
      UI.initExport();
      handlersInitialized = true;
    }

    return true;
  }

  // ── Auto-refresh every 5 minutes ─────────────────────────
  setInterval(async () => {
    if (Object.keys(panelUserLocks).some(type => hasRecentUserPanelRequest(type))) return;
    console.log('[App] Auto-refreshing data...');
    Object.keys(localStorage)
      .filter(k => k.startsWith('cybervulndb_ts_'))
      .forEach(k => localStorage.removeItem(k));
    const rendered = await loadAndRender();
    if (rendered) UI.showToast('Data auto-refreshed', 'info');
  }, 5 * 60 * 1000);

  // ── Live news refresh every 3 minutes (silent, no full reload) ─
  let newsLastFetchTime = null;

  async function refreshNewsPanel() {
    if (activeFullLoadToken) return;
    if (hasRecentUserPanelRequest('news')) return;
    const token = beginPanelRequest('news');
    try {
      const timeRange = getTimeRange('news');
      const news = await API.fetchNewsBySource('all', timeRange, currentCountryFocus);
      if (isPanelRequestStale('news', token)) return;
      if (news.length > 0) {
        updateCyberDataSection('news', news);
        newsLastFetchTime = Date.now();
        renderActiveData();
        updateNewsTimestamp();
        console.log(`[App] News live-refreshed: ${news.length} items`);
      }
    } catch (err) {
      console.warn('[App] News refresh failed:', err.message);
      const el = document.getElementById('news-last-updated');
      if (el) el.textContent = 'refresh failed';
      showRefreshWarning('news', 'News refresh failed; showing last loaded data');
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
    if (activeFullLoadToken) return;
    if (hasRecentUserPanelRequest('cve')) return;
    const token = beginPanelRequest('cve');
    try {
      const timeRange = getTimeRange('cve');
      const fresh = await API.fetchCVEsBySource(currentCVESource, timeRange, currentSeverityFilter);
      if (isPanelRequestStale('cve', token)) return;
      if (!fresh || !fresh.length) {
        const el = document.getElementById('cve-last-updated');
        if (el) el.textContent = 'refresh returned no data';
        showRefreshWarning('cve', 'CVE refresh returned no data; showing last loaded data');
        return;
      }

      // Enrich with EPSS
      await API.enrichWithEPSS(fresh);
      if (isPanelRequestStale('cve', token)) return;

      // Find IDs that are truly new since last render
      const newIds = fresh.filter(c => !knownCveIds.has(c.id)).map(c => c.id);

      // Merge: new CVEs first, then existing ones not in fresh list
      const existing = (window.cyberData?.cves || []).filter(
        c => !fresh.find(f => f.id === c.id)
      );
      const merged = [...fresh, ...existing].slice(0, 50);

      updateCyberDataSection('cves', merged);
      cveLastFetchTime = Date.now();

      // Re-render with "new" IDs flagged (respect active search)
      renderActiveData(undefined, { newCveIds: new Set(newIds) });
      updateCveTimestamp();

      if (newIds.length > 0) {
        UI.showToast(`${newIds.length} new CVE${newIds.length > 1 ? 's' : ''} detected`, 'info');
        console.log(`[App] CVE live-refresh: ${newIds.length} new, ${fresh.length} total`);
      }
    } catch (err) {
      console.warn('[App] CVE refresh failed:', err.message);
      const el = document.getElementById('cve-last-updated');
      if (el) el.textContent = 'refresh failed';
      showRefreshWarning('cve', 'CVE refresh failed; showing last loaded data');
    }
  }

  // Refresh CVE panel every 2 minutes
  setInterval(refreshCVEPanel, 2 * 60 * 1000);

  // ── Search state & filter helper ─────────────────────────
  let currentSearchQuery = '';
  let currentCountryFocus = 'global';

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

  function filterForCountryFocus(items, type) {
    return (items || []).filter(item => API.matchesCountryFocus(item, type, currentCountryFocus));
  }

  function applyActiveFilters(data = window.cyberData || { cves: [], ransomware: [], apt: [], news: [] }) {
    const focused = {
      cves: filterForCountryFocus(data.cves || [], 'cve'),
      ransomware: filterForCountryFocus(data.ransomware || [], 'ransomware'),
      apt: filterForCountryFocus(data.apt || [], 'apt'),
      news: filterForCountryFocus(data.news || [], 'news')
    };
    return {
      cves: filterForSearch(focused.cves, 'cve'),
      ransomware: filterForSearch(focused.ransomware, 'ransomware'),
      apt: filterForSearch(focused.apt, 'apt'),
      news: filterForSearch(focused.news, 'news')
    };
  }

  function renderActiveData(data = window.cyberData || { cves: [], ransomware: [], apt: [], news: [] }, options = {}) {
    const visible = applyActiveFilters(data);
    MapManager.clearMarkers();
    renderCVEs(visible.cves, options.newCveIds || new Set());
    renderRansomware(visible.ransomware);
    renderAPT(visible.apt);
    renderNews(visible.news);
    updateStatsBar(visible);
    updateThreatTicker(visible);

    const markerCountEl = document.getElementById('status-markers');
    if (markerCountEl) markerCountEl.textContent = `Map: ${MapManager.getMarkerCount()} markers`;

    const statusCount = document.getElementById('status-count');
    if (statusCount) {
      const total = visible.cves.length + visible.ransomware.length + visible.apt.length + visible.news.length;
      statusCount.innerHTML = `<span class="status-icon">›</span> ${total} threats`;
    }
    return visible;
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
        renderActiveData(data);
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
      knownCveIds.add(cve.id);
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

    MapManager.clearAttackLines();

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
      const officialBadge = item.official ? '<span class="source-badge official-source">Official</span>' : '';
      const safeLink = safeHttpUrl(item.link);
      return `
        <div class="threat-card news ${isFresh ? 'news-fresh' : ''}" data-link="${escapeHtml(safeLink)}">
          <div class="threat-card-header">
            <span class="threat-card-type${isFresh ? ' news-live-badge' : ''}">
              ${isFresh ? '<span class="news-dot"></span>' : ''}${categoryLabel}
            </span>
            ${officialBadge}
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
        if (link) window.open(link, '_blank', 'noopener,noreferrer');
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

function safeHttpUrl(value) {
  const raw = String(value || '').trim();
  if (!/^https?:\/\//i.test(raw)) return '';
  try {
    const url = new URL(raw);
    return ['http:', 'https:'].includes(url.protocol) ? url.href : '';
  } catch {
    return '';
  }
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
      ? cve.references
          .map(ref => ({ raw: ref, url: safeHttpUrl(ref) }))
          .filter(ref => ref.url)
          .map(ref => `<a href="${escapeHtml(ref.url)}" target="_blank" rel="noopener noreferrer" class="modal-link">${escapeHtml(String(ref.raw).substring(0, 60))}...</a>`)
          .join('<br>')
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
          <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}" target="_blank" rel="noopener noreferrer" class="btn-primary">View on NVD →</a>
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
          renderActiveData(data);
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
          renderActiveData(data);
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

    const countryFocusFilter = document.getElementById('country-focus-filter');
    if (countryFocusFilter) {
      countryFocusFilter.addEventListener('change', async () => {
        currentCountryFocus = countryFocusFilter.value || 'global';
        const token = beginPanelRequest('news', true);
        const source = document.getElementById('news-source-filter')?.value || 'all';
        const timeRange = getTimeRange('news');
        const container = document.getElementById('news-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading focused news...</div></div>';
        }
        try {
          const items = await API.fetchNewsBySource(source, timeRange, currentCountryFocus);
          if (isPanelRequestStale('news', token)) return;
          updateCyberDataSection('news', items);
          renderActiveData();
          UI.showToast(`Focus set to ${API.getCountryFocusLabel(currentCountryFocus)}`, 'info');
        } catch (err) {
          renderActiveData();
          UI.showToast('Failed to fetch focused news', 'error');
        }
      });
    }

    // News source selector
    const newsSourceFilter = document.getElementById('news-source-filter');
    if (newsSourceFilter) {
      newsSourceFilter.addEventListener('change', async () => {
        const token = beginPanelRequest('news', true);
        const source = newsSourceFilter.value;
        const timeRange = getTimeRange('news');
        const container = document.getElementById('news-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading news...</div></div>';
        }
        try {
          const items = await API.fetchNewsBySource(source, timeRange, currentCountryFocus);
          if (isPanelRequestStale('news', token)) return;
          updateCyberDataSection('news', items);
          renderActiveData();
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
        const token = beginPanelRequest('news', true);
        const source = document.getElementById('news-source-filter')?.value || 'all';
        const timeRange = newsTimeFilter.value;
        const container = document.getElementById('news-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading news...</div></div>';
        }
        try {
          const items = await API.fetchNewsBySource(source, timeRange, currentCountryFocus);
          if (isPanelRequestStale('news', token)) return;
          updateCyberDataSection('news', items);
          renderActiveData();
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
        const token = beginPanelRequest('malware', true);
        const source = malwareFilter.value;
        const timeRange = getTimeRange('malware');
        const container = document.getElementById('ransomware-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading from source...</div></div>';
        }
        try {
          const items = await API.fetchMalwareBySource(source, timeRange);
          if (isPanelRequestStale('malware', token)) return;
          updateCyberDataSection('ransomware', items);
          renderActiveData();
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
        const token = beginPanelRequest('malware', true);
        const source = document.getElementById('malware-source-filter')?.value || 'all';
        const timeRange = malwareTimeFilter.value;
        const container = document.getElementById('ransomware-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading from source...</div></div>';
        }
        try {
          const items = await API.fetchMalwareBySource(source, timeRange);
          if (isPanelRequestStale('malware', token)) return;
          updateCyberDataSection('ransomware', items);
          renderActiveData();
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
        const token = beginPanelRequest('apt', true);
        const source = aptFilter.value;
        const timeRange = getTimeRange('apt');
        const container = document.getElementById('apt-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading APT data...</div></div>';
        }
        try {
          const items = await API.fetchAPTBySource(source, timeRange);
          if (isPanelRequestStale('apt', token)) return;
          updateCyberDataSection('apt', items);
          renderActiveData();
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
        const token = beginPanelRequest('apt', true);
        const source = document.getElementById('apt-source-filter')?.value || 'all';
        const timeRange = aptTimeFilter.value;
        const container = document.getElementById('apt-list');
        if (container) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading APT data...</div></div>';
        }
        try {
          const items = await API.fetchAPTBySource(source, timeRange);
          if (isPanelRequestStale('apt', token)) return;
          updateCyberDataSection('apt', items);
          renderActiveData();
          UI.showToast(`Loaded ${items.length} APT groups`, 'info');
        } catch (err) {
          UI.showToast('Failed to fetch APT data', 'error');
        }
      });
    }
  }

  // Fetch CVEs from the selected source and re-render
  async function refetchCVESource() {
    const token = beginPanelRequest('cve', true);
    const container = document.getElementById('cve-list');
    if (container) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon loading-spin">⟳</div><div class="empty-state-text">Loading from source...</div></div>';
    }

    try {
      const timeRange = getTimeRange('cve');
      const cves = await API.fetchCVEsBySource(currentCVESource, timeRange, currentSeverityFilter);
      if (isPanelRequestStale('cve', token)) return;
      updateCyberDataSection('cves', cves);
      renderActiveData();
      cveLastFetchTime = Date.now();
      updateCveTimestamp();

      // Update threat counter
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
      renderActiveData(data);
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
