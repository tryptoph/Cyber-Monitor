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
    Utils.storageSet('cybervulndb_ts', null);
    await loadAndRender();
    UI.showToast('Data refreshed!', 'success');
  }

  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', refreshData);

  // ── Core load + render cycle ───────────────────────────────
  async function loadAndRender() {
    let data = { cves: [], ransomware: [], apt: [], news: [] };
    let sourceOk = false;
    
    try {
      data = await API.loadAllData();
      sourceOk = true;
    } catch (err) {
      console.error('[App] Failed to load data:', err);
      UI.showToast('Could not fetch live data.', 'error');
    }

    // Store data globally for UI to access
    window.cyberData = data;

    // Render all panels
    renderCVEs(data.cves);
    renderRansomware(data.ransomware);
    renderAPT(data.apt);
    renderNews(data.news);

    // Update status
    UI.updateStatus(sourceOk, data.cves.length + data.ransomware.length + data.news.length);
    UI.hideLoading();

    // ── Wire up tab navigation ───────────────────────────────
    initTabs();

    // ── Wire up filters ─────────────────────────────────────
    initFilters();

    // ── Wire up search ─────────────────────────────────────
    initSearch();

    // ── Wire up sidebar toggle ─────────────────────────────
    UI.initSidebarToggle();

    // ── Wire up export ─────────────────────────────────────
    UI.initExport();
  }

  // ── Auto-refresh every 5 minutes ─────────────────────────
  setInterval(async () => {
    console.log('[App] Auto-refreshing data...');
    Utils.storageSet('cybervulndb_ts', null);
    await loadAndRender();
    UI.showToast('Data auto-refreshed', 'info');
  }, 5 * 60 * 1000); // 5 minutes

  // ── Render functions ──────────────────────────────────────
  // Store current filter
  let currentSeverityFilter = '';
  
  function renderCVEs(cves) {
    const container = document.getElementById('cve-list');
    if (!container) return;
    
    // Sort by date (newest first)
    cves.sort((a, b) => new Date(b.published) - new Date(a.published));
    
    // Apply severity filter if set
    let filteredCves = cves;
    if (currentSeverityFilter) {
      filteredCves = cves.filter(c => c.cvss.severity === currentSeverityFilter);
    }
    
    if (!filteredCves.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟩</div><div class="empty-state-text">No CVEs found</div></div>';
      return;
    }

    container.innerHTML = filteredCves.map(cve => {
      const severityClass = getSeverityClass(cve.cvss.severity);
      const countryCode = detectCountryFromText(cve.description);
      const coords = API.getCoords(countryCode);
      
      return `
        <div class="threat-card cve" data-id="${cve.id}" data-coords="${coords.join(',')}">
          <div class="threat-card-header">
            <span class="threat-card-type">CVE</span>
            <span class="threat-card-date">${formatDate(cve.published)}</span>
          </div>
          <div class="threat-card-title">${escapeHtml(cve.description.substring(0, 100))}...</div>
          <div class="threat-card-meta">
            <span class="cve-id">${cve.id}</span>
            <span class="badge ${severityClass}">${cve.cvss.score.toFixed(1)}</span>
          </div>
        </div>
      `;
    }).join('');

    // Add click handlers
    container.querySelectorAll('.threat-card').forEach(card => {
      card.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        try {
          const cveId = card.dataset.id;
          const cve = cves.find(c => c.id === cveId);
          if (cve) showCVEModal(cve);
        } catch (err) {
          console.error('[App] Error showing CVE modal:', err);
        }
      });
      
      // Add to map
      const coords = card.dataset.coords.split(',').map(Number);
      if (coords[0]) {
        MapManager.addMarker(coords[0], coords[1], 'cve', card.dataset.id);
      }
    });
  }

  function renderRansomware(victims) {
    const container = document.getElementById('ransomware-list');
    if (!container) return;
    
    if (!victims.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟩</div><div class="empty-state-text">No ransomware data</div></div>';
      return;
    }

    container.innerHTML = victims.map(v => {
      const coords = API.getCoords(v.countryCode);
      
      return `
        <div class="threat-card ransomware" data-id="${v.id}" data-coords="${coords.join(',')}">
          <div class="threat-card-header">
            <span class="threat-card-type">RANSOMWARE</span>
            <span class="threat-card-date">${formatDate(v.discovered)}</span>
          </div>
          <div class="threat-card-title">${escapeHtml(v.organization)}</div>
          <div class="threat-card-meta">
            <span class="badge high">${v.group}</span>
            <span>${v.country}</span>
          </div>
        </div>
      `;
    }).join('');

    // Add click handlers and map markers
    container.querySelectorAll('.threat-card').forEach(card => {
      card.addEventListener('click', () => {
        const id = card.dataset.id;
        const victim = victims.find(v => v.id === id);
        if (victim) showRansomwareModal(victim);
      });
      
      const coords = card.dataset.coords.split(',').map(Number);
      if (coords[0]) {
        MapManager.addMarker(coords[0], coords[1], 'ransomware', card.dataset.id);
      }
    });
  }

  function renderAPT(groups) {
    const container = document.getElementById('apt-list');
    if (!container) return;
    
    if (!groups.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟩</div><div class="empty-state-text">No APT data</div></div>';
      return;
    }

    container.innerHTML = groups.map(apt => {
      const coords = API.getCoords(apt.country);
      
      return `
        <div class="threat-card apt" data-id="${apt.id}" data-coords="${coords.join(',')}">
          <div class="threat-card-header">
            <span class="threat-card-type">APT GROUP</span>
            <span>${apt.country}</span>
          </div>
          <div class="threat-card-title">${escapeHtml(apt.name)}</div>
          <div class="threat-card-meta">
            <span>${apt.targetSectors.slice(0, 2).join(', ')}</span>
          </div>
        </div>
      `;
    }).join('');

    // Add click handlers and map markers
    container.querySelectorAll('.threat-card').forEach(card => {
      card.addEventListener('click', () => {
        const id = card.dataset.id;
        const apt = groups.find(a => a.id === id);
        if (apt) showAPTModal(apt);
      });
      
      const coords = card.dataset.coords.split(',').map(Number);
      if (coords[0]) {
        MapManager.addMarker(coords[0], coords[1], 'apt', card.dataset.id);
      }
    });
  }

  function renderNews(news) {
    const container = document.getElementById('news-list');
    if (!container) return;
    
    if (!news.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟩</div><div class="empty-state-text">No news available</div></div>';
      return;
    }

    container.innerHTML = news.map(item => {
      return `
        <div class="threat-card news" data-link="${item.link}">
          <div class="threat-card-header">
            <span class="threat-card-type">${item.category}</span>
            <span class="threat-card-date">${formatDate(item.published)}</span>
          </div>
          <div class="threat-card-title">${escapeHtml(item.title)}</div>
          <div class="threat-card-meta">
            <span>${item.source}</span>
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
    const s = severity?.toUpperCase() || '';
    if (s === 'CRITICAL') return 'critical';
    if (s === 'HIGH') return 'high';
    if (s === 'MEDIUM') return 'medium';
    if (s === 'LOW') return 'low';
    return 'info';
  }

  function detectCountryFromText(text) {
    const lower = text.toLowerCase();
    if (/china|chinese|beijing/i.test(lower)) return 'CN';
    if (/russia|russian|moscow/i.test(lower)) return 'RU';
    if (/iran|iranian|tehran/i.test(lower)) return 'IR';
    if (/north korea|dprk/i.test(lower)) return 'KP';
    if (/korea|seoul/i.test(lower)) return 'KR';
    if (/germany|berlin/i.test(lower)) return 'DE';
    if (/uk|britain|london/i.test(lower)) return 'GB';
    return 'US';
  }

  function formatDate(dateStr) {
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now - date;
    const hours = Math.floor(diff / (1000 * 60 * 60));
    
    if (hours < 1) return 'Just now';
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;
    // Show actual date for older items
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ── Modal functions ─────────────────────────────────────
  function showCVEModal(cve) {
    const overlay = document.getElementById('modal-overlay');
    const content = document.getElementById('modal-content');
    if (!overlay || !content) return;

    content.innerHTML = `
      <div class="modal-header">
        <div>
          <div class="modal-type-badge badge-${getSeverityClass(cve.cvss.severity)}">CVE</div>
          <div class="modal-title">${cve.id}</div>
        </div>
        <button class="modal-close" onclick="document.getElementById('modal-overlay').classList.add('hidden')">×</button>
      </div>
      <div class="modal-body">
        <div class="modal-meta-row">
          <span class="badge ${getSeverityClass(cve.cvss.severity)}">CVSS: ${cve.cvss.score}</span>
          <span>${cve.cvss.severity}</span>
          <span>Published: ${formatDate(cve.published)}</span>
        </div>
        <p class="modal-description">${cve.description}</p>
        ${cve.references.length ? `<a href="${cve.references[0]}" target="_blank" class="btn-primary">View on NVD</a>` : ''}
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
          <div class="modal-title">${victim.organization}</div>
        </div>
        <button class="modal-close" onclick="document.getElementById('modal-overlay').classList.add('hidden')">×</button>
      </div>
      <div class="modal-body">
        <div class="modal-meta-row">
          <span class="badge high">${victim.group}</span>
          <span>${victim.country}</span>
          <span>${victim.sector}</span>
        </div>
        <p class="modal-description">${victim.description || 'Ransomware attack reported.'}</p>
        <p class="modal-meta-item">Discovered: ${formatDate(victim.discovered)}</p>
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
          <div class="modal-title">${apt.name}</div>
        </div>
        <button class="modal-close" onclick="document.getElementById('modal-overlay').classList.add('hidden')">×</button>
      </div>
      <div class="modal-body">
        <div class="modal-meta-row">
          <span>Country: ${apt.country}</span>
        </div>
        <p class="modal-description">${apt.description}</p>
        <p><strong>Aliases:</strong> ${apt.aliases.join(', ')}</p>
        <p><strong>Target Sectors:</strong> ${apt.targetSectors.join(', ')}</p>
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
      });
    });
  }

  // ── Filters ───────────────────────────────────────────
  function initFilters() {
    const cveFilter = document.getElementById('cve-severity-filter');
    if (cveFilter) {
      cveFilter.addEventListener('change', () => {
        currentSeverityFilter = cveFilter.value;
        const data = window.cyberData || { cves: [] };
        renderCVEs(data.cves);
      });
    }

    const newsFilter = document.getElementById('news-category-filter');
    if (newsFilter) {
      newsFilter.addEventListener('change', () => {
        const category = newsFilter.value;
        const data = window.cyberData || { news: [] };
        let filtered = data.news;
        if (category) {
          filtered = data.news.filter(n => n.category === category);
        }
        renderNews(filtered);
      });
    }
  }

  // ── Search ──────────────────────────────────────────────
  function initSearch() {
    const searchInput = document.getElementById('search-input');
    if (!searchInput) return;

    searchInput.addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase();
      if (!query) {
        // Reset views
        loadAndRender();
        return;
      }

      const data = window.cyberData;
      if (!data) return;

      // Filter all data by query
      const filteredCVEs = data.cves.filter(c => 
        c.id.toLowerCase().includes(query) || 
        c.description.toLowerCase().includes(query)
      );
      
      const filteredRansomware = data.ransomware.filter(r => 
        r.organization.toLowerCase().includes(query) ||
        r.group.toLowerCase().includes(query)
      );
      
      const filteredAPT = data.apt.filter(a => 
        a.name.toLowerCase().includes(query) ||
        a.aliases.some(alias => alias.toLowerCase().includes(query))
      );
      
      const filteredNews = data.news.filter(n => 
        n.title.toLowerCase().includes(query) ||
        n.description.toLowerCase().includes(query)
      );

      renderCVEs(filteredCVEs);
      renderRansomware(filteredRansomware);
      renderAPT(filteredAPT);
      renderNews(filteredNews);
    });
  }

  // Map reset button
  const resetBtn = document.getElementById('reset-view-btn');
  if (resetBtn) resetBtn.addEventListener('click', () => MapManager.resetView());

  // ── Kick off ───────────────────────────────────────────
  await loadAndRender();
})();
