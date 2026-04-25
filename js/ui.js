/**
 * ui.js — CyberVulnDB UI Interactions
 */

const UI = (() => {
  const els = {};

  function cacheEls() {
    els.searchInput = document.getElementById('search-input');
    els.refreshBtn = document.getElementById('refresh-btn');
    els.exportBtn = document.getElementById('export-btn');
    els.sidebarToggle = document.getElementById('sidebar-toggle');
    els.sidebar = document.getElementById('sidebar');
    els.modalOverlay = document.getElementById('modal-overlay');
    els.loadingOverlay = document.getElementById('loading-overlay');
    els.toastContainer = document.getElementById('toast-container');
    els.statusSource = document.getElementById('status-source');
    els.statusUpdate = document.getElementById('status-update');
    els.statusCount = document.getElementById('status-count');
    
    // Modal click outside to close
    if (els.modalOverlay) {
      els.modalOverlay.addEventListener('click', (e) => {
        if (e.target === els.modalOverlay) {
          els.modalOverlay.classList.add('hidden');
        }
      });
    }
  }

  function showLoading() {
    if (els.loadingOverlay) els.loadingOverlay.classList.remove('hidden');
  }

  function hideLoading() {
    if (els.loadingOverlay) els.loadingOverlay.classList.add('hidden');
  }

  function showToast(message, type = 'info', duration = 3500) {
    const icons = { success: '✓', error: '✗', info: '›' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${icons[type] || ''}</span><span>${message}</span>`;
    els.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 400);
    }, duration);
  }

  function updateStatus(ok, count) {
    if (els.statusSource) {
      els.statusSource.innerHTML = ok ? '[OK] Connected' : '[WARN] Using cached data';
      els.statusSource.className = 'status-item ' + (ok ? 'status-ok' : 'status-error');
    }
    if (els.statusUpdate) {
      els.statusUpdate.textContent = new Date().toLocaleTimeString();
    }
    if (els.statusCount) {
      els.statusCount.textContent = `${count} threats`;
    }
  }

  function initSidebarToggle() {
    const toggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    if (!toggle || !sidebar) return;

    toggle.addEventListener('click', () => {
      sidebar.classList.toggle('collapsed');
      toggle.classList.toggle('collapsed');
      toggle.textContent = sidebar.classList.contains('collapsed') ? '›' : '‹';
    });
  }

  function initExport() {
    const btn = document.getElementById('export-btn');
    if (!btn) return;

    btn.addEventListener('click', () => {
      const data = window.cyberData;
      if (!data) {
        showToast('No data to export', 'error');
        return;
      }
      
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cybervulndb-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Data exported!', 'success');
    });
  }

  return {
    cacheEls,
    showLoading,
    hideLoading,
    showToast,
    updateStatus,
    initSidebarToggle,
    initExport
  };
})();
