/**
 * utils.js — Helper functions
 */

const Utils = (() => {
  /**
   * Format a Unix timestamp (seconds) or Date into a relative time string.
   */
  function timeAgo(timestamp) {
    const date = typeof timestamp === 'string' ? new Date(timestamp) : new Date(timestamp);
    const diff = Date.now() - date.getTime();
    if (diff < 0) return 'just now';
    const sec = Math.floor(diff / 1000);
    const min = Math.floor(sec / 60);
    const hr = Math.floor(min / 60);
    const days = Math.floor(hr / 24);

    if (sec < 60) return 'just now';
    if (min < 60) return `${min}m ago`;
    if (hr < 24) return min % 60 ? `${hr}h ${min % 60}m ago` : `${hr}h ago`;
    if (days < 2) return `${days}d ago`;

    const sameYear = date.getFullYear() === new Date().getFullYear();
    const opts = sameYear
      ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }
      : { month: 'short', day: 'numeric', year: 'numeric' };
    return date.toLocaleDateString('en-US', opts);
  }

  /**
   * Format a date to a readable string.
   */
  function formatDate(ts) {
    const d = ts < 1e12 ? new Date(ts * 1000) : new Date(ts);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  /**
   * Truncate text to maxLen characters.
   */
  function truncate(text, maxLen = 120) {
    if (!text) return '';
    return text.length <= maxLen ? text : text.slice(0, maxLen).trimEnd() + '…';
  }

  /**
   * Escape HTML to prevent XSS.
   */
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Debounce a function.
   */
  function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  }

  /**
   * Generate a random ID.
   */
  function uid() {
    return Math.random().toString(36).slice(2, 9);
  }

  /**
   * Deep clone a plain object.
   */
  function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  /**
   * Get from localStorage with JSON parse; return fallback on error.
   */
  function storageGet(key, fallback = null) {
    try {
      const raw = localStorage.getItem(key);
      return raw === null ? fallback : JSON.parse(raw);
    } catch {
      return fallback;
    }
  }

  /**
   * Save to localStorage with JSON stringify.
   */
  function storageSet(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (err) {
      if (err.name === 'QuotaExceededError' || err.code === 22) {
        console.warn(`[Utils] localStorage quota exceeded for key: ${key}`);
        // Try to clear old cache entries
        try {
          const keysToRemove = [];
          for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            if (k && k.startsWith('cybervulndb_')) {
              keysToRemove.push(k);
            }
          }
          // Remove oldest entries (keep last 5)
          if (keysToRemove.length > 5) {
            keysToRemove.slice(0, -5).forEach(k => localStorage.removeItem(k));
            console.log('[Utils] Cleared old cache entries');
            // Retry once
            try {
              localStorage.setItem(key, JSON.stringify(value));
              return true;
            } catch {
              console.error('[Utils] Still failed after clearing cache');
            }
          }
        } catch (e) {
          console.error('[Utils] Error clearing cache:', e);
        }
      }
      return false;
    }
  }

  /**
   * Determine if cached data is still fresh (within maxAgeMs).
   */
  function isCacheFresh(timestamp, maxAgeMs) {
    return timestamp && (Date.now() - timestamp) < maxAgeMs;
  }

  /**
   * Slugify a string for use as an ID.
   */
  function slugify(str) {
    return str.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
  }

  return {
    timeAgo,
    formatDate,
    truncate,
    escapeHtml,
    debounce,
    uid,
    clone,
    storageGet,
    storageSet,
    isCacheFresh,
    slugify,
  };
})();
