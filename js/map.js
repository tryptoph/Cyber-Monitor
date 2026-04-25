/**
 * map.js — CyberVulnDB Leaflet.js Map Management
 * Enhanced with popups, pulsing markers, APT labels, and attack flow lines
 */

const MapManager = (() => {
  let map = null;
  let markers = [];
  let attackLines = [];
  let heatmapLayer = null;
  let heatmapVisible = false;

  function hashCode(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    return h;
  }

  const TYPE_ICONS = {
    cve: '⚡',
    ransomware: '🔒',
    apt: '🎯',
    news: '📰',
  };

  const TYPE_COLORS = {
    cve: '#f59e0b',
    ransomware: '#ef4444',
    apt: '#8b5cf6',
    news: '#3b82f6',
  };

  function init(containerId) {
    map = L.map(containerId, {
      center: [20, 10],
      zoom: 2,
      minZoom: 2,
      maxZoom: 10,
      zoomControl: false,
      worldCopyJump: false,
      maxBounds: [[-85, -180], [85, 180]],
      maxBoundsViscosity: 0.8,
    });

    L.tileLayer(
      'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
      {
        attribution: '&copy; OpenStreetMap &copy; CARTO',
        subdomains: 'abcd',
        maxZoom: 19,
      }
    ).addTo(map);

    L.control.zoom({ position: 'bottomright' }).addTo(map);

    return map;
  }

  function createIcon(type, id, size) {
    const icon = TYPE_ICONS[type] || '📍';
    const color = TYPE_COLORS[type] || '#64748b';
    const s = size || (type === 'apt' ? 30 : type === 'ransomware' ? 26 : 22);

    const pulse = type === 'apt' ? 'marker-pulse-ring' : '';

    const html = `
      <div class="custom-marker marker-${type}" 
           style="width:${s}px;height:${s}px;background:${color};border:2px solid rgba(255,255,255,0.3);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:${Math.round(s * 0.5)}px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.4),0 0 12px ${color}40;">
        <span>${icon}</span>
      </div>
      ${pulse ? `<div class="${pulse}" style="border-color:${color}"></div>` : ''}`;

    return L.divIcon({
      html,
      className: 'marker-wrapper',
      iconSize: [s, s],
      iconAnchor: [s / 2, s / 2],
    });
  }

  function buildPopupContent(type, data) {
    if (!data) return '';
    const color = TYPE_COLORS[type] || '#64748b';

    if (type === 'apt') {
      const targets = data.targetSectors ? data.targetSectors.slice(0, 4).join(', ') : 'Unknown';
      const aliases = data.aliases ? data.aliases.slice(0, 3).join(', ') : '';
      return `
        <div class="map-popup-content">
          <div class="popup-type-badge" style="background:${color}20;color:${color};border:1px solid ${color}50">🎯 APT GROUP</div>
          <div class="popup-title">${data.name || 'Unknown'}</div>
          <div class="popup-country">
            <span class="popup-flag">${data.countryFlag || '🌍'}</span>
            <span>${data.countryName || data.country || 'Unknown'}</span>
          </div>
          ${aliases ? `<div class="popup-aliases">aka: ${aliases}</div>` : ''}
          <div class="popup-detail"><span class="popup-label">Targets:</span> ${targets}</div>
          ${data.victims ? `<div class="popup-detail"><span class="popup-label">Known victims:</span> ${data.victims.slice(0, 3).join(', ')}</div>` : ''}
        </div>`;
    }

    if (type === 'cve') {
      const sev = data.severity || 'N/A';
      const sevColor = sev === 'CRITICAL' ? '#ff2d55' : sev === 'HIGH' ? '#ff9500' : sev === 'MEDIUM' ? '#ffcc00' : '#30d158';
      return `
        <div class="map-popup-content">
          <div class="popup-type-badge" style="background:${color}20;color:${color};border:1px solid ${color}50">⚡ CVE</div>
          <div class="popup-title">${data.id || 'Unknown'}</div>
          <div class="popup-detail">
            <span class="popup-severity" style="color:${sevColor}">● ${sev}</span>
            ${data.score ? `<span class="popup-score">${data.score}</span>` : ''}
          </div>
          <div class="popup-desc">${(data.description || '').substring(0, 120)}${(data.description || '').length > 120 ? '...' : ''}</div>
        </div>`;
    }

    if (type === 'ransomware') {
      return `
        <div class="map-popup-content">
          <div class="popup-type-badge" style="background:${color}20;color:${color};border:1px solid ${color}50">🔒 RANSOMWARE</div>
          <div class="popup-title">${data.organization || data.name || 'Unknown'}</div>
          <div class="popup-detail"><span class="popup-label">Group:</span> ${data.group || 'Unknown'}</div>
          <div class="popup-detail"><span class="popup-label">Country:</span> ${data.country || 'Unknown'}</div>
        </div>`;
    }

    return `<div class="map-popup-content"><div class="popup-title">${data.name || data.id || 'Item'}</div></div>`;
  }

  function addMarker(lat, lng, type, id, data) {
    if (!map || !Number.isFinite(lat) || !Number.isFinite(lng)) return;

    const existing = markers.find(m => m._id === id);
    if (existing) return;

    const icon = createIcon(type, id);
    const marker = L.marker([lat, lng], { icon });

    marker._id = id;
    marker._type = type;
    marker._data = data;

    // Add popup if data provided
    if (data) {
      const popupContent = buildPopupContent(type, data);
      if (popupContent) {
        marker.bindPopup(popupContent, {
          className: 'cyber-popup',
          maxWidth: 280,
          minWidth: 200,
        });
      }
    }

    // Add tooltip for quick hover
    if (data && (data.name || data.id)) {
      marker.bindTooltip(data.name || data.id, {
        className: 'cyber-tooltip',
        direction: 'top',
        offset: [0, -15],
      });
    }

    marker.addTo(map);
    markers.push(marker);
  }

  // Add APT label marker (country name label on map)
  function addLabel(lat, lng, text, color) {
    if (!map || !Number.isFinite(lat) || !Number.isFinite(lng)) return;

    const labelIcon = L.divIcon({
      html: `<div class="map-label" style="color:${color || '#8b5cf6'}">${text}</div>`,
      className: 'map-label-wrapper',
      iconSize: [100, 20],
      iconAnchor: [50, -8],
    });

    const labelMarker = L.marker([lat, lng], { icon: labelIcon, interactive: false });
    labelMarker._isLabel = true;
    labelMarker.addTo(map);
    markers.push(labelMarker);
  }

  // Draw attack flow line from APT origin to target country
  function addAttackLine(fromLat, fromLng, toLat, toLng, color) {
    if (!map) return;
    if (!Number.isFinite(fromLat) || !Number.isFinite(fromLng)) return;
    if (!Number.isFinite(toLat) || !Number.isFinite(toLng)) return;

    // Create curved line using intermediate point
    const offset = ((hashCode(String(fromLat) + String(fromLng)) & 0xFFFF) / 0xFFFF - 0.5) * 2;
    const midLat = (fromLat + toLat) / 2 + offset * 5;
    const midLng = (fromLng + toLng) / 2;

    const line = L.polyline(
      [[fromLat, fromLng], [midLat, midLng], [toLat, toLng]],
      {
        color: color || '#8b5cf640',
        weight: 1.5,
        opacity: 0.4,
        dashArray: '6, 8',
        className: 'attack-flow-line',
      }
    );

    line.addTo(map);
    attackLines.push(line);

    // Animated dot at the target end
    const targetDot = L.circleMarker([toLat, toLng], {
      radius: 4,
      fillColor: color || '#8b5cf6',
      color: 'transparent',
      fillOpacity: 0.5,
      className: 'attack-target-dot',
    });
    targetDot.addTo(map);
    attackLines.push(targetDot);
  }

  function clearAttackLines() {
    attackLines.forEach(l => { if (map) map.removeLayer(l); });
    attackLines = [];
  }

  function clearMarkers() {
    if (!map) return;
    markers.forEach(m => map.removeLayer(m));
    markers = [];
    clearAttackLines();
  }

  function flyTo(lat, lng, zoom = 5) {
    if (map && Number.isFinite(lat) && Number.isFinite(lng)) {
      map.flyTo([lat, lng], zoom, { duration: 1 });
    }
  }

  function resetView() {
    if (map) {
      map.flyTo([20, 10], 2, { duration: 1 });
    }
  }

  function toggleHeatmap() {
    if (!map) return;

    heatmapVisible = !heatmapVisible;

    if (heatmapVisible) {
      const heatData = markers.filter(m => !m._isLabel).map(m => ({
        lat: m.getLatLng().lat,
        lng: m.getLatLng().lng,
        type: m._type
      }));

      const locationMap = new Map();
      heatData.forEach(point => {
        const key = `${point.lat.toFixed(1)},${point.lng.toFixed(1)}`;
        if (!locationMap.has(key)) {
          locationMap.set(key, { lat: point.lat, lng: point.lng, count: 0, types: new Set() });
        }
        const loc = locationMap.get(key);
        loc.count++;
        loc.types.add(point.type);
      });

      heatmapLayer = [];
      locationMap.forEach(loc => {
        const intensity = Math.min(loc.count / 5, 1);
        const radius = 20 + loc.count * 10;
        const color = loc.types.has('ransomware') ? 'rgba(255, 45, 85,' :
                     loc.types.has('apt') ? 'rgba(139, 92, 246,' :
                     loc.types.has('cve') ? 'rgba(245, 158, 11,' :
                     'rgba(59, 130, 246,';

        const circle = L.circleMarker([loc.lat, loc.lng], {
          radius: radius / 4,
          fillColor: color + (0.1 + intensity * 0.3) + ')',
          color: color + (0.3 + intensity * 0.4) + ')',
          weight: 1,
          opacity: 0.5,
          fillOpacity: 0.4
        }).addTo(map);
        heatmapLayer.push(circle);
      });
      return true;
    } else {
      if (heatmapLayer) {
        heatmapLayer.forEach(circle => map.removeLayer(circle));
        heatmapLayer = null;
      }
      return false;
    }
  }

  function getMap() {
    return map;
  }

  function getMarkerCount() {
    return markers.filter(m => !m._isLabel).length;
  }

  return {
    init,
    addMarker,
    addLabel,
    addAttackLine,
    clearAttackLines,
    clearMarkers,
    flyTo,
    resetView,
    toggleHeatmap,
    getMap,
    getMarkerCount,
    TYPE_COLORS
  };
})();
