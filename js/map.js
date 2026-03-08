/**
 * map.js — CyberVulnDB Leaflet.js Map Management
 */

const MapManager = (() => {
  let map = null;
  let markers = [];
  let heatmapLayer = null;
  let heatmapVisible = false;

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

    // Dark tile layer
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

  function createIcon(type, id) {
    const icon = TYPE_ICONS[type] || '📍';
    const color = TYPE_COLORS[type] || '#64748b';

    const html = `
      <div class="custom-marker marker-${type}" 
           style="width:24px;height:24px;background:${color};border:2px solid rgba(255,255,255,0.3);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.4);">
        <span>${icon}</span>
      </div>`;

    return L.divIcon({
      html,
      className: '',
      iconSize: [24, 24],
      iconAnchor: [12, 12],
    });
  }

  function addMarker(lat, lng, type, id) {
    if (!map || !Number.isFinite(lat) || !Number.isFinite(lng)) return;

    // Check if marker already exists
    const existing = markers.find(m => m._id === id);
    if (existing) return;

    const icon = createIcon(type, id);
    const marker = L.marker([lat, lng], { icon });
    
    marker._id = id;
    marker._type = type;
    marker.addTo(map);
    markers.push(marker);
  }

  function clearMarkers() {
    markers.forEach(m => map.removeLayer(m));
    markers = [];
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
      // Create simple heatmap using circle markers
      const heatData = markers.map(m => ({
        lat: m.getLatLng().lat,
        lng: m.getLatLng().lng,
        type: m._type
      }));

      // Group by location
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

      // Create heat circles
      heatmapLayer = [];
      locationMap.forEach(loc => {
        const intensity = Math.min(loc.count / 5, 1);
        const radius = 20 + loc.count * 10;
        const color = loc.types.has('ransomware') ? 'rgba(255, 45, 85,' :
                     loc.types.has('cve') ? 'rgba(245, 158, 11,' :
                     loc.types.has('apt') ? 'rgba(139, 92, 246,' :
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

      console.log('[Map] Heatmap enabled with', locationMap.size, 'clusters');
      return true;
    } else {
      // Remove heatmap
      if (heatmapLayer) {
        heatmapLayer.forEach(circle => map.removeLayer(circle));
        heatmapLayer = null;
      }
      console.log('[Map] Heatmap disabled');
      return false;
    }
  }

  function getMap() {
    return map;
  }

  return {
    init,
    addMarker,
    clearMarkers,
    flyTo,
    resetView,
    toggleHeatmap,
    getMap,
    TYPE_COLORS
  };
})();
