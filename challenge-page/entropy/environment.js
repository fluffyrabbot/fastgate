// environment.js - Environment signal collection for entropy fingerprinting
// Part of Phase 3: Privacy-preserving bot detection

/**
 * Gathers environment signals that are difficult for bots to spoof correctly.
 * All signals are bucketed/coarsened for privacy (no unique fingerprinting).
 * @returns {Object} Environment signals object
 */
export function gatherEnvironmentSignals() {
  return {
    screen: getScreenInfo(),
    timezone: getTimezoneInfo(),
    languages: getLanguageInfo(),
    features: getBrowserFeatures(),
    colorDepth: getColorDepth(),
    platform: getPlatformInfo(),
    plugins: getPluginInfo(),
    timestamp: Date.now()
  };
}

/**
 * Gets bucketed screen information (privacy-preserving).
 * @returns {Object} Screen info with bucketed dimensions
 */
function getScreenInfo() {
  // Bucket screen sizes to prevent unique fingerprinting
  const width = screen.width;
  const height = screen.height;

  // Common buckets: mobile (< 768), tablet (768-1024), desktop (> 1024)
  let bucket = 'desktop';
  if (width < 768) {
    bucket = 'mobile';
  } else if (width < 1024) {
    bucket = 'tablet';
  }

  return {
    bucket,
    aspectRatio: Math.round((width / height) * 100) / 100,
    availWidth: screen.availWidth,
    availHeight: screen.availHeight,
    orientation: width > height ? 'landscape' : 'portrait',
    pixelRatio: window.devicePixelRatio || 1
  };
}

/**
 * Gets timezone information.
 * @returns {Object} Timezone info
 */
function getTimezoneInfo() {
  try {
    const offset = new Date().getTimezoneOffset();
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

    return {
      offset,
      name: tz || 'unknown'
    };
  } catch (e) {
    return {
      offset: new Date().getTimezoneOffset(),
      name: 'unknown'
    };
  }
}

/**
 * Gets language preferences.
 * @returns {Object} Language info
 */
function getLanguageInfo() {
  const languages = navigator.languages || [navigator.language || 'en'];

  return {
    primary: languages[0] || 'unknown',
    count: languages.length,
    // Don't send full list for privacy, just count
    hasMultiple: languages.length > 1
  };
}

/**
 * Detects browser feature support.
 * Headless browsers often lack certain features.
 * @returns {Object} Feature support flags
 */
function getBrowserFeatures() {
  return {
    localStorage: testLocalStorage(),
    sessionStorage: testSessionStorage(),
    indexedDB: 'indexedDB' in window,
    webGL: testWebGL(),
    webGL2: testWebGL2(),
    webRTC: testWebRTC(),
    serviceWorker: 'serviceWorker' in navigator,
    notifications: 'Notification' in window,
    geolocation: 'geolocation' in navigator,
    webAssembly: typeof WebAssembly !== 'undefined',
    sharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined',
    bigInt: typeof BigInt !== 'undefined',
    webSockets: 'WebSocket' in window,
    webWorkers: 'Worker' in window
  };
}

/**
 * Tests localStorage availability (some headless browsers fail here).
 * @returns {boolean} True if localStorage is available
 */
function testLocalStorage() {
  try {
    const test = '__test__';
    localStorage.setItem(test, test);
    localStorage.removeItem(test);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Tests sessionStorage availability.
 * @returns {boolean} True if sessionStorage is available
 */
function testSessionStorage() {
  try {
    const test = '__test__';
    sessionStorage.setItem(test, test);
    sessionStorage.removeItem(test);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Tests WebGL support.
 * @returns {boolean} True if WebGL is supported
 */
function testWebGL() {
  try {
    const canvas = document.createElement('canvas');
    return !!(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
  } catch (e) {
    return false;
  }
}

/**
 * Tests WebGL2 support.
 * @returns {boolean} True if WebGL2 is supported
 */
function testWebGL2() {
  try {
    const canvas = document.createElement('canvas');
    return !!canvas.getContext('webgl2');
  } catch (e) {
    return false;
  }
}

/**
 * Tests WebRTC support.
 * @returns {boolean} True if WebRTC is supported
 */
function testWebRTC() {
  return !!(
    window.RTCPeerConnection ||
    window.webkitRTCPeerConnection ||
    window.mozRTCPeerConnection
  );
}

/**
 * Gets color depth information.
 * @returns {number} Color depth in bits
 */
function getColorDepth() {
  return screen.colorDepth || -1;
}

/**
 * Gets platform information.
 * @returns {Object} Platform info
 */
function getPlatformInfo() {
  const nav = navigator;

  // Detect headless Chrome via userAgent and platform mismatches
  const ua = nav.userAgent || '';
  const platform = nav.platform || '';

  return {
    platform,
    vendor: nav.vendor || 'unknown',
    // Don't send full userAgent for privacy, just detect headless signatures
    hasHeadlessUA: ua.toLowerCase().includes('headless'),
    hasChromeUA: ua.includes('Chrome'),
    hasPhantomUA: ua.includes('PhantomJS'),
    cookieEnabled: nav.cookieEnabled,
    doNotTrack: nav.doNotTrack || 'unspecified',
    maxTouchPoints: nav.maxTouchPoints || 0
  };
}

/**
 * Gets plugin information (limited for privacy).
 * @returns {Object} Plugin info
 */
function getPluginInfo() {
  const plugins = navigator.plugins || [];

  // Don't send plugin names/details for privacy
  // Just count and detect suspicious patterns (e.g., exactly 0 or 1 plugin is unusual)
  return {
    count: plugins.length,
    hasFlash: Array.from(plugins).some(p => p.name && p.name.toLowerCase().includes('flash')),
    hasPDF: Array.from(plugins).some(p => p.name && p.name.toLowerCase().includes('pdf'))
  };
}

/**
 * Detects environment anomalies that indicate headless/automation.
 * @param {Object} signals Environment signals object
 * @returns {Array<string>} Array of detected anomalies
 */
export function detectEnvironmentAnomalies(signals) {
  const anomalies = [];

  // Check for headless signatures in platform
  if (signals.platform.hasHeadlessUA) {
    anomalies.push('headless_ua');
  }

  if (signals.platform.hasPhantomUA) {
    anomalies.push('phantom_ua');
  }

  // Check for missing localStorage (common headless issue)
  if (!signals.features.localStorage) {
    anomalies.push('no_localstorage');
  }

  // Check for missing WebGL (unusual for modern browsers)
  if (!signals.features.webGL) {
    anomalies.push('no_webgl');
  }

  // Check for suspicious plugin count (0 or 1 is unusual)
  if (signals.plugins.count === 0) {
    anomalies.push('no_plugins');
  }

  // Check for missing languages (headless signature)
  if (signals.languages.count === 0 || signals.languages.primary === 'unknown') {
    anomalies.push('missing_languages');
  }

  // Check for unusual timezone (missing or invalid)
  if (signals.timezone.name === 'unknown') {
    anomalies.push('unknown_timezone');
  }

  // Check for impossible combinations (Chrome on Linux with vendor "Apple Computer, Inc.")
  if (signals.platform.hasChromeUA && signals.platform.vendor.includes('Apple') &&
      !signals.platform.platform.includes('Mac') && !signals.platform.platform.includes('iPhone')) {
    anomalies.push('vendor_platform_mismatch');
  }

  // Check for missing touch on mobile screen
  const isMobile = signals.screen.bucket === 'mobile';
  if (isMobile && signals.platform.maxTouchPoints === 0) {
    anomalies.push('mobile_no_touch');
  }

  // Check for suspiciously low pixel ratio on high-res screens
  const isDesktop = signals.screen.bucket === 'desktop';
  if (isDesktop && signals.screen.pixelRatio < 1) {
    anomalies.push('low_pixel_ratio');
  }

  // Check for cookies disabled (unusual for real users)
  if (!signals.platform.cookieEnabled) {
    anomalies.push('cookies_disabled');
  }

  // Check for missing modern features (WebAssembly, Workers)
  const missingModernFeatures = !signals.features.webAssembly || !signals.features.webWorkers;
  if (signals.platform.hasChromeUA && missingModernFeatures) {
    anomalies.push('missing_modern_features');
  }

  return anomalies;
}

/**
 * Calculates a privacy-preserving environment hash.
 * Used for deduplication without unique fingerprinting.
 * @param {Object} signals Environment signals
 * @returns {string} Coarse environment hash
 */
export function getEnvironmentHash(signals) {
  // Create a coarse hash from bucketed values only
  const parts = [
    signals.screen.bucket,
    signals.screen.orientation,
    Math.floor(signals.screen.pixelRatio),
    signals.timezone.name,
    signals.languages.primary,
    signals.colorDepth,
    signals.platform.platform
  ];

  // Simple hash (not cryptographic, just for grouping)
  let hash = 0;
  const str = parts.join('|');
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }

  return hash.toString(36);
}
