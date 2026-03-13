const DESKTOP_ORIGIN_PATTERNS = [
  /^https?:\/\/tauri\.localhost(:\d+)?$/,
  /^https?:\/\/[a-z0-9-]+\.tauri\.localhost(:\d+)?$/i,
  /^tauri:\/\/localhost$/,
  /^asset:\/\/localhost$/,
];

const BROWSER_ORIGIN_PATTERNS = [
  /^https:\/\/(.*\.)?worldmonitor\.app$/,
  /^https:\/\/[a-z0-9-]+\.vercel\.app$/,
  ...(process.env.NODE_ENV === 'production' ? [] : [
    /^https?:\/\/localhost(:\d+)?$/,
    /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
  ]),
];

const PUBLIC_WEB_API_ENABLED = /^(1|true|yes)$/i.test(process.env.WORLDMONITOR_PUBLIC_WEB_API || '');

function isDesktopOrigin(origin) {
  return Boolean(origin) && DESKTOP_ORIGIN_PATTERNS.some(p => p.test(origin));
}

function isTrustedBrowserOrigin(origin) {
  return Boolean(origin) && BROWSER_ORIGIN_PATTERNS.some(p => p.test(origin));
}

function extractHostname(urlLike) {
  if (!urlLike) return '';
  try {
    return new URL(urlLike).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function normalizeHostname(hostname) {
  return String(hostname || '').toLowerCase().replace(/:\d+$/, '');
}

function isTrustedBrowserHost(hostname) {
  hostname = normalizeHostname(hostname);
  if (!hostname) return false;
  if (hostname === 'worldmonitor.app' || hostname === 'www.worldmonitor.app' || hostname.endsWith('.worldmonitor.app')) {
    return true;
  }
  if (/^[a-z0-9-]+\.vercel\.app$/.test(hostname)) {
    return true;
  }
  return process.env.NODE_ENV !== 'production' && (hostname === 'localhost' || hostname === '127.0.0.1');
}

function hasTrustedBrowserFetchMetadata(req) {
  const site = String(req.headers.get('Sec-Fetch-Site') || '').toLowerCase();
  const mode = String(req.headers.get('Sec-Fetch-Mode') || '').toLowerCase();
  return (site === 'same-origin' || site === 'same-site')
    && (mode === 'cors' || mode === 'same-origin' || mode === 'no-cors');
}

function extractOriginFromReferer(referer) {
  if (!referer) return '';
  try {
    return new URL(referer).origin;
  } catch {
    return '';
  }
}

export function validateApiKey(req, options = {}) {
  const forceKey = options.forceKey === true;
  const key = req.headers.get('X-WorldMonitor-Key');
  // Same-origin browser requests don't send Origin (per CORS spec).
  // Fall back to Referer to identify trusted same-origin callers.
  const origin = req.headers.get('Origin') || extractOriginFromReferer(req.headers.get('Referer')) || '';
  const requestHosts = [
    extractHostname(req.url),
    normalizeHostname(req.headers.get('Host')),
    normalizeHostname(req.headers.get('X-Forwarded-Host')),
  ];

  // Desktop app — always require API key
  if (isDesktopOrigin(origin)) {
    if (!key) return { valid: false, required: true, error: 'API key required for desktop access' };
    const validKeys = (process.env.WORLDMONITOR_VALID_KEYS || '').split(',').filter(Boolean);
    if (!validKeys.includes(key)) return { valid: false, required: true, error: 'Invalid API key' };
    return { valid: true, required: true };
  }

  // Explicit web-only preview/self-host bypass. Enable only when you intend to
  // expose non-premium browser APIs publicly without API keys.
  if (PUBLIC_WEB_API_ENABLED) {
    if (forceKey && !key) {
      return { valid: false, required: true, error: 'API key required' };
    }
    if (key) {
      const validKeys = (process.env.WORLDMONITOR_VALID_KEYS || '').split(',').filter(Boolean);
      if (!validKeys.includes(key)) return { valid: false, required: true, error: 'Invalid API key' };
    }
    return { valid: true, required: forceKey };
  }

  // Trusted browser origin (worldmonitor.app, Vercel previews, localhost dev) — no key needed
  if (isTrustedBrowserOrigin(origin)) {
    if (forceKey && !key) {
      return { valid: false, required: true, error: 'API key required' };
    }
    if (key) {
      const validKeys = (process.env.WORLDMONITOR_VALID_KEYS || '').split(',').filter(Boolean);
      if (!validKeys.includes(key)) return { valid: false, required: true, error: 'Invalid API key' };
    }
    return { valid: true, required: forceKey };
  }

  if (hasTrustedBrowserFetchMetadata(req)) {
    if (forceKey && !key) {
      return { valid: false, required: true, error: 'API key required' };
    }
    if (key) {
      const validKeys = (process.env.WORLDMONITOR_VALID_KEYS || '').split(',').filter(Boolean);
      if (!validKeys.includes(key)) return { valid: false, required: true, error: 'Invalid API key' };
    }
    return { valid: true, required: forceKey };
  }

  // Same-origin deploy requests may not reliably preserve Origin/Referer on all
  // Vercel preview paths, so trust requests addressed to known web hosts.
  if (requestHosts.some(isTrustedBrowserHost)) {
    if (forceKey && !key) {
      return { valid: false, required: true, error: 'API key required' };
    }
    if (key) {
      const validKeys = (process.env.WORLDMONITOR_VALID_KEYS || '').split(',').filter(Boolean);
      if (!validKeys.includes(key)) return { valid: false, required: true, error: 'Invalid API key' };
    }
    return { valid: true, required: forceKey };
  }

  // Explicit key provided from unknown origin — validate it
  if (key) {
    const validKeys = (process.env.WORLDMONITOR_VALID_KEYS || '').split(',').filter(Boolean);
    if (!validKeys.includes(key)) return { valid: false, required: true, error: 'Invalid API key' };
    return { valid: true, required: true };
  }

  // No origin, no key — require API key (blocks unauthenticated curl/scripts)
  return { valid: false, required: true, error: 'API key required' };
}
