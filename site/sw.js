/* Privana SW — cache public shell, never cache private/auth routes */
const CACHE = 'privana-v1';
const ORIGIN = self.location.origin;

const PRECACHE = [
  "/",
  "/site/assets/privana.css",
  "/site/assets/privana-mark.png",
  "/site/assets/apple-touch-icon.png",
  "/site/assets/privana-192.png",
  "/site/assets/privana-512.png",
  "/site/quantum.html",
  "/site/cookie.html",
  "/site/terms.html",
  "/site/policy.html",
  "/site/affiliates.html",
  "/site/offline.html"
];

// Paths we DO NOT cache (auth/private/dynamic)
const NO_CACHE_PATHS = ['/auth', '/dashboard', '/download', '/webauthn'];

// Hot update
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

// Install: pre-cache public shell.
// Security: do not silently ignore cache failures. If precache fails,
// abort install so a broken/compromised shell is not installed silently.
self.addEventListener('install', (evt) => {
  evt.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    try {
      await cache.addAll(PRECACHE);
    } catch (e) {
      console.error('Privana service worker precache failed:', e);
      throw e;
    }
  })());
  self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', (evt) => {
  evt.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)));
  })());
  self.clients.claim();
});

// Fetch strategy:
// - same-origin only
// - never touch sensitive routes
// - navigation: network-first → offline fallback
// - static assets: stale-while-revalidate
self.addEventListener('fetch', (evt) => {
  const req = evt.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== ORIGIN) return;
  if (NO_CACHE_PATHS.some(p => url.pathname.startsWith(p))) return;

  // Navigations
  if (req.mode === 'navigate') {
    evt.respondWith((async () => {
      try { return await fetch(req); }
      catch { return await caches.match('/site/offline.html'); }
    })());
    return;
  }

  // Static & same-origin: stale-while-revalidate
  evt.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const cached = await cache.match(req);
    const fetched = fetch(req).then(res => {
      if (res && res.status === 200) cache.put(req, res.clone());
      return res;
    }).catch(() => cached);
    return cached || fetched;
  })());
});
