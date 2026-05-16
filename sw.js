/* ══════════════════════════════════════════════════════════
   LE FIL D'ARIANE — Service Worker Durable
══════════════════════════════════════════════════════════ */

const CACHE_NAME = 'fil-ariane-v2';
const ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/security.js',
  '/manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // Stratégie : Cache-first avec mise à jour en tâche de fond pour les ressources locales
  if (ASSETS.includes(url.pathname) || url.origin === location.origin) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        const networked = fetch(event.request).then((response) => {
          if (response.ok) {
            const cacheCopy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, cacheCopy));
          }
          return response;
        }).catch(() => null);

        return cached || networked;
      })
    );
  }
});
