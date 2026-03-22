/* ══════════════════════════════════════════════════════════
   LE FIL D'ARIANE — Service Worker
   Cache stratégie : Cache-first pour assets, Network-first pour data
══════════════════════════════════════════════════════════ */

const CACHE_NAME = 'fil-ariane-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/manifest.json',
  'https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400;0,600;1,300;1,400&family=DM+Sans:wght@300;400;500&display=swap'
];

// ── INSTALL : cache tous les assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS.filter(a => !a.startsWith('https://fonts')));
    }).then(() => self.skipWaiting())
  );
});

// ── ACTIVATE : nettoyer les anciens caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// ── FETCH : Cache-first pour assets, network pour le reste
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Skip cross-origin requests except fonts
  if (url.origin !== location.origin && !url.hostname.includes('fonts')) return;
  
  // Cache-first strategy for static assets
  if (
    event.request.method === 'GET' &&
    (url.pathname.endsWith('.css') || 
     url.pathname.endsWith('.js') || 
     url.pathname.endsWith('.html') ||
     url.pathname === '/' ||
     url.hostname.includes('fonts'))
  ) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        if (cached) return cached;
        return fetch(event.request).then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        });
      })
    );
    return;
  }
  
  // Network-first for everything else
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});

// ── PUSH NOTIFICATIONS
self.addEventListener('push', (event) => {
  const data = event.data ? event.data.json() : {};
  const options = {
    body: data.body || 'Votre transmission vous attend.',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    vibrate: [200, 100, 200],
    data: { url: data.url || '/' },
    actions: [
      { action: 'open', title: 'Ouvrir' },
      { action: 'dismiss', title: 'Plus tard' }
    ]
  };
  event.waitUntil(
    self.registration.showNotification(data.title || 'Le Fil d\'Ariane', options)
  );
});

// ── NOTIFICATION CLICK
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  if (event.action === 'dismiss') return;
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow('/');
    })
  );
});

// ── BACKGROUND SYNC (pour envoi différé d'invitations gardiens)
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-invitations') {
    event.waitUntil(syncPendingInvitations());
  }
});

async function syncPendingInvitations() {
  // En production : envoyer les invitations en attente au backend
  console.log('[SW] Syncing pending invitations...');
}
