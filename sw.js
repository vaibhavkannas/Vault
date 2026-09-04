// Push notifications (FCM). A service worker has no shared scope with index.html, so the SDK and
// firebaseConfig have to be loaded/duplicated here independently rather than imported — these are
// the same literal values as index.html's own firebaseConfig, none of them secret.
importScripts('https://www.gstatic.com/firebasejs/10.14.1/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.14.1/firebase-messaging-compat.js');
firebase.initializeApp({
  apiKey: "AIzaSyC9zVPWgTekPiDUDn1YcLDInHBFRRUgW9w",
  authDomain: "elite-vault-7b00a.firebaseapp.com",
  projectId: "elite-vault-7b00a",
  storageBucket: "elite-vault-7b00a.firebasestorage.app",
  messagingSenderId: "713625816347",
  appId: "1:713625816347:web:72d45d04fbb9e6944c97be"
});
const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
  const title = (payload.notification && payload.notification.title) || 'Vault';
  self.registration.showNotification(title, {
    body: payload.notification && payload.notification.body,
    icon: './icon.svg',
    badge: './icon.svg',
    data: payload.data || {}
  });
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({type: 'window', includeUncontrolled: true}).then((clientList) => {
      for(const client of clientList){
        if(client.url.startsWith(self.location.origin) && 'focus' in client) return client.focus();
      }
      if(self.clients.openWindow) return self.clients.openWindow('./');
    })
  );
});

// Caches the app shell (this page and the pinned-version library scripts it loads) so the app can
// still open with no connection at all — not just survive a connection drop mid-session. Without
// this, a document already cached for offline viewing (see index.html's offline document cache)
// would be unreachable the moment the tab is closed and reopened offline, since the browser could
// never load the page in the first place.
//
// CACHE_VERSION must be bumped by hand whenever SHELL_URLS changes (a new library version, a new
// static asset) — activate() below deletes every other "vault-shell-*" cache, so bumping this is
// what lets a new deploy actually replace what's cached instead of being stuck behind it forever.
// index.html/manifest.json/icon.svg themselves don't need a bump for ordinary content edits:
// they're fetched network-first below, so the live copy always wins whenever a connection is
// available — the cached copy is only ever a fallback for when it isn't.
const CACHE_VERSION = '3';
const SHELL_CACHE = 'vault-shell-v' + CACHE_VERSION;

// Same-origin, could change between deploys — always prefer a live fetch.
const NETWORK_FIRST_REL = ['./index.html', './manifest.json', './icon.svg'];
// External libraries pinned to an exact version in the URL itself — that exact URL's content
// never changes, so serving the cached copy immediately, before even checking the network, is
// always safe.
const CACHE_FIRST_URLS = [
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
  'https://cdn.jsdelivr.net/npm/tesseract.js@5.0.4/dist/tesseract.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js',
  'https://www.gstatic.com/firebasejs/10.14.1/firebase-app-compat.js',
  'https://www.gstatic.com/firebasejs/10.14.1/firebase-auth-compat.js',
  'https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore-compat.js',
  'https://www.gstatic.com/firebasejs/10.14.1/firebase-messaging-compat.js',
  'https://accounts.google.com/gsi/client',
  'https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap'
];
const NETWORK_FIRST_ABS = NETWORK_FIRST_REL.map(u => new URL(u, self.location).href);

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(SHELL_CACHE).then(cache => Promise.all([
      cache.add('./').catch(e => console.warn('Shell pre-cache failed for ./', e)),
      ...NETWORK_FIRST_REL.map(u => cache.add(u).catch(e => console.warn('Shell pre-cache failed for', u, e))),
      // Cross-origin, fetched in no-cors mode so caching works regardless of whether that CDN
      // happens to send permissive CORS headers. Deliberately fetch+put, not cache.add(): add()
      // rejects any response whose status isn't 200, and a no-cors response is always reported as
      // status 0 (opaque, by design, to avoid leaking cross-origin data) — add() would fail on
      // every one of these even though the fetch itself succeeded. put() has no such check, and
      // the browser can still use a stored opaque response to satisfy a plain <script src> load.
      ...CACHE_FIRST_URLS.map(u => fetch(new Request(u, {mode: 'no-cors'}))
        .then(res => cache.put(u, res))
        .catch(e => console.warn('Shell pre-cache failed for', u, e)))
    ]))
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(Promise.all([
    self.clients.claim(),
    caches.keys().then(names => Promise.all(
      names.filter(n => n.startsWith('vault-shell-') && n !== SHELL_CACHE).map(n => caches.delete(n))
    ))
  ]));
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if(req.method !== 'GET') return; // never intercept writes — Firestore, Drive, Apps Script

  if(req.mode === 'navigate'){
    event.respondWith(networkFirst(req, './index.html'));
    return;
  }
  if(NETWORK_FIRST_ABS.includes(req.url)){
    event.respondWith(networkFirst(req, req.url));
    return;
  }
  if(CACHE_FIRST_URLS.includes(req.url)){
    event.respondWith(cacheFirstOpaque(req.url));
    return;
  }
  // Everything else — Firestore, Drive, Apps Script, GIS/OAuth, and any other dynamic request —
  // is left alone entirely, same as before this file did any caching at all.
});

function networkFirst(req, fallbackKey){
  // Plain fetch(req) still honors the browser's own HTTP cache, not just this function's Cache
  // Storage — GitHub Pages sends Cache-Control: max-age=600 on index.html, so for up to 10 minutes
  // after any deploy, "network first" here could be silently satisfied out of the browser's HTTP
  // cache without a real round-trip, serving a stale app shell even though the whole point of this
  // function (see the comment on NETWORK_FIRST_REL above) is "always prefer whatever's live."
  // cache:'no-store' forces an actual network request every time; the try/catch fallback below is
  // unaffected since it still reads from this file's own Cache Storage, not the HTTP cache.
  return fetch(new Request(req, {cache: 'no-store'})).then(res => {
    const copy = res.clone();
    caches.open(SHELL_CACHE).then(cache => cache.put(req, copy));
    return res;
  }).catch(() => caches.match(req).then(cached => cached || caches.match(fallbackKey)));
}

function cacheFirstOpaque(url){
  return caches.match(url).then(cached => {
    const network = fetch(new Request(url, {mode: 'no-cors'})).then(res => {
      caches.open(SHELL_CACHE).then(cache => cache.put(url, res.clone()));
      return res;
    }).catch(() => cached);
    return cached || network;
  });
}
