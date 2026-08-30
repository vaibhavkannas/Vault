// Minimal service worker — exists only to satisfy PWA installability criteria (a controlling
// service worker with a fetch handler). Deliberately does no offline caching: this app requires
// a live connection to Firestore/Drive regardless, so caching the shell alone wouldn't make it
// usable offline and would risk serving a stale index.html after an update.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {}); // pass-through: let the browser handle every request normally
