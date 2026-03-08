const CACHE = "mak-v34";

const PRECACHE = [
  "/",
  "/index.html",
  "/boot.js",
  "/app.js",
  "/manifest.json",
  "/images/icon-48x48.png",
  "/images/icon-192x192.png",
  "/images/icon-512x512.png",
  "/images/apple-icon-180x180.png",
  "/icon-192.png",
  "/icon-512.png",
  "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js",
  "https://www.gstatic.com/firebasejs/10.12.0/firebase-database.js",
  "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js",
  "https://www.gstatic.com/firebasejs/10.12.0/firebase-functions.js",
  "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
];

self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(CACHE).then(cache =>
      cache.addAll(PRECACHE).catch(err => console.warn("Precache partial fail", err))
    )
  );
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  if (!e.request.url.startsWith("http")) return;

  // Only serve precached files from cache — everything else goes straight to network
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) {
        // Background update for HTML so new deploys are picked up
        if (e.request.mode === "navigate" || e.request.url.endsWith(".html") || e.request.url.endsWith("/")) {
          fetch(e.request).then(res => {
            if (res.ok) caches.open(CACHE).then(c => c.put(e.request, res));
          }).catch(() => {});
        }
        return cached;
      }
      return fetch(e.request);
    })
  );
});
