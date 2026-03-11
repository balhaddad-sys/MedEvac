const CACHE = "mak-v49";

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
    ).then(() => self.clients.claim())
     .then(() => self.clients.matchAll({type: "window"}))
     .then(clients => {
       clients.forEach(c => c.postMessage({type: "SW_UPDATED", cache: CACHE}));
     })
  );
});

self.addEventListener("message", e => {
  if (e.data && e.data.type === "SKIP_WAITING") self.skipWaiting();
});

self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  if (!e.request.url.startsWith("http")) return;

  const url = new URL(e.request.url);
  const isAppFile = url.origin === self.location.origin &&
    (e.request.mode === "navigate" || url.pathname.endsWith(".html") || url.pathname.endsWith(".js") || url.pathname === "/");

  if (isAppFile) {
    // Network-first for app files — always get fresh content, fall back to cache offline
    e.respondWith(
      fetch(e.request).then(res => {
        if (res.ok) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      }).catch(() => caches.match(e.request))
    );
    return;
  }

  // Cache-first for external resources (fonts, Firebase SDK, images)
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request))
  );
});
