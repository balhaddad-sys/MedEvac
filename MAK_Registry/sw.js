const CACHE = "mak-v8";

self.addEventListener("install", e => {
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  const url = e.request.url;
  if (url.includes("firebase") || url.includes("googleapis") || url.includes("gstatic") || url.includes("generativelanguage")) return;
  // Always network-first for HTML
  if (e.request.mode === "navigate" || url.endsWith(".html") || url.endsWith("/")) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }
  // Cache-first for other static assets
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});
