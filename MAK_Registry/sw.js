const CACHE = "mak-v5";
const ASSETS = ["/", "/index.html", "/manifest.json"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  // Never cache sensitive API calls or database requests
  const url = e.request.url;
  if (url.includes("firebasedatabase") || url.includes("googleapis") ||
      url.includes("gstatic.com") || url.includes("fonts.googleapis.com") ||
      url.includes("fonts.gstatic.com") || url.includes("generativelanguage")) return;
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request).then(res => {
      if (res.ok) { const c = res.clone(); caches.open(CACHE).then(cache => cache.put(e.request, c)); }
      return res;
    }))
  );
});
