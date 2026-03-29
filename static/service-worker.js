const CACHE_NAME = "sandelys-secure-v1";
const URLS_TO_CACHE = [
  "/login",
  "/dashboard",
  "/inventorius",
  "/judejimai",
  "/korekcijos",
  "/truksta",
  "/scanner",
  "/static/style.css",
  "/static/app.js",
  "/static/manifest.webmanifest"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(URLS_TO_CACHE)));
});

self.addEventListener("fetch", (event) => {
  event.respondWith(caches.match(event.request).then((response) => response || fetch(event.request)));
});