/*
 * Service Worker for Privana PWA
 * Handles caching and offline capabilities.
 */

const CACHE_NAME = 'privana-cache-v1';
const urlsToCache = [
  '/',
  '/site/assets/privana.css',
  '/site/assets/pwa.js',
  '/site/assets/favicon.svg',
  '/site/assets/apple-touch-icon.png',
  '/site/assets/favicon.ico',
  '/site/assets/privana-mark.png',
  '/manifest.webmanifest',
  // Add other assets you want to cache for offline use
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        // Cache hit - return response
        if (response) {
          return response;
        }
        // No cache match - fetch from network
        return fetch(event.request);
      })
  );
});

// Activate event: clean up old caches
self.addEventListener('activate', (event) => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// This is an event listener that's triggered when the service worker receives a message from the client (e.g., from pwa.js).
// It's used here to allow the service worker to skip the waiting phase and activate immediately upon receiving a 'SKIP_WAITING' message.
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

