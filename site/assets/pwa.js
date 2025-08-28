// /site/assets/pwa.js
(function () {
  "use strict";

  // ---- minimal inline styles for update bar & toasts (theme-friendly) ----
  const css = `
  .pwa-bar{position:fixed;left:16px;right:16px;bottom:16px;z-index:99999;
    border-radius:12px;padding:10px 12px;
    background:linear-gradient(90deg,#06b6d4,#8b5cf6);color:#fff;
    box-shadow:0 10px 30px rgba(2,6,23,.2);
    display:flex;align-items:center;justify-content:space-between;
    font:600 14px/1.2 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  .pwa-bar button{margin-left:12px;padding:8px 12px;border-radius:10px;border:0;
    background:#fff;color:#0f172a;font-weight:800;cursor:pointer}
  .pwa-toast{position:fixed;left:50%;transform:translateX(-50%);bottom:16px;
    background:#0f172a;color:#fff;padding:8px 12px;border-radius:10px;
    z-index:99998;opacity:.92;font:600 13px/1 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  @media (prefers-color-scheme: dark){
    .pwa-bar{box-shadow:0 10px 30px rgba(0,0,0,.35)}
  }`;
  const style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);

  function toast(msg, t = 2400) {
    const el = document.createElement("div");
    el.className = "pwa-toast";
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), t);
  }
  function showUpdateBar(onRefresh) {
    if (document.getElementById("pwa-update-bar")) return;
    const el = document.createElement("div");
    el.id = "pwa-update-bar";
    el.className = "pwa-bar";
    el.innerHTML = `<span>Update available.</span>
                    <span><button type="button" id="pwa-refresh-btn">Refresh</button></span>`;
    document.body.appendChild(el);
    el.querySelector("#pwa-refresh-btn").addEventListener("click", onRefresh);
  }

  // ---- Service worker registration & update flow --------------------------
  if ("serviceWorker" in navigator) {
    let refreshing = false;
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (refreshing) return; refreshing = true; location.reload();
    });

    window.addEventListener("load", async () => {
      try {
        const reg = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
        window.PWA = Object.assign(window.PWA || {}, { _reg: reg });

        if (reg.waiting) promptUpdate(reg.waiting);
        reg.addEventListener("updatefound", () => {
          const sw = reg.installing;
          if (!sw) return;
          sw.addEventListener("statechange", () => {
            if (sw.state === "installed" && navigator.serviceWorker.controller) {
              promptUpdate(sw);
            }
          });
        });

        function promptUpdate(sw) {
          showUpdateBar(() => {
            sw.postMessage({ type: "SKIP_WAITING" });
            setTimeout(() => location.reload(), 1500);
          });
        }
      } catch (err) {
        console.warn("ServiceWorker registration failed:", err);
      }
    });
  }

  // ---- Install prompt (A2HS) ---------------------------------------------
  let deferredPrompt = null;
  const installBtn =
    document.querySelector("[data-pwa-install]") ||
    document.getElementById("pwa-install");

  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredPrompt = e;
    if (installBtn) installBtn.classList.remove("hidden");
  });

  if (installBtn) {
    installBtn.addEventListener("click", async () => {
      if (!deferredPrompt) return;
      deferredPrompt.prompt();
      try { await deferredPrompt.userChoice; } catch {}
      deferredPrompt = null;
      installBtn.classList.add("hidden");
    });
  }

  // iOS hint (Safari doesn’t fire beforeinstallprompt)
  const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
  const standalone =
    window.matchMedia("(display-mode: standalone)").matches ||
    window.navigator.standalone === true;
  if (isIOS && !standalone && !localStorage.getItem("pwa_ios_hint_shown")) {
    localStorage.setItem("pwa_ios_hint_shown", "1");
    setTimeout(() => {
      const bar = document.createElement("div");
      bar.className = "pwa-bar";
      bar.innerHTML =
        'Install Privana: tap <strong>Share</strong> → <strong>Add to Home Screen</strong>. <button type="button">Got it</button>';
      document.body.appendChild(bar);
      bar.querySelector("button").addEventListener("click", () => bar.remove());
    }, 800);
  }

  // Offline/online micro-toasts
  window.addEventListener("offline", () => toast("You’re offline."));
  window.addEventListener("online",  () => toast("Back online."));

  // Public helpers
  window.PWA = Object.assign(window.PWA || {}, {
    install: () => {
      if (deferredPrompt) { deferredPrompt.prompt(); deferredPrompt = null; }
      else toast("Install not available here.");
    },
    checkForUpdate: () => {
      if (navigator.serviceWorker && window.PWA._reg) window.PWA._reg.update();
    },
  });
})();
