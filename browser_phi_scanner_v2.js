/*
Browser PHI Scanner v2
Advanced browser-side heuristic scanner for potential PHI exposure.

How to use:
1. Open app in Chrome/Edge.
2. Open DevTools Console.
3. Paste this file and press Enter.
4. Continue navigating in the app to capture fetch/XHR responses.
5. Inspect results at window.__PHI_SCAN_RESULTS__.

This is heuristic and may produce false positives.
*/

(() => {
  if (window.__PHI_SCANNER_V2_INSTALLED__) {
    console.warn("[PHI] Scanner v2 is already installed.");
    return;
  }
  window.__PHI_SCANNER_V2_INSTALLED__ = true;

  const PHI_REGEX = /\b(patient|participant|email|name|dob|birth(?:date)?|diagnosis|medical|study|site|trial|record|mrn|subject|enrollment|investigator|clinic|hospital|chart)\b/i;
  const MAX_TEXT_LEN = 600;
  const MAX_DOM_NODES = 5000;

  const results = {
    startedAt: new Date().toISOString(),
    findings: [],
    networkInstalled: false,
    notes: []
  };

  function addFinding(area, key, value, meta = {}) {
    const entry = {
      ts: new Date().toISOString(),
      area,
      key: String(key || ""),
      sample: String(value || "").slice(0, MAX_TEXT_LEN),
      meta
    };
    results.findings.push(entry);
    console.warn("[PHI WARNING]", entry);
  }

  function safeString(v) {
    try {
      if (v == null) return "";
      if (typeof v === "string") return v;
      return JSON.stringify(v);
    } catch {
      return String(v);
    }
  }

  function scanWebStorage(storage, label) {
    try {
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        const value = storage.getItem(key);
        const joined = `${key} ${value}`;
        if (PHI_REGEX.test(joined)) {
          addFinding(label, key, value);
        }
      }
    } catch (e) {
      results.notes.push(`Failed scanning ${label}: ${e.message}`);
    }
  }

  function scanCookies() {
    try {
      const cookies = document.cookie ? document.cookie.split(";") : [];
      for (const c of cookies) {
        if (PHI_REGEX.test(c)) {
          addFinding("cookies", "document.cookie", c.trim());
        }
      }
    } catch (e) {
      results.notes.push(`Failed scanning cookies: ${e.message}`);
    }
  }

  function scanUrl() {
    try {
      const href = window.location.href;
      if (PHI_REGEX.test(href)) {
        addFinding("url", "window.location.href", href);
      }
    } catch (e) {
      results.notes.push(`Failed scanning URL: ${e.message}`);
    }
  }

  async function scanIndexedDbNames() {
    try {
      if (!indexedDB.databases) {
        results.notes.push("indexedDB.databases() not supported in this browser.");
        return;
      }
      const dbs = await indexedDB.databases();
      for (const db of dbs || []) {
        const s = safeString(db);
        if (PHI_REGEX.test(s)) {
          addFinding("indexeddb", db.name || "db", s);
        }
      }
    } catch (e) {
      results.notes.push(`Failed scanning IndexedDB: ${e.message}`);
    }
  }

  async function scanCacheKeys() {
    try {
      if (!("caches" in window)) {
        results.notes.push("Cache API not supported.");
        return;
      }
      const keys = await caches.keys();
      for (const key of keys) {
        if (PHI_REGEX.test(key)) {
          addFinding("cache-storage", key, key);
        }
      }
    } catch (e) {
      results.notes.push(`Failed scanning caches: ${e.message}`);
    }
  }

  function scanDomText() {
    try {
      const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
      let count = 0;
      while (walker.nextNode()) {
        const text = (walker.currentNode.nodeValue || "").trim();
        if (!text) continue;
        count++;
        if (count > MAX_DOM_NODES) {
          results.notes.push(`DOM scan capped at ${MAX_DOM_NODES} text nodes.`);
          break;
        }
        if (PHI_REGEX.test(text)) {
          const parent = walker.currentNode.parentElement;
          addFinding("dom-text", parent ? parent.tagName : "TEXT", text, {
            selector: parent ? cssPath(parent) : null
          });
        }
      }
    } catch (e) {
      results.notes.push(`Failed scanning DOM text: ${e.message}`);
    }
  }

  function cssPath(el) {
    if (!el || !el.tagName) return null;
    const parts = [];
    while (el && el.nodeType === 1 && parts.length < 5) {
      let part = el.tagName.toLowerCase();
      if (el.id) {
        part += "#" + el.id;
        parts.unshift(part);
        break;
      }
      if (el.classList && el.classList.length) {
        part += "." + Array.from(el.classList).slice(0, 2).join(".");
      }
      parts.unshift(part);
      el = el.parentElement;
    }
    return parts.join(" > ");
  }

  function installNetworkHooks() {
    if (results.networkInstalled) return;
    results.networkInstalled = true;

    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
      const response = await originalFetch.apply(this, args);
      try {
        const clone = response.clone();
        const text = await clone.text();
        if (PHI_REGEX.test(text)) {
          addFinding("network-fetch", args[0], text, {
            status: response.status
          });
        }
      } catch (e) {
        results.notes.push(`Fetch clone/read failed: ${e.message}`);
      }
      return response;
    };

    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      this.__phi_scan_method = method;
      this.__phi_scan_url = url;
      return originalOpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function(...args) {
      this.addEventListener("load", function() {
        try {
          const text = this.responseText || "";
          if (PHI_REGEX.test(text)) {
            addFinding("network-xhr", this.__phi_scan_url || "xhr", text, {
              status: this.status,
              method: this.__phi_scan_method || "GET"
            });
          }
        } catch (e) {
          results.notes.push(`XHR response read failed: ${e.message}`);
        }
      });
      return originalSend.apply(this, args);
    };
  }

  async function runInitialScan() {
    console.log("[PHI] Starting Browser PHI Scanner v2...");
    scanWebStorage(localStorage, "localStorage");
    scanWebStorage(sessionStorage, "sessionStorage");
    scanCookies();
    scanUrl();
    scanDomText();
    await scanIndexedDbNames();
    await scanCacheKeys();
    installNetworkHooks();
    results.completedInitialScanAt = new Date().toISOString();
    window.__PHI_SCAN_RESULTS__ = results;
    console.log("[PHI] Initial scan complete.");
    console.log("[PHI] Continue using the app to collect network findings.");
    console.log("[PHI] Results available at window.__PHI_SCAN_RESULTS__");
    if (results.findings.length === 0) {
      console.log("[PHI] No heuristic matches found during initial scan.");
    }
  }

  window.__PHI_SCAN_RESULTS__ = results;
  runInitialScan();
})();
