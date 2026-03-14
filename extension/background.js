// AI Smart Firewall — Background Service Worker (MV3)
const API_URL = "http://127.0.0.1:5000/check-url";
const API_TIMEOUT_MS = 6000; // Increased to 6s to account for slow networks + 3.5s backend timeout

// Whitelist patterns that should NEVER be intercepted
const IGNORE_PATTERNS = [
    "chrome://",
    "chrome-extension://",
    "edge://",
    "http://127.0.0.1",
    "http://localhost",
    "https://localhost",
    "about:",
    "file://",
    "view-source:",
    "https://www.google.com/search" // Don't intercept search result pages to reduce lag
];

function shouldIgnore(url) {
    if (!url) return true;
    return IGNORE_PATTERNS.some(pattern => url.startsWith(pattern));
}

// Utility: fetch with timeout to prevent hanging the browser
async function fetchWithTimeout(url, options, ms) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), ms);
    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } finally {
        clearTimeout(id);
    }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only intercept top-level frame navigations
    if (details.frameId !== 0) return;

    const url = details.url;
    
    // 1. Filtering: Ignore internal, local, and search engine query pages (for performance)
    if (shouldIgnore(url)) {
        return;
    }

    // Ignore our own blocked page
    if (url.includes(chrome.runtime.id)) return;

    console.log(`[AI Firewall] Checking: ${url}`);

    try {
        const response = await fetchWithTimeout(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        }, API_TIMEOUT_MS);

        if (!response.ok) {
            console.warn(`[AI Firewall] API error ${response.status}. Allowing.`);
            return;
        }

        const result = await response.json();
        
        console.log(`[AI Firewall] Result: ${result.decision} (Score: ${result.score || result.risk_score || 0})`);

        // Update badge
        let color = "#00ff00"; // Safe
        let text = "";
        
        if (result.decision === "BLOCK") {
            color = "#ff0000";
            text = "!";
        } else if (result.decision === "WARN") {
            color = "#ffcc00";
            text = "?";
        }
        
        chrome.action.setBadgeBackgroundColor({ color, tabId: details.tabId });
        chrome.action.setBadgeText({ text, tabId: details.tabId });

        // Store result for popup and blocked.html using local storage (more reliable than session)
        chrome.storage.local.set({ 
            lastResult: { url, ...result, tabId: details.tabId, timestamp: Date.now() } 
        }, () => {
            // 2. BLOCK REDIRECTION (Wait for storage to save first)
            if (result.decision === "BLOCK") {
                const blockedPageUrl = chrome.runtime.getURL("blocked.html");
                console.log(`[AI Firewall] Blocking threat: ${url}`);
                chrome.tabs.update(details.tabId, { url: blockedPageUrl });
            }
        });

    } catch (err) {
        // Log detail but allow navigation to prevent breaking the web on network lag
        console.warn(`[AI Firewall] Pass-through (Timeout/Unreachable): ${err.message}`);
    }
});

// Clear badge on new loads
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
        chrome.action.setBadgeText({ text: "", tabId });
    }
});
