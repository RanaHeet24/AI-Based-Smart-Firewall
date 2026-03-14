// AI Smart Firewall - Popup Script
// Reads the last firewall decision from storage and displays it in the popup.

function getDecisionIcon(decision) {
    switch (decision) {
        case "BLOCK": return "⛔";
        case "WARN": return "⚠️";
        case "ALLOW": return "✅";
        default: return "🔍";
    }
}

function getDecisionText(decision) {
    switch (decision) {
        case "BLOCK": return "BLOCKED - Threat Detected";
        case "WARN": return "WARNING - Suspicious";
        case "ALLOW": return "SAFE";
        default: return "Unknown";
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const area = document.getElementById("result-area");

    chrome.storage.session.get("lastResult", (data) => {
        const r = data.lastResult;
        if (!r) {
            area.innerHTML = `<p class="no-data">Browse a website to see the firewall analysis.</p>`;
            return;
        }

        const score = parseFloat(r.score || 0);
        const barWidth = Math.round(score * 100);

        area.innerHTML = `
            <div class="status-card">
                <div class="status-label">Firewall Decision</div>
                <div class="decision ${r.decision}">
                    ${getDecisionIcon(r.decision)} ${getDecisionText(r.decision)}
                </div>
                <div class="score-bar-bg">
                    <div class="score-bar ${r.decision}" style="width: ${barWidth}%"></div>
                </div>
                <div style="margin-top: 6px; font-size: 11px; color: #8b949e;">
                    Risk Score: <strong style="color: #e6edf3;">${score.toFixed(2)}</strong>
                </div>
            </div>
            <div class="status-label" style="margin-bottom: 6px;">Analyzed URL</div>
            <div class="url-box">${r.url}</div>
        `;
    });
});
