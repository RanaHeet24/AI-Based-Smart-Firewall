document.addEventListener('DOMContentLoaded', () => {
    // Fetch the exact details from Chrome Local Storage (set by background.js)
    chrome.storage.local.get(['lastResult'], function(data) {
        const result = data.lastResult || {};
        
        // 1. Set URL (Fallback to unknown if missing)
        const finalUrl = result.url || 'Unknown Target URL';
        document.getElementById('url-text').textContent = finalUrl;
        
        // 2. Set Score
        // Ensure we grab the score accurately regardless of the field name
        let scoreVal = 0.85; // Default high risk score
        if (result.score !== undefined) scoreVal = parseFloat(result.score);
        else if (result.risk_score !== undefined) scoreVal = parseFloat(result.risk_score);
        else if (result.final_score !== undefined) scoreVal = parseFloat(result.final_score);
        
        document.getElementById('score-text').textContent = scoreVal.toFixed(2);
        
        // Animate progress bar slightly after load for effect
        setTimeout(() => {
            const percentage = Math.min(100, Math.max(0, scoreVal * 100));
            document.getElementById('score-bar').style.width = percentage + '%';
        }, 100);

        // 3. Set Category Tag
        const category = result.category || 'MALWARE';
        if (category === 'PHISHING') {
            document.getElementById('tag-phishing').classList.add('active');
        } else if (category === 'PIRACY') {
            document.getElementById('tag-piracy').classList.add('active');
        } else if (category === 'MALWARE') {
            document.getElementById('tag-malware').classList.add('active');
        } else {
            document.getElementById('tag-suspicious').classList.add('active');
        }

        // 4. Set Reasons List
        const reasonsText = document.getElementById('reasons-text');
        const finalReasons = (result.reasons && result.reasons.length > 0) 
                             ? result.reasons 
                             : ["Unauthorized or malicious indicators found."];
        reasonsText.textContent = finalReasons.join(" | ");
    });

    // 5. Button Actions
    document.getElementById('btn-back').addEventListener('click', () => {
         // Try to go back in history. 
         if (window.history.length > 2) {
             window.history.back();
         } else {
             // If no history exists, go to Google as fallback, or close the tab
             chrome.tabs.getCurrent(function(tab) {
                 if (tab) {
                     chrome.tabs.remove(tab.id);
                 } else {
                     window.location.href = "https://www.google.com";
                 }
             });
         }
    });

    document.getElementById('btn-new').addEventListener('click', () => {
        // Attempt to create a new tab. window.location.href = "chrome://newtab/" is blocked by CSP
        chrome.tabs.create({});
    });
});
