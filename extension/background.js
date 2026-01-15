const API_URL = 'http://localhost:5000/predict';
const REPORT_API_URL = 'http://localhost:5000/report';

const SYSTEM_EXEMPTIONS = [
    'chrome://',
    'chrome-extension://',
    'edge://',
    'about:',
    'view-source:',
    'localhost',
    '127.0.0.1'
];

// --- ENTROPY CALCULATION (To capture random domains) ---
function calculateEntropy(str) {
    const len = str.length;
    if (len === 0) return 0;
    const freq = {};
    for (let i = 0; i < len; i++) {
        freq[str[i]] = (freq[str[i]] || 0) + 1;
    }
    let entropy = 0;
    for (const char in freq) {
        const p = freq[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

// --- FUNCTION 1: ADVANCED FEATURE EXTRACTION ---
function extractFeatures(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.replace('www.', '');
        
        // Sensitive Words and Dangerous Extensions
        const sensitiveWords = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'wallet', 'binance', 'confirm'];
        const suspiciousTlds = ['.cyou', '.info', '.top', '.xyz', '.online', '.site', '.click', '.pw'];
        const shortenedServices = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'rebrand.ly'];

        const letters = (url.match(/[a-zA-Z]/g) || []).length;
        const digits = (url.match(/\d/g) || []).length;
        const specials = (url.match(/[^a-zA-Z0-9]/g) || []).length;

        // Brand and Word Analysis
        const numSensitive = sensitiveWords.filter(word => url.toLowerCase().includes(word)).length;
        const brandInSub = (hostname.split('.').length > 2 && sensitiveWords.some(word => hostname.split('.')[0].includes(word))) ? 1 : 0;

        return {
            // Old Features (For Model Compatibility)
            URLLength: url.length,
            DomainLength: hostname.length,
            IsDomainIP: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname) ? 1 : 0,
            TLDLength: hostname.split('.').pop().length,
            NoOfSubDomain: hostname.split('.').length - 2,
            LetterRatioInURL: letters / url.length,
            DegitRatioInURL: digits / url.length,
            NoOfOtherSpecialCharsInURL: specials,
            IsHTTPS: urlObj.protocol === 'https:' ? 1 : 0,

            // --- NEW FEATURES ---
            EntropyScore: calculateEntropy(hostname),
            NumDashURL: (url.split('-').length - 1),
            BrandInSubdomain: brandInSub,
            NoOfSensitiveWords: numSensitive,
            ShortenedURL: shortenedServices.some(s => hostname.includes(s)) ? 1 : 0,
            TldType: suspiciousTlds.some(tld => hostname.endsWith(tld)) ? 1 : 0,
            AbnormalDomain: (hostname.match(/\.(com|net|org|gov|edu|com\.tr)\./) ? 1 : 0)
        };
    } catch (e) { return null; }
}

// --- FUNCTION 2: REAL-TIME MACHINE LEARNING ANALYSIS ---
async function performMLAnalysis(features) {
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(features)
        });
        if (!response.ok) throw new Error(`API error: ${response.status}`);
        return await response.json(); 
    } catch (error) {
        console.error("ML API error:", error);
        return { isPhishing: false, confidence: 0.0, status: 'error' }; 
    }
}

// --- FUNCTION 3: ANALYSIS WORKFLOW ---
async function runAnalysis(tabId, url) {
    const settings = await chrome.storage.local.get(['extensionEnabled']);
    if (settings.extensionEnabled === false) return;

    if (url && SYSTEM_EXEMPTIONS.some(ex => url.startsWith(ex))) {
        try {
            chrome.runtime.sendMessage({ 
                action: "updatePopupStatus", 
                result: { status: 'browser_protected' } 
            });
        } catch (e) {}
        return;
    }

    const urlFeatures = extractFeatures(url);

    try {
        chrome.tabs.sendMessage(tabId, { action: "getPageContentFeatures" }, async (contentFeatures) => {
            
            const defaultContentFeatures = {
                LineOfCode: 0, 
                HasPasswordField: 0, 
                HasHiddenFields: 0, 
                NoOfImage: 0, 
                NoOfCSS: 0, 
                NoOfJS: 0, 
                NoOfExternalRef: 0
            };

            const finalFeatures = { 
                ...urlFeatures, 
                ...(contentFeatures || defaultContentFeatures),
                url: url 
            };
            
            const result = await performMLAnalysis(finalFeatures);
            
            const HIGH_RISK_THRESHOLD = 0.33; 

            if (result.status === 'trusted_global') {
                console.log("This website is on the whitelist");
            } else if (result.confidence >= HIGH_RISK_THRESHOLD || result.usom_detected) {
                chrome.tabs.sendMessage(tabId, {
                    action: "showWarning",
                    riskPercent: (result.confidence * 100).toFixed(2),
                    usomDetected: result.usom_detected
                });
            }
            
            try {
                chrome.runtime.sendMessage({ action: "updatePopupStatus", result: result });
            } catch (e) {}
        });
    } catch (e) {
        console.error("Analysis error:", e);
    }
}

// --- LISTENERS ---
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        runAnalysis(tabId, tab.url);
    }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyzeCurrentTab") {
        runAnalysis(request.tabId, request.url); 
        return true; 
    }
    if (request.action === "closeTab" && sender.tab) {
        chrome.tabs.remove(sender.tab.id);
        return true;
    }
    if (request.action === "reportFromModal") {
        fetch(REPORT_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(request)
        })
        .then(() => sendResponse({ success: true }))
        .catch(() => sendResponse({ error: true }));
        return true;
    }
});